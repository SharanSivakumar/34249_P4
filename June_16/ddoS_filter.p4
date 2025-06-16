#include <core.p4>
#include <v1model.p4>

const bit<32> DDOS_THRESHOLD = 100;
const bit<32> BLOOM_SIZE = 1024;

// ----------------- HEADERS ------------------
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct my_headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    bit<32> bloom_idx1;
    bit<32> bloom_idx2;
    bit<32> count_idx;
    bit<1> drop_flag;
}

// ----------------- REGISTERS ------------------
register<bit<1>>(BLOOM_SIZE) bloom1;
register<bit<1>>(BLOOM_SIZE) bloom2;
register<bit<16>>(BLOOM_SIZE) pkt_count;

// ----------------- PARSER ------------------
parser MyParser(packet_in pkt,
                out my_headers_t hdr,
                inout metadata meta,
                inout standard_metadata_t stdmeta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// ----------------- CHECKSUM VERIFICATION ------------------
control MyVerifyChecksum(inout my_headers_t hdr,
                         inout metadata meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// ----------------- INGRESS ------------------
control MyIngress(inout my_headers_t hdr,
                  inout metadata meta,
                  inout standard_metadata_t stdmeta) {

    action compute_hashes() {
        bit<32> h1;
        hash(h1, HashAlgorithm.crc32, (bit<32>)0x12345678, {hdr.ipv4.srcAddr}, BLOOM_SIZE);
        meta.bloom_idx1 = h1;

        bit<32> h2;
        hash(h2, HashAlgorithm.crc32, (bit<32>)0x87654321, {hdr.ipv4.srcAddr}, BLOOM_SIZE);
        meta.bloom_idx2 = h2;

        bit<32> h3;
        hash(h3, HashAlgorithm.crc32, (bit<32>)0xA5A5A5A5, {hdr.ipv4.srcAddr}, BLOOM_SIZE);
        meta.count_idx = h3;

        meta.drop_flag = 0;
    }

    action check_bloom() {
        bit<1> b1;
        bit<1> b2;
        bloom1.read(b1, meta.bloom_idx1);
        bloom2.read(b2, meta.bloom_idx2);
        meta.drop_flag = b1 & b2;
    }

    action increment_counter() {
        bit<16> cnt;
        pkt_count.read(cnt, meta.count_idx);
        cnt = cnt + 1;
        pkt_count.write(meta.count_idx, cnt);
    }

    action read_counter_and_check() {
        bit<16> cnt;
        pkt_count.read(cnt, meta.count_idx);
        bit<32> cnt32 = (bit<32>)cnt;
        meta.drop_flag = (cnt32 >= DDOS_THRESHOLD) ? (bit<1>)1 : (bit<1>)0;
    }

    action set_bloom_filter() {
        bloom1.write(meta.bloom_idx1, 1);
        bloom2.write(meta.bloom_idx2, 1);
    }

    action forward(bit<9> port) {
        stdmeta.egress_spec = port;
    }

    action drop() {
        mark_to_drop(stdmeta);
    }

    table forwarding {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            compute_hashes();
            check_bloom();

            if (meta.drop_flag == 0) {
                increment_counter();
                read_counter_and_check();
                if (meta.drop_flag == 1) {
                    set_bloom_filter();
                }
            }

            if (meta.drop_flag == 1) {
                drop();
                return;
            }

            // Forward packet if not dropped
            forwarding.apply();
        } else {
            drop();
        }
    }
}

// ----------------- EGRESS ------------------
control MyEgress(inout my_headers_t hdr,
                 inout metadata meta,
                 inout standard_metadata_t stdmeta) {
    apply { }
}

// ----------------- CHECKSUM UPDATE ------------------
control MyComputeChecksum(inout my_headers_t hdr,
                          inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// ----------------- DEPARSER ------------------
control MyDeparser(packet_out pkt,
                   in my_headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

// ----------------- SWITCH PACKAGE ------------------
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;