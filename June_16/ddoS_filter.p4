#include <core.p4>
#include <v1model.p4>

const bit<32> GLOBAL_DDOS_THRESHOLD = 5;
const bit<32> SYN_FLOOD_THRESHOLD = 20;
typedef bit<9> egressSpec_t;

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
    bit<16> len;
    bit<16> checksum;
}

struct headers {
    ethernet_t eth;
    ipv4_t ip;
    tcp_t tcp;
    udp_t udp;
}

struct metadata {
    bit<16> l4_dstPort;
}

register<bit<32>>(1024) ip_pkt_cnt;
register<bit<32>>(1024) ip_syn_cnt;
register<bit<32>>(1024) port_thresh;
register<bit<1>>(1) blackhole_flag;

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t smeta) {
    state start {
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ip);
        transition select(hdr.ip.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t smeta) {

    action drop() {
        mark_to_drop(smeta);
    }

    action allow() {
        // Do nothing
    }

    action count_ip() {
        bit<32> c;
        bit<32> idx = hdr.ip.srcAddr & 0x3FF;
        ip_pkt_cnt.read(c, idx);
        ip_pkt_cnt.write(idx, c + 1);
    }

    action count_syn() {
        bit<32> c;
        bit<32> idx = hdr.ip.srcAddr & 0x3FF;
        ip_syn_cnt.read(c, idx);
        ip_syn_cnt.write(idx, c + 1);
    }

    action alert_digest() {
        digest(0, { hdr.ip.srcAddr });
    }

    table whitelist {
        key = { hdr.ip.srcAddr : exact; }
        actions = { allow; }
        size = 64;
        default_action = allow();
    }

    table blacklist_check {
        key = { hdr.ip.srcAddr : exact; }
        actions = { drop; allow; }
        size = 64;
        default_action = allow();
    }

    table allowed_ports {
        key = { meta.l4_dstPort : exact; }
        actions = { allow; drop; }
        size = 32;
        default_action = drop();
    }

    apply {
        if (!hdr.ip.isValid()) return;

        bit<32> ip_idx = hdr.ip.srcAddr & 0x3FF;

        if (hdr.tcp.isValid()) {
            meta.l4_dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.l4_dstPort = hdr.udp.dstPort;
        } else {
            meta.l4_dstPort = 0;
        }

        bit<1> bh;
        blackhole_flag.read(bh, 0);
        if (bh == 1w1) {
            drop();
            return;
        }

        if (whitelist.apply().hit) {
            count_ip();
            return;
        }

        if (blacklist_check.apply().hit) {
            return;
        }

        bit<32> pcount;
        ip_pkt_cnt.read(pcount, ip_idx);

        bit<32> thresh;
        bit<32> p_idx = (bit<32>) meta.l4_dstPort & 0x3FF;
        port_thresh.read(thresh, p_idx);
        if (thresh == 0) {
            thresh = GLOBAL_DDOS_THRESHOLD;
        }

        if (pcount >= thresh) {
            alert_digest();
            drop();
            return;
        }

        if (hdr.tcp.isValid() && hdr.tcp.flags == 0x02) {
            count_syn();
            bit<32> scount;
            ip_syn_cnt.read(scount, ip_idx);
            if (scount >= SYN_FLOOD_THRESHOLD) {
                alert_digest();
                drop();
                return;
            }
        }

        allowed_ports.apply();
        count_ip();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t smeta) {
    apply { }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ip);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
