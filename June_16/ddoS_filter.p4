#include <core.p4>
#include <v1model.p4>

const bit<32> DDOS_THRESHOLD = 5;

typedef bit<9>  egressSpec_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers {
    ethernet_t eth;
    ipv4_t     ip;
    tcp_t      tcp;
}

struct metadata {}

register<bit<32>>(1024) pkt_count;

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
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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
        // no-op
    }

    action count_packet() {
        bit<32> count;
        pkt_count.read(count, hdr.ip.srcAddr);
        count = count + 1;
        pkt_count.write(hdr.ip.srcAddr, count);
    }

    table blacklist_check {
        key = {
            hdr.ip.srcAddr: exact;
        }
        actions = {
            drop;
            allow;
        }
        size = 64;
        default_action = allow();
    }

    table allowed_ports {
        key = {
            hdr.tcp.dstPort: exact;
        }
        actions = {
            drop;
            allow;
        }
        size = 32;
        default_action = drop();
    }

    apply {
        if (hdr.ip.isValid() && hdr.tcp.isValid()) {
            blacklist_check.apply();
            allowed_ports.apply();

            // Count packets from source IP
            count_packet();

            // Re-read to check threshold
            bit<32> count;
            pkt_count.read(count, hdr.ip.srcAddr);
            if (count > DDOS_THRESHOLD) {
                mark_to_drop(smeta);
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t smeta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ip);
        packet.emit(hdr.tcp);
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
