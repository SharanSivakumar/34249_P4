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

struct headers {
    ethernet_t eth;
    ipv4_t     ip;
}

struct metadata {}

register<bit<32>>(1024) pkt_count;

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ip);
        transition accept;
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t smeta) {

    action count_and_filter() {
        bit<32> count;
        pkt_count.read(count, hdr.ip.srcAddr[11:0]);
        count = count + 1;
        pkt_count.write(hdr.ip.srcAddr[11:0], count);

        if (count > DDOS_THRESHOLD) {
            smeta.drop = 1;
        }
    }

    apply {
        if (hdr.ip.isValid()) {
            count_and_filter();
        }
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ip);
    }
}

control MyVerifyChecksum(...) { apply {} }
control MyComputeChecksum(...) { apply {} }

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
