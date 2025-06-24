#include <core.p4>
#include <tna.p4>

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
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
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
    ipv4_t     ip;
    tcp_t      tcp;
    udp_t      udp;
}

struct digest_t {
    PortId_t port;
    bit<32> srcAddr;
}

struct metadata {
    digest_t digest_a;
    PortId_t port;
    bit<16> l4_dstPort;
    bit<3> drop_ctl;
    bit<3> digest_type;
    bit<3> resubmit_type;
}

Register<bit<32>, bit<32>>(1024) ip_pkt_cnt;
Register<bit<32>, bit<32>>(1024) ip_syn_cnt;
Register<bit<32>, bit<32>>(1024) port_thresh;
Register<bit<1>, bit>(1)     blackhole_flag;

parser MyIngressParser(packet_in packet,
                out headers hdr,
                out metadata meta,
                out ingress_intrinsic_metadata_t smeta)
{
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
                  in ingress_intrinsic_metadata_t smeta,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{

    Digest<digest_t>() digest_a;
    Digest<digest_t>() digest_b;

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action allow() { }

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

        if (hdr.tcp.isValid()) {
            meta.l4_dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.l4_dstPort = hdr.udp.dstPort;
        } else {
            meta.l4_dstPort = 0;
        }

        bit<1> bh;
        bh = blackhole_flag.read(0);
        if (bh == 1w1) {
            drop(); return;
        }

        if (whitelist.apply().hit) {
            bit<32> idx = hdr.ip.srcAddr & 0x3FF;
            bit<32> c;
            c = ip_pkt_cnt.read(idx);
            ip_pkt_cnt.write(idx, c + 1);
            return;
        }

        if (blacklist_check.apply().hit) return;

        if (!allowed_ports.apply().hit) {
            drop(); return;
        }

        bit<32> ip_idx = hdr.ip.srcAddr & 0x3FF;
        bit<32> port_idx = (bit<32>) meta.l4_dstPort & 0x3FF;

        bit<32> pcount;
        pcount = ip_pkt_cnt.read(ip_idx);
        pcount = pcount + 1;
        ip_pkt_cnt.write(ip_idx, pcount);

        bit<32> thresh;
        thresh = port_thresh.read(port_idx);
        if (thresh == 0) {
            thresh = GLOBAL_DDOS_THRESHOLD;
        }

        if (pcount >= thresh) {
            digest_a.pack({0, hdr.ip.srcAddr });
            drop(); return;
        }

        if (hdr.tcp.isValid() && (hdr.tcp.flags & 0x02) != 0x00) {
            bit<32> syn_count;
            syn_count = ip_syn_cnt.read(ip_idx);
            syn_count = syn_count + 1;
            ip_syn_cnt.write(ip_idx, syn_count);

            if (syn_count >= SYN_FLOOD_THRESHOLD) {
                digest_b.pack({0, hdr.ip.srcAddr });
                drop(); return;
            }
        }
    }
}

control MyIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in metadata md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
        apply {
        // emit headers for out-of-ingress packets here
        }
}

parser MyEgressParser(
        packet_in pkt,
        out headers hdr,
        out metadata md,
        out egress_intrinsic_metadata_t eg_intr_md)
{
        state start {
        // parser code begins here
        transition accept;
        }
}

control MyEgress(inout headers hdr,
                 inout metadata eg_md,
                 in egress_intrinsic_metadata_t eg_intr_md) {
    apply { }
}

control MyEgressDeparser(packet_out packet, inout headers hdr, in metadata eg_md) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.ip);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

Pipeline(
    MyIngressParser(),
    MyIngress(),
    MyIngressDeparser(),
    MyEgressParser(),
    MyEgress(),
    MyEgressDeparser()
) pipe;
Switch(pipe) main;
