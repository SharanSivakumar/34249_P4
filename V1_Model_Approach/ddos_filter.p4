
#include <core.p4>
#include <v1model.p4>

const bit<32> GLOBAL_DDOS_THRESHOLD = 200;  
const bit<32> SYN_FLOOD_THRESHOLD   = 100;  
const bit<32> TIME_WINDOW_MS        = 1000;
const bit<32> RATE_LIMIT_PPS        = 10;
const bit<32> SYN_RATE_LIMIT_PPS    = 5;


typedef bit<9> egressSpec_t;

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

struct metadata {
    bit<16> l4_dstPort;
}

// Registers
register<bit<32>>(1024) ip_pkt_cnt;
register<bit<32>>(1024) ip_syn_cnt;
register<bit<32>>(1024) port_thresh;
register<bit<1>>(1)     blackhole_flag;

register<bit<48>>(1024) ip_last_seen;
register<bit<32>>(1024) ip_window_count;
register<bit<48>>(1024) ip_window_start;
register<bit<32>>(1024) ip_syn_window_count;
register<bit<48>>(1024) ip_syn_window_start;
// Emulated time-based rate limiting
register<bit<32>>(1) global_tick;
register<bit<32>>(1024) ip_tick_last;
register<bit<32>>(1024) ip_tick_count;
register<bit<32>>(1024) ip_syn_tick_last;
register<bit<32>>(1024) ip_syn_tick_count;

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t smeta)
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
                  inout standard_metadata_t smeta)
{
    action drop() {
        mark_to_drop(smeta);
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

        // L4 port extraction
        if (hdr.tcp.isValid()) {
            meta.l4_dstPort = hdr.tcp.dstPort;
        } else if (hdr.udp.isValid()) {
            meta.l4_dstPort = hdr.udp.dstPort;
        } else {
            meta.l4_dstPort = 0;
        }

        // Blackhole flag check
        bit<1> bh;
        blackhole_flag.read(bh, 0);
        if (bh == 1w1) {
            drop(); return;
        }

        // Whitelist logic
        if (whitelist.apply().hit) {
            bit<32> idx = hdr.ip.srcAddr & 0x3FF;
            bit<32> c;
            ip_pkt_cnt.read(c, idx);
            ip_pkt_cnt.write(idx, c + 1);
            return;
        }

        // Blacklist logic
        if (blacklist_check.apply().hit) {
            drop(); return;
        }

        // Port filtering
        if (!allowed_ports.apply().hit) {
            drop(); return;
        }

        // Index calculations
        bit<32> ip_idx = hdr.ip.srcAddr & 0x3FF;
        bit<32> port_idx = (bit<32>) meta.l4_dstPort & 0x3FF;
        bit<48> current_time = smeta.ingress_global_timestamp;
        bit<48> time_window_ns = (bit<48>) TIME_WINDOW_MS * 1000000;

        // --- Packet rate limiting ---
        bit<32> tick;
        bit<32> last_tick;
        bit<32> tick_count;

        global_tick.read(tick, 0);
        ip_tick_last.read(last_tick, ip_idx);
        ip_tick_count.read(tick_count, ip_idx);

        bit<32> updated_tick_count;
        bit<32> updated_last_tick;

        if (tick != last_tick) {
            updated_last_tick = tick;
            updated_tick_count = 1;
        } else {
            updated_last_tick = last_tick;
            updated_tick_count = tick_count + 1;
        }

        ip_tick_last.write(ip_idx, updated_last_tick);
        ip_tick_count.write(ip_idx, updated_tick_count);

        if (updated_tick_count >= RATE_LIMIT_PPS) {
            digest(0, { hdr.ip.srcAddr });
            drop(); return;
        }
        
        // --- SYN packet rate limiting ---
        if (hdr.tcp.isValid() && (hdr.tcp.flags & 0x02) != 0x00) {
            bit<48> syn_window_start;
            bit<32> syn_window_count;
            ip_syn_window_start.read(syn_window_start, ip_idx);
            ip_syn_window_count.read(syn_window_count, ip_idx);

            bit<48> updated_syn_start;
            bit<32> updated_syn_count;

            if (current_time - syn_window_start >= time_window_ns || syn_window_start == 0) {
                updated_syn_start = current_time;
                updated_syn_count = 1;
            } else {
                updated_syn_start = syn_window_start;
                updated_syn_count = syn_window_count + 1;
            }

            ip_syn_window_start.write(ip_idx, updated_syn_start);
            ip_syn_window_count.write(ip_idx, updated_syn_count);

            if (updated_syn_count >= SYN_RATE_LIMIT_PPS) {
                digest(0, { hdr.ip.srcAddr });
                drop(); return;
            }

            // Fallback: Legacy SYN counter
            bit<32> syn_total;
            ip_syn_cnt.read(syn_total, ip_idx);
            syn_total = syn_total + 1;
            ip_syn_cnt.write(ip_idx, syn_total);

            if (syn_total >= SYN_FLOOD_THRESHOLD) {
                digest(0, { hdr.ip.srcAddr });
                drop(); return;
            }
        }

            if (hdr.tcp.isValid() && (hdr.tcp.flags & 0x02) != 0x00) {
            bit<32> syn_tick;
            bit<32> last_syn_tick;
            bit<32> syn_tick_count;

            global_tick.read(syn_tick, 0);
            ip_syn_tick_last.read(last_syn_tick, ip_idx);
            ip_syn_tick_count.read(syn_tick_count, ip_idx);

            bit<32> updated_syn_tick;
            bit<32> updated_syn_count;

            if (syn_tick != last_syn_tick) {
                updated_syn_tick = syn_tick;
                updated_syn_count = 1;
            } else {
                updated_syn_tick = last_syn_tick;
                updated_syn_count = syn_tick_count + 1;
            }

            ip_syn_tick_last.write(ip_idx, updated_syn_tick);
            ip_syn_tick_count.write(ip_idx, updated_syn_count);

            if (updated_syn_count >= SYN_RATE_LIMIT_PPS) {
                digest(0, { hdr.ip.srcAddr });
                drop(); return;
            }
        }

        // --- Legacy port-threshold check ---
        bit<32> pkt_count;
        ip_pkt_cnt.read(pkt_count, ip_idx);
        pkt_count = pkt_count + 1;
        ip_pkt_cnt.write(ip_idx, pkt_count);

        bit<32> threshold;
        port_thresh.read(threshold, port_idx);
        if (threshold == 0) {
            threshold = GLOBAL_DDOS_THRESHOLD;
        }

        if (pkt_count >= threshold) {
            digest(0, { hdr.ip.srcAddr });
            drop(); return;
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t smeta) {
    apply { }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

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