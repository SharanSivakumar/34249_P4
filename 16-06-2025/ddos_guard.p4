/* ddos_guard.p4  ────────────────
 * Simple per-source-IP rate-limit firewall for BMv2 (v1model)
 * - Drops traffic from any IPv4 src that exceeds 100 pps
 * - Uses 1 k-entry register array as a hash table
 * Tested with p4c-bm2-ss build 2025-04-23
 */

#include <core.p4>
#include <v1model.p4>

/* ───────── header formats ───────────────────────────────────── */
header ethernet_t { bit<48> dst; bit<48> src; bit<16> ethtype; }
header ipv4_t {
    bit<4>  ver;  bit<4> ihl;   bit<8> dscp;
    bit<16> len;  bit<16> id;   bit<3> flags; bit<13> frag;
    bit<8>  ttl;  bit<8> proto; bit<16> csum;
    bit<32> src;  bit<32> dst;
}

/* ───────── composite structs ───────────────────────────────── */
struct Headers { ethernet_t eth; ipv4_t ip; }
struct Meta    { }

/* ───────── constants ───────────────────────────────────────── */
const bit<32> THRESHOLD_PPS = 100;     // packets-per-second limit
const bit<32> REG_SIZE      = 1024;    // register entries
const bit<32> INDEX_MASK    = 1023;    // 0x3ff (REG_SIZE-1)

/* ───────── register array (64-b per slot) ────────────────────
 * upper 32 bits = epoch second
 * lower 32 bits = packet counter within that second
 */
register<bit<64>>(REG_SIZE) pkt_counter;

/* ───────── parser ──────────────────────────────────────────── */
parser MyParser(packet_in pkt,
                out Headers h,
                inout Meta m,
                inout standard_metadata_t sm)
{
    state start {
        pkt.extract(h.eth);
        transition select(h.eth.ethtype) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(h.ip);
        transition accept;
    }
}

/* ───────── ingress control ─────────────────────────────────── */
control MyIngress(inout Headers h,
                  inout Meta m,
                  inout standard_metadata_t sm)
{
    action fwd()  { sm.egress_spec = 1; }
    action drop() { mark_to_drop(sm); }

    apply {
        if (!h.ip.isValid()) { fwd(); return; }

        /* --- hash src-IP → bucket [0,1023] -------------------- */
        bit<32> hv;
        hash(hv,
             HashAlgorithm.crc32,
             (bit<32>)0,                // explicit base width
             { h.ip.src },
             REG_SIZE);

        bit<32> idx = hv & INDEX_MASK;

        /* --- read current counter ----------------------------- */
        bit<64> cell;
        pkt_counter.read(cell, idx);     // read(out value, index)

        bit<32> stored_sec = (bit<32>)(cell >> 32);
        bit<32> stored_cnt = (bit<32>) cell;

        /* ingress_global_timestamp is 48-bit nanoseconds        */
        bit<48> ts48    = sm.ingress_global_timestamp;
        bit<32> now_sec = (bit<32>)(ts48 >> 30);     // coarse seconds

        bit<32> new_cnt;
        if (now_sec == stored_sec) {
            new_cnt = stored_cnt + 1;
        } else {
            stored_sec = now_sec;
            new_cnt    = 1;
        }

        bit<64> new_cell = (((bit<64>)stored_sec) << 32) | (bit<64>)new_cnt;
        pkt_counter.write(idx, new_cell);

        /* --- enforce rate limit ------------------------------- */
        if (new_cnt > THRESHOLD_PPS) { drop(); }
        else                         { fwd();  }
    }
}

/* ───────── empty stages required by v1model ────────────────── */
control MyVerify(inout Headers h, inout Meta m)  { apply { } }
control MyCompute(inout Headers h, inout Meta m) { apply { } }
control MyEgress(inout Headers h,
                 inout Meta m,
                 inout standard_metadata_t sm)  { apply { } }

/* ───────── deparser ────────────────────────────────────────── */
control MyDeparser(packet_out pkt, in Headers h)
{
    apply { pkt.emit(h.eth); pkt.emit(h.ip); }
}

/* ───────── switch instantiation ────────────────────────────── */
V1Switch(MyParser(),
         MyVerify(),
         MyIngress(),
         MyEgress(),
         MyCompute(),
         MyDeparser()) main;