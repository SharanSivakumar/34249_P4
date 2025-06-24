#!/usr/bin/env python3
"""
send_packets.py
• Test 1:  20 packets @ ~20 pps  (all should pass)
• Test 2: 150-packet burst       (≈100 should pass)
"""

from scapy.all import Ether, IP, UDP, sendp, AsyncSniffer
import time

SEND_IFACE = "veth0"     # ingress
RECV_IFACE = "veth1"     # egress

SRC_SLOW   = "10.0.0.100"
SRC_FLOOD  = "10.0.0.100"
DST_IP     = "10.0.0.2"
DST_MAC    = "bb:bb:bb:bb:bb:bb"

def capture_and_send(src_ip, count, inter, timeout):
    """Start sniffer, send packets, stop sniffer, return # received"""
    sniffer = AsyncSniffer(
        iface=RECV_IFACE,
        filter=f"ip src {src_ip}",
        store=True
    )
    sniffer.start()                # begin capture
    pkt = Ether(dst=DST_MAC)/IP(src=src_ip, dst=DST_IP)/UDP()
    sendp(pkt, iface=SEND_IFACE, count=count, inter=inter, verbose=False)
    time.sleep(timeout)            # give switch time to forward / drop
    sniffer.stop()                 # stop capture
    return len(sniffer.results)

def main():
    print("=== Test 1: 20 packets at ~20 pps ===")
    recv1 = capture_and_send(SRC_SLOW, 20, 0.05, 2)
    print(f"  received {recv1}/20 packets  ->  {'PASS' if recv1==20 else 'FAIL'}")

    print("\n=== Test 2: Burst of 150 packets ===")
    recv2 = capture_and_send(SRC_FLOOD, 150, 0, 2)
    ok = 90 <= recv2 <= 110
    print(f"  received {recv2}/150 packets (expected ≈100)  ->  {'PASS' if ok else 'FAIL'}")

    print("\n=== SUMMARY ===")
    if recv1 == 20 and ok:
        print("Firewall behaves as expected: low-rate traffic passes; flood is capped.")
    else:
        print("Unexpected result – check switch JSON, interfaces or timestamp shift.")

if __name__ == "__main__":
    main()
    # end of tests
    import os, time
    time.sleep(0.5)   # wait for last packets to drain
    os._exit(0)       # ensure no background flood keeps running
