#!/usr/bin/env python3
from scapy.all import Ether, IP, sendp, AsyncSniffer
import time

def report(pkt_sent, pkt_received):
    print("\nPacket sent:")
    pkt_sent.show2()
    print("Packet received:")
    pkt_received.show2()

def main():
    # Build a packet with a spoofed source IP.
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2")

    for i in range(10):
        print(f"\nSending packet #{i + 1}")
        sniffer = AsyncSniffer(
            iface='veth3',
            count=1,
            timeout=1,
            prn=lambda pkt_received: report(pkt, pkt_received)
        )
        sniffer.start()

        sendp(pkt, iface="veth1")

        sniffer.join()

if __name__ == "__main__":
    main()
