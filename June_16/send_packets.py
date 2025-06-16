from scapy.all import Ether, IP, TCP, sendp

src_mac = "00:00:00:00:00:01"
dst_mac = "00:00:00:00:00:02"
src_ip = "10.0.0.100"
dst_ip = "10.0.0.2"
interface = "veth0"

for i in range(150):
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=1234, dport=80)
    sendp(pkt, iface=interface, verbose=False)

print("✅ 150 packets sent from 10.0.0.100 to 10.0.0.2")
