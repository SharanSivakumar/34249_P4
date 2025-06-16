from scapy.all import Ether, IP, TCP, UDP, sendp
import time
import subprocess

default_src_ip = "10.0.0.100"
dst_ip = "10.0.0.2"
src_mac = "00:00:00:00:00:01"
dst_mac = "00:00:00:00:00:02"
interface = "veth0"
thrift_port = 9090
results = {}

def ip_to_index(ip, mask_bits=10):
    ip_bytes = list(map(int, ip.split(".")))
    ip_int = (ip_bytes[0] << 24) | (ip_bytes[1] << 16) | (ip_bytes[2] << 8) | ip_bytes[3]
    return ip_int & ((1 << mask_bits) - 1)

def port_to_index(port, mask_bits=10):
    return port & ((1 << mask_bits) - 1)


def read_register(reg_name, index):
    try:
        cmd = f'echo "register_read {reg_name} {index}" | simple_switch_CLI --thrift-port {thrift_port}'
        output = subprocess.check_output(cmd, shell=True, text=True)
        value_line = [line for line in output.splitlines() if reg_name in line]
        return value_line[0] if value_line else "No entry"
    except subprocess.CalledProcessError:
        return "Failed to read register"


def send_packets(src_ip, count, sport=1234, dport=80, proto='TCP', flags='S', label=""):
    print(f"\nSending {count} packet(s) from {src_ip} to {dst_ip}:{dport} [{label}]")

    if proto == 'TCP':
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    elif proto == 'UDP':
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    else:
        raise ValueError("Unsupported protocol")

    for _ in range(count):
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(0.005)

    print("Packets sent.")
    ip_idx = ip_to_index(src_ip)
    port_idx = port_to_index(dport)

    pkt_reg = read_register("ip_pkt_cnt", ip_idx)
    syn_reg = read_register("ip_syn_cnt", ip_idx)
    port_thresh = read_register("port_thresh", port_idx)
    results[label] = f"{count} packets from {src_ip}:{sport} → {dst_ip}:{dport}, pkt_cnt: {pkt_reg}, syn_cnt: {syn_reg}, port_thresh: {port_thresh}"

def run_all_tests():
    print("Running Comprehensive DDoS Mitigation Test Suite")

    # Basic Behavior Tests
    send_packets(default_src_ip, 1, dport=80, label="Allowed TCP traffic")
    send_packets("10.0.0.1", 1, dport=80, label="Blacklisted IP")
    send_packets(default_src_ip, 1, dport=12345, label="Disallowed port")
    send_packets(default_src_ip, 150, dport=80, label="DDoS Burst (default threshold)")

    # SYN Flood Detection Test
    send_packets(default_src_ip, 25, dport=80, flags='S', label="SYN Flood Trigger")

    # UDP Protocol Test
    send_packets(default_src_ip, 1, dport=53, proto='UDP', label="Allowed UDP packet (Port 53)")

    # Custom Port Threshold Test
    send_packets(default_src_ip, 10, dport=7777, label="Custom Port Threshold Test")

    # IP Variation Tests
    send_packets("10.0.0.101", 3, dport=80, label="New IP under limit")
    send_packets("10.0.0.101", 10, dport=80, label="New IP over threshold")

    # Whitelisted IP Test
    send_packets("10.0.0.200", 3, dport=80, label="Whitelisted IP (should always pass)")

    # Blackhole Mode Test
    print("\nEnsure blackhole mode is enabled in the switch before running the following test")
    send_packets("10.0.0.100", 1, dport=80, label="Blackhole Mode Drop Test")

    print("\nTest Summary:")
    for label, outcome in results.items():
        print(f"{label}: {outcome}")

if __name__ == "__main__":
    run_all_tests()
