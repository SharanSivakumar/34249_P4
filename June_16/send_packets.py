from scapy.all import Ether, IP, TCP, UDP, sendp
import time
import subprocess

# Network and environment configuration
default_src_ip = "10.0.0.100"
dst_ip = "10.0.0.2"
src_mac = "00:00:00:00:00:01"
dst_mac = "00:00:00:00:00:02"
interface = "veth0"
thrift_port = 9090
results = {}

# Color codes for terminal formatting
YELLOW = '\033[93m'
RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Utility: Convert IP address to register index
def ip_to_index(ip, mask_bits=10):
    ip_bytes = list(map(int, ip.split(".")))
    ip_int = (ip_bytes[0] << 24) | (ip_bytes[1] << 16) | (ip_bytes[2] << 8) | ip_bytes[3]
    return ip_int & ((1 << mask_bits) - 1)

# Utility: Convert port number to register index
def port_to_index(port, mask_bits=10):
    return port & ((1 << mask_bits) - 1)

# Function to read a register value
def read_register(reg_name, index):
    try:
        cmd = f'echo "register_read {reg_name} {index}" | simple_switch_CLI --thrift-port {thrift_port}'
        output = subprocess.check_output(cmd, shell=True, text=True)
        value_line = [line for line in output.splitlines() if reg_name in line]
        return value_line[0].split()[-1] if value_line else "No entry"
    except subprocess.CalledProcessError:
        return "Failed"

# Function to send packets and log formatted output
def send_packets(src_ip, count, sport=1234, dport=80, proto='TCP', flags='S', label=""):
    color = CYAN if "Allowed" in label or "New IP" in label or "Whitelisted" in label else RED if "Drop" in label or "Blacklisted" in label or "DDoS" in label else YELLOW

    print(f"\n{BOLD}{color}>>> Sending {count} packet(s) - {label}{RESET}")
    print(f"{color}    From {src_ip}:{sport} -> {dst_ip}:{dport} using {proto}{RESET}")

    if proto == 'TCP':
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    elif proto == 'UDP':
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    else:
        raise ValueError("Unsupported protocol")

    for _ in range(count):
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(0.005)

    print(f"{GREEN}    Packets sent successfully.{RESET}")

    ip_idx = ip_to_index(src_ip)
    port_idx = port_to_index(dport)

    pkt_reg = read_register("ip_pkt_cnt", ip_idx)
    syn_reg = read_register("ip_syn_cnt", ip_idx)
    port_thresh = read_register("port_thresh", port_idx)

    results[label] = {
        "src_ip": src_ip,
        "dst_port": dport,
        "pkt_cnt": pkt_reg,
        "syn_cnt": syn_reg,
        "port_thresh": port_thresh
    }

# Function to print results in tabular format
def print_results():
    print(f"\n{BOLD}Final Test Summary:{RESET}")
    print("-" * 80)
    print(f"{'Test Label':<30} | {'Src IP':<15} | {'Dst Port':<8} | {'Pkt Cnt':<8} | {'SYN Cnt':<8} | {'Threshold':<9}")
    print("-" * 80)

    for label, data in results.items():
        print(f"{label:<30} | {data['src_ip']:<15} | {data['dst_port']:<8} | {data['pkt_cnt']:<8} | {data['syn_cnt']:<8} | {data['port_thresh']:<9}")
    print("-" * 80)

# Main controller
def run_all_tests():
    print(f"{BOLD}\nRunning DDoS Mitigation Evaluation Suite{RESET}")

    # Traffic Behavior Tests
    send_packets(default_src_ip, 1, dport=80, label="Allowed TCP traffic")
    send_packets("10.0.0.1", 1, dport=80, label="Blacklisted IP")
    send_packets(default_src_ip, 1, dport=12345, label="Disallowed port")
    send_packets(default_src_ip, 150, dport=80, label="DDoS Burst (default threshold)")

    # SYN Flood Test
    send_packets(default_src_ip, 25, dport=80, flags='S', label="SYN Flood Trigger")

    # UDP Behavior
    send_packets(default_src_ip, 1, dport=53, proto='UDP', label="Allowed UDP packet (Port 53)")

    # Custom Threshold Port
    send_packets(default_src_ip, 10, dport=7777, label="Custom Port Threshold Test")

    # IP Variation Test
    send_packets("10.0.0.101", 3, dport=80, label="New IP under limit")
    send_packets("10.0.0.101", 10, dport=80, label="New IP over threshold")

    # Whitelist Test
    send_packets("10.0.0.200", 3, dport=80, label="Whitelisted IP (should always pass)")

    # Blackhole Mode
    print(f"{YELLOW}\nAttention: Ensure blackhole mode is enabled on switch before next test{RESET}")
    send_packets("10.0.0.100", 1, dport=80, label="Blackhole Mode Drop Test")

    print_results()

if __name__ == "__main__":
    run_all_tests()