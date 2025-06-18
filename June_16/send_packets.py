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
pre_counters = {}

# Terminal formatting
BOLD = '\033[1m'
RESET = '\033[0m'
GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'

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
        return int(value_line[0].split()[-1]) if value_line else -1
    except subprocess.CalledProcessError:
        return -1

def snapshot_registers(label, src_ip, dport):
    ip_idx = ip_to_index(src_ip)
    port_idx = port_to_index(dport)
    return {
        "pkt_cnt": read_register("ip_pkt_cnt", ip_idx),
        "syn_cnt": read_register("ip_syn_cnt", ip_idx),
        "port_thresh": read_register("port_thresh", port_idx)
    }

def send_packets(src_ip, count, sport=1234, dport=80, proto='TCP', flags='S', label=""):
    print(f"\n{BOLD}>>> Sending {count} packet(s) - {label}{RESET}")
    print(f"    From {src_ip}:{sport} -> {dst_ip}:{dport} using {proto}")

    ip_idx = ip_to_index(src_ip)
    port_idx = port_to_index(dport)

    # Snapshot before sending
    pre = snapshot_registers(label, src_ip, dport)

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

    # Snapshot after sending
    post = snapshot_registers(label, src_ip, dport)

    # Determine behavior
    pkt_change = post["pkt_cnt"] - pre["pkt_cnt"]
    syn_change = post["syn_cnt"] - pre["syn_cnt"]
    verdict = "DROPPED"
    if pkt_change > 0:
        verdict = "ALLOWED"
    elif pkt_change == 0 and count > 0:
        verdict = "DROPPED"
    else:
        verdict = "NO CHANGE"

    results[label] = {
        "src_ip": src_ip,
        "dst_port": dport,
        "pkt_cnt": post["pkt_cnt"],
        "syn_cnt": post["syn_cnt"],
        "threshold": post["port_thresh"],
        "verdict": verdict
    }

def print_results():
    print(f"\n{BOLD}Test Summary:{RESET}")
    print("-" * 90)
    print(f"{'Test Label':<32} | {'Src IP':<15} | {'Port':<5} | {'Pkt Cnt':<8} | {'SYN Cnt':<8} | {'Thresh':<7} | {'Verdict'}")
    print("-" * 90)

    for label, data in results.items():
        v_color = GREEN if data["verdict"] == "ALLOWED" else RED if data["verdict"] == "DROPPED" else YELLOW
        print(f"{label:<32} | {data['src_ip']:<15} | {data['dst_port']:<5} | "
              f"{data['pkt_cnt']:<8} | {data['syn_cnt']:<8} | {data['threshold']:<7} | "
              f"{v_color}{data['verdict']}{RESET}")
    print("-" * 90)

def run_all_tests():
    print(f"{BOLD}Running DDoS Mitigation Evaluation Suite{RESET}")

    send_packets(default_src_ip, 1, dport=80, label="Allowed TCP traffic")
    send_packets("10.0.0.1", 1, dport=80, label="Blacklisted IP")
    send_packets(default_src_ip, 1, dport=12345, label="Disallowed port")
    send_packets(default_src_ip, 150, dport=80, label="DDoS Burst (default threshold)")
    send_packets(default_src_ip, 25, dport=80, flags='S', label="SYN Flood Trigger")
    send_packets(default_src_ip, 1, dport=53, proto='UDP', label="Allowed UDP packet (Port 53)")
    send_packets(default_src_ip, 10, dport=7777, label="Custom Port Threshold Test")
    send_packets("10.0.0.101", 3, dport=80, label="New IP under limit")
    send_packets("10.0.0.101", 10, dport=80, label="New IP over threshold")
    send_packets("10.0.0.200", 3, dport=80, label="Whitelisted IP ")

    print(f"{YELLOW}\nAttention: Ensure blackhole mode is enabled on switch before next test{RESET}")
    send_packets("10.0.0.100", 1, dport=80, label="Blackhole Mode Drop Test")

    print_results()

if __name__ == "__main__":
    run_all_tests()
