from scapy.all import Ether, IP, TCP, sendp
import time
import subprocess

# Common settings
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

def read_register(index):
    try:
        cmd = f'echo "register_read pkt_count {index}" | simple_switch_CLI --thrift-port {thrift_port}'
        output = subprocess.check_output(cmd, shell=True, text=True)
        value_line = [line for line in output.splitlines() if "pkt_count" in line]
        return value_line[0] if value_line else "No entry"
    except subprocess.CalledProcessError:
        return "Failed to read register"

def send_packets(src_ip, count, sport=1234, dport=80, label=""):
    print(f"\nSending {count} packet(s) from {src_ip} to {dst_ip}:{dport} [{label}]")
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport)
    for i in range(count):
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(0.005)
    print("Packets sent.")

    index = ip_to_index(src_ip)
    reg_value = read_register(index)
    print(f"Register index = {index} -> {reg_value}")

    results[label] = f"{count} packets sent from {src_ip} to port {dport}, Register: {reg_value}"

def run_all_tests():
    print("Running All DDoS Mitigation Test Cases\n")

    # Test 1: Allowed traffic
    send_packets(default_src_ip, 1, dport=80, label="Allowed traffic")

    # Test 2: Blacklisted IP
    send_packets("10.0.0.1", 1, dport=80, label="Blacklisted IP")

    # Test 3: Disallowed port
    send_packets(default_src_ip, 1, dport=12345, label="Disallowed port")

    # Test 4: DDoS simulation
    send_packets(default_src_ip, 150, dport=80, label="DDoS burst")

    print("\nTest Summary:")
    for label, outcome in results.items():
        print(f"{label}: {outcome}")

if __name__ == "__main__":
    run_all_tests()
