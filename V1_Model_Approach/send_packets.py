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
pre_counters = {}

BOLD = '\033[1m'
RESET = '\033[0m'
GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'

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
        "port_thresh": read_register("port_thresh", port_idx),
        "window_count": read_register("ip_window_count", ip_idx),
        "syn_window_count": read_register("ip_syn_window_count", ip_idx),
        "last_seen": read_register("ip_last_seen", ip_idx),
        "window_start": read_register("ip_window_start", ip_idx),
        "syn_window_start": read_register("ip_syn_window_start", ip_idx)
    }

def send_packets(src_ip, count, sport=1234, dport=80, proto='TCP', flags='S', label="", 
                 rate_pps=None, burst_delay=0):
    print(f"\n{BOLD}>>> Sending {count} packet(s) - {label}{RESET}")
    if rate_pps:
        print(f"    Rate-limited: {rate_pps} packets/second")
    if burst_delay:
        print(f"    Burst delay: {burst_delay} seconds between bursts")
    print(f"    From {src_ip}:{sport} -> {dst_ip}:{dport} using {proto}")

    ip_idx = ip_to_index(src_ip)
    port_idx = port_to_index(dport)

    pre = snapshot_registers(label, src_ip, dport)

    if proto == 'TCP':
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    elif proto == 'UDP':
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    else:
        raise ValueError("Unsupported protocol")

    if rate_pps:
        delay = 1.0 / rate_pps
        for i in range(count):
            sendp(pkt, iface=interface, verbose=False)
            if i < count - 1:  
                time.sleep(delay)
    else:
        for _ in range(count):
            sendp(pkt, iface=interface, verbose=False)
            time.sleep(0.005)  

    if burst_delay:
        time.sleep(burst_delay)

    print(f"{GREEN}    Packets sent successfully.{RESET}")

    time.sleep(0.1)

    post = snapshot_registers(label, src_ip, dport)

    
    pkt_change = post["pkt_cnt"] - pre["pkt_cnt"]
    window_change = post["window_count"] - pre["window_count"]
    syn_change = post["syn_cnt"] - pre["syn_cnt"]
    syn_window_change = post["syn_window_count"] - pre["syn_window_count"]
    
    verdict = "DROPPED"
    if pkt_change > 0 or window_change > 0:
        verdict = "ALLOWED"
    elif pkt_change == 0 and window_change == 0 and count > 0:
        verdict = "DROPPED"
    else:
        verdict = "NO CHANGE"

    results[label] = {
        "src_ip": src_ip,
        "dst_port": dport,
        "pkt_cnt": post["pkt_cnt"],
        "syn_cnt": post["syn_cnt"],
        "window_count": post["window_count"],
        "syn_window_count": post["syn_window_count"],
        "threshold": post["port_thresh"],
        "verdict": verdict,
        "pkt_change": pkt_change,
        "window_change": window_change,
        "syn_change": syn_change,
        "syn_window_change": syn_window_change
    }

def send_burst_pattern(src_ip, bursts, packets_per_burst, burst_interval, dport=80, label=""):
    """Send packets in burst patterns to test time-based detection"""
    print(f"\n{BOLD}>>> Burst Pattern Test - {label}{RESET}")
    print(f"    {bursts} bursts of {packets_per_burst} packets, {burst_interval}s apart")
    
    pre = snapshot_registers(label, src_ip, dport)
    
    for burst in range(bursts):
        print(f"    Sending burst {burst + 1}/{bursts}...")
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=1234, dport=dport, flags='S')
        
        for _ in range(packets_per_burst):
            sendp(pkt, iface=interface, verbose=False)
            time.sleep(0.01)  
        
        if burst < bursts - 1:
            time.sleep(burst_interval)
    
    time.sleep(0.2)  
    post = snapshot_registers(label, src_ip, dport)
    
    pkt_change = post["pkt_cnt"] - pre["pkt_cnt"]
    window_change = post["window_count"] - pre["window_count"]
    
    verdict = "ALLOWED" if pkt_change > 0 or window_change > 0 else "DROPPED"
    
    results[label] = {
        "src_ip": src_ip,
        "dst_port": dport,
        "pkt_cnt": post["pkt_cnt"],
        "syn_cnt": post["syn_cnt"],
        "window_count": post["window_count"],
        "syn_window_count": post["syn_window_count"],
        "threshold": post["port_thresh"],
        "verdict": verdict,
        "pattern": f"{bursts}x{packets_per_burst} @ {burst_interval}s"
    }

def print_results():
    print(f"\n{BOLD}Test Summary:{RESET}")
    print("-" * 120)
    print(f"{'Test Label':<40} | {'Src IP':<15} | {'Port':<5} | {'Legacy':<20} | {'Timestamp':<25} | {'Verdict'}")
    print(f"{'':40} | {'':15} | {'':5} | {'Pkt/SYN/Thr':<20} | {'Win/SynWin':<25} | {''}")
    print("-" * 120)

    for label, data in results.items():
        v_color = GREEN if data["verdict"] == "ALLOWED" else RED if data["verdict"] == "DROPPED" else YELLOW
        
        legacy_info = f"{data['pkt_cnt']}/{data['syn_cnt']}/{data['threshold']}"
        timestamp_info = f"{data['window_count']}/{data['syn_window_count']}"
        
        print(f"{label:<40} | {data['src_ip']:<15} | {data['dst_port']:<5} | "
              f"{legacy_info:<20} | {timestamp_info:<25} | "
              f"{v_color}{data['verdict']}{RESET}")
    print("-" * 120)

def run_timestamp_tests():
    print(f"\n{BLUE}{BOLD}=== TIMESTAMP-BASED RATE LIMITING TESTS ==={RESET}")
    
    # Test 1: Rate within limits (should pass)
    send_packets("10.0.0.110", 8, dport=80, rate_pps=8, 
                label="T1: Rate within limit (8 pps)")
    
    # Test 2: Rate exceeding limits (should be blocked)
    send_packets("10.0.0.111", 12, dport=80, rate_pps=12, 
                label="T2: Rate over limit (15 pps)")
    
    # Test 3: SYN rate within limits
    send_packets("10.0.0.112", 4, dport=80, flags='S', rate_pps=4,
                label="T3: SYN rate within limit (4 pps)")
    
    # Test 4: SYN rate exceeding limits
    send_packets("10.0.0.113", 7, dport=80, flags='S', rate_pps=8,
                label="T4: SYN rate over limit (8 pps)")
    time.sleep(1.1)
    
    # Test 5: Burst then wait (should recover)
    send_packets("10.0.0.114", 12, dport=80, rate_pps=50, 
                label="T5: Fast burst (50 pps)")
    time.sleep(1.5)
    time.sleep(1.2)  # Wait for window reset
    send_packets("10.0.0.114", 5, dport=80, rate_pps=5,
                label="T6: Same IP after window reset")
    
    # Test 7: Legitimate burst pattern (should pass)
    send_burst_pattern("10.0.0.115", bursts=3, packets_per_burst=3, 
                      burst_interval=1.2, label="T7: Legitimate bursts (3x3@1.2s)")
    
    # Test 8: Attack burst pattern (should be blocked)
    send_burst_pattern("10.0.0.116", bursts=3, packets_per_burst=6, 
                      burst_interval=0.5, label="T8: Attack bursts (3x8@0.5s)")
    
    # Test 9: Sustained low rate (should pass)
    print(f"\n{BOLD}>>> T9: Sustained low rate test{RESET}")
    for i in range(10):
        send_packets("10.0.0.117", 1, dport=80, 
                    label=f"T9-{i+1}: Sustained packet {i+1}/10")
        time.sleep(0.8)  
    
    # Test 10: Cross-window attack detection
    print(f"\n{BOLD}>>> T10: Cross-window attack simulation{RESET}")
    send_packets("10.0.0.118", 9, dport=80, rate_pps=18,  
                label="T10a: First window (9 pps)")
    time.sleep(0.5)  
    send_packets("10.0.0.118", 9, dport=80, rate_pps=18,  
                label="T10b: Same window continuation")

def run_all_tests():
    print(f"{BOLD}Running Enhanced DDoS Mitigation Evaluation Suite{RESET}")
    print(f"{CYAN}Testing both Legacy and Timestamp-based Protection{RESET}")

    # Old tests
    print(f"\n{MAGENTA}{BOLD}=== LEGACY FUNCTIONALITY TESTS ==={RESET}")
    send_packets(default_src_ip, 1, dport=80, label="L1: Allowed TCP traffic")
    send_packets("10.0.0.1", 1, dport=80, label="L2: Blacklisted IP")
    send_packets(default_src_ip, 1, dport=12345, label="L3: Disallowed port")
    send_packets(default_src_ip, 150, dport=80, label="L4: DDoS Burst (legacy threshold)")
    send_packets(default_src_ip, 25, dport=80, flags='S', label="L5: SYN Flood Trigger (legacy)")
    send_packets(default_src_ip, 1, dport=53, proto='UDP', label="L6: Allowed UDP packet (Port 53)")
    send_packets(default_src_ip, 10, dport=7777, label="L7: Custom Port Threshold Test")
    send_packets("10.0.0.101", 3, dport=80, label="L8: New IP under limit")
    send_packets("10.0.0.101", 10, dport=80, label="L9: New IP over threshold")
    send_packets("10.0.0.200", 3, dport=80, label="L10: Whitelisted IP")


    run_timestamp_tests()

    # Blackhole test
    print(f"\n{YELLOW}{BOLD}=== BLACKHOLE MODE TEST ==={RESET}")
    print(f"{YELLOW}Attention: Ensure blackhole mode is enabled on switch before next test{RESET}")
    send_packets("10.0.0.100", 1, dport=80, label="BH1: Blackhole Mode Drop Test")

    print_results()
    
    print(f"\n{BOLD}Analysis Notes:{RESET}")
    print(f"{CYAN}• Legacy counters are cumulative and never reset{RESET}")
    print(f"{CYAN}• Timestamp windows reset every 1 second{RESET}")
    print(f"{CYAN}• Rate limits: 10 pps general, 5 pps for SYN packets{RESET}")
    print(f"{CYAN}• Window counts should be ≤10 for allowed traffic{RESET}")
    print(f"{CYAN}• SYN window counts should be ≤5 for allowed SYN traffic{RESET}")

if __name__ == "__main__":
    run_all_tests()