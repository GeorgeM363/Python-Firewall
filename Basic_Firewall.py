import os
import sys
import time
import subprocess
import ipaddress
import Email_API
import Code_Red_Dummy
from collections import defaultdict
from scapy.all import sniff, IP, TCP, Raw, UDP


THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Validates IP address

# Rejects invalid IPs that are not IPv4 or IPv6
# Prevents injection attacks from smuggled instructions
def validate_ip(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError: # Not a valid IP
        return None

# Read IPs from a file
def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Check for Nimda worm signature
def is_Nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80: #Checks the port for HTTP
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

# Checks for Code Red Worm
def is_http_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        if packet.haslayer(Raw): # Needs to extract raw layer bytes to check syntax
            payload = packet[Raw].load
            return b".ida?" in payload and payload.count(b"X") > 100
    return False

# Checks for SQL Slammer
def IS_SQL_SLAMMER(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == 1434:
        if packet.haslayer(Raw): # Needs to extract raw layer bytes to check syntax
            payload = packet[Raw].load
            return 300 < len(payload) < 500 # Slammer payloads usually around 376 bytes
    return False

def is_Mirai(packet):
    if packet.haslayer(TCP) and packet[TCP].dport in (23, 2323):
        return

#def is_possible_backdoor():


#def is_possible_malware():

# Log events to a file
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

# Function to block an IP
def block_ip(ip):
    subprocess.run(
        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        check=True
    )
    # Notifies user by sending them an email
    Email_API.send_simple_message(ip)


def packet_callback(packet):
    if not packet.haslayer(IP):
        return
    
    src_ip = packet[IP].src # Finds source IP from packet

    # Validate IP
    ip_obj = validate_ip(src_ip)
    if ip_obj is None or ip_obj.version != 4:
        return
    
    src_ip = str(ip_obj)

    # Check if IP is in the whitelist
    if src_ip in whitelist_ips:
        return # Return immediately

    # Check if IP is in the blacklist
    if src_ip in blacklist_ips:
        block_ip(src_ip) # Drops packet and blocks IP
        log_event(f"Blocking blacklisted IP: {src_ip}") # Writes to the log file
        return
    
    # Check for Nimda worm signature
    if is_Nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        block_ip(src_ip) # Drops IP packets associated with Nimda worm
        log_event(f"Blocking Nimda source IP: {src_ip}") # Writes to log file
        return

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                block_ip(ip)
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

# Main guard
if __name__ == "__main__":
    pkt = Code_Red_Dummy.generate_dummy_codered_packet()
    print(is_HTTP_worm(pkt))
    """if os.geteuid() != 0: # Checks if script has root privileges
        print("This script requires root privileges.")
        sys.exit(1)

    # Import whitelist and blacklist IPs
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()] # Tracks each beginning time interval
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)"""


    
    # Sniff function from Scapy, filters only ip packets and runs packet_callback for each captured packet

    # Web dashboard: Visualize data by displaying packet rates, blocked IPs, malware signatures, and geolocational data, use Flash + Django and chartJS or djJS

    # Improve Signature Detection: Use OWASP to learn more common attacks, learn signatures, network threats