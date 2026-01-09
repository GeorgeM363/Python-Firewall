import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

# Threshold for a DOS attack
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}") 
    
# Increments packet count for each source IP address
# Calculates packet rate and blocks traffic 
def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]
    
    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            #print(f"IP: {ip}, Packet rate: {packet_rate}")  
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time

# Root access is required whena script performs privileged systems operations that regular users are not allowed to do
# Needed in this case for network-level operations
if __name__ == "__main__": #Ensures code only runs when the file is executed directly
    if os.geteuid() != 0: #Checks effective user ID, on Linux and Unix systems 0 is the root user
        print("This script requires root privileges.")
        sys.exit(1)

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)