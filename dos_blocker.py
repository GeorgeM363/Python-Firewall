import os
import subprocess
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
    src_ip = packet[IP].src # Gets source IP address
    packet_count[src_ip] += 1 # Increments the packet count for that source IP

    current_time = time.time()
    time_interval = current_time - start_time[0] # Calculates time interval of packets
    
    if time_interval >= 1: # Script evaluates if a DOS attack in happening at a rate of once eevery second, if statement evaluates once time interval is greater than or equal to 1
        for ip, count in packet_count.items(): # Iterates through the packet counts for each IP address
            packet_rate = count / time_interval # Calculates packet rate
            #print(f"IP: {ip}, Packet rate: {packet_rate}")  
            if packet_rate > THRESHOLD and ip not in blocked_ips: # Checks if the rate is greater than the threashold and if it is a known dangerous IP
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                subprocess.run( 
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True) # Executes a system-level firewall command, requires root priveledges, used subprocess instead of os.system
                blocked_ips.add(ip) # Adds the ip to the set of blocked IPs

        packet_count.clear() # Clears packet count
        start_time[0] = current_time #Restarts time

# Root access is required whena script performs privileged systems operations that regular users are not allowed to do
# Needed in this case for network-level operations
if __name__ == "__main__": #Ensures code only runs when the file is executed directly
    if os.geteuid() != 0: #Checks effective user ID, on Linux and Unix systems 0 is the root user
        print("This script requires root privileges.")
        sys.exit(1)

    packet_count = defaultdict(int) # Special 
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)