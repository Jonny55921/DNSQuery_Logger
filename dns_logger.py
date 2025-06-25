"""

@Jonny55921

"""

from scapy.all import sniff, DNSQR, UDP
from datetime import datetime
import os

os.makedirs("logs", exist_ok=True)

def process_packet(packet):
    if packet.haslayer(DNSQR) and packet.haslayer(UDP) and packet[UDP].dport == 53:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        queried_domain = packet[DNSQR].qname.decode('utf-8')

        log_entry = f"{timestamp} - Queried Domain: {queried_domain}\n"
        print(log_entry, end='')

        with open("logs/dns_queries.log", "a") as log_file:
            log_file.write(log_entry+"\n")
        
print("Starting DNS query logger on UDP Port 53. Press Ctrl+C to stop.")
sniff(filter="udp port 53", prn=process_packet, store=False)
print("DNS query logger stopped.")