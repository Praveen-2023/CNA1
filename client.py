import socket
from scapy.all import *
from datetime import datetime

# CONFIGURATION
PCAP_FILE = "2.pcap"       
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5353

# Load PCAP and extract DNS queries
packets = rdpcap(PCAP_FILE)
dns_queries = []

print(f"Loading DNS queries from {PCAP_FILE}...")

for pkt in packets:
    # Check if packet has DNS layer AND is a QUERY (qr=0)
    if pkt.haslayer("DNS") and pkt["DNS"].qr == 0:
        # Extract domain name (remove trailing dot)
        qname = pkt["DNS"].qd.qname.decode().rstrip('.')
        dns_queries.append(qname)

# Remove duplicates while preserving order
dns_queries = list(dict.fromkeys(dns_queries))

print(f"Found {len(dns_queries)} unique DNS queries.")

# Create UDP socket to talk to server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("\n Sending queries to server...\n")

results = []  

for i, domain in enumerate(dns_queries):
    # Generate HHMMSSID header
    now = datetime.now()
    hh = now.strftime("%H")    
    mm = now.strftime("%M")    
    ss = now.strftime("%S")    
    seq_id = f"{i:02d}"         

    custom_header = hh + mm + ss + seq_id  # Total 8 characters

    # Construct message: [8-byte header] + [domain name]
    message = custom_header.encode() + domain.encode()

    # Send to server
    sock.sendto(message, (SERVER_IP, SERVER_PORT))

    # Wait for response (timeout after 5 seconds)
    sock.settimeout(5)
    try:
        response, _ = sock.recvfrom(1024)
        resolved_ip = response.decode().strip()
    except socket.timeout:
        resolved_ip = "TIMEOUT"

    # Log result
    results.append({
        "Custom Header": custom_header,
        "Domain Name": domain,
        "Resolved IP": resolved_ip
    })

    print(f"{i+1:2d}. {domain:<20} → {resolved_ip:<15} (Header: {custom_header})")

# Save results to CSV
import pandas as pd
df = pd.DataFrame(results)
df.to_csv("dns_results.csv", index=False)
print("\n Results saved to 'dns_results.csv'")