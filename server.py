import socket
from datetime import datetime

# CONFIGURATION: IP POOL AND RULES 
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

# Define time slots with their rules
TIME_RULES = {
    "morning": {
        "start": 4,   # 04:00
        "end": 11,    # 11:59
        "pool_start": 0,
        "hash_mod": 5
    },
    "afternoon": {
        "start": 12,  # 12:00
        "end": 19,    # 19:59
        "pool_start": 5,
        "hash_mod": 5
    },
    "night": {
        "start": 20,  # 20:00
        "end": 3,     # 03:59 (wrap around midnight)
        "pool_start": 10,
        "hash_mod": 5
    }
}

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5353

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))

print("DNS SERVER (RULE-BASED) STARTED")
print(f"Listening on {SERVER_IP}:{SERVER_PORT}...")
print("="*60)

# Store results for report
results = []

while True:
    try:
        # Wait for incoming packet
        data, client_addr = sock.recvfrom(1024)

        # Split header (first 8 bytes) and domain (rest)
        header_bytes = data[:8]
        domain_bytes = data[8:]

        # Decode to strings
        header = header_bytes.decode('utf-8')
        domain = domain_bytes.decode('utf-8').strip()

        print(f"\n Received: Header={header}, Domain={domain}")

        # Extract HH and ID from header 
        hh = int(header[0:2])   # First two chars = hour
        id_str = header[6:8]    # Last two chars = ID
        seq_id = int(id_str)    # Convert to integer (e.g., "05" → 5)

        # Determine Time Slot
        if 4 <= hh <= 11:
            slot = "morning"
        elif 12 <= hh <= 19:
            slot = "afternoon"
        elif (20 <= hh <= 23) or (0 <= hh <= 3):
            slot = "night"
        else:
            slot = "afternoon"  

        # Applying Rule
        rule = TIME_RULES[slot]
        pool_start = rule["pool_start"]
        hash_mod = rule["hash_mod"]

        # Compute offset: ID % hash_mod
        offset = seq_id % hash_mod
        final_index = pool_start + offset

        # Validate index 
        if final_index < 0 or final_index >= len(IP_POOL):
            resolved_ip = "ERROR: Invalid Index"
        else:
            resolved_ip = IP_POOL[final_index]

        # Send Response Back to Client
        sock.sendto(resolved_ip.encode(), client_addr)

        # LOG FOR REPORT
        results.append({
            "Custom Header": header,
            "Domain Name": domain,
            "Resolved IP": resolved_ip
        })

        print(f"Sent: {resolved_ip} (Slot: {slot}, Index: {final_index})")

    except Exception as e:
        print(f"Error processing packet: {e}")