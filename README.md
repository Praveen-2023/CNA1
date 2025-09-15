# CNA1# CS331 Assignment 1: DNS Resolver

## Team Members
- Member 1: Praveen Rathod, ID: Last 3 digits: **206**
- Member 2: Yash Patkar, ID: Last 3 digits: **296**

## X.pcap Selection
Sum of last 3 digits: 206 + 296 = 502 → 502 % 10 = **2** → Used `2.pcap`

## How to Run
1. Place `2.pcap` in the same folder.
2. In Terminal 1: `python3 server.py`
3. In Terminal 2: `python3 client.py`
4. Output logs appear in terminal and are saved to `dns_results.csv`
5. Report table is in `report.pdf`

## Important Notes
- The server does **NOT** perform real DNS resolution.
- It uses **static IP pool** and **time-based routing rules** from the assignment PDF.
- All responses are deterministic: same header → same IP always.
- We used Python 3.10+ with Scapy and Pandas.
- Port `5353` is used.

## Files Included
- `server.py`: Implements rule-based IP selection using HHMMSSID header parsing
- `client.py`: Parses PCAP, extracts DNS queries, generates HHMMSSID header, sends via UDP
- `2.pcap`: Chosen pcap file (selected via (206 + 296) % 10 = 2)
- `dns_results.csv`: Raw output data — 9 DNS queries resolved with headers and IPs
- `report.pdf`: Final report with table matching DNS Resolution Rules.pdf format
