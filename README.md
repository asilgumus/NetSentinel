# NetSentinel

This project is a powerful Python-based tool designed for live network traffic monitoring, comprehensive network analysis, and security threat detection. It leverages libraries like Scapy for packet sniffing and analysis, providing a console-based interface for easy interaction with various monitoring and protection features.

## Features

### Monitoring
- Live Traffic Monitoring:
  - Monitor all IP packets
  - Incoming packets only
  - Outgoing packets only
- Real-time Bandwidth Usage Display
- Protocol Distribution Analysis
- Top Talkers Identification (IPs generating the most traffic)
- Active Connections Listing

### Analysis
- Network traffic analysis reports showing bandwidth, protocol usage, and active connections.

### Security
- DoS/DDoS and Flood Attack Detection
- Port Scanning Attempt Detection
- ARP Poisoning Detection and Alerts
- Suspicious DNS Query Monitoring

## Installation

### Prerequisites
- Python 3.x
- WinPcap/Npcap (for Windows packet capture support)

### Python Dependencies
Install required Python packages with:

```
pip install scapy psutil colorama
```

## Usage

Run the main application:

```bash
python app.py
```

The console will display a menu with options categorized by functionality:

- **Live Traffic Monitoring**
  - 11: Monitor all packets
  - 12: Monitor outgoing packets only
  - 13: Monitor incoming packets only
- **Network Analysis and Reporting**
  - 21: Show real-time bandwidth usage
  - 22: Display protocol distribution over a number of packets
  - 23: Show IPs generating the most traffic (Top Talkers)
  - 24: List active network connections
- **Security Analysis**
  - 31: Start DoS/DDoS and flood attack protection
  - 32: Detect port scanning attempts
  - 33: Detect ARP poisoning attacks
  - 34: Monitor suspicious DNS queries

Choose an option by entering its number and follow additional prompts, if any.

## Project Modules

- **app.py** — Main interactive console interface and program entry point.
- **net_watch.py** — Functions to display incoming, outgoing, or all network packets.
- **analyze_report.py** — Network traffic analysis functions including bandwidth monitoring and protocol distribution.
- **security.py** — NetworkProtector class for real-time attack detection and protection.
- **port_search.py** — Port scanning detection logic.
- **arp_detector.py** — ARP poisoning detection module.
- **dns_monitor_module.py** — Suspicious DNS query monitoring module.
- **unblock_ip.py** — Utilities to unblock IP addresses (unblock file present as a helper).

## License

This project is provided as-is under no specified license. Use and modify at your own risk.
