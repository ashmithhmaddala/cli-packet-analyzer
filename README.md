# CLI Packet Analyzer - Kali Linux Edition

A powerful command-line packet analyzer optimized for Kali Linux. Capture live network traffic, analyze pcap files, and extract protocol information in human-readable formats with Kali-specific interface detection and tools integration.

## Features

- **Live Packet Capture**: Capture packets from network interfaces with BPF filters
- **PCAP File Analysis**: Read and analyze existing packet capture files
- **Protocol Dissection**: Parse Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, and HTTP
- **Kali-Optimized Interface Detection**: Smart recognition of common Kali interfaces (eth0, wlan0, tun0, mon0)
- **Multiple Output Formats**: Pretty-printed terminal output or JSON Lines for downstream processing
- **Python Module API**: Import and use programmatically in Python scripts

## Requirements

- Kali Linux (optimized for this distribution)
- Python 3.7+
- Root privileges for live packet capture

## Quick Installation (Kali Linux)

### From GitHub

```bash
# Clone the repository
git clone https://github.com/yourusername/cli-pcap-analyzer.git
cd cli-pcap-analyzer

# Make install script executable and run it
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip tcpdump wireshark-common

# Install Python dependencies
pip3 install -r requirements.txt

# Install the package
pip3 install -e .
```

The installer will:
- ✅ Check if you're running Kali Linux
- ✅ Install system dependencies (tcpdump, wireshark-common)
- ✅ Install Python dependencies (scapy)
- ✅ Install the package with console commands
- ✅ Run installation tests to verify everything works

## Usage

### As a Command-Line Tool

After installation, use the `pcap-analyzer` command:

```bash
# List network interfaces with Kali-specific descriptions
pcap-analyzer --list-ifaces

# Capture 10 packets on eth0
sudo pcap-analyzer --iface eth0 --count 10

# Capture HTTP traffic with BPF filter
sudo pcap-analyzer --iface eth0 --bpf "tcp port 80"

# Analyze PCAP file
pcap-analyzer --read capture.pcap

# Export analysis to JSON
pcap-analyzer --read capture.pcap --json-out analysis.jsonl
```

### As a Python Module

```python
from cli_pcap_analyzer import PacketAnalyzer

# Create analyzer
analyzer = PacketAnalyzer()

# List interfaces
analyzer.list_interfaces()

# Analyze live traffic
analyzer.analyze_live('eth0', count=10, bpf_filter='tcp port 80')

# Analyze PCAP file
analyzer.analyze_pcap('capture.pcap', json_output=True)
```

## Output Formats

### Pretty Print (Default)
```
2025-10-30T20:15:12.345678Z TCP  10.0.0.5               -> 93.184.216.34           GET / HTTP/1.1
2025-10-30T20:15:12.456789Z TCP  93.184.216.34           -> 10.0.0.5               HTTP/1.1 200 OK
```

### JSON Lines
Each packet is represented as a JSON object with parsed protocol fields:

```json
{
  "ts": "2025-10-30T20:15:12.345678Z",
  "len": 74,
  "iface": "eth0",
  "eth": {"src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66", "type": 2048},
  "ip": {"version": 4, "src": "10.0.0.5", "dst": "93.184.216.34", "proto": 6},
  "tcp": {"sport": 45322, "dport": 80, "flags": "PA", "seq": 12345, "ack": 67890},
  "http": {"request_line": "GET / HTTP/1.1", "host": "example.com"}
}
```

## Protocol Support

- **Ethernet**: Source/destination MAC addresses, ethertype
- **ARP**: Operation type, IP and MAC address mappings
- **IPv4**: Source/destination IPs, protocol, TTL
- **TCP**: Ports, flags (SYN, ACK, FIN, etc.), sequence/acknowledgment numbers
- **UDP**: Source/destination ports
- **ICMP**: Type and code
- **HTTP**: Basic request/response line parsing, Host header extraction
- **DNS**: Basic heuristic detection for DNS traffic

## Safety Notice

⚠️ **Important**: Only capture packets on networks and hosts you own or have explicit permission to monitor. Unauthorized packet capture may violate laws and policies.

## Architecture

The analyzer follows a modular design:
- **CLI Frontend**: Command-line argument parsing
- **Capture Engine**: Live sniffing or PCAP file reading with BPF filters
- **Dissector Pipeline**: Protocol-specific parsers that extract fields
- **Normalizer**: Converts packets to standardized JSON format
- **Output**: Multiple output formats for different use cases

## Future Enhancements

The design supports extension with:
- Additional protocol dissectors (TLS, HTTP/2, MQTT, etc.)
- TCP stream reassembly and follow-stream functionality
- Rich filtering and display options
- Export to CSV, PCAP, or databases
- Plugin system for custom dissectors
- Performance optimizations for high-throughput analysis

## License

This tool is provided for educational and authorized network analysis purposes only.
