#!/bin/bash

# Kali Linux Installation Script for CLI Packet Analyzer

set -e

echo "=== CLI Packet Analyzer - Kali Linux Edition ==="
echo ""

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo "Warning: This script is optimized for Kali Linux."
    echo "Some features may not work on other distributions."
    echo ""
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "Please do not run this script as root."
    echo "It will prompt for sudo when needed for package installation."
    exit 1
fi

echo "Installing system dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip tcpdump wireshark-common

echo ""
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

echo ""
echo "Installing the packet analyzer package..."
pip3 install -e .

echo ""
echo "Running installation test..."
python3 test_install.py

echo ""
echo "=== Installation Complete! ==="
echo ""
echo "Usage examples:"
echo ""
echo "  # List network interfaces"
echo "  pcap-analyzer --list-ifaces"
echo ""
echo "  # Capture packets on eth0"
echo "  sudo pcap-analyzer --iface eth0 --count 10"
echo ""
echo "  # Capture HTTP traffic"
echo "  sudo pcap-analyzer --iface eth0 --bpf 'tcp port 80'"
echo ""
echo "  # Analyze PCAP file"
echo "  pcap-analyzer --read capture.pcap"
echo ""
echo "  # Export to JSON"
echo "  pcap-analyzer --read capture.pcap --json-out analysis.jsonl"
echo ""
echo "Note: Live packet capture requires root privileges (sudo)"
echo "Common Kali interfaces: eth0, wlan0, tun0 (VPN), mon0 (monitor mode)"
echo ""
echo "For more help: pcap-analyzer --help"
