#!/usr/bin/env python3
"""
Example usage of CLI Packet Analyzer as a Python module.
"""

from cli_pcap_analyzer import PacketAnalyzer, dissect_packet, analyze_live

def example_basic_usage():
    """Basic usage example."""
    print("=== CLI Packet Analyzer - Python Module Example ===\n")

    # Create analyzer instance
    analyzer = PacketAnalyzer()

    # List available interfaces
    print("Available interfaces:")
    analyzer.list_interfaces()
    print()

def example_programmatic_analysis():
    """Example of programmatic packet analysis."""
    print("=== Programmatic Packet Analysis Example ===\n")

    # This would require a sample PCAP file
    # For demonstration, we'll show how to dissect a packet programmatically

    print("Example of dissecting packets programmatically:")
    print("from cli_pcap_analyzer import dissect_packet")
    print("# packet_data = dissect_packet(scapy_packet)")
    print("# Process packet_data as needed")
    print()

def example_live_capture():
    """Example of live capture setup."""
    print("=== Live Capture Setup Example ===\n")
    print("To capture live packets (requires root):")
    print("from cli_pcap_analyzer import analyze_live")
    print("analyze_live('eth0', count=10, bpf_filter='tcp port 80')")
    print()

if __name__ == "__main__":
    example_basic_usage()
    example_programmatic_analysis()
    example_live_capture()

    print("For more examples, see the README.md file.")
