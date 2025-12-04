"""
CLI Packet Analyzer - Kali Linux Edition

A powerful command-line packet analyzer with protocol dissection capabilities.

Usage:
    # As a command-line tool
    pcap-analyzer --iface eth0 --count 10

    # As a Python module
    from cli_pcap_analyzer import PacketAnalyzer

    analyzer = PacketAnalyzer()
    analyzer.analyze_live('eth0', count=10)
"""

__version__ = "1.0.0"
__author__ = "Ashmith Maddala"

# Main classes
from .analyzer import PacketAnalyzer, analyze_live, analyze_pcap, list_interfaces
from .dissectors import dissect_packet
from .output import PacketOutput, create_output_handler
from .capture import PacketCapture

__all__ = [
    # Main classes
    "PacketAnalyzer",
    "PacketOutput",
    "PacketCapture",

    # Functions
    "analyze_live",
    "analyze_pcap",
    "list_interfaces",
    "dissect_packet",
    "create_output_handler",
]
