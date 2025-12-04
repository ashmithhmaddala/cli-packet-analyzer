#!/usr/bin/env python3
"""
CLI interface for the packet analyzer.
"""

import argparse
import sys
from typing import Optional

from .analyzer import PacketAnalyzer
from .capture import require_root_warning


def print_banner():
    """Print the ASCII art banner."""
    banner = r"""
 /$$$$$$  /$$       /$$$$$$       /$$$$$$$                     /$$                   /$$            /$$$$$$                      /$$                                        
 /$$__  $$| $$      |_  $$_/      | $$__  $$                   | $$                  | $$           /$$__  $$                    | $$                                        
| $$  \__/| $$        | $$        | $$  \ $$ /$$$$$$   /$$$$$$$| $$   /$$  /$$$$$$  /$$$$$$        | $$  \ $$ /$$$$$$$   /$$$$$$ | $$ /$$   /$$ /$$$$$$$$  /$$$$$$   /$$$$$$ 
| $$      | $$        | $$        | $$$$$$$/|____  $$ /$$_____/| $$  /$$/ /$$__  $$|_  $$_/        | $$$$$$$$| $$__  $$ |____  $$| $$| $$  | $$|____ /$$/ /$$__  $$ /$$__  $$
| $$      | $$        | $$        | $$____/  /$$$$$$$| $$      | $$$$$$/ | $$$$$$$$  | $$          | $$__  $$| $$  \ $$  /$$$$$$$| $$| $$  | $$   /$$$$/ | $$$$$$$$| $$  \__/
| $$    $$| $$        | $$        | $$      /$$__  $$| $$      | $$_  $$ | $$_____/  | $$ /$$      | $$  | $$| $$  | $$ /$$__  $$| $$| $$  | $$  /$$__/  | $$_____/| $$      
|  $$$$$$/| $$$$$$$$ /$$$$$$      | $$     |  $$$$$$$|  $$$$$$$| $$ \  $$|  $$$$$$$  |  $$$$/      | $$  | $$| $$  | $$|  $$$$$$$| $$|  $$$$$$$ /$$$$$$$$|  $$$$$$$| $$      
 \______/ |________/|______/      |__/      \_______/ \_______/|__/  \__/ \_______/   \___/        |__/  |__/|__/  |__/ \_______/|__/ \____  $$|________/ \_______/|__/      
                                                                                                                                      /$$  | $$                              
                                                                                                                                     |  $$$$$$/                              
                                                                                                                                      \______/                               
"""
    print(banner)


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="CLI Packet Analyzer - Kali Linux Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List network interfaces
  pcap-analyzer --list-ifaces

  # Capture 10 packets on eth0
  sudo pcap-analyzer --iface eth0 --count 10

  # Capture HTTP traffic
  sudo pcap-analyzer --iface eth0 --bpf "tcp port 80"

  # Analyze PCAP file
  pcap-analyzer --read capture.pcap

  # Export analysis to JSON
  pcap-analyzer --read capture.pcap --json-out analysis.jsonl

Common Kali interfaces: eth0, wlan0, tun0, mon0
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--list-ifaces",
        action="store_true",
        help="list available network interfaces"
    )

    group.add_argument(
        "--read",
        metavar="PCAP_FILE",
        help="analyze packets from PCAP file"
    )

    group.add_argument(
        "--iface",
        metavar="INTERFACE",
        help="capture live packets from network interface"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="number of packets to capture (0 = unlimited)"
    )

    parser.add_argument(
        "--bpf",
        metavar="FILTER",
        help="BPF filter expression (e.g., 'tcp port 80')"
    )

    parser.add_argument(
        "--json-out",
        metavar="FILE",
        help="export analysis results to JSON Lines file"
    )

    parser.add_argument(
        "--write", "-w",
        metavar="PCAP_FILE",
        help="write captured packets to PCAP file"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="verbose output"
    )

    return parser


def main() -> None:
    """Main CLI entry point."""
    print_banner()
    parser = create_parser()
    args = parser.parse_args()

    analyzer = PacketAnalyzer()

    try:
        if args.list_ifaces:
            analyzer.list_interfaces()
            return

        # Determine output format
        json_output = args.json_out is not None

        if args.read:
            # Analyze PCAP file
            analyzer.analyze_pcap(
                filepath=args.read,
                output_file=args.json_out,
                json_output=json_output
            )

        elif args.iface:
            # Live capture - check for root warning
            if not json_output:
                require_root_warning()

            analyzer.analyze_live(
                interface=args.iface,
                count=args.count,
                bpf_filter=args.bpf,
                output_file=args.json_out,
                json_output=json_output,
                write_pcap=args.write
            )

    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
