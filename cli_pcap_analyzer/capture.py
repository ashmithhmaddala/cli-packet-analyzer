"""
Packet capture functionality for live and file-based capture.
"""

import subprocess
import sys
from typing import Callable, Optional, List, Dict, Any

from scapy.all import sniff, rdpcap, conf

from .dissectors import dissect_packet
from .output import PacketOutput


class PacketCapture:
    """Handles packet capture operations."""

    def __init__(self):
        self.interfaces = self._get_interfaces()

    def _get_interfaces(self) -> Dict[str, Any]:
        """Get available network interfaces."""
        return dict(conf.ifaces)

    def list_interfaces(self) -> List[str]:
        """List available network interfaces with Kali-specific descriptions."""
        interfaces = list(self.interfaces.keys())

        # Add Kali-specific interface information
        print("Available network interfaces:")
        print("=" * 50)

        for iface in sorted(interfaces):
            info = self.get_interface_info(iface)
            desc = info.get('description', '') if info else ''

            # Add helpful descriptions for common Kali interfaces
            kali_desc = self._get_kali_interface_description(iface)
            if kali_desc:
                desc = f"{desc} ({kali_desc})" if desc else kali_desc

            status = self._get_interface_status(iface)
            print("20")

        print()
        print("Common Kali Linux interfaces:")
        print("  eth0     - Primary Ethernet")
        print("  wlan0    - Primary Wireless")
        print("  tun0     - VPN Tunnel")
        print("  mon0     - Monitor Mode")
        print("  lo       - Loopback")

        return interfaces

    def capture_live(self,
                    iface: str,
                    count: int = 0,
                    bpf_filter: Optional[str] = None,
                    output_handler: Optional[PacketOutput] = None) -> None:
        """
        Capture packets live from an interface.

        Args:
            iface: Network interface name
            count: Number of packets to capture (0 = unlimited)
            bpf_filter: BPF filter string
            output_handler: Output handler for processed packets
        """

        def packet_handler(pkt):
            packet_data = dissect_packet(pkt, iface=iface)
            if output_handler:
                output_handler.write_packet(packet_data)
            else:
                # Default pretty print
                from .output import create_output_handler
                handler = create_output_handler()
                handler.write_packet(packet_data)

        print(f"Capturing on {iface} filter={bpf_filter or 'none'} count={count or 'unlimited'}")
        print("Press Ctrl+C to stop")

        try:
            sniff(iface=iface,
                  prn=packet_handler,
                  filter=bpf_filter,
                  count=count if count > 0 else None)
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        except Exception as e:
            print(f"Error during capture: {e}", file=sys.stderr)
            sys.exit(1)

    def read_pcap(self,
                 filepath: str,
                 output_handler: Optional[PacketOutput] = None) -> None:
        """
        Read and analyze packets from a PCAP file.

        Args:
            filepath: Path to PCAP file
            output_handler: Output handler for processed packets
        """
        try:
            packets = rdpcap(filepath)
            print(f"Reading {len(packets)} packets from {filepath}")

            for pkt in packets:
                packet_data = dissect_packet(pkt)
                if output_handler:
                    output_handler.write_packet(packet_data)
                else:
                    # Default pretty print
                    from .output import create_output_handler
                    handler = create_output_handler()
                    handler.write_packet(packet_data)

        except FileNotFoundError:
            print(f"Error: PCAP file '{filepath}' not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading PCAP file: {e}", file=sys.stderr)
            sys.exit(1)

    def get_interface_info(self, iface: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific interface."""
        return self.interfaces.get(iface)

    def _get_kali_interface_description(self, iface: str) -> Optional[str]:
        """Get Kali-specific description for common interface names."""
        descriptions = {
            'eth0': 'Primary Ethernet',
            'eth1': 'Secondary Ethernet',
            'wlan0': 'Primary Wireless',
            'wlan1': 'Secondary Wireless',
            'mon0': 'Monitor Mode',
            'mon1': 'Secondary Monitor Mode',
            'tun0': 'VPN Tunnel',
            'tun1': 'Secondary VPN Tunnel',
            'lo': 'Loopback',
            'docker0': 'Docker Bridge',
            'veth': 'Virtual Ethernet',
        }

        # Check for exact matches
        if iface in descriptions:
            return descriptions[iface]

        # Check for patterns
        if iface.startswith('wlan'):
            return 'Wireless Interface'
        if iface.startswith('eth'):
            return 'Ethernet Interface'
        if iface.startswith('mon'):
            return 'Monitor Mode Interface'
        if iface.startswith('tun'):
            return 'VPN Tunnel Interface'

        return None

    def _get_interface_status(self, iface: str) -> str:
        """Get interface status (UP/DOWN) using ip command."""
        try:
            result = subprocess.run(['ip', 'link', 'show', iface],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and 'UP' in result.stdout:
                return 'UP'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return 'DOWN'


def check_root_privileges() -> bool:
    """Check if running with root privileges."""
    try:
        return subprocess.check_output(['id', '-u']).decode().strip() == '0'
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback for Windows or systems without 'id' command
        import os
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def require_root_warning():
    """Print warning if not running as root."""
    if not check_root_privileges():
        print("Warning: Live packet capture typically requires root privileges.")
        print("If capture fails, try running with 'sudo'.")
        print()
