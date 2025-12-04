"""
Main packet analyzer class and API.
"""

from typing import Optional, Dict, Any
from .capture import PacketCapture
from .output import PacketOutput


class PacketAnalyzer:
    """Main packet analyzer class."""

    def __init__(self):
        self.capture = PacketCapture()

    def analyze_live(self,
                    interface: str,
                    count: int = 0,
                    bpf_filter: Optional[str] = None,
                    output_file: Optional[str] = None,
                    json_output: bool = False,
                    write_pcap: Optional[str] = None) -> None:
        """
        Analyze packets from live capture.

        Args:
            interface: Network interface name
            count: Number of packets to capture (0 = unlimited)
            bpf_filter: BPF filter expression
            output_file: Output file path (None for stdout)
            json_output: True for JSON output, False for pretty print
            write_pcap: Path to write captured packets to PCAP file
        """
        with PacketOutput(output_file, json_output) as output:
            self.capture.capture_live(interface, count, bpf_filter, output, write_pcap)

    def analyze_pcap(self,
                    filepath: str,
                    output_file: Optional[str] = None,
                    json_output: bool = False) -> None:
        """
        Analyze packets from PCAP file.

        Args:
            filepath: Path to PCAP file
            output_file: Output file path (None for stdout)
            json_output: True for JSON output, False for pretty print
        """
        with PacketOutput(output_file, json_output) as output:
            self.capture.read_pcap(filepath, output)

    def list_interfaces(self) -> None:
        """List available network interfaces (delegates to capture)."""
        interfaces = self.capture.list_interfaces()
        if not interfaces:
            print("No interfaces found")
            return


# Convenience functions for direct use
def analyze_live(interface: str,
                count: int = 0,
                bpf_filter: Optional[str] = None,
                output_file: Optional[str] = None,
                json_output: bool = False) -> None:
    """Convenience function for live packet analysis."""
    analyzer = PacketAnalyzer()
    analyzer.analyze_live(interface, count, bpf_filter, output_file, json_output)


def analyze_pcap(filepath: str,
                output_file: Optional[str] = None,
                json_output: bool = False) -> None:
    """Convenience function for PCAP file analysis."""
    analyzer = PacketAnalyzer()
    analyzer.analyze_pcap(filepath, output_file, json_output)


def list_interfaces() -> None:
    """Convenience function to list interfaces."""
    analyzer = PacketAnalyzer()
    analyzer.list_interfaces()
