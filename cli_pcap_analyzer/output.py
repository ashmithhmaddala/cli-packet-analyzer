"""
Output formatting for packet analysis results.
"""

import json
from typing import Dict, Any, TextIO, Optional


class PacketOutput:
    """Handles different output formats for packet data."""

    def __init__(self, output_file: Optional[str] = None, json_format: bool = False):
        """
        Initialize output handler.

        Args:
            output_file: Path to output file, or None for stdout
            json_format: If True, output JSON lines; if False, pretty print
        """
        self.output_file = output_file
        self.json_format = json_format
        self._file_handle: Optional[TextIO] = None

    def __enter__(self):
        if self.output_file:
            self._file_handle = open(self.output_file, "w", encoding="utf-8")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file_handle:
            self._file_handle.close()

    def write_packet(self, packet_data: Dict[str, Any]) -> None:
        """Write a single packet's data."""
        if self.json_format:
            self._write_json(packet_data)
        else:
            self._write_pretty(packet_data)

    def _write_json(self, packet_data: Dict[str, Any]) -> None:
        """Write packet data as JSON line."""
        output = json.dumps(packet_data)
        if self._file_handle:
            self._file_handle.write(output + "\n")
            self._file_handle.flush()
        else:
            print(output)

    def _write_pretty(self, packet_data: Dict[str, Any]) -> None:
        """Write packet data in human-readable format."""
        ts = packet_data.get("ts", "")
        src = packet_data.get("ip", {}).get("src") or \
              packet_data.get("arp", {}).get("psrc", "") or "-"
        dst = packet_data.get("ip", {}).get("dst") or \
              packet_data.get("arp", {}).get("pdst", "") or "-"

        proto = "?"
        if "tcp" in packet_data:
            proto = "TCP"
        elif "udp" in packet_data:
            proto = "UDP"
        elif "arp" in packet_data:
            proto = "ARP"
        elif "icmp" in packet_data:
            proto = "ICMP"

        info = ""
        if "http" in packet_data:
            info = packet_data["http"].get("request_line", "") or \
                   packet_data["http"].get("status_line", "")
        elif "dns_guess" in packet_data:
            info = "dns?"

        line = f"{ts} {proto:4} {src:22} -> {dst:22} {info}".rstrip()

        if self._file_handle:
            self._file_handle.write(line + "\n")
            self._file_handle.flush()
        else:
            print(line)


def create_output_handler(output_file: Optional[str] = None,
                         json_format: bool = False) -> PacketOutput:
    """
    Factory function to create output handler.

    Args:
        output_file: Output file path or None for stdout
        json_format: True for JSON output, False for pretty print

    Returns:
        Configured PacketOutput instance
    """
    return PacketOutput(output_file, json_format)
