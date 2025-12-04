"""
Output formatting for packet analysis results.
"""

import json
from typing import Dict, Any, TextIO, Optional
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)


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
        color = Fore.WHITE
        if "tcp" in packet_data:
            proto = "TCP"
            color = Fore.GREEN
        elif "udp" in packet_data:
            proto = "UDP"
            color = Fore.CYAN
        elif "arp" in packet_data:
            proto = "ARP"
            color = Fore.YELLOW
        elif "icmp" in packet_data:
            proto = "ICMP"
            color = Fore.MAGENTA

        info = ""
        info_color = Fore.WHITE
        alert_msg = ""
        
        if "http" in packet_data:
            http = packet_data["http"]
            info = http.get("request_line", "") or http.get("status_line", "")
            info_color = Fore.LIGHTGREEN_EX
            
            if http.get("auth_basic"):
                alert_msg += " [BASIC AUTH]"
            if http.get("user_agent"):
                # Truncate UA if too long
                ua = http["user_agent"]
                if len(ua) > 30: ua = ua[:27] + "..."
                info += f" (UA: {ua})"
                
        elif "tls" in packet_data:
            info = f"TLS SNI: {packet_data['tls'].get('sni', 'unknown')}"
            info_color = Fore.LIGHTYELLOW_EX
        elif "udp" in packet_data and packet_data["udp"].get("dns_tunnel_suspect"):
            info = "DNS Tunneling Suspected (Large Payload)"
            info_color = Fore.RED
        elif "dns_guess" in packet_data:
            info = f"DNS? {packet_data['dns_guess']}"
            info_color = Fore.LIGHTBLUE_EX

        # Format: Timestamp Protocol Source -> Dest Info [ALERTS]
        # We only colorize if writing to stdout (no file handle)
        if self._file_handle:
            line = f"{ts} {proto:4} {src:22} -> {dst:22} {info}{alert_msg}".rstrip()
            self._file_handle.write(line + "\n")
            self._file_handle.flush()
        else:
            # Colorized output for terminal
            alert_part = f" {Fore.RED}{Style.BRIGHT}{alert_msg}{Style.RESET_ALL}" if alert_msg else ""
            line = f"{Style.DIM}{ts}{Style.RESET_ALL} {color}{proto:4}{Style.RESET_ALL} {src:22} -> {dst:22} {info_color}{info}{Style.RESET_ALL}{alert_part}".rstrip()
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
