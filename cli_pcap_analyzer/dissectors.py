"""
Protocol dissectors for packet analysis.
"""

import json
import time
import pkgutil
import importlib
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

_PLUGINS: List[Any] = []
_PLUGINS_LOADED = False


def load_plugins() -> None:
    """Load plugins from the plugins directory."""
    global _PLUGINS, _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return

    # Add the parent directory to sys.path to ensure we can import 'plugins'
    # This assumes the standard structure where cli_pcap_analyzer and plugins are siblings
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)

    try:
        import plugins
        path = plugins.__path__
        prefix = plugins.__name__ + "."

        for _, name, _ in pkgutil.iter_modules(path, prefix):
            try:
                module = importlib.import_module(name)
                if hasattr(module, "dissect") and hasattr(module, "PROTOCOL"):
                    _PLUGINS.append(module)
            except Exception as e:
                print(f"Failed to load plugin {name}: {e}", file=sys.stderr)
    except ImportError:
        # Plugins directory might not exist or not be a package
        pass
    
    _PLUGINS_LOADED = True


def ts_iso(ts: Optional[float] = None) -> str:
    """Convert timestamp to ISO format."""
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def dissect_ethernet(pkt) -> Optional[Dict[str, Any]]:
    """Dissect Ethernet layer."""
    if Ether in pkt:
        e = pkt[Ether]
        return {"src": e.src, "dst": e.dst, "type": int(e.type)}
    return None


def dissect_arp(pkt) -> Optional[Dict[str, Any]]:
    """Dissect ARP layer."""
    if ARP in pkt:
        a = pkt[ARP]
        return {
            "op": int(a.op),
            "psrc": a.psrc,
            "pdst": a.pdst,
            "hwsrc": a.hwsrc,
            "hwdst": a.hwdst
        }
    return None


def dissect_ip(pkt) -> Optional[Dict[str, Any]]:
    """Dissect IP layer."""
    if IP in pkt:
        ip = pkt[IP]
        return {
            "version": 4,
            "src": ip.src,
            "dst": ip.dst,
            "proto": int(ip.proto),
            "ttl": int(ip.ttl)
        }
    return None


def dissect_icmp(pkt) -> Optional[Dict[str, Any]]:
    """Dissect ICMP layer."""
    if ICMP in pkt:
        ic = pkt[ICMP]
        return {"type": int(ic.type), "code": int(ic.code)}
    return None


def dissect_tcp(pkt) -> Optional[Dict[str, Any]]:
    """Dissect TCP layer with HTTP detection."""
    if TCP not in pkt:
        return None

    t = pkt[TCP]
    flags = []
    if t.flags & 0x01: flags.append("F")
    if t.flags & 0x02: flags.append("S")
    if t.flags & 0x04: flags.append("R")
    if t.flags & 0x08: flags.append("P")
    if t.flags & 0x10: flags.append("A")
    if t.flags & 0x20: flags.append("U")

    result = {
        "sport": int(t.sport),
        "dport": int(t.dport),
        "flags": "".join(flags),
        "seq": int(t.seq),
        "ack": int(t.ack)
    }

    # HTTP detection
    payload = bytes(t.payload)
    if payload:
        try:
            s = payload.decode("utf-8", errors="replace")
            # Check for common HTTP methods and response
            is_http = False
            if s.startswith("HTTP/"):
                is_http = True
            else:
                method = s.split(" ", 1)[0]
                if method in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}:
                    is_http = True

            if is_http:
                lines = s.splitlines()
                first = lines[0].strip()
                parts = first.split()

                if parts:
                    if parts[0].startswith("HTTP/"):
                        result["http"] = {"status_line": first}
                    else:
                        result["http"] = {"request_line": first}
                        # Find Host header and other interesting headers
                        for line in lines[1:15]: # Check first 15 lines
                            line_lower = line.lower()
                            if line_lower.startswith("host:"):
                                result["http"]["host"] = line.split(":", 1)[1].strip()
                            elif line_lower.startswith("authorization: basic"):
                                result["http"]["auth_basic"] = True
                            elif line_lower.startswith("user-agent:"):
                                result["http"]["user_agent"] = line.split(":", 1)[1].strip()
        except Exception:
            pass

    return result


def dissect_tls(pkt) -> Optional[Dict[str, Any]]:
    """
    Dissect TLS layer to extract SNI from Client Hello.
    """
    if TCP not in pkt:
        return None

    payload = bytes(pkt[TCP].payload)
    if not payload:
        return None

    # Check for TLS Handshake (0x16) and version (0x0301, 0x0302, 0x0303, 0x0304)
    # Content Type: 22 (0x16) Handshake
    if len(payload) > 5 and payload[0] == 0x16:
        try:
            # Skip Record Header (5 bytes)
            # Handshake Header: Type (1), Length (3)
            handshake_type = payload[5]
            
            # Client Hello is type 1
            if handshake_type == 1:
                # Pointer to current position
                pos = 5 + 4 # Skip Record Header + Handshake Header
                
                # Skip Client Version (2) + Random (32)
                pos += 34
                
                # Session ID Length (1)
                if pos >= len(payload): return None
                session_id_len = payload[pos]
                pos += 1 + session_id_len
                
                # Cipher Suites Length (2)
                if pos + 2 >= len(payload): return None
                cipher_suites_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2 + cipher_suites_len
                
                # Compression Methods Length (1)
                if pos >= len(payload): return None
                comp_methods_len = payload[pos]
                pos += 1 + comp_methods_len
                
                # Extensions Length (2)
                if pos + 2 >= len(payload): return None
                extensions_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2
                
                # Parse Extensions
                end_extensions = pos + extensions_len
                while pos + 4 <= end_extensions and pos + 4 <= len(payload):
                    ext_type = int.from_bytes(payload[pos:pos+2], 'big')
                    ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
                    pos += 4
                    
                    # SNI Extension is type 0
                    if ext_type == 0:
                        # Server Name List Length (2)
                        if pos + 2 > len(payload): break
                        # sn_list_len = int.from_bytes(payload[pos:pos+2], 'big')
                        pos += 2
                        
                        # Server Name Type (1)
                        if pos + 1 > len(payload): break
                        sn_type = payload[pos]
                        pos += 1
                        
                        # Host Name is type 0
                        if sn_type == 0:
                            # Server Name Length (2)
                            if pos + 2 > len(payload): break
                            sn_len = int.from_bytes(payload[pos:pos+2], 'big')
                            pos += 2
                            
                            if pos + sn_len <= len(payload):
                                sni = payload[pos:pos+sn_len].decode('utf-8')
                                return {"sni": sni}
                        break
                    
                    pos += ext_len
                    
        except Exception:
            pass
            
    return None


def dissect_udp(pkt) -> Optional[Dict[str, Any]]:
    """Dissect UDP layer with DNS detection."""
    if UDP not in pkt:
        return None

    u = pkt[UDP]
    result = {"sport": int(u.sport), "dport": int(u.dport)}

    # DNS heuristic
    payload = bytes(u.payload)
    if payload and (result["dport"] == 53 or result["sport"] == 53):
        try:
            s = payload.decode("utf-8", errors="ignore")
            # Simple heuristic: look for domain-like strings
            # In real DNS packets, this is binary, but for simple display we try to find the name
            # A better approach would be to use Scapy's DNS layer, but we are doing manual dissection here for speed/simplicity
            # or if Scapy fails.
            
            # Check for unusually long payload which might indicate tunneling
            if len(payload) > 200: # Threshold for DNS tunneling suspicion
                result["dns_tunnel_suspect"] = True
                
            result["dns_guess"] = s[:120]
        except Exception:
            pass

    return result


def dissect_packet(pkt, iface: Optional[str] = None) -> Dict[str, Any]:
    """
    Main dissector function that analyzes a packet and returns structured data.

    Args:
        pkt: Scapy packet object
        iface: Interface name where packet was captured

    Returns:
        Dictionary containing packet analysis
    """
    out = {
        "ts": ts_iso(pkt.time),
        "len": len(pkt),
        "iface": iface
    }

    # Ensure plugins are loaded
    load_plugins()

    # Run all dissectors
    eth_data = dissect_ethernet(pkt)
    if eth_data:
        out["eth"] = eth_data

    arp_data = dissect_arp(pkt)
    if arp_data:
        out["arp"] = arp_data

    ip_data = dissect_ip(pkt)
    if ip_data:
        out["ip"] = ip_data

    icmp_data = dissect_icmp(pkt)
    if icmp_data:
        out["icmp"] = icmp_data

    tcp_data = dissect_tcp(pkt)
    if tcp_data:
        out["tcp"] = tcp_data
        # Extract HTTP if present
        if "http" in tcp_data:
            out["http"] = tcp_data["http"]
        
        # Extract TLS SNI if present
        tls_data = dissect_tls(pkt)
        if tls_data:
            out["tls"] = tls_data

    udp_data = dissect_udp(pkt)
    if udp_data:
        out["udp"] = udp_data
        if "dns_guess" in udp_data:
            out["dns_guess"] = udp_data["dns_guess"]

    # Run plugins
    # Create a layers dict for plugins to use easily
    layers = {}
    if "eth" in out: layers["eth"] = out["eth"]
    if "ip" in out: layers["ip"] = out["ip"]
    if "tcp" in out: layers["tcp"] = out["tcp"]
    if "udp" in out: layers["udp"] = out["udp"]
    if "icmp" in out: layers["icmp"] = out["icmp"]
    if "arp" in out: layers["arp"] = out["arp"]

    for plugin in _PLUGINS:
        try:
            # Pass the current output, the raw packet, and the parsed layers
            res = plugin.dissect(out, pkt, layers)
            if res:
                out[plugin.PROTOCOL] = res
        except Exception:
            pass

    return out
