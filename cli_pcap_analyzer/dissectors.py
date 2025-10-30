"""
Protocol dissectors for packet analysis.
"""

import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP


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
            if s.startswith("GET ") or s.startswith("POST ") or s.startswith("HTTP/"):
                lines = s.splitlines()
                first = lines[0].strip()
                parts = first.split()

                if parts:
                    if parts[0].startswith("HTTP/"):
                        result["http"] = {"status_line": first}
                    else:
                        result["http"] = {"request_line": first}
                        # Find Host header
                        for line in lines[1:8]:
                            if line.lower().startswith("host:"):
                                result["http"]["host"] = line.split(":", 1)[1].strip()
                                break
        except Exception:
            pass

    return result


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

    udp_data = dissect_udp(pkt)
    if udp_data:
        out["udp"] = udp_data
        if "dns_guess" in udp_data:
            out["dns_guess"] = udp_data["dns_guess"]

    return out
