
import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw
from cli_pcap_analyzer.dissectors import dissect_packet

def test_basic_auth_alert():
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: target.com\r\n"
        b"Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n"
    )
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/TCP(dport=80)/Raw(load=payload)
    result = dissect_packet(pkt)
    
    assert "http" in result
    assert result["http"].get("auth_basic") is True

def test_user_agent_extraction():
    ua_string = "Mozilla/5.0 (TestAgent)"
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: target.com\r\n" +
        f"User-Agent: {ua_string}\r\n\r\n".encode('utf-8')
    )
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/TCP(dport=80)/Raw(load=payload)
    result = dissect_packet(pkt)
    
    assert "http" in result
    assert result["http"]["user_agent"] == ua_string

def test_dns_tunneling_detection():
    # Create a large DNS payload (> 200 bytes)
    dns_payload = b"A" * 250
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/UDP(dport=53)/Raw(load=dns_payload)
    result = dissect_packet(pkt)
    
    assert "udp" in result
    assert result["udp"].get("dns_tunnel_suspect") is True

def test_normal_dns_no_alert():
    # Normal small DNS payload
    dns_payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01"
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/UDP(dport=53)/Raw(load=dns_payload)
    result = dissect_packet(pkt)
    
    assert "udp" in result
    assert result["udp"].get("dns_tunnel_suspect") is None
