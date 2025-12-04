
import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw
from cli_pcap_analyzer.dissectors import dissect_packet

def test_ethernet_dissection():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")
    result = dissect_packet(pkt)
    
    assert "eth" in result
    assert result["eth"]["src"] == "00:11:22:33:44:55"
    assert result["eth"]["dst"] == "66:77:88:99:AA:BB"

def test_ip_dissection():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP(src="192.168.1.1", dst="192.168.1.2", ttl=64)
    result = dissect_packet(pkt)
    
    assert "ip" in result
    assert result["ip"]["src"] == "192.168.1.1"
    assert result["ip"]["dst"] == "192.168.1.2"
    assert result["ip"]["ttl"] == 64

def test_tcp_dissection():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/TCP(sport=12345, dport=80, flags="S")
    result = dissect_packet(pkt)
    
    assert "tcp" in result
    assert result["tcp"]["sport"] == 12345
    assert result["tcp"]["dport"] == 80
    assert "S" in result["tcp"]["flags"]

def test_udp_dissection():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/UDP(sport=53, dport=12345)
    result = dissect_packet(pkt)
    
    assert "udp" in result
    assert result["udp"]["sport"] == 53
    assert result["udp"]["dport"] == 12345

def test_http_dissection():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/TCP(dport=80)/Raw(load=payload)
    result = dissect_packet(pkt)
    
    assert "http" in result
    assert result["http"]["request_line"] == "GET /index.html HTTP/1.1"
    assert result["http"]["host"] == "example.com"

def test_tls_sni_dissection():
    # Construct a minimal TLS Client Hello with SNI
    sni_name = "test.com"
    sni_bytes = sni_name.encode('utf-8')
    sni_len = len(sni_bytes)
    
    # SNI Extension
    ext_len = 2 + 1 + 2 + sni_len
    sni_ext = (
        b'\x00\x00' +                   # Extension Type: Server Name
        ext_len.to_bytes(2, 'big') +    # Extension Length
        (sni_len + 3).to_bytes(2, 'big') + # Server Name List Length
        b'\x00' +                       # Server Name Type: Host Name
        sni_len.to_bytes(2, 'big') +    # Server Name Length
        sni_bytes                       # Server Name
    )
    
    # Handshake Protocol: Client Hello
    handshake_body = (
        b'\x03\x03' +                   # Version: TLS 1.2
        b'\x00' * 32 +                  # Random
        b'\x00' +                       # Session ID Length: 0
        b'\x00\x02\xc0\x2b' +           # Cipher Suites
        b'\x01\x00' +                   # Compression Methods
        len(sni_ext).to_bytes(2, 'big') + # Extensions Length
        sni_ext
    )
    
    handshake_header = b'\x01' + len(handshake_body).to_bytes(3, 'big')
    handshake = handshake_header + handshake_body
    
    record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/TCP(dport=443)/Raw(load=record)
    result = dissect_packet(pkt)
    
    assert "tls" in result
    assert result["tls"]["sni"] == "test.com"
