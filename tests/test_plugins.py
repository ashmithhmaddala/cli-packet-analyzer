
import pytest
import sys
import os
from scapy.all import Ether, IP, TCP, Raw
from cli_pcap_analyzer.dissectors import dissect_packet, load_plugins, _PLUGINS

# Ensure plugins are loaded before tests
@pytest.fixture(scope="module", autouse=True)
def setup_plugins():
    # Add project root to path to find plugins
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    load_plugins()

def test_plugin_loading():
    # Check if sample plugin is loaded
    plugin_names = [p.__name__ for p in _PLUGINS]
    assert any("sample_plugin" in name for name in plugin_names)

def test_sample_plugin_execution():
    # Sample plugin triggers on TCP port 9999
    # Payload: version=1, command=2, length=10 (0x000A)
    payload = b'\x01\x02\x00\x0A' + b'\x00' * 6
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP()/TCP(dport=9999)/Raw(load=payload)
    
    result = dissect_packet(pkt)
    
    assert "sample" in result
    assert result["sample"]["version"] == 1
    assert result["sample"]["command"] == 2
    assert result["sample"]["length"] == 10
