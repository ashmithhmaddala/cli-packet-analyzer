#!/usr/bin/env python3
"""
Test script to verify CLI Packet Analyzer installation.
"""

def test_imports():
    """Test that all modules can be imported."""
    try:
        import cli_pcap_analyzer
        print("✓ Package import successful")

        from cli_pcap_analyzer import PacketAnalyzer, dissect_packet, analyze_live
        print("✓ Main classes/functions import successful")

        from cli_pcap_analyzer.capture import PacketCapture
        print("✓ PacketCapture import successful")

        from cli_pcap_analyzer.output import PacketOutput, create_output_handler
        print("✓ Output modules import successful")

        from cli_pcap_analyzer.dissectors import dissect_packet as dissect_func
        print("✓ Dissectors import successful")

        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without network access."""
    try:
        from cli_pcap_analyzer import PacketAnalyzer

        analyzer = PacketAnalyzer()
        print("✓ PacketAnalyzer instantiation successful")

        # Test interface listing (this will work without root)
        interfaces = analyzer.list_interfaces()
        print(f"✓ Interface listing successful (found {len(interfaces)} interfaces)")

        return True
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=== CLI Packet Analyzer - Installation Test ===\n")

    print("Testing imports...")
    imports_ok = test_imports()
    print()

    print("Testing basic functionality...")
    functionality_ok = test_basic_functionality()
    print()

    if imports_ok and functionality_ok:
        print("🎉 All tests passed! CLI Packet Analyzer is ready to use.")
        print()
        print("Usage:")
        print("  pcap-analyzer --list-ifaces")
        print("  sudo pcap-analyzer --iface eth0 --count 5")
        print("  pcap-analyzer --read sample.pcap")
        return 0
    else:
        print("❌ Some tests failed. Check the error messages above.")
        return 1

if __name__ == "__main__":
    exit(main())
