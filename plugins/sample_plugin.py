# Sample plugin for CLI Packet Analyzer
# This demonstrates the plugin architecture for adding custom protocol dissectors

from scapy.layers.inet import TCP

PROTOCOL = "sample"

def dissect(packet_json, raw_packet, layers):
    """
    Custom dissector function.

    Args:
        packet_json: Current packet JSON object being built
        raw_packet: Raw scapy packet object
        layers: Dict of already parsed layers

    Returns:
        Dict of fields to add under packet_json[PROTOCOL], or None if no match
    """

    # Example: Check if this is a custom protocol on a specific port
    if "tcp" in layers:
        tcp_layer = layers["tcp"]
        # Hypothetical protocol on port 9999
        if tcp_layer.get("dport") == 9999 or tcp_layer.get("sport") == 9999:
            # Extract some sample fields from the raw payload
            try:
                payload = bytes(raw_packet[TCP].payload)
                if len(payload) >= 4:
                    # Parse custom protocol fields
                    version = payload[0]
                    command = payload[1]
                    length = int.from_bytes(payload[2:4], byteorder='big')

                    return {
                        "version": version,
                        "command": command,
                        "length": length,
                        "payload_hex": payload.hex()
                    }
            except Exception as e:
                return {"error": str(e)}

    return None  # No dissection performed
