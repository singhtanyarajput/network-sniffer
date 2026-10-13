"""Ethernet frame parser (Layer 2)."""

import struct
from typing import Tuple


def format_mac(raw_mac: bytes) -> str:
    """Format 6 raw bytes into a colon-separated MAC address string."""
    return ":".join(f"{b:02x}" for b in raw_mac)


def parse_ethernet(raw_data: bytes) -> Tuple[str, str, str, bytes]:
    """Parse a 14-byte Ethernet frame header.

    Args:
        raw_data: Raw Ethernet frame bytes.

    Returns:
        Tuple of (destination_mac, source_mac, protocol_hex, payload):
            - destination_mac: Formatted destination MAC address (e.g. '00:1a:2b:3c:4d:5e')
            - source_mac: Formatted source MAC address (e.g. '00:1a:2b:3c:4d:5e')
            - protocol_hex: Protocol EtherType as a hex string (e.g. '0x0800')
            - payload: Remaining frame payload bytes
    """
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_data[:14])
    return format_mac(dest_mac), format_mac(src_mac), f"0x{proto:04x}", raw_data[14:]

