"""IPv4 packet parser (Layer 3)."""

import struct
from typing import Tuple


def format_ipv4(ip_bytes: bytes) -> str:
    """Format 4 raw bytes into a dotted-decimal IPv4 address string."""
    return ".".join(str(b) for b in ip_bytes)


def parse_ipv4(payload: bytes) -> Tuple[int, int, int, int, str, str, bytes]:
    """Parse a 20-byte IPv4 packet header.

    Extracts IP Version and Header Length using bitwise operations.

    Args:
        payload: Packet bytes starting at the IPv4 header.

    Returns:
        Tuple of (version, ihl, ttl, protocol, source_ip, target_ip, payload):
            - version (int): IP version (e.g. 4)
            - ihl (int): Internet Header Length in 32-bit words (e.g. 5)
            - ttl (int): Time to Live
            - protocol (int): Upper-layer protocol number (e.g. 6 for TCP, 17 for UDP)
            - source_ip (str): Formatted source IP address (e.g. '192.168.1.1')
            - target_ip (str): Formatted target IP address (e.g. '192.168.1.254')
            - payload (bytes): Remaining payload bytes after the IP header
    """
    version_ihl, _, _, _, _, ttl, protocol, _, src_ip, target_ip = struct.unpack(
        "!BBHHHBBH4s4s", payload[:20]
    )

    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_length = ihl * 4

    return (
        version,
        ihl,
        ttl,
        protocol,
        format_ipv4(src_ip),
        format_ipv4(target_ip),
        payload[header_length:],
    )

