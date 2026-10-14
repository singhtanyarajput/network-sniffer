"""TCP and UDP transport layer parsers (Layer 4)."""

import struct
from typing import Any, Dict


def parse_tcp(payload: bytes) -> Dict[str, Any]:
    """Parse a TCP segment header (Layer 4).

    Args:
        payload: Packet bytes starting at the TCP header.

    Returns:
        Structured dictionary containing:
            - src_port (int): Source port
            - dest_port (int): Destination port
            - sequence (int): Sequence number
            - acknowledgment (int): Acknowledgment number
            - offset (int): Data offset (header length in bytes)
            - flags (dict): Individual TCP control flags (URG, ACK, PSH, RST, SYN, FIN)
            - flag_urg (int): URG flag (bit 5)
            - flag_ack (int): ACK flag (bit 4)
            - flag_psh (int): PSH flag (bit 3)
            - flag_rst (int): RST flag (bit 2)
            - flag_syn (int): SYN flag (bit 1)
            - flag_fin (int): FIN flag (bit 0)
            - payload (bytes): Remaining payload data after the TCP header
    """
    src_port, dest_port, sequence, acknowledgment, offset_reserved, flags, _, _, _ = struct.unpack(
        "!HHLLBBHHH", payload[:20]
    )
    offset = (offset_reserved >> 4) * 4

    flag_urg = (flags & 32) >> 5
    flag_ack = (flags & 16) >> 4
    flag_psh = (flags & 8) >> 3
    flag_rst = (flags & 4) >> 2
    flag_syn = (flags & 2) >> 1
    flag_fin = flags & 1

    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "offset": offset,
        "flags": {
            "URG": flag_urg,
            "ACK": flag_ack,
            "PSH": flag_psh,
            "RST": flag_rst,
            "SYN": flag_syn,
            "FIN": flag_fin,
        },
        "flag_urg": flag_urg,
        "flag_ack": flag_ack,
        "flag_psh": flag_psh,
        "flag_rst": flag_rst,
        "flag_syn": flag_syn,
        "flag_fin": flag_fin,
        "payload": payload[offset:],
    }


def parse_udp(payload: bytes) -> Dict[str, Any]:
    """Parse an 8-byte UDP datagram header (Layer 4).

    Args:
        payload: Packet bytes starting at the UDP header.

    Returns:
        Structured dictionary containing:
            - src_port (int): Source port
            - dest_port (int): Destination port
            - length (int): UDP length in bytes
            - checksum (int): UDP checksum
            - payload (bytes): Remaining payload data after the 8-byte UDP header
    """
    src_port, dest_port, length, checksum = struct.unpack("!HHHH", payload[:8])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length,
        "checksum": checksum,
        "payload": payload[8:],
    }

