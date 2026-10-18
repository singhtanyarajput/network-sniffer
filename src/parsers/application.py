"""Layer 7 Deep Packet Inspection (DPI) parsers."""

import struct
from typing import Any, Dict, Optional


def parse_http(payload: bytes) -> Optional[str]:
    """Parse HTTP headers from payload if payload starts with standard HTTP methods.

    Args:
        payload: Application layer payload bytes.

    Returns:
        HTTP headers as a decoded string if valid HTTP, otherwise None.
    """
    prefixes = (b"GET ", b"POST ", b"HTTP/1.", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
    if not any(payload.startswith(p) for p in prefixes):
        return None

    try:
        if b"\r\n\r\n" in payload:
            header_bytes = payload.split(b"\r\n\r\n", 1)[0]
        elif b"\n\n" in payload:
            header_bytes = payload.split(b"\n\n", 1)[0]
        else:
            header_bytes = payload
        return header_bytes.decode("utf-8")
    except Exception:
        return None


def parse_dns(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse basic DNS header fields (Layer 7).

    Args:
        payload: DNS datagram payload bytes.

    Returns:
        Dictionary containing transaction ID, flags, and record counts, or None.
    """
    if len(payload) < 12:
        return None

    try:
        transaction_id, flags, questions, answers, authority, additional = struct.unpack(
            "!HHHHHH", payload[:12]
        )
        is_response = bool((flags >> 15) & 1)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "flags_hex": f"0x{flags:04x}",
            "is_response": is_response,
            "type": "Response" if is_response else "Query",
            "opcode": opcode,
            "rcode": rcode,
            "questions": questions,
            "answers": answers,
            "authority": authority,
            "additional": additional,
        }
    except Exception:
        return None

