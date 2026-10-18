"""Utility helper functions for network packet formatting and hex dumping."""


def generate_hexdump(raw_data: bytes, length: int = 16) -> str:
    """Return a multi-line string formatted like Wireshark or xxd.

    Example format:
    0000  45 00 00 54 00 00 40 00  40 01 c2 b5 7f 00 00 01  E..T..@.@.......
    """
    lines = []
    for i in range(0, len(raw_data), length):
        chunk = raw_data[i : i + length]
        offset = f"{i:04x}"

        first_half = " ".join(f"{b:02x}" for b in chunk[:8])
        second_half = " ".join(f"{b:02x}" for b in chunk[8:])

        if len(chunk) > 8:
            hex_str = f"{first_half}  {second_half}"
        else:
            hex_str = first_half

        hex_str = f"{hex_str:<48}"
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset}  {hex_str}  {ascii_str}")

    return "\n".join(lines)


def format_mac(raw_mac: bytes) -> str:
    """Format 6 raw bytes into a colon-separated MAC address string."""
    return ":".join(f"{b:02x}" for b in raw_mac)


def format_ipv4(ip_bytes: bytes) -> str:
    """Format 4 raw bytes into a dotted-decimal IPv4 address string."""
    return ".".join(str(b) for b in ip_bytes)

