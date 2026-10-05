"""Raw socket capture layer.

Job: pull raw bytes off the network card and hand them to whoever asks.
It does NOT parse, print, or decide anything.
"""

import socket
from typing import Iterator, Optional, Tuple

ETH_P_ALL = 0x0003       # Linux constant meaning "give me every protocol"
MAX_FRAME_SIZE = 65535   # largest buffer we'll accept for one packet


def create_raw_socket(interface: Optional[str] = None) -> socket.socket:
    """Open a Layer 2 raw socket. Needs root (raises PermissionError otherwise)."""
    sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL)
    )
    if interface:
        sock.bind((interface, 0))  # listen on one interface only, e.g. "eth0"
    return sock


def capture_packets(interface: Optional[str] = None) -> Iterator[Tuple[bytes, str]]:
    """Yield (raw_frame_bytes, interface_name) forever, one packet at a time."""
    sock = create_raw_socket(interface)
    try:
        while True:
            raw_data, addr = sock.recvfrom(MAX_FRAME_SIZE)
            yield raw_data, addr[0]
    finally:
        sock.close()  # always runs, even on Ctrl+C or an error