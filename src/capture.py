"""Raw socket capture layer.

Job: pull raw bytes off the network card and push them to a processing queue.
It does NOT parse, print, or decide anything.
"""

import select
import socket
from typing import Optional

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


def capture_worker(packet_queue, stop_event, interface: Optional[str] = None) -> None:
    """Capture raw packets in a loop and push (raw_data, interface) into packet_queue."""
    try:
        sock = create_raw_socket(interface)
    except PermissionError:
        print("[!] Permission denied. Raw sockets require root, so run with sudo.")
        stop_event.set()
        return
    except OSError as e:
        print(f"[!] Socket error: {e}")
        stop_event.set()
        return

    try:
        while True:
            if stop_event.is_set():
                break

            readable, _, _ = select.select([sock], [], [], 0.5)
            if readable:
                raw_data, addr = sock.recvfrom(MAX_FRAME_SIZE)
                packet_queue.put((raw_data, addr[0]))
    finally:
        sock.close()