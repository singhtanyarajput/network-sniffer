"""Raw socket capture layer.

Job: pull raw bytes off the network card and push them to a processing queue.
It does NOT parse, print, or decide anything.
"""

import ctypes
import fcntl
import select
import socket
from typing import Optional

ETH_P_ALL = 0x0003       # Linux constant meaning "give me every protocol"
MAX_FRAME_SIZE = 65535   # largest buffer we'll accept for one packet

SIOCGIFFLAGS = 0x8913    # ioctl: get interface flags
SIOCSIFFLAGS = 0x8914    # ioctl: set interface flags
IFF_PROMISC = 0x100      # Promiscuous mode flag


class ifreq(ctypes.Structure):
    """Structure for passing interface requests to ioctl."""

    _fields_ = [
        ("ifr_name", ctypes.c_char * 16),
        ("ifr_flags", ctypes.c_short),
        ("_pad", ctypes.c_byte * 22),
    ]


def set_promiscuous_mode(
    sock: socket.socket, interface_name: str, enable: bool = True
) -> None:
    """Enable or disable promiscuous mode on the specified network interface."""
    ifr = ifreq()
    ifr.ifr_name = interface_name.encode("utf-8")[:15]
    fcntl.ioctl(sock, SIOCGIFFLAGS, ifr)
    if enable:
        ifr.ifr_flags |= IFF_PROMISC
    else:
        ifr.ifr_flags &= ~IFF_PROMISC
    fcntl.ioctl(sock, SIOCSIFFLAGS, ifr)


def create_raw_socket(interface: Optional[str] = None) -> socket.socket:
    """Open a Layer 2 raw socket. Needs root (raises PermissionError otherwise)."""
    sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL)
    )
    if interface:
        sock.bind((interface, 0))  # listen on one interface only, e.g. "eth0"
    return sock


def capture_worker(
    packet_queue, stop_event, interface: str = "eth0"
) -> None:
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
        set_promiscuous_mode(sock, interface, enable=True)
    except Exception as e:
        print(f"[!] Warning: Could not enable promiscuous mode on {interface}: {e}")

    try:
        while True:
            if stop_event.is_set():
                break

            readable, _, _ = select.select([sock], [], [], 0.5)
            if readable:
                raw_data, addr = sock.recvfrom(MAX_FRAME_SIZE)
                packet_queue.put((raw_data, addr[0]))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            set_promiscuous_mode(sock, interface, enable=False)
        except Exception:
            pass
        sock.close()