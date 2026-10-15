"""Binary PCAP file exporter."""

import struct
import time
from typing import Optional


class PCAPWriter:
    """Writes raw packet captures to disk in standard libpcap (.pcap) format."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.file = open(filepath, "wb")

        # Standard 24-byte PCAP Global Header (little-endian microsecond format)
        # Magic: 0xa1b2c3d4, Major: 2, Minor: 4, Zone: 0, Sigfigs: 0, Snaplen: 65535, Network: 1 (Ethernet)
        global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.file.write(global_header)
        self.file.flush()

    def write_packet(self, raw_data: bytes, timestamp: Optional[float] = None) -> None:
        """Write a packet header and raw frame bytes to the PCAP file.

        Args:
            raw_data: Raw Ethernet frame bytes.
            timestamp: Packet timestamp in epoch seconds (float). Defaults to time.time().
        """
        if timestamp is None:
            timestamp = time.time()

        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        incl_len = len(raw_data)
        orig_len = len(raw_data)

        # 16-byte PCAP Packet Header
        packet_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        self.file.write(packet_header)
        self.file.write(raw_data)
        self.file.flush()

    def close(self) -> None:
        """Flush and close the PCAP file handle."""
        if self.file and not self.file.closed:
            self.file.flush()
            self.file.close()

    def __enter__(self) -> "PCAPWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

