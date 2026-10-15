"""Threat detection and traffic pattern analyzer."""

from collections import defaultdict
import time
from typing import Any, Dict, Union


class ThreatAnalyzer:
    """Analyzes network packet streams to detect suspicious traffic patterns."""

    def __init__(self, port_scan_window: float = 5.0) -> None:
        self.syn_counts = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.port_scan_times = defaultdict(list)
        self.port_scan_window = port_scan_window

    def detect(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        tcp_flags: Union[Dict[str, Any], int, tuple],
    ) -> None:
        """Detect potential threats like SYN floods and port scans.

        Args:
            src_ip: Source IP address.
            dst_ip: Destination / target IP address.
            dst_port: Destination TCP port.
            tcp_flags: TCP control flags mapping or representation.
        """
        now = time.time()

        if isinstance(tcp_flags, dict):
            is_syn = bool(tcp_flags.get("SYN", 0) or tcp_flags.get("syn", 0))
            is_ack = bool(tcp_flags.get("ACK", 0) or tcp_flags.get("ack", 0))
        elif isinstance(tcp_flags, (tuple, list)):
            is_syn = bool(tcp_flags[0])
            is_ack = bool(tcp_flags[1])
        elif isinstance(tcp_flags, int):
            is_syn = bool((tcp_flags & 2) >> 1)
            is_ack = bool((tcp_flags & 16) >> 4)
        else:
            is_syn = bool(getattr(tcp_flags, "syn", False))
            is_ack = bool(getattr(tcp_flags, "ack", False))

        # SYN Flood Detection: SYN set without ACK
        if is_syn and not is_ack:
            self.syn_counts[src_ip].append(now)

        # Clean up SYN timestamps older than 1 second
        self.syn_counts[src_ip] = [
            ts for ts in self.syn_counts[src_ip] if now - ts <= 1.0
        ]
        if len(self.syn_counts[src_ip]) > 50:
            print(f"\033[91m[!] SYN FLOOD DETECTED from {src_ip}\033[0m")

        # Port Scan Detection: track unique ports within time window
        self.port_scans[src_ip].add(dst_port)
        self.port_scan_times[src_ip].append((now, dst_port))

        # Clean up port scan records older than the sliding window
        self.port_scan_times[src_ip] = [
            (ts, p)
            for ts, p in self.port_scan_times[src_ip]
            if now - ts <= self.port_scan_window
        ]
        self.port_scans[src_ip] = {p for _, p in self.port_scan_times[src_ip]}

        if len(self.port_scans[src_ip]) > 20:
            print(f"\033[93m[!] PORT SCAN DETECTED from {src_ip}\033[0m")

