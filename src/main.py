import argparse
import os
import queue
import sys
from multiprocessing import Event, Process, Queue

from src.analyzer import ThreatAnalyzer
from src.capture import capture_worker
from src.parsers.ethernet import parse_ethernet
from src.parsers.ipv4 import parse_ipv4
from src.parsers.tcp_udp import parse_tcp, parse_udp
from src.pcap_writer import PCAPWriter


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Network Sniffer")
    parser.add_argument(
        "-i", "--interface", default="eth0", help="Network interface to sniff"
    )
    args = parser.parse_args()

    print("[*] Sentinel Sniffer starting...")
    print(f"[*] Listening on interface {args.interface}... (Ctrl+C to stop)\n")

    os.makedirs("data/captures", exist_ok=True)
    pcap_writer = PCAPWriter("data/captures/live_capture.pcap")

    packet_queue = Queue()
    stop_event = Event()

    capture_process = Process(
        target=capture_worker,
        args=(packet_queue, stop_event, args.interface),
    )
    capture_process.start()

    analyzer = ThreatAnalyzer()
    count = 0
    try:
        while not stop_event.is_set():
            try:
                raw_data, interface = packet_queue.get(timeout=1)
            except queue.Empty:
                if not capture_process.is_alive():
                    break
                continue

            count += 1
            pcap_writer.write_packet(raw_data)

            print(f"[{count:05}] {interface:<8} {len(raw_data):>5} bytes")
            dest_mac, src_mac, eth_proto, eth_payload = parse_ethernet(raw_data)
            print(f"  Ethernet: {src_mac} -> {dest_mac} | Protocol: {eth_proto}")

            if eth_proto in (0x0800, "0x0800"):
                version, ihl, ttl, protocol, src_ip, target_ip, ip_payload = parse_ipv4(eth_payload)
                print(
                    f"  IPv4: {src_ip} -> {target_ip} | Version: {version} | IHL: {ihl} | TTL: {ttl} | Protocol: {protocol}"
                )

                if protocol == 6:
                    tcp = parse_tcp(ip_payload)
                    flags = [flag for flag, val in tcp["flags"].items() if val]
                    flags_str = " ".join(f"[{f}]" for f in flags) if flags else "[None]"
                    print(
                        f"    TCP: {tcp['src_port']} -> {tcp['dest_port']} | Flags: {flags_str} | Payload: {len(tcp['payload'])} bytes"
                    )

                    syn_flag = tcp["flags"]["SYN"]
                    ack_flag = tcp["flags"]["ACK"]
                    analyzer.detect(
                        src_ip,
                        target_ip,
                        tcp["dest_port"],
                        {"SYN": syn_flag, "ACK": ack_flag},
                    )
                elif protocol == 17:
                    udp = parse_udp(ip_payload)
                    print(
                        f"    UDP: {udp['src_port']} -> {udp['dest_port']} | Payload: {len(udp['payload'])} bytes"
                    )
                elif protocol == 1:
                    print("    ICMP: Control frame (ping)")
    except KeyboardInterrupt:
        print(f"\n[*] Sniffer stopped. {count} packets captured.")
    finally:
        stop_event.set()
        pcap_writer.close()
        capture_process.join(timeout=2)
        if capture_process.is_alive():
            capture_process.terminate()
        print("[*] Saved capture to data/captures/live_capture.pcap")

    return 0


if __name__ == "__main__":
    sys.exit(main())