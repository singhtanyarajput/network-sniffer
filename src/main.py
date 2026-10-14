
import sys
from src.capture import capture_packets
from src.parsers.ethernet import parse_ethernet
from src.parsers.ipv4 import parse_ipv4
from src.parsers.tcp_udp import parse_tcp, parse_udp


def main() -> int:
    print("[*] Sentinel Sniffer starting...")
    print("[*] Listening for packets... (Ctrl+C to stop)\n")

    count = 0
    try:
        for raw_data, interface in capture_packets():
            count += 1
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
                elif protocol == 17:
                    udp = parse_udp(ip_payload)
                    print(
                        f"    UDP: {udp['src_port']} -> {udp['dest_port']} | Payload: {len(udp['payload'])} bytes"
                    )
                elif protocol == 1:
                    print("    ICMP: Control frame (ping)")
    except PermissionError:  # must come before OSError (it's a subclass)
        print("[!] Permission denied. Raw sockets require root, so run with sudo.")
        return 1
    except OSError as e:
        print(f"[!] Socket error: {e}")
        return 1
    except KeyboardInterrupt:
        print(f"\n[*] Sniffer stopped. {count} packets captured.")
    return 0


if __name__ == "__main__":
    sys.exit(main())