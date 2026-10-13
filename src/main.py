
import sys
from src.capture import capture_packets
from src.parsers.ethernet import parse_ethernet
from src.parsers.ipv4 import parse_ipv4


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