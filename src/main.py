
import sys
from src.capture import capture_packets
def main() -> int:
    print("[*] Sentinel Sniffer starting...")
    print("[*] Listening for packets... (Ctrl+C to stop)\n")

    count = 0
    try:
        for raw_data, interface in capture_packets():
            count += 1
            print(f"[{count:05}] {interface:<8} {len(raw_data):>5} bytes")
            # NEXT STEP: pass raw_data to parse_ethernet() here
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