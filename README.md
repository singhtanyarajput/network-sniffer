#  Network Sniffer & Security Analyzer

A low-level network packet sniffer built from scratch in Python. No Scapy, no
high-level packet libraries: every header is unpacked by hand with `socket`
and `struct` to understand how the TCP/IP stack works at the byte level.

> **Status:** early development. Currently capturing raw frames; parsers and
> threat detection are being built one layer at a time.

## Goals

- Capture raw Layer 2 frames using `AF_PACKET` sockets
- Manually parse Ethernet, IPv4, TCP and UDP headers (bitwise operations, byte order)
- Detect suspicious traffic patterns (planned)
- Save captures for later analysis (planned)

## Roadmap

- [x] Raw socket capture (`capture.py`)
- [ ] Ethernet parser (`parsers/ethernet.py`)
- [ ] IPv4 parser (`parsers/ipv4.py`)
- [ ] TCP / UDP parser (`parsers/tcp_udp.py`)
- [ ] Formatting helpers (`utils.py`)
- [ ] Threat detection (`analyzer.py`)
- [ ] Configuration via `config.yaml`
- [ ] Save captures to `data/captures/`
- [ ] Tests

## Tech Stack

- Python 3 (standard library only: `socket`, `struct`)
- Developed on Kali Linux (WSL2) with VS Code

## Project Structure

```
network-sniffer/
├── README.md
├── requirements.txt
├── config.yaml
├── data/captures/        # saved captures
├── src/
│   ├── main.py           # entry point
│   ├── capture.py        # raw socket listener
│   ├── analyzer.py       # threat detection logic
│   ├── utils.py          # MAC/IP formatting helpers
│   └── parsers/
│       ├── ethernet.py   # Layer 2
│       ├── ipv4.py       # Layer 3
│       └── tcp_udp.py    # Layer 4
└── tests/
```

## Getting Started

**Requirements:** Linux (or WSL2), Python 3.8+, root privileges (raw sockets).

```bash
git clone https://github.com/singhtanyarajput/network-sniffer.git
cd network-sniffer
sudo python3 -m src.main
```

Run from the project root so `src` imports resolve. Press `Ctrl+C` to stop.

## Ethical Use

This tool is for learning and for analyzing networks **you own or have
explicit permission to monitor**. Capturing other people's traffic without
consent may be illegal.

## License

TBD