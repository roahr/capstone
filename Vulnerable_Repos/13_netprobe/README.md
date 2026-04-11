# netprobe

Network diagnostic utility for analyzing packet captures and performing DNS lookups.

## Build

```bash
make
```

## Usage

```bash
./netprobe capture -i eth0 -c 100
./netprobe dns example.com
./netprobe analyze capture.pcap
```

## Features

- Raw packet capture and header parsing
- DNS forward and reverse lookups
- Packet statistics and latency analysis
- PCAP file analysis

## Options

| Flag | Description |
|------|-------------|
| `-i` | Network interface |
| `-c` | Packet count limit |
| `-t` | Timeout in seconds |
| `-v` | Verbose output |

## License

MIT
