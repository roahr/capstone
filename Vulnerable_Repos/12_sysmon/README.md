# sysmon

Lightweight system monitoring daemon for Linux servers.

Collects CPU, memory, and disk usage metrics at configurable intervals and writes them to a local log file or forwards to a remote aggregator.

## Build

```bash
make
```

## Usage

```bash
./sysmon -i 5 -l /var/log/sysmon.log
./sysmon -i 10 -r 192.168.1.50:9090
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Collection interval (seconds) | 5 |
| `-l` | Log file path | `/var/log/sysmon.log` |
| `-r` | Remote aggregator address | disabled |
| `-d` | Run as daemon | false |

## License

MIT
