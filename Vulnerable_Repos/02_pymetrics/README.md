# PyMetrics

A lightweight system monitoring dashboard. Collects CPU, memory, disk, and network metrics and displays them in a simple web UI.

## Features

- Real-time system metrics (CPU, RAM, disk, network)
- Custom metric expressions for computed fields
- YAML-based configuration
- Metric history with configurable retention
- Export metrics as JSON or CSV
- Filtering and aggregation support

## Quickstart

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml
python dashboard.py
```

Open `http://localhost:8080` in your browser.

## Configuration

Edit `config.yaml` to set collection intervals, retention periods, and alert thresholds.

```yaml
collection:
  interval_seconds: 10
  retention_hours: 24

alerts:
  cpu_threshold: 90
  memory_threshold: 85
```

## Custom Metrics

Define computed metrics using expressions in the dashboard:

```
avg(cpu_percent, 5)    # 5-minute CPU average
delta(bytes_sent)      # Network throughput
```

## License

MIT
