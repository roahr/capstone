# DataFlow

A configurable ETL data pipeline for batch processing. Supports YAML-defined pipelines with pluggable transforms and database connectors.

## Features

- YAML pipeline definitions
- Pluggable transform functions
- SQLite and PostgreSQL connectors
- Pipeline state checkpointing for restartability
- CLI for running and monitoring pipelines

## Quick Start

```bash
pip install -r requirements.txt
python cli.py run --config pipeline.yaml
```

## Pipeline Configuration

```yaml
name: daily_sync
source:
  type: sqlite
  path: ./data/source.db
  query: "SELECT * FROM events WHERE date > :last_run"
transforms:
  - normalize_timestamps
  - apply_expression: "row['total'] * 1.1"
sink:
  type: sqlite
  path: ./data/target.db
  table: processed_events
```

## Commands

| Command | Description |
|---------|-------------|
| `run` | Execute a pipeline |
| `status` | Show pipeline state |
| `reset` | Clear checkpoint data |

## License

MIT
