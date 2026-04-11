# LogStream

Centralized log aggregation service for distributed applications.

## Features

- Ingest logs from multiple sources via HTTP
- Full-text search across log entries
- Export logs to file with date range filters
- Automatic log rotation and archival

## Getting Started

```bash
npm install
npm run dev
```

## Configuration

Set environment variables or use `.env`:

```
LOG_DIR=./logs
DB_PATH=./data/logs.db
RETENTION_DAYS=90
MAX_EXPORT_SIZE=50000
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /ingest | Submit log entries |
| GET | /query | Search logs |
| GET | /export | Export logs to file |
| POST | /rotate | Trigger log rotation |

## License

MIT
