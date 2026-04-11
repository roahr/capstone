# DocVault

A lightweight REST API for document storage and retrieval, built with Flask and SQLite.

## Features

- Upload, download, list, and delete documents
- API key authentication
- SQLite metadata store with file-system backing
- Configurable storage directory

## Quick Start

```bash
pip install -r requirements.txt
python api.py
```

The server starts on `http://localhost:5000` by default.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/documents` | Upload a document |
| GET | `/api/documents` | List all documents |
| GET | `/api/documents/<name>` | Download a document |
| DELETE | `/api/documents/<name>` | Delete a document |

## Configuration

Set `DOCVAULT_STORAGE` to customize the storage directory (default: `./vault`).
Set `DOCVAULT_API_KEY` to override the default API key.

## License

MIT
