# configsvc

Centralized configuration management service with HTTP API.

Stores key-value configuration entries in SQLite and exposes them through a REST interface. Supports bulk import from local files.

## Build

```bash
go build -o configsvc .
```

## Usage

```bash
./configsvc -addr :8080 -db configs.db
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config?key=<name>` | Retrieve config value |
| POST | `/config` | Create/update config entry |
| DELETE | `/config?key=<name>` | Remove config entry |
| POST | `/config/import` | Bulk import from file |
| POST | `/config/reload` | Reload and apply configs |

## Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `-addr` | Listen address | `:8080` |
| `-db` | Database path | `configs.db` |

## License

MIT
