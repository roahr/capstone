# filesync

Cross-server file synchronization utility.

Synchronizes files between local and remote servers using rsync/scp with configurable transfer options and logging.

## Build

```bash
go build -o filesync .
```

## Usage

```bash
filesync -src /data/files -dst user@server:/backup
filesync -src /var/logs -dst /mnt/archive -local
filesync -list -logdb sync.db
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-src` | Source directory | `.` |
| `-dst` | Destination path | required |
| `-local` | Local copy mode | false |
| `-port` | SSH port for remote | 22 |
| `-logdb` | Sync log database | `sync.db` |
| `-list` | List sync history | false |
| `-dry-run` | Show what would sync | false |

## License

MIT
