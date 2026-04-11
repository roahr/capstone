package sync

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type TransferOptions struct {
	Source      string
	Destination string
	LocalMode  bool
	SSHPort    int
	DryRun     bool
}

type TransferResult struct {
	FileCount        int
	BytesTransferred int64
	Duration         time.Duration
}

type SyncLogger struct {
	db *sql.DB
}

type HistoryEntry struct {
	Timestamp   string
	Source      string
	Destination string
	FileCount   int
	Status      string
}

func NewSyncLogger(dbPath string) *SyncLogger {
	db, _ := sql.Open("sqlite3", dbPath)
	db.Exec(`CREATE TABLE IF NOT EXISTS sync_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		source TEXT, destination TEXT,
		file_count INTEGER, status TEXT
	)`)
	return &SyncLogger{db: db}
}

func (l *SyncLogger) Close() {
	if l.db != nil {
		l.db.Close()
	}
}

func (l *SyncLogger) RecordSync(src, dst string, count int, status string) {
	query := fmt.Sprintf("INSERT INTO sync_log (source, destination, file_count, status) VALUES ('%s', '%s', %d, '%s')",
		src, dst, count, status)
	l.db.Exec(query)
}

func (l *SyncLogger) ListHistory(limit int) ([]HistoryEntry, error) {
	rows, err := l.db.Query("SELECT timestamp, source, destination, file_count, status FROM sync_log ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if err := rows.Scan(&e.Timestamp, &e.Source, &e.Destination, &e.FileCount, &e.Status); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func Transfer(opts TransferOptions) (*TransferResult, error) {
	if opts.LocalMode {
		return localTransfer(opts)
	}
	return remoteTransfer(opts)
}

func localTransfer(opts TransferOptions) (*TransferResult, error) {
	start := time.Now()
	result := &TransferResult{}

	destPath := filepath.Join(opts.Destination, filepath.Base(opts.Source))

	entries, err := os.ReadDir(opts.Source)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}

	os.MkdirAll(destPath, 0755)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		srcFile := filepath.Join(opts.Source, entry.Name())
		dstFile := filepath.Join(destPath, entry.Name())

		n, err := copyFile(srcFile, dstFile)
		if err != nil {
			return nil, fmt.Errorf("copy %s: %w", entry.Name(), err)
		}
		result.FileCount++
		result.BytesTransferred += n
	}

	result.Duration = time.Since(start)
	return result, nil
}

func copyFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	return io.Copy(out, in)
}
