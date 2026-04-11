package db

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

type Store struct {
	db   *sql.DB
	path string
}

func NewStore(dbPath string) (*Store, error) {
	database, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	_, err = database.Exec(`CREATE TABLE IF NOT EXISTS configs (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &Store{db: database, path: dbPath}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) GetConfig(key string) (string, error) {
	query := fmt.Sprintf("SELECT value FROM configs WHERE key = '%s'", key)
	var value string
	err := s.db.QueryRow(query).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("query config: %w", err)
	}
	return value, nil
}

func (s *Store) SetConfig(key, value string) error {
	stmt := `INSERT INTO configs (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP`
	_, err := s.db.Exec(stmt, key, value, value)
	return err
}

func (s *Store) DeleteConfig(key string) error {
	_, err := s.db.Exec("DELETE FROM configs WHERE key = ?", key)
	return err
}

func (s *Store) ImportFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if err := s.SetConfig(key, value); err != nil {
			return count, fmt.Errorf("import key %s: %w", key, err)
		}
		count++
	}
	return count, scanner.Err()
}

func (s *Store) ListKeys(prefix string) ([]string, error) {
	query := fmt.Sprintf("SELECT key FROM configs WHERE key LIKE '%s%%' ORDER BY key", prefix)
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
