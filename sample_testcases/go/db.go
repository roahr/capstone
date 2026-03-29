package main

import (
	"database/sql"
	"fmt"
	"log"
)

// Database handle, initialized elsewhere.
var db *sql.DB

// validStatuses is the exhaustive set of allowed status values.
var validStatuses = map[string]bool{
	"active":   true,
	"inactive": true,
}

// ---------------------------------------------------------------------------
// TRUE POSITIVE: CWE-89 SQL Injection
// User-supplied name is concatenated directly into the query string.
// ---------------------------------------------------------------------------

func SearchUsers(name string) (*sql.Rows, error) {
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("SearchUsers error: %v", err)
		return nil, err
	}
	return rows, nil
}

// ---------------------------------------------------------------------------
// TRUE POSITIVE: CWE-89 SQL Injection #2
// User-supplied id is interpolated with fmt.Sprintf into the query string.
// ---------------------------------------------------------------------------

func DeleteUser(id string) error {
	query := fmt.Sprintf("DELETE FROM users WHERE id = '%s'", id)
	_, err := db.Exec(query)
	if err != nil {
		log.Printf("DeleteUser error: %v", err)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE: CWE-89 (Basic tier — SAST resolves)
// Parameterized query with placeholder $1; no injection possible.
// ---------------------------------------------------------------------------

func GetUserByID(id int) (*sql.Row, error) {
	row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)
	return row, nil
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE: CWE-89 (Contextual tier — Graph resolves)
// fmt.Sprintf is used, but `status` is validated against a fixed allowlist
// before it ever reaches the query. A SAST tool will flag the Sprintf, but
// data-flow analysis shows the value is always one of {"active","inactive"}.
// ---------------------------------------------------------------------------

func GetUsersByStatus(status string) (*sql.Rows, error) {
	if !validStatuses[status] {
		return nil, fmt.Errorf("invalid status: %s", status)
	}
	query := fmt.Sprintf("SELECT * FROM users WHERE status = '%s'", status)
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("GetUsersByStatus error: %v", err)
		return nil, err
	}
	return rows, nil
}
