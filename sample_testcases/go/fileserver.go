package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// baseDir is the root directory for served files.
var baseDir = "/var/www/files"

// uploadDir is where uploaded avatars are stored.
var uploadDir = "/var/www/avatars"

// ---------------------------------------------------------------------------
// TRUE POSITIVE: CWE-22 Path Traversal
// User-supplied "file" query parameter is joined to baseDir with no
// sanitization. An attacker can pass "../../etc/passwd" to escape.
// ---------------------------------------------------------------------------

func HandleDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "missing file parameter", http.StatusBadRequest)
		return
	}

	path := filepath.Join(baseDir, filename)

	f, err := os.Open(path)
	if err != nil {
		http.Error(w, fmt.Sprintf("file not found: %v", err), http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(path)))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE: CWE-22 (Contextual tier — Graph resolves)
// filepath.Join + user input triggers SAST, but the code calls
// filepath.Clean and then validates that the cleaned path is still under
// baseDir via strings.HasPrefix. This is the standard Go mitigation.
// Data-flow / graph analysis can confirm the prefix check guards the Open.
// ---------------------------------------------------------------------------

func HandleAvatar(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "missing user parameter", http.StatusBadRequest)
		return
	}

	requested := filepath.Join(uploadDir, username+".png")
	cleaned := filepath.Clean(requested)

	if !strings.HasPrefix(cleaned, uploadDir) {
		http.Error(w, "invalid path", http.StatusForbidden)
		return
	}

	f, err := os.Open(cleaned)
	if err != nil {
		http.Error(w, "avatar not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "image/png")
	io.Copy(w, f)
}
