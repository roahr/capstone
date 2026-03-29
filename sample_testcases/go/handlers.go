package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// TRUE POSITIVE: CWE-78 Command Injection
// User-supplied hostname is concatenated into a shell command string.
// ---------------------------------------------------------------------------

func HandlePing(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("host")
	if hostname == "" {
		http.Error(w, "missing host parameter", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("sh", "-c", "ping -c 3 "+hostname)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("ping failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// ---------------------------------------------------------------------------
// TRUE POSITIVE: CWE-78 Command Injection #2
// Domain is passed as a separate argument, which looks safe. However,
// nslookup interprets certain domain strings (e.g., containing spaces or
// shell metacharacters on some platforms) in unexpected ways, enabling
// argument injection or DNS rebinding attacks.
// ---------------------------------------------------------------------------

func HandleLookup(w http.ResponseWriter, r *http.Request) {
	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "missing domain parameter", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("nslookup", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("lookup failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE: CWE-78 (Basic tier — SAST resolves)
// exec.Command is called with a hard-coded binary and NO user input.
// ---------------------------------------------------------------------------

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("uptime")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "health check failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "OK\n%s", output)
}

// ---------------------------------------------------------------------------
// FALSE POSITIVE: CWE-78 (Adversarial tier — LLM resolves)
// exec.Command uses inputPath from user upload, but the path is a temporary
// file named with a UUID — no user-controlled content appears in args.
// A SAST tool flags exec.Command usage near user input. Graph analysis may
// still consider it tainted because the upload triggers the path creation.
// Only an LLM can reason that UUID-named temp files are not exploitable.
// ---------------------------------------------------------------------------

func HandleConvert(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "missing image upload", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Write uploaded data to a temp file with a safe UUID-based name.
	inputPath := filepath.Join(os.TempDir(), uuid.New().String()+".png")
	outputPath := filepath.Join(os.TempDir(), uuid.New().String()+".jpg")

	tmp, err := os.Create(inputPath)
	if err != nil {
		http.Error(w, "failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(inputPath)
	defer tmp.Close()

	if _, err := io.Copy(tmp, file); err != nil {
		http.Error(w, "failed to save upload", http.StatusInternalServerError)
		return
	}
	tmp.Close()

	// Convert using ImageMagick — args are all safe generated paths.
	cmd := exec.Command("convert", inputPath, outputPath)
	if err := cmd.Run(); err != nil {
		http.Error(w, fmt.Sprintf("conversion failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer os.Remove(outputPath)

	w.Header().Set("Content-Type", "image/jpeg")
	http.ServeFile(w, r, outputPath)
}
