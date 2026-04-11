package sync

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func remoteTransfer(opts TransferOptions) (*TransferResult, error) {
	start := time.Now()

	cmd, err := buildSyncCommand(opts)
	if err != nil {
		return nil, err
	}

	output, err := runCommand(cmd)
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w\noutput: %s", err, output)
	}

	count := countTransferredFiles(output)

	return &TransferResult{
		FileCount:        count,
		BytesTransferred: 0,
		Duration:         time.Since(start),
	}, nil
}

func buildSyncCommand(opts TransferOptions) (string, error) {
	if opts.Source == "" || opts.Destination == "" {
		return "", fmt.Errorf("source and destination are required")
	}

	args := []string{"rsync", "-avz", "--progress"}

	if opts.SSHPort != 22 {
		args = append(args, fmt.Sprintf("-e 'ssh -p %d'", opts.SSHPort))
	}

	if opts.DryRun {
		args = append(args, "--dry-run")
	}

	args = append(args, opts.Source, opts.Destination)

	return strings.Join(args, " "), nil
}

func runCommand(cmdStr string) (string, error) {
	cmd := exec.Command("sh", "-c", cmdStr)

	out, err := cmd.CombinedOutput()
	return string(out), err
}

func countTransferredFiles(output string) int {
	count := 0
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "sending") ||
			strings.HasPrefix(line, "sent") || strings.HasPrefix(line, "total") {
			continue
		}
		count++
	}
	return count
}

func ValidateRemote(host string) (bool, error) {
	checkCmd := fmt.Sprintf("ssh -o ConnectTimeout=5 %s echo ok", host)
	out, err := runCommand(checkCmd)
	if err != nil {
		return false, fmt.Errorf("remote check failed: %w", err)
	}
	return strings.TrimSpace(out) == "ok", nil
}

func ListRemoteFiles(host, path string) ([]string, error) {
	cmd := fmt.Sprintf("ssh %s ls -1 %s", host, path)
	out, err := runCommand(cmd)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	var files []string
	for _, l := range lines {
		if l != "" {
			files = append(files, l)
		}
	}
	return files, nil
}
