package main

import (
	"filesync/sync"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	src := flag.String("src", ".", "source directory")
	dst := flag.String("dst", "", "destination path")
	local := flag.Bool("local", false, "local copy mode")
	port := flag.Int("port", 22, "SSH port for remote transfers")
	logdb := flag.String("logdb", "sync.db", "sync log database path")
	list := flag.Bool("list", false, "list sync history")
	dryRun := flag.Bool("dry-run", false, "show what would be synced")
	flag.Parse()

	logger := sync.NewSyncLogger(*logdb)
	defer logger.Close()

	if *list {
		entries, err := logger.ListHistory(50)
		if err != nil {
			log.Fatalf("failed to list history: %v", err)
		}
		for _, e := range entries {
			fmt.Printf("[%s] %s -> %s (%d files, %s)\n",
				e.Timestamp, e.Source, e.Destination, e.FileCount, e.Status)
		}
		return
	}

	if *dst == "" {
		fmt.Fprintln(os.Stderr, "destination (-dst) is required")
		flag.Usage()
		os.Exit(1)
	}

	opts := sync.TransferOptions{
		Source:      *src,
		Destination: *dst,
		LocalMode:  *local,
		SSHPort:    *port,
		DryRun:     *dryRun,
	}

	result, err := sync.Transfer(opts)
	if err != nil {
		log.Fatalf("transfer failed: %v", err)
	}

	logger.RecordSync(opts.Source, opts.Destination, result.FileCount, "completed")

	fmt.Printf("Synced %d files (%d bytes) to %s\n",
		result.FileCount, result.BytesTransferred, opts.Destination)
}
