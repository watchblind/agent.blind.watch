package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry represents a single finalized batch stored as a JSON file on disk.
// Used by logtail and the legacy single-file batch path. Scheduler now uses
// OpenBatch for incremental writes; both produce *.wal files that drain
// through the same Pending/Ack lifecycle.
type Entry struct {
	BatchID    string `json:"batch_id"`
	AgentID    string `json:"agent_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
}

// Default limits. See design doc 2026-04-14-agent-reconnection-and-crash-safe-buffering-design.md §4.5.
const (
	defaultMaxSizeMB  = 1024
	defaultMaxEntries = 2000
	defaultMaxAge     = 7 * 24 * time.Hour
)

// WAL is a directory of *.wal files plus, when scheduler is using OpenBatch,
// transient *.open files. Only *.wal files are exposed via Pending().
type WAL struct {
	dir        string
	maxSizeMB  int
	maxEntries int
	maxAge     time.Duration

	mu sync.Mutex
}

// New creates a WAL in the given directory with the given limits. Pass 0 for
// either limit to use the package defaults (1024 MB, 2000 files).
func New(dir string, maxSizeMB, maxEntries int) (*WAL, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = defaultMaxSizeMB
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating WAL directory: %w", err)
	}
	return &WAL{
		dir:        dir,
		maxSizeMB:  maxSizeMB,
		maxEntries: maxEntries,
		maxAge:     defaultMaxAge,
	}, nil
}

// Dir returns the WAL directory path.
func (w *WAL) Dir() string { return w.dir }

// Append writes a finalized Entry to disk atomically (temp + rename + dir
// fsync). Used by logtail and the legacy single-file batch path.
func (w *WAL) Append(entry Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.enforceLimitsLocked()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling WAL entry: %w", err)
	}

	safeName := filepath.Base(entry.BatchID)
	if safeName == "." || safeName == "/" || safeName == "" {
		return fmt.Errorf("invalid batch_id: %q", entry.BatchID)
	}
	path := filepath.Join(w.dir, safeName+".wal")
	return atomicReplace(path, data, 0600)
}

// Ack deletes the WAL entry for the given batch ID. Idempotent — missing files
// are not an error.
func (w *WAL) Ack(batchID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	safeName := filepath.Base(batchID)
	path := filepath.Join(w.dir, safeName+".wal")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing WAL entry: %w", err)
	}
	return fsyncDir(w.dir)
}

// Pending returns all unacknowledged finalized (.wal) entries, sorted by
// timestamp. *.open files are not included.
func (w *WAL) Pending() ([]Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, err := w.listWALFilesLocked()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})
	return entries, nil
}

// Count returns the number of pending finalized (.wal) entries.
func (w *WAL) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, _ := w.listWALFilesLocked()
	return len(files)
}

// PendingBytes returns the total on-disk size of pending finalized entries.
func (w *WAL) PendingBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, _ := w.listWALFilesLocked()
	var total int64
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			total += info.Size()
		}
	}
	return total
}

func (w *WAL) listWALFilesLocked() ([]string, error) {
	dirEntries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, fmt.Errorf("reading WAL directory: %w", err)
	}
	var files []string
	for _, e := range dirEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".wal") {
			files = append(files, filepath.Join(w.dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// enforceLimitsLocked applies (in order) the TTL, the max-entries, and the
// max-size policies. Caller must hold w.mu.
func (w *WAL) enforceLimitsLocked() {
	files, _ := w.listWALFilesLocked()

	// 1. TTL — drop anything older than maxAge by mtime.
	cutoff := time.Now().Add(-w.maxAge)
	kept := files[:0]
	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil && info.ModTime().Before(cutoff) {
			os.Remove(f)
			continue
		}
		kept = append(kept, f)
	}
	files = kept

	// 2. Max entries — drop oldest first.
	for len(files) >= w.maxEntries && len(files) > 0 {
		os.Remove(files[0])
		files = files[1:]
	}

	// 3. Max bytes — drop oldest first until under cap.
	maxBytes := int64(w.maxSizeMB) * 1024 * 1024
	var total int64
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			total += info.Size()
		}
	}
	for total > maxBytes && len(files) > 0 {
		if info, err := os.Stat(files[0]); err == nil {
			total -= info.Size()
		}
		os.Remove(files[0])
		files = files[1:]
	}
}
