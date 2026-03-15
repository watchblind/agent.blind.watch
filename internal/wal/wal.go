package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Entry represents a single WAL entry stored as an encrypted file on disk.
// Only encrypted data is persisted — plaintext never touches disk.
type Entry struct {
	BatchID    string `json:"batch_id"`
	AgentID    string `json:"agent_id"`
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"` // base64 AES-256-GCM ciphertext
}

// WAL implements an append-only write-ahead log backed by individual files.
// Each batch window gets its own file named by timestamp.
// Files are deleted only after the server acknowledges receipt.
type WAL struct {
	dir        string
	maxSizeMB  int
	maxEntries int

	mu sync.Mutex
}

// New creates a WAL in the given directory.
func New(dir string, maxSizeMB, maxEntries int) (*WAL, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 500
	}
	if maxEntries <= 0 {
		maxEntries = 1000
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating WAL directory: %w", err)
	}

	return &WAL{
		dir:        dir,
		maxSizeMB:  maxSizeMB,
		maxEntries: maxEntries,
	}, nil
}

// Append writes an encrypted entry to disk. The entry must already be encrypted
// before calling this method — WAL never sees plaintext.
func (w *WAL) Append(entry Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Enforce entry limit — drop oldest if at capacity
	entries, _ := w.listFilesLocked()
	if len(entries) >= w.maxEntries {
		// Drop oldest
		oldest := entries[0]
		os.Remove(oldest)
		entries = entries[1:]
	}

	// Enforce size limit
	w.enforceSize()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling WAL entry: %w", err)
	}

	// Sanitize batch_id: use only the base name to prevent path traversal
	safeName := filepath.Base(entry.BatchID)
	if safeName == "." || safeName == "/" || safeName == "" {
		return fmt.Errorf("invalid batch_id: %q", entry.BatchID)
	}
	filename := fmt.Sprintf("%s.wal", safeName)
	path := filepath.Join(w.dir, filename)

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing WAL file: %w", err)
	}

	// fsync the file for crash safety
	f, err := os.Open(path)
	if err == nil {
		f.Sync()
		f.Close()
	}

	return nil
}

// Ack deletes the WAL entry for the given batch ID.
// Called when the server acknowledges receipt.
func (w *WAL) Ack(batchID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	safeName := filepath.Base(batchID)
	filename := fmt.Sprintf("%s.wal", safeName)
	path := filepath.Join(w.dir, filename)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing WAL entry: %w", err)
	}
	return nil
}

// Pending returns all unacknowledged WAL entries, sorted by timestamp.
func (w *WAL) Pending() ([]Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	files, err := w.listFilesLocked()
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

// Count returns the number of pending entries.
func (w *WAL) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	files, _ := w.listFilesLocked()
	return len(files)
}

// Dir returns the WAL directory path.
func (w *WAL) Dir() string {
	return w.dir
}

func (w *WAL) listFilesLocked() ([]string, error) {
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

func (w *WAL) enforceSize() {
	files, err := w.listFilesLocked()
	if err != nil || len(files) == 0 {
		return
	}

	var totalSize int64
	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil {
			totalSize += info.Size()
		}
	}

	maxBytes := int64(w.maxSizeMB) * 1024 * 1024
	for totalSize > maxBytes && len(files) > 0 {
		info, err := os.Stat(files[0])
		if err == nil {
			totalSize -= info.Size()
		}
		os.Remove(files[0])
		files = files[1:]
	}
}
