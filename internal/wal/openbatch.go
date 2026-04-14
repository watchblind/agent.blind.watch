package wal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// BatchMeta is the first JSON line of every .open file. Recovery uses it to
// reconstruct the wal.Entry that wraps the appended payload entries.
type BatchMeta struct {
	BatchID   string `json:"batch_id"`
	AgentID   string `json:"agent_id"`
	Epoch     int    `json:"epoch"`
	StartedAt int64  `json:"started_at"`
}

// OpenBatch is an in-progress NDJSON batch file. Each call to Append (added in
// Task 4) appends one CRC-tagged entry line and fsyncs. Finalize (Task 5)
// atomically renames .open -> .wal. The zero value is unusable; obtain one
// via WAL.OpenBatch.
//
// Concurrency: future Append may be called from multiple goroutines but is
// serialized internally via mu. Close/Finalize must not race with Append.
type OpenBatch struct {
	wal  *WAL
	meta BatchMeta
	path string // <dir>/<batch_id>.open

	mu     sync.Mutex
	file   *os.File
	closed bool
	count  int // number of payload entries appended (excludes meta)
}

func safeBatchName(batchID string) (string, error) {
	name := filepath.Base(batchID)
	if name == "." || name == "/" || name == "" || name == ".." {
		return "", fmt.Errorf("invalid batch_id: %q", batchID)
	}
	for _, r := range batchID {
		if r == '/' || r == '\\' || r == 0 {
			return "", fmt.Errorf("invalid batch_id: %q", batchID)
		}
	}
	return name, nil
}

// OpenBatch creates a new in-progress batch file and writes the meta line.
// The returned OpenBatch must be Finalize'd or Close'd by the caller.
func (w *WAL) OpenBatch(meta BatchMeta) (*OpenBatch, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.enforceLimitsLocked()

	name, err := safeBatchName(meta.BatchID)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(w.dir, name+".open")

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create open-batch file: %w", err)
	}

	metaLine, err := json.Marshal(struct {
		Meta BatchMeta `json:"meta"`
	}{Meta: meta})
	if err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("marshal meta: %w", err)
	}
	metaLine = append(metaLine, '\n')
	if _, err := f.Write(metaLine); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write meta: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("fsync meta: %w", err)
	}
	if err := fsyncDir(w.dir); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("fsync dir: %w", err)
	}

	return &OpenBatch{
		wal:  w,
		meta: meta,
		path: path,
		file: f,
	}, nil
}

// Close releases the file handle and removes the .open file if no payload
// entries were appended. Safe to call multiple times.
func (ob *OpenBatch) Close() error {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	if ob.closed {
		return nil
	}
	ob.closed = true
	closeErr := ob.file.Close()
	if ob.count == 0 {
		os.Remove(ob.path)
		fsyncDir(filepath.Dir(ob.path))
	}
	return closeErr
}

// Count returns the number of payload entries appended (excludes meta).
func (ob *OpenBatch) Count() int {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	return ob.count
}

// Meta returns a copy of the batch metadata.
func (ob *OpenBatch) Meta() BatchMeta {
	return ob.meta
}

// EntryRecord is one payload line in an .open or recovered .wal file. The CRC
// is computed over the JSON encoding of the same struct with CRC=0 (so a
// reader can recompute and compare). All fields except CRC are required.
type EntryRecord struct {
	Epoch      int    `json:"epoch"`
	Timestamp  int64  `json:"timestamp"`
	EncPayload string `json:"enc_payload"`
	CRC        uint32 `json:"crc"`
}

// crcTable uses Castagnoli (the same polynomial as ext4 / btrfs / Snappy).
// Faster than IEEE on modern CPUs and adequate for torn-write detection.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

func computeCRC(rec EntryRecord) (uint32, []byte, error) {
	rec.CRC = 0
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, nil, err
	}
	return crc32.Checksum(data, crcTable), data, nil
}

// Append serializes rec, computes its CRC, writes it as a single NDJSON line,
// and fsyncs. Safe for concurrent calls from multiple goroutines on the same
// OpenBatch.
func (ob *OpenBatch) Append(rec EntryRecord) error {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	if ob.closed {
		return fmt.Errorf("openbatch: closed")
	}

	crc, _, err := computeCRC(rec)
	if err != nil {
		return fmt.Errorf("compute crc: %w", err)
	}
	rec.CRC = crc

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	line = append(line, '\n')

	if _, err := ob.file.Write(line); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}
	if err := ob.file.Sync(); err != nil {
		return fmt.Errorf("fsync entry: %w", err)
	}
	ob.count++
	return nil
}

// ErrEmptyBatch is returned by Finalize when no payload entries were appended.
// The .open file is removed and the caller should not send any message.
var ErrEmptyBatch = errors.New("openbatch: no entries appended")

// Finalize closes the .open file, renames it to .wal atomically, and returns a
// wal.Entry suitable for sending as a batch / wal_sync / flush message. The
// returned EncPayload is a JSON array of the appended encrypted payload strings,
// matching the format the scheduler already serializes for transport.
func (ob *OpenBatch) Finalize() (Entry, error) {
	ob.mu.Lock()
	defer ob.mu.Unlock()
	if ob.closed {
		return Entry{}, fmt.Errorf("openbatch: closed")
	}
	if ob.count == 0 {
		ob.closed = true
		ob.file.Close()
		os.Remove(ob.path)
		fsyncDir(filepath.Dir(ob.path))
		return Entry{}, ErrEmptyBatch
	}

	if err := ob.file.Sync(); err != nil {
		return Entry{}, fmt.Errorf("fsync open file: %w", err)
	}
	if err := ob.file.Close(); err != nil {
		return Entry{}, fmt.Errorf("close open file: %w", err)
	}
	ob.closed = true

	payloads, err := readOpenFilePayloads(ob.path)
	if err != nil {
		return Entry{}, fmt.Errorf("read open file: %w", err)
	}

	wrapped, err := json.Marshal(payloads)
	if err != nil {
		return Entry{}, fmt.Errorf("marshal payloads: %w", err)
	}

	finalPath := strings.TrimSuffix(ob.path, ".open") + ".wal"
	if err := os.Rename(ob.path, finalPath); err != nil {
		return Entry{}, fmt.Errorf("rename to .wal: %w", err)
	}
	if err := fsyncDir(filepath.Dir(finalPath)); err != nil {
		return Entry{}, fmt.Errorf("fsync dir: %w", err)
	}

	return Entry{
		BatchID:    ob.meta.BatchID,
		AgentID:    ob.meta.AgentID,
		Epoch:      ob.meta.Epoch,
		Timestamp:  ob.meta.StartedAt,
		EncPayload: string(wrapped),
	}, nil
}

// readOpenFilePayloads reads an .open or finalized .wal NDJSON file (with meta
// line + payload lines) and returns the EncPayload strings in file order.
// Lines that fail JSON parse or CRC validation are dropped — the scan stops at
// the first bad line (used for both finalize round-trip and crash recovery).
func readOpenFilePayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var payloads []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // up to 4 MB per line
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip meta
		}
		var rec EntryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			break
		}
		want, _, err := computeCRC(rec)
		if err != nil || want != rec.CRC {
			break
		}
		payloads = append(payloads, rec.EncPayload)
	}
	if err := scanner.Err(); err != nil {
		return payloads, err
	}
	return payloads, nil
}
