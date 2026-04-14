package wal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// RecoverOrphans scans the WAL directory for in-progress (.open) files left
// over from an unclean shutdown, validates each line via CRC (dropping the
// final torn line if any), and either:
//   - finalizes the file by renaming .open -> .wal (so the existing wal_sync
//     path picks it up), or
//   - removes the file if no valid payload entries remain.
//
// Safe to call once on startup before the scheduler enters its run loop.
func (w *WAL) RecoverOrphans() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	dirEntries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	for _, e := range dirEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".open") {
			continue
		}
		path := filepath.Join(w.dir, e.Name())
		if err := w.recoverOneLocked(path); err != nil {
			log.Printf("[wal] recover %s: %v", e.Name(), err)
		}
	}
	return nil
}

func (w *WAL) recoverOneLocked(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var meta BatchMeta
	gotMeta := false
	var payloads []string
	for scanner.Scan() {
		if !gotMeta {
			var line struct {
				Meta BatchMeta `json:"meta"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &line); err != nil || line.Meta.BatchID == "" {
				f.Close()
				os.Remove(path)
				log.Printf("[wal] recover: %s missing/invalid meta, removed", filepath.Base(path))
				return nil
			}
			meta = line.Meta
			gotMeta = true
			continue
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
	f.Close()

	if !gotMeta || len(payloads) == 0 {
		os.Remove(path)
		log.Printf("[wal] recover: %s had no valid entries, removed", filepath.Base(path))
		return nil
	}

	wrapped, err := json.Marshal(payloads)
	if err != nil {
		return fmt.Errorf("marshal payloads: %w", err)
	}
	entry := Entry{
		BatchID:    meta.BatchID,
		AgentID:    meta.AgentID,
		Epoch:      meta.Epoch,
		Timestamp:  meta.StartedAt,
		EncPayload: string(wrapped),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	finalPath := strings.TrimSuffix(path, ".open") + ".wal"
	if err := atomicReplace(finalPath, data, 0600); err != nil {
		return fmt.Errorf("atomicReplace: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove .open: %w", err)
	}
	if err := fsyncDir(w.dir); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	log.Printf("[wal] recovered %s with %d entries", meta.BatchID, len(payloads))
	return nil
}
