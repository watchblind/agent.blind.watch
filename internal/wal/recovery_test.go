package wal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// helper: build a .open file with the given meta and entries (correct CRCs).
func writeOpenFile(t *testing.T, dir, batchID string, agentID string, epoch int, startedAt int64, payloads []string, tornLast bool) {
	t.Helper()
	path := filepath.Join(dir, batchID+".open")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()

	metaLine, _ := json.Marshal(struct {
		Meta BatchMeta `json:"meta"`
	}{Meta: BatchMeta{BatchID: batchID, AgentID: agentID, Epoch: epoch, StartedAt: startedAt}})
	f.Write(append(metaLine, '\n'))

	for i, p := range payloads {
		rec := EntryRecord{Epoch: epoch, Timestamp: startedAt + int64(i), EncPayload: p}
		crc, _, _ := computeCRC(rec)
		rec.CRC = crc
		line, _ := json.Marshal(rec)
		if tornLast && i == len(payloads)-1 {
			f.Write(line[:len(line)/2])
			break
		}
		f.Write(append(line, '\n'))
	}
}

func TestRecoverOrphans_FinalizesValidOpenFile(t *testing.T) {
	dir := t.TempDir()
	w, _ := New(dir, 10, 100)
	writeOpenFile(t, dir, "b1", "ag", 1, 100, []string{"p1", "p2"}, false)

	if err := w.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, _ := w.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	if pending[0].BatchID != "b1" {
		t.Errorf("BatchID = %q, want b1", pending[0].BatchID)
	}
	var payloads []string
	if err := json.Unmarshal([]byte(pending[0].EncPayload), &payloads); err != nil {
		t.Fatalf("EncPayload not JSON array: %v", err)
	}
	if len(payloads) != 2 {
		t.Errorf("payloads = %d, want 2", len(payloads))
	}
}

func TestRecoverOrphans_DropsTornFinalLine(t *testing.T) {
	dir := t.TempDir()
	w, _ := New(dir, 10, 100)
	writeOpenFile(t, dir, "b1", "ag", 1, 100, []string{"p1", "p2", "p3"}, true)

	if err := w.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, _ := w.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	var payloads []string
	json.Unmarshal([]byte(pending[0].EncPayload), &payloads)
	if len(payloads) != 2 {
		t.Errorf("payloads = %d, want 2 (torn final dropped)", len(payloads))
	}
}

func TestRecoverOrphans_DropsEmptyOpenFile(t *testing.T) {
	dir := t.TempDir()
	w, _ := New(dir, 10, 100)
	writeOpenFile(t, dir, "b1", "ag", 1, 100, nil, false)

	if err := w.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	if w.Count() != 0 {
		t.Errorf("Count = %d, want 0 (empty .open dropped)", w.Count())
	}
	if _, err := os.Stat(filepath.Join(dir, "b1.open")); !os.IsNotExist(err) {
		t.Error(".open file should have been removed")
	}
}
