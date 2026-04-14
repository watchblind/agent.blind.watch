package wal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenBatch_CreatesOpenFileWithMeta(t *testing.T) {
	w, err := New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ob, err := w.OpenBatch(BatchMeta{
		BatchID:   "b_1000_ag",
		AgentID:   "ag",
		Epoch:     2,
		StartedAt: 1000,
	})
	if err != nil {
		t.Fatalf("OpenBatch: %v", err)
	}
	defer ob.Close()

	path := filepath.Join(w.Dir(), "b_1000_ag.open")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("no first line: %v", scanner.Err())
	}
	var line struct {
		Meta *BatchMeta `json:"meta"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
		t.Fatalf("first line not JSON: %v", err)
	}
	if line.Meta == nil || line.Meta.BatchID != "b_1000_ag" {
		t.Errorf("meta = %+v, want batch_id=b_1000_ag", line.Meta)
	}
}

func TestOpenBatch_RejectsUnsafeBatchID(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	_, err := w.OpenBatch(BatchMeta{BatchID: "../escape", AgentID: "ag", Epoch: 1})
	if err == nil {
		t.Error("expected error for path-traversal batch_id")
	}
}

func TestOpenBatch_DuplicateOpenFails(t *testing.T) {
	w, _ := New(t.TempDir(), 10, 100)
	meta := BatchMeta{BatchID: "b1", AgentID: "ag", Epoch: 1}
	ob1, err := w.OpenBatch(meta)
	if err != nil {
		t.Fatalf("first OpenBatch: %v", err)
	}
	defer ob1.Close()
	if _, err := w.OpenBatch(meta); err == nil {
		t.Error("expected error opening same batch_id twice")
	}
}
