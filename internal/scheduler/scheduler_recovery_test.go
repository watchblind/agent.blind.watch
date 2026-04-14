package scheduler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
)

// newTestSchedulerWithWAL builds a minimal Scheduler backed by the supplied WAL.
// The transport.Connection points at an invalid address — bufferSnapshot never
// dials, so this is safe for write-only tests.
func newTestSchedulerWithWAL(t *testing.T, w *wal.WAL) *Scheduler {
	t.Helper()

	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	orch := collector.NewOrchestrator()
	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")

	return New("test-agent", 1, enc, orch, conn, w)
}

// TestCrashMidWindow_RecoversAllSnapshots simulates appending several snapshots
// to an open batch, then "crashing" (dropping the scheduler reference without
// finalizing), then booting fresh and verifying RecoverOrphans + Pending picks
// up exactly those snapshots.
func TestCrashMidWindow_RecoversAllSnapshots(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("wal.New: %v", err)
	}

	s1 := newTestSchedulerWithWAL(t, w)

	for _, ts := range []int64{100, 110, 120, 130} {
		s1.bufferSnapshot(&Snapshot{Timestamp: ts})
	}

	// Verify the .open file exists with 4 payload lines.
	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf(".open files = %d, want 1", len(openFiles))
	}

	// Simulate crash by dropping the reference; do NOT call flush/sendBatch.
	_ = s1

	// Fresh WAL on the same dir; recover orphans.
	w2, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("wal.New (w2): %v", err)
	}
	if err := w2.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, err := w2.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1 batch", len(pending))
	}
	var payloads []string
	if err := json.Unmarshal([]byte(pending[0].EncPayload), &payloads); err != nil {
		t.Fatalf("EncPayload not JSON array: %v", err)
	}
	if len(payloads) != 4 {
		t.Errorf("payloads = %d, want 4", len(payloads))
	}
	openAfter, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openAfter) != 0 {
		t.Errorf(".open files after recovery = %d, want 0", len(openAfter))
	}
	walAfter, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	if len(walAfter) != 1 {
		t.Errorf(".wal files after recovery = %d, want 1", len(walAfter))
	}
}

// TestCrashMidWindow_TornFinalLineDropped corrupts the last line of the .open
// file and verifies the surviving entries still recover while the torn line is
// dropped.
func TestCrashMidWindow_TornFinalLineDropped(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("wal.New: %v", err)
	}

	s := newTestSchedulerWithWAL(t, w)

	for _, ts := range []int64{100, 110, 120, 130} {
		s.bufferSnapshot(&Snapshot{Timestamp: ts})
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(files) != 1 {
		t.Fatalf(".open files = %d, want 1", len(files))
	}
	// Read the file and truncate to cut halfway through the last line, which
	// guarantees JSON parse failure (just removing the trailing '\n' is not
	// enough — the scanner returns the line without it and the JSON is still
	// valid). This mirrors the writeOpenFile helper in the wal package tests.
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Find the start of the last line (after the last '\n' that is not the
	// very final byte).
	lastNL := -1
	for i := len(raw) - 2; i >= 0; i-- {
		if raw[i] == '\n' {
			lastNL = i
			break
		}
	}
	if lastNL < 0 {
		t.Fatal("could not find newline before last record line")
	}
	lastLineLen := len(raw) - (lastNL + 1)
	if err := os.Truncate(files[0], int64(lastNL+1)+int64(lastLineLen/2)); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	w2, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("wal.New (w2): %v", err)
	}
	if err := w2.RecoverOrphans(); err != nil {
		t.Fatalf("RecoverOrphans: %v", err)
	}
	pending, err := w2.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	var payloads []string
	if err := json.Unmarshal([]byte(pending[0].EncPayload), &payloads); err != nil {
		t.Fatalf("EncPayload not JSON array: %v", err)
	}
	if len(payloads) != 3 {
		t.Errorf("payloads = %d, want 3 (last torn line dropped)", len(payloads))
	}
}
