package logtail

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
)

// newTestManager returns a Manager wired with real dependencies sufficient to
// exercise handleLogEntry and flushOpenBatch. The Connection points nowhere —
// we never dial, and live mode is off by default so handleLogEntry never calls Send.
func newTestManager(t *testing.T, w *wal.WAL) *Manager {
	t.Helper()

	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")

	// Use a temp dir for the position store.
	dir := t.TempDir()
	storePath := filepath.Join(dir, "log_positions.json")
	store, err := NewPositionStore(storePath)
	if err != nil {
		t.Fatalf("creating position store: %v", err)
	}

	return &Manager{
		agentID:   "test-agent",
		dataDir:   dir,
		encryptor: enc,
		epoch:     1,
		conn:      conn,
		walLog:    w,
		store:     store,
		entries:   make(chan LogEntry, entryChannelSize),
		flushCh:   make(chan struct{}, 1),
		tailers:   make(map[string]context.CancelFunc),
	}
}

func TestManager_AppendsLogEntryToOpenBatch(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}
	m := newTestManager(t, w)

	m.handleLogEntry(LogEntry{Timestamp: 100, Message: "hello", Source: "syslog"})

	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf(".open files = %d, want 1", len(openFiles))
	}
}

func TestManager_MultipleEntriesSameOpenBatch(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}
	m := newTestManager(t, w)

	m.handleLogEntry(LogEntry{Timestamp: 100, Message: "first", Source: "syslog"})
	m.handleLogEntry(LogEntry{Timestamp: 101, Message: "second", Source: "syslog"})
	m.handleLogEntry(LogEntry{Timestamp: 102, Message: "third", Source: "syslog"})

	// All three entries go into the same open batch file.
	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf(".open files = %d, want 1", len(openFiles))
	}

	m.openMu.Lock()
	count := m.openBatch.Count()
	m.openMu.Unlock()

	if count != 3 {
		t.Fatalf("openBatch.Count() = %d, want 3", count)
	}
}

func TestManager_FlushOpenBatch_RenamesToWAL(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}
	m := newTestManager(t, w)

	m.handleLogEntry(LogEntry{Timestamp: 200, Message: "flush me", Source: "auth"})

	m.flushOpenBatch()

	// .open must be gone (renamed to .wal).
	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 0 {
		t.Errorf(".open files after flush = %d, want 0", len(openFiles))
	}

	walFiles, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	if len(walFiles) != 1 {
		t.Errorf(".wal files after flush = %d, want 1", len(walFiles))
	}

	// openBatch pointer must be nil.
	m.openMu.Lock()
	ob := m.openBatch
	m.openMu.Unlock()
	if ob != nil {
		t.Fatal("expected openBatch=nil after flushOpenBatch")
	}
}

func TestManager_FlushOpenBatch_EmptyIsNoOp(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}
	m := newTestManager(t, w)

	// No entries — flush should be a complete no-op.
	m.flushOpenBatch()

	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	walFiles, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	if len(openFiles) != 0 || len(walFiles) != 0 {
		t.Errorf("unexpected files: open=%d wal=%d", len(openFiles), len(walFiles))
	}
}

func TestManager_BufferedEntries_ReadsOpenFile(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}
	m := newTestManager(t, w)

	m.handleLogEntry(LogEntry{Timestamp: 300, Message: "a", Source: "kern"})
	m.handleLogEntry(LogEntry{Timestamp: 301, Message: "b", Source: "kern"})

	entries := m.BufferedEntries()
	if len(entries) != 2 {
		t.Fatalf("BufferedEntries() = %d entries, want 2", len(entries))
	}
	if entries[0].Timestamp != 300 {
		t.Errorf("entry[0].Timestamp = %d, want 300", entries[0].Timestamp)
	}
	if entries[1].Timestamp != 301 {
		t.Errorf("entry[1].Timestamp = %d, want 301", entries[1].Timestamp)
	}
	// Each payload must be a non-empty encrypted blob.
	for i, e := range entries {
		if e.EncPayload == "" {
			t.Errorf("entry[%d].EncPayload is empty", i)
		}
	}
}

func TestManager_BufferedEntries_NilWhenNoBatch(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}
	m := newTestManager(t, w)

	entries := m.BufferedEntries()
	if entries != nil {
		t.Fatalf("expected nil BufferedEntries with no open batch, got %v", entries)
	}
}
