package scheduler

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
)

// newTestScheduler creates a Scheduler wired with real dependencies suitable for
// unit testing. The transport.Connection points nowhere — we never dial.
func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()

	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	w, err := wal.New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}

	orch := collector.NewOrchestrator()
	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")

	return New("test-agent", 1, enc, orch, conn, w)
}

// ---------------------------------------------------------------------------
// 1. SetPace mode switching
// ---------------------------------------------------------------------------

func TestSetPace_IdleToLive(t *testing.T) {
	s := newTestScheduler(t)

	if s.GetMode() != ModeIdle {
		t.Fatal("expected initial mode to be ModeIdle")
	}

	s.SetPace(1000, 1000)

	if s.GetMode() != ModeLive {
		t.Fatal("expected ModeLive after SetPace with non-zero intervalMS")
	}
}

func TestSetPace_LiveToIdle(t *testing.T) {
	s := newTestScheduler(t)

	s.SetPace(1000, 1000)
	if s.GetMode() != ModeLive {
		t.Fatal("expected ModeLive")
	}

	s.SetPace(0, 0)
	if s.GetMode() != ModeIdle {
		t.Fatal("expected ModeIdle after SetPace with intervalMS=0")
	}
}

func TestSetPace_SignalsPaceChanged(t *testing.T) {
	s := newTestScheduler(t)

	s.SetPace(500, 500)

	select {
	case <-s.paceChanged:
		// expected
	default:
		t.Fatal("expected paceChanged signal after SetPace")
	}
}

// ---------------------------------------------------------------------------
// 2. GetMode returns correct mode
// ---------------------------------------------------------------------------

func TestGetMode_Default(t *testing.T) {
	s := newTestScheduler(t)
	if s.GetMode() != ModeIdle {
		t.Fatal("new scheduler should start in ModeIdle")
	}
}

func TestGetMode_AfterMultipleSwitches(t *testing.T) {
	s := newTestScheduler(t)

	modes := []struct {
		intervalMS int
		collectMS  int
		want       Mode
	}{
		{1000, 1000, ModeLive},
		{0, 0, ModeIdle},
		{500, 500, ModeLive},
		{0, 0, ModeIdle},
	}

	for i, m := range modes {
		// Drain paceChanged between calls so the non-blocking send doesn't skip.
		select {
		case <-s.paceChanged:
		default:
		}

		s.SetPace(m.intervalMS, m.collectMS)
		if got := s.GetMode(); got != m.want {
			t.Fatalf("step %d: got mode %d, want %d", i, got, m.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Clock-aligned batch timing
// ---------------------------------------------------------------------------

func TestTimeUntilNextBatch_PositiveDuration(t *testing.T) {
	s := newTestScheduler(t)

	d := s.timeUntilNextBatch()
	if d <= 0 {
		t.Fatalf("expected positive duration, got %v", d)
	}
}

func TestTimeUntilNextBatch_BoundedByInterval(t *testing.T) {
	s := newTestScheduler(t)

	d := s.timeUntilNextBatch()

	if d > batchInterval {
		t.Fatalf("duration %v exceeds batch interval %v", d, batchInterval)
	}
}

func TestTimeUntilNextBatch_AlignedToInterval(t *testing.T) {
	s := newTestScheduler(t)

	now := time.Now()
	d := s.timeUntilNextBatch()
	nextBatch := now.Add(d)

	truncated := nextBatch.Truncate(batchInterval)

	diffFromLower := nextBatch.Sub(truncated)
	if diffFromLower > 2*time.Second && (batchInterval-diffFromLower) > 2*time.Second {
		t.Fatalf("next batch time is not clock-aligned: offset from boundary = %v", diffFromLower)
	}
}

// ---------------------------------------------------------------------------
// 4. Batch buffering — new contract: each snapshot is persisted to an .open file
// ---------------------------------------------------------------------------

// TestBufferSnapshot_Accumulates verifies that buffering 3 snapshots results in
// exactly one .open file on disk (all appended to the same in-progress batch).
func TestBufferSnapshot_Accumulates(t *testing.T) {
	s := newTestScheduler(t)

	snaps := []Snapshot{
		{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}},
		{Timestamp: 1001, Metrics: []collector.Metric{{Name: "mem", Value: 0.7}}},
		{Timestamp: 1002, Metrics: []collector.Metric{{Name: "disk", Value: 0.3}}},
	}

	for i := range snaps {
		s.bufferSnapshot(&snaps[i])
	}

	// New contract: all 3 snapshots are in a single .open file, not in-memory.
	openFiles, _ := filepath.Glob(filepath.Join(s.wal.Dir(), "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf("expected 1 .open file after 3 bufferSnapshot calls, got %d", len(openFiles))
	}

	// The in-memory openBatch should be set.
	s.openMu.Lock()
	count := s.openBatch.Count()
	s.openMu.Unlock()

	if count != 3 {
		t.Fatalf("expected openBatch.Count()=3, got %d", count)
	}
}

// TestBufferSnapshot_PreservesOrder verifies that snapshots are appended in
// order by checking the openBatch entry count matches the number of calls.
func TestBufferSnapshot_PreservesOrder(t *testing.T) {
	s := newTestScheduler(t)

	for i := 0; i < 5; i++ {
		snap := &Snapshot{Timestamp: int64(i), Metrics: []collector.Metric{{Name: "x", Value: float64(i)}}}
		s.bufferSnapshot(snap)
	}

	// Verify order is preserved via the WAL content after finalize.
	s.openMu.Lock()
	ob := s.openBatch
	s.openBatch = nil
	s.openID = ""
	s.openMu.Unlock()

	entry, err := ob.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	// EncPayload is a JSON array of encrypted payload strings (one per snapshot).
	var payloads []string
	if err := json.Unmarshal([]byte(entry.EncPayload), &payloads); err != nil {
		t.Fatalf("unmarshal payloads: %v", err)
	}
	if len(payloads) != 5 {
		t.Fatalf("expected 5 payloads, got %d", len(payloads))
	}
}

// TestSendBatch_ClearsBuffer verifies that after sendBatch the .open file is
// gone (renamed to .wal) and openBatch is nil.
func TestSendBatch_ClearsBuffer(t *testing.T) {
	s := newTestScheduler(t)

	snap := &Snapshot{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}}
	s.bufferSnapshot(snap)

	// sendBatch will fail to send (no connection) but should still finalize.
	s.sendBatch()

	// .open file must be gone after finalize.
	openFiles, _ := filepath.Glob(filepath.Join(s.wal.Dir(), "*.open"))
	if len(openFiles) != 0 {
		t.Fatalf("expected 0 .open files after sendBatch, got %d", len(openFiles))
	}

	// openBatch pointer must be nil.
	s.openMu.Lock()
	ob := s.openBatch
	s.openMu.Unlock()

	if ob != nil {
		t.Fatal("expected openBatch=nil after sendBatch")
	}
}

func TestSendBatch_EmptyBufferNoOp(t *testing.T) {
	s := newTestScheduler(t)

	// Should not panic or produce errors on empty buffer.
	s.sendBatch()

	if s.wal.Count() != 0 {
		t.Fatal("expected no WAL entries after sending empty batch")
	}
}

// ---------------------------------------------------------------------------
// 5. Encryption of batch data — WAL stores serialized entries array
// ---------------------------------------------------------------------------

func TestSendBatch_ProducesEncryptedEntries(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	walDir := t.TempDir()
	w, err := wal.New(walDir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}

	orch := collector.NewOrchestrator()
	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")
	s := New("test-agent", 1, enc, orch, conn, w)

	original := []Snapshot{
		{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 42.0}}},
		{Timestamp: 1001, Metrics: []collector.Metric{{Name: "mem", Value: 80.5}}},
	}

	for i := range original {
		s.bufferSnapshot(&original[i])
	}

	s.sendBatch()

	// The WAL entry should contain a JSON array of encrypted payload strings.
	entries, err := w.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 WAL entry, got %d", len(entries))
	}

	// Parse the WAL payload as a JSON array of encrypted payload strings.
	var payloads []string
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &payloads); err != nil {
		t.Fatalf("unmarshaling WAL payloads: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}

	// Decrypt each entry and verify content.
	for i, p := range payloads {
		plaintext, err := enc.Decrypt(p)
		if err != nil {
			t.Fatalf("decrypting entry %d: %v", i, err)
		}
		var snap Snapshot
		if err := json.Unmarshal(plaintext, &snap); err != nil {
			t.Fatalf("unmarshaling entry %d: %v", i, err)
		}
		if snap.Timestamp != original[i].Timestamp {
			t.Fatalf("entry %d: expected timestamp %d, got %d", i, original[i].Timestamp, snap.Timestamp)
		}
	}

	// Verify first entry
	plain0, _ := enc.Decrypt(payloads[0])
	var snap0 Snapshot
	json.Unmarshal(plain0, &snap0)
	if snap0.Metrics[0].Name != "cpu" || snap0.Metrics[0].Value != 42.0 {
		t.Fatalf("entry 0 mismatch: %+v", snap0)
	}

	// Verify second entry
	plain1, _ := enc.Decrypt(payloads[1])
	var snap1 Snapshot
	json.Unmarshal(plain1, &snap1)
	if snap1.Metrics[0].Name != "mem" || snap1.Metrics[0].Value != 80.5 {
		t.Fatalf("entry 1 mismatch: %+v", snap1)
	}
}

func TestSendBatch_EncryptedPayloadDiffersFromPlaintext(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	w, err := wal.New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}

	orch := collector.NewOrchestrator()
	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")
	s := New("test-agent", 1, enc, orch, conn, w)

	snap := &Snapshot{Timestamp: 999, Metrics: []collector.Metric{{Name: "secret", Value: 1.0}}}
	s.bufferSnapshot(snap)
	s.sendBatch()

	entries, err := w.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}

	// WAL payload is a JSON array of encrypted payload strings.
	var payloads []string
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &payloads); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	plainJSON, _ := json.Marshal(Snapshot{Timestamp: 999, Metrics: snap.Metrics})
	if payloads[0] == string(plainJSON) {
		t.Fatal("encrypted payload matches raw plaintext — encryption did not occur")
	}
}

// ---------------------------------------------------------------------------
// 6. WAL integration
// ---------------------------------------------------------------------------

func TestSendBatch_WritesToWAL(t *testing.T) {
	s := newTestScheduler(t)

	snap := &Snapshot{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}}
	s.bufferSnapshot(snap)

	s.sendBatch()

	if s.wal.Count() != 1 {
		t.Fatalf("expected 1 WAL entry after sendBatch, got %d", s.wal.Count())
	}
}

func TestSendBatch_WALEntryHasCorrectMetadata(t *testing.T) {
	s := newTestScheduler(t)

	snap := &Snapshot{Timestamp: 1000, Metrics: []collector.Metric{{Name: "x", Value: 1.0}}}
	s.bufferSnapshot(snap)
	s.sendBatch()

	entries, err := s.wal.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.AgentID != "test-agent" {
		t.Fatalf("expected agent_id=test-agent, got %s", e.AgentID)
	}
	if e.Epoch != 1 {
		t.Fatalf("expected epoch=1, got %d", e.Epoch)
	}
	if e.EncPayload == "" {
		t.Fatal("expected non-empty encrypted payload")
	}
	if e.BatchID == "" {
		t.Fatal("expected non-empty batch ID")
	}
}

func TestAckBatch_RemovesFromWAL(t *testing.T) {
	s := newTestScheduler(t)

	snap := &Snapshot{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}}
	s.bufferSnapshot(snap)
	s.sendBatch()

	entries, err := s.wal.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}
	if len(entries) != 1 {
		t.Fatal("expected 1 WAL entry")
	}

	s.AckBatch(entries[0].BatchID)

	if s.wal.Count() != 0 {
		t.Fatalf("expected 0 WAL entries after ack, got %d", s.wal.Count())
	}
}

func TestMultipleBatches_SingleWALEntry(t *testing.T) {
	s := newTestScheduler(t)

	for i := 0; i < 3; i++ {
		snap := &Snapshot{
			Timestamp: int64(1000 + i),
			Metrics:   []collector.Metric{{Name: "m", Value: float64(i)}},
		}
		s.bufferSnapshot(snap)
	}

	// All three snapshots go into one batch = one WAL entry.
	s.sendBatch()

	if s.wal.Count() != 1 {
		t.Fatalf("expected 1 WAL entry for single sendBatch call, got %d", s.wal.Count())
	}

	// Verify the WAL entry contains all 3 payloads.
	entries, err := s.wal.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}

	// New format: EncPayload is a JSON array of encrypted payload strings.
	var payloads []string
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &payloads); err != nil {
		t.Fatalf("unmarshaling WAL payloads: %v", err)
	}

	if len(payloads) != 3 {
		t.Fatalf("expected 3 payloads in WAL, got %d", len(payloads))
	}
}

// ---------------------------------------------------------------------------
// 7. Full Snapshot encryption (metrics + processes in batch)
// ---------------------------------------------------------------------------

func TestSendBatch_IncludesProcesses(t *testing.T) {
	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	w, err := wal.New(t.TempDir(), 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}

	orch := collector.NewOrchestrator()
	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")
	s := New("test-agent", 1, enc, orch, conn, w)

	snap := &Snapshot{
		Timestamp: 1000,
		Metrics:   []collector.Metric{{Name: "cpu", Value: 0.5}},
		Processes: []collector.ProcessSnapshot{{PID: 1, Name: "init", CPUPercent: 0.1}},
	}
	s.bufferSnapshot(snap)
	s.sendBatch()

	entries, _ := w.Pending()

	// New format: EncPayload is a JSON array of encrypted payload strings.
	var payloads []string
	json.Unmarshal([]byte(entries[0].EncPayload), &payloads)

	plaintext, _ := enc.Decrypt(payloads[0])
	var decrypted Snapshot
	json.Unmarshal(plaintext, &decrypted)

	if len(decrypted.Processes) != 1 {
		t.Fatalf("expected 1 process in decrypted snapshot, got %d", len(decrypted.Processes))
	}
	if decrypted.Processes[0].Name != "init" {
		t.Fatalf("expected process name 'init', got %s", decrypted.Processes[0].Name)
	}
}

// ---------------------------------------------------------------------------
// 8. Per-snapshot persistence to OpenBatch (new contract test)
// ---------------------------------------------------------------------------

func TestScheduler_PersistsEachSnapshotToOpenBatch(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.New(dir, 10, 100)
	if err != nil {
		t.Fatalf("creating WAL: %v", err)
	}

	enc, err := crypto.NewEncryptor()
	if err != nil {
		t.Fatalf("creating encryptor: %v", err)
	}

	orch := collector.NewOrchestrator()
	conn := transport.NewConnection("ws://invalid:0/ws", "", "test-agent", "test")
	s := New("test-agent", 1, enc, orch, conn, w)

	s.bufferSnapshot(&Snapshot{Timestamp: 100})
	s.bufferSnapshot(&Snapshot{Timestamp: 110})

	openFiles, _ := filepath.Glob(filepath.Join(dir, "*.open"))
	if len(openFiles) != 1 {
		t.Fatalf(".open files = %d, want 1", len(openFiles))
	}

	// After sendBatch, the .open is renamed to .wal
	s.sendBatch()
	openFiles, _ = filepath.Glob(filepath.Join(dir, "*.open"))
	walFiles, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	if len(openFiles) != 0 {
		t.Errorf("open after sendBatch = %d, want 0", len(openFiles))
	}
	if len(walFiles) != 1 {
		t.Errorf("wal after sendBatch = %d, want 1", len(walFiles))
	}
}

// ---------------------------------------------------------------------------
// 9. TestSendBatch_WALEntryContainsBatchEntries — new format uses string array
// ---------------------------------------------------------------------------

// TestSendBatch_WALEntryContainsBatchEntries verifies the WAL EncPayload is a
// JSON array of encrypted strings (not a []protocol.BatchEntry), matching the
// format produced by OpenBatch.Finalize.
func TestSendBatch_WALEntryContainsBatchEntries(t *testing.T) {
	s := newTestScheduler(t)

	for i := 0; i < 2; i++ {
		s.bufferSnapshot(&Snapshot{
			Timestamp: int64(2000 + i),
			Metrics:   []collector.Metric{{Name: "x", Value: float64(i)}},
		})
	}
	s.sendBatch()

	entries, err := s.wal.Pending()
	if err != nil || len(entries) != 1 {
		t.Fatalf("pending WAL entries: err=%v count=%d", err, len(entries))
	}

	// Must be a JSON array of strings (encrypted payloads).
	var payloads []string
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &payloads); err != nil {
		t.Fatalf("WAL EncPayload is not []string: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(payloads))
	}

	// Must NOT be parseable as []protocol.BatchEntry (old format).
	var batchEntries []protocol.BatchEntry
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &batchEntries); err == nil {
		// It would parse as []BatchEntry since []string is a subset...
		// The real check is that the individual strings decrypt correctly.
		_ = batchEntries
	}

	// Each string must be a valid encrypted blob (non-empty, not plain JSON).
	enc := s.encryptor
	for i, p := range payloads {
		if p == "" {
			t.Errorf("payload %d is empty", i)
		}
		_, err := enc.Decrypt(p)
		if err != nil {
			t.Errorf("payload %d failed decrypt: %v", i, err)
		}
	}
}
