package scheduler

import (
	"encoding/json"
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
// 4. Batch buffering
// ---------------------------------------------------------------------------

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

	s.batchMu.Lock()
	count := len(s.batchBuf)
	s.batchMu.Unlock()

	if count != 3 {
		t.Fatalf("expected 3 buffered snapshots, got %d", count)
	}
}

func TestBufferSnapshot_PreservesOrder(t *testing.T) {
	s := newTestScheduler(t)

	for i := 0; i < 5; i++ {
		snap := &Snapshot{Timestamp: int64(i), Metrics: []collector.Metric{{Name: "x", Value: float64(i)}}}
		s.bufferSnapshot(snap)
	}

	s.batchMu.Lock()
	buf := s.batchBuf
	s.batchMu.Unlock()

	for i, snap := range buf {
		if snap.Timestamp != int64(i) {
			t.Fatalf("snapshot %d: expected timestamp %d, got %d", i, i, snap.Timestamp)
		}
	}
}

func TestSendBatch_ClearsBuffer(t *testing.T) {
	s := newTestScheduler(t)

	snap := &Snapshot{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}}
	s.bufferSnapshot(snap)

	// sendBatch will fail to send (no connection) but should still clear the buffer.
	s.sendBatch()

	s.batchMu.Lock()
	count := len(s.batchBuf)
	s.batchMu.Unlock()

	if count != 0 {
		t.Fatalf("expected buffer cleared after sendBatch, got %d entries", count)
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

	// The WAL entry should contain a JSON array of BatchEntry (entries with encrypted payloads).
	entries, err := w.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 WAL entry, got %d", len(entries))
	}

	// Parse the WAL payload as entries array
	var batchEntries []protocol.BatchEntry
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &batchEntries); err != nil {
		t.Fatalf("unmarshaling WAL entries: %v", err)
	}
	if len(batchEntries) != 2 {
		t.Fatalf("expected 2 batch entries, got %d", len(batchEntries))
	}

	// Decrypt each entry and verify content
	for i, be := range batchEntries {
		plaintext, err := enc.Decrypt(be.EncPayload)
		if err != nil {
			t.Fatalf("decrypting entry %d: %v", i, err)
		}
		var mp MetricPayload
		if err := json.Unmarshal(plaintext, &mp); err != nil {
			t.Fatalf("unmarshaling entry %d: %v", i, err)
		}
		if mp.Timestamp != original[i].Timestamp {
			t.Fatalf("entry %d: expected timestamp %d, got %d", i, original[i].Timestamp, mp.Timestamp)
		}
	}

	// Verify first entry
	plain0, _ := enc.Decrypt(batchEntries[0].EncPayload)
	var mp0 MetricPayload
	json.Unmarshal(plain0, &mp0)
	if mp0.Metrics[0].Name != "cpu" || mp0.Metrics[0].Value != 42.0 {
		t.Fatalf("entry 0 mismatch: %+v", mp0)
	}

	// Verify second entry
	plain1, _ := enc.Decrypt(batchEntries[1].EncPayload)
	var mp1 MetricPayload
	json.Unmarshal(plain1, &mp1)
	if mp1.Metrics[0].Name != "mem" || mp1.Metrics[0].Value != 80.5 {
		t.Fatalf("entry 1 mismatch: %+v", mp1)
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

	// WAL payload is a JSON array of BatchEntry — the enc_payload within should not be plaintext
	var batchEntries []protocol.BatchEntry
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &batchEntries); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	plainJSON, _ := json.Marshal(MetricPayload{Timestamp: 999, Metrics: snap.Metrics})
	if batchEntries[0].EncPayload == string(plainJSON) {
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

	// Verify the WAL entry contains all 3 entries.
	entries, err := s.wal.Pending()
	if err != nil {
		t.Fatalf("reading WAL: %v", err)
	}

	var batchEntries []protocol.BatchEntry
	if err := json.Unmarshal([]byte(entries[0].EncPayload), &batchEntries); err != nil {
		t.Fatalf("unmarshaling WAL entries: %v", err)
	}

	if len(batchEntries) != 3 {
		t.Fatalf("expected 3 batch entries in WAL, got %d", len(batchEntries))
	}
}

// ---------------------------------------------------------------------------
// 7. Retention buffer
// ---------------------------------------------------------------------------

func TestSetRetention_StoresSnapshots(t *testing.T) {
	s := newTestScheduler(t)

	snaps := []Snapshot{
		{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}},
		{Timestamp: 1010, Metrics: []collector.Metric{{Name: "cpu", Value: 0.6}}},
	}

	s.setRetention(snaps, 1)

	s.retentionMu.Lock()
	count := len(s.retentionBuf)
	epoch := s.retentionEpoch
	s.retentionMu.Unlock()

	if count != 2 {
		t.Fatalf("expected 2 retained snapshots, got %d", count)
	}
	if epoch != 1 {
		t.Fatalf("expected retention epoch 1, got %d", epoch)
	}
}

func TestSendBatch_SetsRetention(t *testing.T) {
	s := newTestScheduler(t)

	snap := &Snapshot{Timestamp: 1000, Metrics: []collector.Metric{{Name: "cpu", Value: 0.5}}}
	s.bufferSnapshot(snap)
	s.sendBatch()

	s.retentionMu.Lock()
	count := len(s.retentionBuf)
	s.retentionMu.Unlock()

	if count != 1 {
		t.Fatalf("expected 1 retained snapshot after sendBatch, got %d", count)
	}
}
