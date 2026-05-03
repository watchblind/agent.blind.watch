package scheduler

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
)

// Mode represents the current operating mode.
type Mode int

const (
	ModeIdle Mode = iota
	ModeLive
)

// Snapshot is a timestamped collection of metrics and processes, serializable for encryption.
// The full Snapshot (metrics + processes) is encrypted and stored in R2 — no AE size limit.
type Snapshot struct {
	Timestamp int64                      `json:"timestamp"`
	Metrics   []collector.Metric         `json:"metrics"`
	Processes []collector.ProcessSnapshot `json:"processes,omitempty"`
}

const (
	idleCollectInterval = 10 * time.Second
	liveCollectInterval = 1 * time.Second
	batchInterval       = 10 * time.Minute

	// retentionWindow controls how long the most recently sent batch is
	// kept in memory so it can be re-emitted in a `replay` message when a
	// dashboard viewer connects right after a 10-minute boundary. The
	// window covers R2 LIST eventual consistency (the dashboard's initial
	// LIST may not yet see the just-PUT batch object). After the window,
	// the batch is guaranteed visible via R2 LIST and the retained copy
	// can be discarded.
	retentionWindow = 90 * time.Second
)

// lastSentBatch holds the most recently sent batch so it can be included
// in a replay message until R2 LIST is guaranteed to surface it.
type lastSentBatch struct {
	mu      sync.Mutex
	sentAt  time.Time
	entries []protocol.BatchEntry
}

// record stores entries with the current wall-clock time. Older retained
// data is overwritten.
func (l *lastSentBatch) record(entries []protocol.BatchEntry) {
	if len(entries) == 0 {
		return
	}
	l.mu.Lock()
	l.sentAt = time.Now()
	// Take a defensive copy so subsequent mutations to the caller's slice
	// can't poison the retention buffer.
	l.entries = append(l.entries[:0], entries...)
	l.mu.Unlock()
}

// snapshot returns the retained entries if they are still within the
// retention window; otherwise clears them and returns nil.
func (l *lastSentBatch) snapshot() []protocol.BatchEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		return nil
	}
	if time.Since(l.sentAt) > retentionWindow {
		l.entries = nil
		return nil
	}
	out := make([]protocol.BatchEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Scheduler orchestrates metric collection, batching, encryption, and sending.
//
// Two independent data paths:
//
// Idle path (always running): collects every 10s, buffers locally, sends ONE
// "batch" message with all entries on 10-minute wall-clock boundaries. On ack
// the WAL entry is deleted. Full Snapshot (metrics + processes) is encrypted
// and stored in R2 by the server.
//
// Live path (purely additive, when viewer connected): sends "live" message
// each second. Does NOT interact with idle batching — the idle ticker and
// batch timer continue unchanged. Live data is display-only (not stored).
type Scheduler struct {
	agentID   string
	epoch     int
	encryptor *crypto.Encryptor
	orch      *collector.Orchestrator
	conn      *transport.Connection
	wal       *wal.WAL

	mu   sync.RWMutex
	mode Mode

	// In-progress batch, opened lazily on first idle-tick collect of a window.
	openMu    sync.Mutex
	openBatch *wal.OpenBatch
	openID    string

	// Most recently sent batch, retained for ~90s to bridge the gap
	// between R2 PUT and R2 LIST eventual consistency on viewer connect.
	lastSent lastSentBatch

	// Channel to signal pace changes to the run loop.
	paceChanged chan struct{}

	// LogManager for replay support (set after construction).
	logManager LogBufferProvider
}

// LogBufferProvider exposes the log manager's current buffer for replay.
type LogBufferProvider interface {
	BufferedEntries() []protocol.LogBatchEntry
	SetLive(live bool)
}

func New(
	agentID string,
	epoch int,
	enc *crypto.Encryptor,
	orch *collector.Orchestrator,
	conn *transport.Connection,
	w *wal.WAL,
) *Scheduler {
	return &Scheduler{
		agentID:     agentID,
		epoch:       epoch,
		encryptor:   enc,
		orch:        orch,
		conn:        conn,
		wal:         w,
		mode:        ModeIdle,
		paceChanged: make(chan struct{}, 1),
	}
}

// SetLogManager sets the log manager reference for replay and live mode control.
func (s *Scheduler) SetLogManager(lm LogBufferProvider) {
	s.logManager = lm
}

// SetPace updates the operating mode. Called when server sends a pace message.
// intervalMS=0 means idle mode; non-zero means live mode.
func (s *Scheduler) SetPace(intervalMS, collectMS int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if intervalMS == 0 {
		s.mode = ModeIdle
		log.Printf("[scheduler] switching to idle mode (collect=10s, batch=10m)")
	} else {
		s.mode = ModeLive
		log.Printf("[scheduler] switching to live mode (collect=1s)")
	}

	// Signal run loop to reset ticker
	select {
	case s.paceChanged <- struct{}{}:
	default:
	}
}

// SetEncryptor swaps the encryptor and epoch at runtime (DEK rotation).
func (s *Scheduler) SetEncryptor(enc *crypto.Encryptor, epoch int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptor = enc
	s.epoch = epoch
	log.Printf("[scheduler] DEK rotated to epoch %d", epoch)
}

// EncryptorAndEpoch returns the current encryptor and epoch under lock.
// Used by callers outside the scheduler (alert forwarding, config decryption)
// to always use the latest DEK after rotations.
func (s *Scheduler) EncryptorAndEpoch() (*crypto.Encryptor, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.encryptor, s.epoch
}

// GetMode returns the current operating mode.
func (s *Scheduler) GetMode() Mode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// Run starts the scheduler. It syncs WAL on startup, then enters the collect/send loop.
func (s *Scheduler) Run(ctx context.Context) {
	// Phase 1: Sync any pending WAL entries
	s.syncWAL()

	// Phase 2: Collection and send loop
	s.runLoop(ctx)
}

// syncWAL resends pending WAL batches on startup. Each WAL file is a full
// batch (entries array) that can be resent as a single wal_sync message.
func (s *Scheduler) syncWAL() {
	if err := s.wal.RecoverOrphans(); err != nil {
		log.Printf("[scheduler] WAL recovery error: %v", err)
	}

	entries, err := s.wal.Pending()
	if err != nil {
		log.Printf("[scheduler] WAL read error: %v", err)
		return
	}

	if len(entries) == 0 {
		return
	}

	log.Printf("[scheduler] syncing %d WAL entries", len(entries))

	for i, e := range entries {
		batchEntries := batchEntriesFromWAL(e)

		if err := s.conn.Send(protocol.WALSyncMessage{
			Type:    "wal_sync",
			BatchID: e.BatchID,
			Entries: batchEntries,
		}); err != nil {
			log.Printf("[scheduler] WAL sync entry %d send failed: %v", i, err)
		}

		// Space out sends to avoid overwhelming the server
		if i < len(entries)-1 {
			time.Sleep(time.Second)
		}
	}
}

// batchEntriesFromWAL expands a recovered wal.Entry into a slice of
// protocol.BatchEntry suitable for a wal_sync (or flush) message.
//
// OpenBatch.Finalize serialises an in-progress batch as `["enc1", "enc2", ...]`
// — a JSON array of per-snapshot ciphertext strings. Each ciphertext must be
// re-emitted as its OWN BatchEntry so the dashboard can decrypt them
// individually; bundling them as a single fake BatchEntry with the JSON
// literal as enc_payload was the bug that ate user data on the v0.6.0 update.
//
// We also still accept the legacy single-blob format (where EncPayload is one
// ciphertext directly) so .wal files written by older code paths drain
// cleanly.
//
// Per-snapshot timestamps are NOT preserved in the on-disk array-of-strings
// format, so we stamp each entry as `meta.StartedAt + i*idleCollectInterval`,
// matching what flush() emits for the live shutdown path. Worst case the
// timestamps drift by one collect interval; better than the previous
// behaviour of losing every snapshot.
func batchEntriesFromWAL(e wal.Entry) []protocol.BatchEntry {
	var payloads []string
	if err := json.Unmarshal([]byte(e.EncPayload), &payloads); err == nil && len(payloads) > 0 {
		entries := make([]protocol.BatchEntry, len(payloads))
		stride := int64(idleCollectInterval / time.Second)
		if stride <= 0 {
			stride = 10
		}
		for j, p := range payloads {
			entries[j] = protocol.BatchEntry{
				Epoch:      e.Epoch,
				Timestamp:  e.Timestamp + int64(j)*stride,
				EncPayload: p,
			}
		}
		return entries
	}

	// Legacy format: one ciphertext per .wal file.
	return []protocol.BatchEntry{{
		Epoch:      e.Epoch,
		Timestamp:  e.Timestamp,
		EncPayload: e.EncPayload,
	}}
}

func (s *Scheduler) runLoop(ctx context.Context) {
	// Idle ticker: always runs at 10s, collects and buffers snapshots.
	idleTicker := time.NewTicker(idleCollectInterval)
	defer idleTicker.Stop()

	// Clock-aligned batch timer: fires every 10 minutes, always runs.
	batchTimer := time.NewTimer(s.timeUntilNextBatch())
	defer batchTimer.Stop()

	// Live ticker: only active when a viewer is connected. Additive to idle.
	var liveTicker *time.Ticker
	var liveCh <-chan time.Time // nil channel when live is off (blocks forever)

	stopLive := func() {
		if liveTicker != nil {
			liveTicker.Stop()
			liveTicker = nil
		}
		liveCh = nil
	}
	defer stopLive()

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown: flush any buffered data
			s.flush()
			return

		case <-s.paceChanged:
			s.mu.RLock()
			newMode := s.mode
			s.mu.RUnlock()

			if newMode == ModeLive {
				// Start additive 1s live ticker
				stopLive()
				liveTicker = time.NewTicker(liveCollectInterval)
				liveCh = liveTicker.C

				// Notify log manager to also send live entries
				if s.logManager != nil {
					s.logManager.SetLive(true)
				}

				// Send replay message with buffered data
				s.sendReplay()

				// Immediately collect+send a fresh snapshot
				if snap := s.collect(ctx); snap != nil {
					s.sendLive(snap)
				}
			} else {
				// Stop live ticker, idle continues unchanged
				stopLive()

				if s.logManager != nil {
					s.logManager.SetLive(false)
				}
			}

		case <-idleTicker.C:
			// Idle path: always runs, collects every 10s, buffers for batch
			snap := s.collect(ctx)
			if snap != nil {
				s.bufferSnapshot(snap)
			}

		case <-liveCh:
			// Live path: additive 1s streaming when viewer connected
			snap := s.collect(ctx)
			if snap != nil {
				s.sendLive(snap)
			}

		case <-batchTimer.C:
			// 10-minute wall-clock boundary: send batch (always runs).
			s.sendBatch()
			batchTimer.Reset(s.timeUntilNextBatch())
		}
	}
}

func (s *Scheduler) collect(ctx context.Context) *Snapshot {
	latest := s.orch.Latest()
	if latest == nil {
		return nil
	}

	return &Snapshot{
		Timestamp: time.Now().Unix(),
		Metrics:   latest.Metrics,
		Processes: latest.Processes,
	}
}

func (s *Scheduler) bufferSnapshot(snap *Snapshot) {
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	plaintext, err := json.Marshal(snap)
	if err != nil {
		log.Printf("[scheduler] marshal snapshot error: %v", err)
		return
	}
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Printf("[scheduler] encrypt snapshot error: %v", err)
		return
	}

	s.openMu.Lock()
	defer s.openMu.Unlock()

	if s.openBatch == nil {
		batchID := fmt.Sprintf("b_%d_%s", time.Now().Unix(), s.agentID)
		ob, err := s.wal.OpenBatch(wal.BatchMeta{
			BatchID:   batchID,
			AgentID:   s.agentID,
			Epoch:     epoch,
			StartedAt: snap.Timestamp,
		})
		if err != nil {
			log.Printf("[scheduler] OpenBatch error: %v", err)
			return
		}
		s.openBatch = ob
		s.openID = batchID
	}

	if err := s.openBatch.Append(wal.EntryRecord{
		Epoch:      epoch,
		Timestamp:  snap.Timestamp,
		EncPayload: encrypted,
	}); err != nil {
		log.Printf("[scheduler] OpenBatch.Append error: %v", err)
	}
}

// sendBatch finalizes the in-progress OpenBatch and sends ONE "batch" message
// with all entries.
func (s *Scheduler) sendBatch() {
	s.openMu.Lock()
	ob := s.openBatch
	s.openBatch = nil
	s.openID = ""
	s.openMu.Unlock()

	if ob == nil {
		return
	}

	entry, err := ob.Finalize()
	if err == wal.ErrEmptyBatch {
		return
	}
	if err != nil {
		log.Printf("[scheduler] Finalize error: %v", err)
		return
	}

	var payloads []string
	if err := json.Unmarshal([]byte(entry.EncPayload), &payloads); err != nil {
		log.Printf("[scheduler] decode payloads error: %v", err)
		return
	}
	entries := make([]protocol.BatchEntry, len(payloads))
	for i, p := range payloads {
		entries[i] = protocol.BatchEntry{
			Epoch:      entry.Epoch,
			Timestamp:  entry.Timestamp + int64(i*10),
			EncPayload: p,
		}
	}

	if err := s.conn.Send(protocol.BatchMessage{
		Type:    "batch",
		BatchID: entry.BatchID,
		Epoch:   entry.Epoch,
		Entries: entries,
	}); err != nil {
		log.Printf("[scheduler] batch send error: %v (data in WAL)", err)
	} else {
		// Retain a copy so a viewer connecting in the next ~90s can be
		// served the just-sent batch via replay even before R2 LIST has
		// propagated the new object.
		s.lastSent.record(entries)
		log.Printf("[scheduler] batch sent: %s (%d entries)", entry.BatchID, len(entries))
	}
}

// sendReplay sends a "replay" message on live mode activation. The replay
// covers the gap between "what the dashboard can already fetch from R2" and
// "now," which has two sources:
//
//  1. The most recently SENT batch, retained for retentionWindow after the
//     send. Bridges R2 LIST eventual consistency — the dashboard's initial
//     LIST after page load may not yet see the just-PUT batch object.
//  2. The current IN-PROGRESS batch (entries collected since the last
//     10-minute boundary). These have not been sent yet, so they cannot be
//     in R2; without replay the dashboard would show a hard cut at the
//     last completed boundary.
//
// Entries are deduplicated downstream by timestamp on the dashboard side, so
// it is safe to over-include here when the windows overlap.
func (s *Scheduler) sendReplay() {
	// (1) Retained last-sent batch (if still within window).
	entries := s.lastSent.snapshot()

	// (2) In-progress entries from the .open file on disk. The file may
	// not exist yet if no idle tick has fired since the last boundary —
	// that's fine, we just send what we have.
	s.openMu.Lock()
	openID := s.openID
	hasOpen := s.openBatch != nil
	s.openMu.Unlock()
	if hasOpen {
		path := filepath.Join(s.wal.Dir(), openID+".open")
		if f, err := os.Open(path); err == nil {
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			first := true
			for scanner.Scan() {
				if first {
					first = false
					continue
				}
				var rec wal.EntryRecord
				if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
					break
				}
				entries = append(entries, protocol.BatchEntry{
					Epoch: rec.Epoch, Timestamp: rec.Timestamp, EncPayload: rec.EncPayload,
				})
			}
			f.Close()
		}
	}

	if len(entries) == 0 {
		return
	}
	s.mu.RLock()
	epoch := s.epoch
	s.mu.RUnlock()
	s.conn.Send(protocol.ReplayMessage{Type: "replay", Epoch: epoch, Entries: entries})
}

func (s *Scheduler) sendLive(snap *Snapshot) {
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	// Send combined metrics+processes as single "live" message.
	// Frontend handleMetricMessage extracts both from the DecryptedSnapshot.
	plaintext, err := json.Marshal(snap)
	if err != nil {
		return
	}
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		return
	}
	s.conn.Send(protocol.LiveMessage{
		Type:       "live",
		Epoch:      epoch,
		Timestamp:  snap.Timestamp,
		EncPayload: encrypted,
	})
}

// FlushNow finalizes the in-progress OpenBatch and sends it synchronously.
// Safe to call from any goroutine — openMu serializes it with the runLoop's
// own bufferSnapshot/sendBatch path. Used by the update flow so the partial
// batch built up since the last 10-minute boundary is not lost when the
// upgrade unit restarts the agent.
func (s *Scheduler) FlushNow() {
	s.flush()
}

// flush finalizes the in-progress OpenBatch and sends a flush message.
// Called on graceful shutdown. Uses SendSync since the process is shutting down.
func (s *Scheduler) flush() {
	s.openMu.Lock()
	ob := s.openBatch
	s.openBatch = nil
	s.openID = ""
	s.openMu.Unlock()

	if ob == nil {
		return
	}

	entry, err := ob.Finalize()
	if err == wal.ErrEmptyBatch {
		return
	}
	if err != nil {
		log.Printf("[scheduler] flush finalize error: %v", err)
		return
	}

	if err := s.conn.SendSync(protocol.FlushMessage{
		Type:    "flush",
		BatchID: entry.BatchID,
		Epoch:   entry.Epoch,
		Entries: batchEntriesFromWAL(entry),
	}); err != nil {
		log.Printf("[scheduler] flush send error: %v (data in WAL)", err)
	}
}

// timeUntilNextBatch returns the duration until the next clock-aligned 10-minute boundary.
func (s *Scheduler) timeUntilNextBatch() time.Duration {
	now := time.Now()
	next := now.Truncate(batchInterval).Add(batchInterval)
	d := next.Sub(now)
	if d <= 0 {
		d = batchInterval
	}
	return d
}

// AckBatch removes a batch from the WAL. Called when server sends an ack.
func (s *Scheduler) AckBatch(batchID string) {
	if err := s.wal.Ack(batchID); err != nil {
		log.Printf("[scheduler] WAL ack error for %s: %v", batchID, err)
	}
}
