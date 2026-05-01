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
)

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
		// Each WAL entry is a full batch stored as JSON array of BatchEntry.
		// Deserialize the entries to resend in proper format.
		var batchEntries []protocol.BatchEntry
		if plainEntries, err := deserializeWALEntries(e.EncPayload); err == nil {
			batchEntries = plainEntries
		} else {
			// Legacy format: single encrypted payload per WAL entry.
			// Wrap it as a single-entry batch for backward compatibility.
			batchEntries = []protocol.BatchEntry{{
				Epoch:      e.Epoch,
				Timestamp:  e.Timestamp,
				EncPayload: e.EncPayload,
			}}
		}

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

// deserializeWALEntries tries to parse a WAL payload as a JSON array of BatchEntry.
// Returns error if it's not in the new batch format (legacy single-entry WAL).
func deserializeWALEntries(payload string) ([]protocol.BatchEntry, error) {
	var entries []protocol.BatchEntry
	if err := json.Unmarshal([]byte(payload), &entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("empty entries array")
	}
	return entries, nil
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
		log.Printf("[scheduler] batch sent: %s (%d entries)", entry.BatchID, len(entries))
	}
}

// sendReplay sends a "replay" message on live mode activation containing
// the current in-progress batch data from the .open file on disk.
// This fills the gap between the last R2-persisted batch and the start of live streaming.
func (s *Scheduler) sendReplay() {
	s.openMu.Lock()
	ob := s.openBatch
	openID := s.openID
	s.openMu.Unlock()
	if ob == nil {
		return
	}
	path := filepath.Join(s.wal.Dir(), openID+".open")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	first := true
	var entries []protocol.BatchEntry
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

	var payloads []string
	_ = json.Unmarshal([]byte(entry.EncPayload), &payloads)
	entries := make([]protocol.BatchEntry, len(payloads))
	for i, p := range payloads {
		entries[i] = protocol.BatchEntry{
			Epoch: entry.Epoch, Timestamp: entry.Timestamp + int64(i*10), EncPayload: p,
		}
	}

	if err := s.conn.SendSync(protocol.FlushMessage{
		Type:    "flush",
		BatchID: entry.BatchID,
		Epoch:   entry.Epoch,
		Entries: entries,
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
