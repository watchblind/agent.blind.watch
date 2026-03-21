package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
type Snapshot struct {
	Timestamp int64                      `json:"timestamp"`
	Metrics   []collector.Metric         `json:"metrics"`
	Processes []collector.ProcessSnapshot `json:"processes,omitempty"`
}

// MetricPayload is the metrics-only portion for AE persistence.
// Combined metrics+processes exceeds AE's 16KB blob limit (~19KB),
// so only metrics (~12KB) are stored in AE.
type MetricPayload struct {
	Timestamp int64              `json:"timestamp"`
	Metrics   []collector.Metric `json:"metrics"`
}

const (
	idleCollectInterval = 10 * time.Second
	liveCollectInterval = 1 * time.Second
	batchInterval       = 10 * time.Minute
	retentionDuration   = 90 * time.Second
)

// Scheduler orchestrates metric collection, batching, encryption, and sending.
//
// Two independent data paths:
//
// Idle path (always running): collects every 10s, buffers locally, sends ONE
// "batch" message with all entries on 10-minute wall-clock boundaries. On ack
// the WAL entry is deleted and entries move to a 90-second retention buffer.
//
// Live path (only when viewer connected): sends "live" message each second.
// Uses single-ticker optimization — every 10th tick also appends to batch buffer.
type Scheduler struct {
	agentID   string
	epoch     int
	encryptor *crypto.Encryptor
	orch      *collector.Orchestrator
	conn      *transport.Connection
	wal       *wal.WAL

	mu   sync.RWMutex
	mode Mode

	// Buffer for accumulating snapshots between batch sends (idle path).
	batchMu  sync.Mutex
	batchBuf []Snapshot

	// Retention: last sent batch kept for 90s to cover AE ingestion lag.
	// Used for replay message on live mode activation.
	retentionMu    sync.Mutex
	retentionBuf   []Snapshot
	retentionEpoch int
	retentionTimer *time.Timer

	// Channel to signal pace changes to the run loop.
	paceChanged chan struct{}

	// Live tick counter for single-collector optimization.
	liveTickCount int
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
	// Start with idle interval; adjusted on pace change.
	collectTicker := time.NewTicker(idleCollectInterval)
	defer collectTicker.Stop()

	// Clock-aligned batch timer (idle path).
	batchTimer := time.NewTimer(s.timeUntilNextBatch())
	defer batchTimer.Stop()

	for {
		s.mu.RLock()
		mode := s.mode
		s.mu.RUnlock()

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
				// Switch to 1s ticker for live mode
				collectTicker.Reset(liveCollectInterval)
				s.liveTickCount = 0

				// Send replay message with retained + buffered data
				s.sendReplay()

				// Immediately collect+send a fresh snapshot
				if snap := s.collect(ctx); snap != nil {
					s.sendLive(snap)
					s.liveTickCount++
				}
			} else {
				// Switch back to 10s ticker for idle mode
				collectTicker.Reset(idleCollectInterval)
				s.liveTickCount = 0
			}

		case <-collectTicker.C:
			snap := s.collect(ctx)
			if snap == nil {
				continue
			}

			if mode == ModeLive {
				// Live path: stream to dashboard every second
				s.sendLive(snap)
				s.liveTickCount++

				// Single-collector optimization: every 10th tick, also
				// append to the batch buffer for AE persistence.
				if s.liveTickCount%10 == 0 {
					s.bufferSnapshot(snap)
				}
			} else {
				// Idle path: collect every 10s, buffer locally
				s.bufferSnapshot(snap)
			}

		case <-batchTimer.C:
			// 10-minute wall-clock boundary: send batch (idle path, always runs).
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
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	s.batchBuf = append(s.batchBuf, *snap)
}

// sendBatch encrypts all buffered snapshots individually, writes to WAL as
// one entry, and sends ONE "batch" message with all entries.
func (s *Scheduler) sendBatch() {
	s.batchMu.Lock()
	snapshots := s.batchBuf
	s.batchBuf = nil
	s.batchMu.Unlock()

	if len(snapshots) == 0 {
		return
	}

	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	batchID := fmt.Sprintf("b_%d_%s", time.Now().Unix(), s.agentID)

	entries := s.encryptSnapshots(snapshots, enc, epoch)
	if len(entries) == 0 {
		return
	}

	// Serialize entries for WAL storage
	walPayload, err := json.Marshal(entries)
	if err != nil {
		log.Printf("[scheduler] marshal WAL entries error: %v", err)
		return
	}

	// WAL: persist full batch before sending
	if err := s.wal.Append(wal.Entry{
		BatchID:    batchID,
		AgentID:    s.agentID,
		Epoch:      epoch,
		Timestamp:  snapshots[0].Timestamp,
		EncPayload: string(walPayload),
	}); err != nil {
		log.Printf("[scheduler] WAL append error: %v", err)
	}

	if err := s.conn.Send(protocol.BatchMessage{
		Type:    "batch",
		BatchID: batchID,
		Epoch:   epoch,
		Entries: entries,
	}); err != nil {
		log.Printf("[scheduler] batch send error: %v (data in WAL)", err)
	} else {
		log.Printf("[scheduler] batch sent: %s (%d entries)", batchID, len(entries))
	}

	// Move snapshots to retention buffer (kept for 90s for replay)
	s.setRetention(snapshots, epoch)
}

// encryptSnapshots encrypts each snapshot's MetricPayload individually.
func (s *Scheduler) encryptSnapshots(snapshots []Snapshot, enc *crypto.Encryptor, epoch int) []protocol.BatchEntry {
	var entries []protocol.BatchEntry
	for _, snap := range snapshots {
		payload := MetricPayload{
			Timestamp: snap.Timestamp,
			Metrics:   snap.Metrics,
		}
		plaintext, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[scheduler] marshal snapshot error: %v", err)
			continue
		}
		encrypted, err := enc.Encrypt(plaintext)
		if err != nil {
			log.Printf("[scheduler] encrypt snapshot error: %v", err)
			continue
		}
		entries = append(entries, protocol.BatchEntry{
			Epoch:      epoch,
			Timestamp:  snap.Timestamp,
			EncPayload: encrypted,
		})
	}
	return entries
}

// setRetention stores the last sent batch for 90 seconds.
// On live mode activation, this is replayed to the viewer.
func (s *Scheduler) setRetention(snapshots []Snapshot, epoch int) {
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()

	s.retentionBuf = snapshots
	s.retentionEpoch = epoch

	// Cancel previous timer if still running
	if s.retentionTimer != nil {
		s.retentionTimer.Stop()
	}

	s.retentionTimer = time.AfterFunc(retentionDuration, func() {
		s.retentionMu.Lock()
		defer s.retentionMu.Unlock()
		s.retentionBuf = nil
		s.retentionEpoch = 0
		log.Printf("[scheduler] retention buffer purged (90s expired)")
	})
}

// sendReplay sends a "replay" message on live mode activation containing
// the retained last batch (if within 90s) plus the current in-progress batch buffer.
func (s *Scheduler) sendReplay() {
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	// Gather retained snapshots
	s.retentionMu.Lock()
	retained := s.retentionBuf
	s.retentionMu.Unlock()

	// Gather current batch buffer (don't drain — idle path still owns it)
	s.batchMu.Lock()
	buffered := make([]Snapshot, len(s.batchBuf))
	copy(buffered, s.batchBuf)
	s.batchMu.Unlock()

	// Combine: retained first, then buffered
	var combined []Snapshot
	combined = append(combined, retained...)
	combined = append(combined, buffered...)

	if len(combined) == 0 {
		return
	}

	entries := s.encryptSnapshots(combined, enc, epoch)
	if len(entries) == 0 {
		return
	}

	if err := s.conn.Send(protocol.ReplayMessage{
		Type:    "replay",
		Epoch:   epoch,
		Entries: entries,
	}); err != nil {
		log.Printf("[scheduler] replay send error: %v", err)
	} else {
		log.Printf("[scheduler] replay sent (%d entries: %d retained + %d buffered)",
			len(entries), len(retained), len(buffered))
	}
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

// flush encrypts and sends any buffered data. Called on graceful shutdown.
// Uses SendSync for each message since the process is shutting down.
// Sends ONE message with all entries (same format as batch).
func (s *Scheduler) flush() {
	s.batchMu.Lock()
	snapshots := s.batchBuf
	s.batchBuf = nil
	s.batchMu.Unlock()

	if len(snapshots) == 0 {
		return
	}

	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	batchID := fmt.Sprintf("flush_%d_%s", time.Now().Unix(), s.agentID)

	entries := s.encryptSnapshots(snapshots, enc, epoch)
	if len(entries) == 0 {
		return
	}

	// Serialize entries for WAL storage
	walPayload, err := json.Marshal(entries)
	if err != nil {
		log.Printf("[scheduler] marshal WAL entries error: %v", err)
		return
	}

	// WAL: persist before sending
	if err := s.wal.Append(wal.Entry{
		BatchID:    batchID,
		AgentID:    s.agentID,
		Epoch:      epoch,
		Timestamp:  snapshots[0].Timestamp,
		EncPayload: string(walPayload),
	}); err != nil {
		log.Printf("[scheduler] WAL flush append error: %v", err)
	}

	if err := s.conn.SendSync(protocol.FlushMessage{
		Type:    "flush",
		BatchID: batchID,
		Epoch:   epoch,
		Entries: entries,
	}); err != nil {
		log.Printf("[scheduler] flush send error: %v (data in WAL)", err)
	} else {
		log.Printf("[scheduler] flush sent: %s (%d entries from %d buffered)",
			batchID, len(entries), len(snapshots))
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
