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

// Scheduler orchestrates metric collection, batching, encryption, and sending.
// In idle mode: collects every collectInterval, batches and sends every batchInterval (clock-aligned).
// In live mode: collects and sends every collectInterval (1s).
type Scheduler struct {
	agentID   string
	epoch     int
	encryptor *crypto.Encryptor
	orch      *collector.Orchestrator
	conn      *transport.Connection
	wal       *wal.WAL

	mu              sync.RWMutex
	mode            Mode
	collectInterval time.Duration
	batchInterval   time.Duration

	// Buffer for accumulating snapshots between batch sends (idle mode).
	batchMu  sync.Mutex
	batchBuf []Snapshot

	// Channel to signal pace changes to the run loop.
	paceChanged chan struct{}
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
		agentID:         agentID,
		epoch:           epoch,
		encryptor:       enc,
		orch:            orch,
		conn:            conn,
		wal:             w,
		mode:            ModeIdle,
		collectInterval: 10 * time.Second,
		batchInterval:   10 * time.Minute,
		paceChanged:     make(chan struct{}, 1),
	}
}

// SetPace updates collection and send intervals. Called when server sends a pace message.
func (s *Scheduler) SetPace(intervalMS, collectMS int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if collectMS > 0 {
		s.collectInterval = time.Duration(collectMS) * time.Millisecond
	}

	if intervalMS == 0 {
		// Return to batch mode
		s.mode = ModeIdle
		s.collectInterval = 10 * time.Second
		log.Printf("[scheduler] switching to idle mode (collect=%v, batch=%v)", s.collectInterval, s.batchInterval)
	} else {
		s.mode = ModeLive
		s.collectInterval = time.Duration(collectMS) * time.Millisecond
		log.Printf("[scheduler] switching to live mode (collect=%v)", s.collectInterval)
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

// Mode returns the current operating mode.
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

	walEntries := make([]protocol.WALSyncEntry, 0, len(entries))
	for _, e := range entries {
		walEntries = append(walEntries, protocol.WALSyncEntry{
			BatchID:    e.BatchID,
			Epoch:      e.Epoch,
			Timestamp:  e.Timestamp,
			EncPayload: e.EncPayload,
		})
	}

	msg := protocol.WALSyncMessage{
		Type:    "wal_sync",
		Entries: walEntries,
	}

	if err := s.conn.Send(msg); err != nil {
		log.Printf("[scheduler] WAL sync send failed: %v", err)
	}
}

func (s *Scheduler) runLoop(ctx context.Context) {
	s.mu.RLock()
	interval := s.collectInterval
	s.mu.RUnlock()

	collectTicker := time.NewTicker(interval)
	defer collectTicker.Stop()

	// Clock-aligned batch timer
	batchTimer := time.NewTimer(s.timeUntilNextBatch())
	defer batchTimer.Stop()

	for {
		s.mu.RLock()
		mode := s.mode
		currentInterval := s.collectInterval
		s.mu.RUnlock()

		select {
		case <-ctx.Done():
			// Graceful shutdown: flush any buffered data
			s.flush()
			return

		case <-s.paceChanged:
			// Pace changed — reset collect ticker immediately
			s.mu.RLock()
			newInterval := s.collectInterval
			s.mu.RUnlock()
			collectTicker.Reset(newInterval)

		case <-collectTicker.C:
			snap := s.collect(ctx)
			if snap == nil {
				continue
			}

			if mode == ModeLive {
				s.sendLive(snap)
			} else {
				s.bufferSnapshot(snap)
			}

			// Reset ticker if interval changed
			s.mu.RLock()
			newInterval := s.collectInterval
			s.mu.RUnlock()
			if newInterval != currentInterval {
				collectTicker.Reset(newInterval)
			}

		case <-batchTimer.C:
			if mode == ModeIdle {
				s.sendBatch()
			}
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

func (s *Scheduler) sendBatch() {
	s.batchMu.Lock()
	snapshots := s.batchBuf
	s.batchBuf = nil
	s.batchMu.Unlock()

	if len(snapshots) == 0 {
		return
	}

	// Snapshot encryptor and epoch under lock (may change during DEK rotation)
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	now := time.Now()
	batchID := fmt.Sprintf("b_%d_%s", now.Unix(), s.agentID)

	plaintext, err := json.Marshal(snapshots)
	if err != nil {
		log.Printf("[scheduler] marshal batch error: %v", err)
		return
	}

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Printf("[scheduler] encrypt batch error: %v", err)
		return
	}

	walEntry := wal.Entry{
		BatchID:    batchID,
		AgentID:    s.agentID,
		Epoch:      epoch,
		Timestamp:  now.Unix(),
		EncPayload: encrypted,
	}

	if err := s.wal.Append(walEntry); err != nil {
		log.Printf("[scheduler] WAL append error: %v", err)
	}

	msg := protocol.BatchMessage{
		Type:       "batch",
		BatchID:    batchID,
		Epoch:      epoch,
		Timestamp:  now.Unix(),
		EncPayload: encrypted,
	}

	if err := s.conn.Send(msg); err != nil {
		log.Printf("[scheduler] batch send error: %v (data preserved in WAL)", err)
	} else {
		log.Printf("[scheduler] batch sent: %s (%d snapshots, %d bytes encrypted)",
			batchID, len(snapshots), len(encrypted))
	}
}

func (s *Scheduler) sendLive(snap *Snapshot) {
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	plaintext, err := json.Marshal(snap)
	if err != nil {
		return
	}

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		return
	}

	msg := protocol.LiveMessage{
		Type:       "live",
		Epoch:      epoch,
		Timestamp:  snap.Timestamp,
		EncPayload: encrypted,
	}

	s.conn.Send(msg)
}

// flush encrypts and sends any buffered data. Called on graceful shutdown.
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

	now := time.Now()
	batchID := fmt.Sprintf("flush_%d_%s", now.Unix(), s.agentID)

	plaintext, err := json.Marshal(snapshots)
	if err != nil {
		log.Printf("[scheduler] flush marshal error: %v", err)
		return
	}

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Printf("[scheduler] flush encrypt error: %v", err)
		return
	}

	walEntry := wal.Entry{
		BatchID:    batchID,
		AgentID:    s.agentID,
		Epoch:      epoch,
		Timestamp:  now.Unix(),
		EncPayload: encrypted,
	}
	s.wal.Append(walEntry)

	msg := protocol.FlushMessage{
		Type:       "flush",
		BatchID:    batchID,
		Epoch:      epoch,
		Timestamp:  now.Unix(),
		EncPayload: encrypted,
	}

	if err := s.conn.SendSync(msg); err != nil {
		log.Printf("[scheduler] flush send failed: %v (data preserved in WAL)", err)
	} else {
		log.Printf("[scheduler] flush sent: %s (%d snapshots)", batchID, len(snapshots))
	}
}

// timeUntilNextBatch returns the duration until the next clock-aligned batch window.
func (s *Scheduler) timeUntilNextBatch() time.Duration {
	s.mu.RLock()
	interval := s.batchInterval
	s.mu.RUnlock()

	now := time.Now()
	next := now.Truncate(interval).Add(interval)
	d := next.Sub(now)
	if d <= 0 {
		d = interval
	}
	return d
}

// AckBatch removes a batch from the WAL. Called when server sends an ack.
func (s *Scheduler) AckBatch(batchID string) {
	if err := s.wal.Ack(batchID); err != nil {
		log.Printf("[scheduler] WAL ack error for %s: %v", batchID, err)
	}
}
