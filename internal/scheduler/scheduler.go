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

	// Send WAL entries one per message to avoid AE dropping writes.
	// Each message triggers exactly 1 writeDataPoint in the DO.
	for i, e := range entries {
		if err := s.conn.Send(protocol.WALSyncMessage{
			Type: "wal_sync",
			Entries: []protocol.WALSyncEntry{{
				BatchID:    e.BatchID,
				Epoch:      e.Epoch,
				Timestamp:  e.Timestamp,
				EncPayload: e.EncPayload,
			}},
		}); err != nil {
			log.Printf("[scheduler] WAL sync entry %d send failed: %v", i, err)
		}

		// 1 write per second to stay safely under AE rate limits
		if i < len(entries)-1 {
			time.Sleep(time.Second)
		}
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
			// Pace changed — reset collect ticker and flush buffered data
			s.mu.RLock()
			newInterval := s.collectInterval
			newMode := s.mode
			s.mu.RUnlock()
			collectTicker.Reset(newInterval)

			// When switching to live mode:
			// 1. Send all buffered idle-mode snapshots as individual live messages
			// 2. Immediately collect+send a fresh snapshot so the dashboard
			//    gets data without waiting for the next ticker (up to 10s delay)
			if newMode == ModeLive {
				s.flushBufferAsLive()
				if snap := s.collect(ctx); snap != nil {
					s.sendLive(snap)
				}
			}

		case <-collectTicker.C:
			snap := s.collect(ctx)
			if snap == nil {
				continue
			}

			if mode == ModeLive {
				// Live mode: stream to dashboard, buffer for batch AE persistence
				s.sendLive(snap)
				s.bufferSnapshot(snap)
			} else {
				// Idle mode: send immediately to AE (1 write per collect interval)
				// No buffering — each snapshot is its own WS message = 1 writeDataPoint
				// per DO invocation, avoiding AE silent write drops.
				s.sendBatchSingle(snap)
			}

			// Reset ticker if interval changed
			s.mu.RLock()
			newInterval := s.collectInterval
			s.mu.RUnlock()
			if newInterval != currentInterval {
				collectTicker.Reset(newInterval)
			}

		case <-batchTimer.C:
			if mode == ModeLive {
				// Run batch send in goroutine so live streaming continues unblocked.
				// sendBatch drains batchBuf under lock before the goroutine starts sleeping.
				go s.sendBatch()
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

	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	now := time.Now()
	baseBatchID := fmt.Sprintf("b_%d_%s", now.Unix(), s.agentID)

	// Downsample to 10-second resolution for AE persistence.
	// In live mode (1s collection), 10 minutes = 600 snapshots, but AE rate limit
	// is ~6 writes/min. Sending every 10th snapshot yields ~60 writes at safe rate.
	// The dashboard already has full 1s resolution from live WS messages.
	var downsampled []Snapshot
	if len(snapshots) > 60 {
		// Live mode: take every Nth snapshot to get ~60 entries
		step := len(snapshots) / 60
		if step < 1 {
			step = 1
		}
		for i := 0; i < len(snapshots); i += step {
			downsampled = append(downsampled, snapshots[i])
		}
		// Always include the last snapshot
		if downsampled[len(downsampled)-1].Timestamp != snapshots[len(snapshots)-1].Timestamp {
			downsampled = append(downsampled, snapshots[len(snapshots)-1])
		}
	} else {
		downsampled = snapshots
	}

	var sentCount int
	var totalBytes int

	for i, snap := range downsampled {
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

		batchID := fmt.Sprintf("%s_%d", baseBatchID, i)

		// WAL: persist before sending
		if err := s.wal.Append(wal.Entry{
			BatchID:    batchID,
			AgentID:    s.agentID,
			Epoch:      epoch,
			Timestamp:  snap.Timestamp,
			EncPayload: encrypted,
		}); err != nil {
			log.Printf("[scheduler] WAL append error: %v", err)
		}

		if err := s.conn.Send(protocol.BatchMessage{
			Type:       "batch",
			BatchID:    batchID,
			Epoch:      epoch,
			Timestamp:  snap.Timestamp,
			EncPayload: encrypted,
		}); err != nil {
			log.Printf("[scheduler] batch entry %d send error: %v (data in WAL)", i, err)
		} else {
			sentCount++
			totalBytes += len(encrypted)
		}

		// ~10 second delay between sends to stay under AE's ~6/min write rate limit
		if i < len(downsampled)-1 {
			time.Sleep(10 * time.Second)
		}
	}

	if sentCount > 0 {
		log.Printf("[scheduler] batch sent: %s (%d/%d snapshots, %d bytes, from %d buffered)",
			baseBatchID, sentCount, len(downsampled), totalBytes, len(snapshots))
	}
}

// sendBatchSingle encrypts and sends a single snapshot for AE persistence.
// Used in idle mode where snapshots are sent immediately on collect.
// Each message triggers exactly 1 writeDataPoint in the DO, avoiding AE write drops.
//
// Only metrics are persisted to AE (processes excluded) because:
// - Combined payload (~19KB) exceeds AE's 16KB blob limit
// - Metrics-only payload (~12KB) fits comfortably
// - Process data is ephemeral and streamed live when viewers are connected
func (s *Scheduler) sendBatchSingle(snap *Snapshot) {
	s.mu.RLock()
	enc := s.encryptor
	epoch := s.epoch
	s.mu.RUnlock()

	batchID := fmt.Sprintf("b_%d_%s", snap.Timestamp, s.agentID)

	// Encrypt metrics-only payload to stay under AE's 16KB blob limit
	payload := MetricPayload{
		Timestamp: snap.Timestamp,
		Metrics:   snap.Metrics,
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[scheduler] marshal snapshot error: %v", err)
		return
	}
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		log.Printf("[scheduler] encrypt snapshot error: %v", err)
		return
	}

	// WAL: persist before sending
	s.wal.Append(wal.Entry{
		BatchID:    batchID,
		AgentID:    s.agentID,
		Epoch:      epoch,
		Timestamp:  snap.Timestamp,
		EncPayload: encrypted,
	})

	if err := s.conn.Send(protocol.BatchMessage{
		Type:       "batch",
		BatchID:    batchID,
		Epoch:      epoch,
		Timestamp:  snap.Timestamp,
		EncPayload: encrypted,
	}); err != nil {
		log.Printf("[scheduler] batch single send error: %v (data in WAL)", err)
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

// flushBufferAsLive sends buffered snapshots as live messages to the dashboard
// without draining the buffer. The buffer is kept intact so batch sends still
// persist all data to AE.
func (s *Scheduler) flushBufferAsLive() {
	s.batchMu.Lock()
	snapshots := make([]Snapshot, len(s.batchBuf))
	copy(snapshots, s.batchBuf)
	s.batchMu.Unlock()

	if len(snapshots) == 0 {
		return
	}

	log.Printf("[scheduler] flushing %d buffered snapshots as live", len(snapshots))
	for i := range snapshots {
		s.sendLive(&snapshots[i])
	}
}

// flush encrypts and sends any buffered data. Called on graceful shutdown.
// Uses SendSync for each message since the process is shutting down.
// Downsamples to ~60 entries if buffer is large (live mode).
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

	// Downsample if buffer is large (live mode with 1s collection)
	toFlush := snapshots
	if len(snapshots) > 60 {
		step := len(snapshots) / 60
		toFlush = nil
		for i := 0; i < len(snapshots); i += step {
			toFlush = append(toFlush, snapshots[i])
		}
		if toFlush[len(toFlush)-1].Timestamp != snapshots[len(snapshots)-1].Timestamp {
			toFlush = append(toFlush, snapshots[len(snapshots)-1])
		}
	}

	now := time.Now()
	baseBatchID := fmt.Sprintf("flush_%d_%s", now.Unix(), s.agentID)
	var sentCount int

	for i, snap := range toFlush {
		payload := MetricPayload{
			Timestamp: snap.Timestamp,
			Metrics:   snap.Metrics,
		}
		plaintext, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		encrypted, err := enc.Encrypt(plaintext)
		if err != nil {
			continue
		}

		batchID := fmt.Sprintf("%s_%d", baseBatchID, i)

		// WAL: persist before sending
		s.wal.Append(wal.Entry{
			BatchID:    batchID,
			AgentID:    s.agentID,
			Epoch:      epoch,
			Timestamp:  snap.Timestamp,
			EncPayload: encrypted,
		})

		if err := s.conn.SendSync(protocol.FlushMessage{
			Type:       "flush",
			BatchID:    batchID,
			Epoch:      epoch,
			Timestamp:  snap.Timestamp,
			EncPayload: encrypted,
		}); err != nil {
			log.Printf("[scheduler] flush entry %d send error: %v (data in WAL)", i, err)
		} else {
			sentCount++
		}
	}

	if sentCount > 0 {
		log.Printf("[scheduler] flush sent: %s (%d/%d snapshots, from %d buffered)",
			baseBatchID, sentCount, len(toFlush), len(snapshots))
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
