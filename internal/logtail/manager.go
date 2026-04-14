package logtail

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

	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
)

const (
	// logBatchInterval is the normal batch interval, wall-clock aligned like metrics.
	logBatchInterval = 10 * time.Minute
	// entryChannelSize is the buffer for the shared log entry channel.
	entryChannelSize = 10000
	// positionFlushInterval is how often positions are persisted to disk.
	positionFlushInterval = 5 * time.Second
)

// Sender abstracts how log messages are sent (WebSocket in production, mock in tests).
type Sender interface {
	Send(msg any) error
}

// Manager coordinates all log tailers, batches entries, encrypts, and sends.
type Manager struct {
	agentID string
	dataDir string
	conn    *transport.Connection
	walLog  *wal.WAL

	mu        sync.RWMutex
	encryptor *crypto.Encryptor
	epoch     int

	store   *PositionStore
	entries chan LogEntry
	flushCh chan struct{} // signal to flush partial batch immediately

	// Live mode: when true, individual entries are also sent via SendLive.
	liveMu sync.RWMutex
	live   bool

	// OpenBatch — each incoming log entry is encrypted + persisted immediately.
	openMu    sync.Mutex
	openBatch *wal.OpenBatch
	openID    string

	// Active tailers keyed by source path/label
	tailerMu sync.Mutex
	tailers  map[string]context.CancelFunc
	configs  []LogSourceConfig
}

// NewManager creates a log manager.
func NewManager(
	agentID string,
	dataDir string,
	enc *crypto.Encryptor,
	epoch int,
	conn *transport.Connection,
	w *wal.WAL,
) (*Manager, error) {
	storePath := filepath.Join(dataDir, "log_positions.json")
	store, err := NewPositionStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("position store: %w", err)
	}

	return &Manager{
		agentID:   agentID,
		dataDir:   dataDir,
		encryptor: enc,
		epoch:     epoch,
		conn:      conn,
		walLog:    w,
		store:     store,
		entries:   make(chan LogEntry, entryChannelSize),
		flushCh:   make(chan struct{}, 1),
		tailers:   make(map[string]context.CancelFunc),
	}, nil
}

// FlushNow triggers an immediate flush of any buffered partial batch.
func (m *Manager) FlushNow() {
	select {
	case m.flushCh <- struct{}{}:
	default:
	}
}

// SetLive enables or disables live log forwarding.
// When live, each incoming entry is also sent individually via SendLive.
func (m *Manager) SetLive(live bool) {
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	m.live = live
	if live {
		log.Printf("[logtail] live mode enabled")
	} else {
		log.Printf("[logtail] live mode disabled")
	}
}

// BufferedEntries returns the entries in the current in-progress .open file
// as encrypted log batch entries, for replay on live mode activation.
// Does not drain or close the open batch.
func (m *Manager) BufferedEntries() []protocol.LogBatchEntry {
	m.openMu.Lock()
	openID := m.openID
	ob := m.openBatch
	m.openMu.Unlock()

	if ob == nil || openID == "" {
		return nil
	}

	path := filepath.Join(m.walLog.Dir(), openID+".open")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	first := true
	var entries []protocol.LogBatchEntry
	for scanner.Scan() {
		if first {
			first = false
			continue // skip meta line
		}
		var rec wal.EntryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			break
		}
		entries = append(entries, protocol.LogBatchEntry{
			Timestamp:  rec.Timestamp,
			EncPayload: rec.EncPayload,
		})
	}
	return entries
}

// SetEncryptor updates the encryptor and epoch (DEK rotation).
func (m *Manager) SetEncryptor(enc *crypto.Encryptor, epoch int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encryptor = enc
	m.epoch = epoch
}

// UpdateConfig applies new log source configuration. Starts new tailers,
// stops removed ones, without affecting unchanged sources.
func (m *Manager) UpdateConfig(sources []LogSourceConfig) {
	m.tailerMu.Lock()
	defer m.tailerMu.Unlock()

	m.configs = sources

	// Build set of desired source keys
	desired := make(map[string]LogSourceConfig)
	for _, src := range sources {
		key := sourceKey(src)
		desired[key] = src
	}

	// Stop tailers that are no longer in config
	for key, cancel := range m.tailers {
		if _, ok := desired[key]; !ok {
			cancel()
			delete(m.tailers, key)
			log.Printf("[logtail] stopped tailer: %s", key)
		}
	}

	// Start tailers for new sources
	for key, src := range desired {
		if _, ok := m.tailers[key]; !ok {
			m.startTailer(key, src)
		}
	}
}

func (m *Manager) startTailer(key string, cfg LogSourceConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	m.tailers[key] = cancel

	switch cfg.Type {
	case "file":
		tailer, err := NewTailer(cfg, m.entries, m.store)
		if err != nil {
			log.Printf("[logtail] failed to create tailer for %s: %v", key, err)
			cancel()
			delete(m.tailers, key)
			return
		}
		go tailer.Run(ctx)
		log.Printf("[logtail] started file tailer: %s → %s", cfg.Label, cfg.Path)

	case "journald":
		jt, err := NewJournaldTailer(cfg, m.entries, m.dataDir)
		if err != nil {
			log.Printf("[logtail] failed to create journald tailer for %s: %v", key, err)
			cancel()
			delete(m.tailers, key)
			return
		}
		go jt.Run(ctx)
		log.Printf("[logtail] started journald tailer: %s → %v", cfg.Label, cfg.Units)

	default:
		log.Printf("[logtail] unknown source type %q for %s", cfg.Type, key)
		cancel()
		delete(m.tailers, key)
	}
}

// timeUntilNextLogBatch returns the duration until the next clock-aligned 10-minute boundary.
func timeUntilNextLogBatch() time.Duration {
	now := time.Now()
	next := now.Truncate(logBatchInterval).Add(logBatchInterval)
	d := next.Sub(now)
	if d <= 0 {
		d = logBatchInterval
	}
	return d
}

// handleLogEntry encrypts and appends a single log entry to the open batch,
// creating the batch file on first call. Also forwards to live mode if active.
func (m *Manager) handleLogEntry(entry LogEntry) {
	m.mu.RLock()
	enc := m.encryptor
	epoch := m.epoch
	m.mu.RUnlock()

	if enc == nil {
		return
	}

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return
	}
	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		return
	}

	m.openMu.Lock()
	defer m.openMu.Unlock()

	if m.openBatch == nil {
		batchID := fmt.Sprintf("lb_%d_%s", time.Now().Unix(), m.agentID)
		ob, err := m.walLog.OpenBatch(wal.BatchMeta{
			BatchID:   batchID,
			AgentID:   m.agentID,
			Epoch:     epoch,
			StartedAt: entry.Timestamp,
		})
		if err != nil {
			log.Printf("[logtail] OpenBatch error: %v", err)
			return
		}
		m.openBatch = ob
		m.openID = batchID
	}

	if err := m.openBatch.Append(wal.EntryRecord{
		Epoch:      epoch,
		Timestamp:  entry.Timestamp,
		EncPayload: encrypted,
	}); err != nil {
		log.Printf("[logtail] OpenBatch.Append error: %v", err)
	}

	m.liveMu.RLock()
	isLive := m.live
	m.liveMu.RUnlock()
	if isLive {
		m.SendLive(entry)
	}
}

// flushOpenBatch finalizes the current open batch and sends it.
// If there is no open batch, or the batch is empty, it is a no-op.
func (m *Manager) flushOpenBatch() {
	m.openMu.Lock()
	ob := m.openBatch
	m.openBatch = nil
	m.openID = ""
	m.openMu.Unlock()

	if ob == nil {
		return
	}

	entry, err := ob.Finalize()
	if err == wal.ErrEmptyBatch {
		return
	}
	if err != nil {
		log.Printf("[logtail] Finalize error: %v", err)
		return
	}

	var payloads []string
	if err := json.Unmarshal([]byte(entry.EncPayload), &payloads); err != nil {
		log.Printf("[logtail] decode payloads error: %v", err)
		return
	}

	protoEntries := make([]protocol.LogBatchEntry, len(payloads))
	for i, p := range payloads {
		protoEntries[i] = protocol.LogBatchEntry{
			Timestamp:  entry.Timestamp + int64(i),
			EncPayload: p,
		}
	}

	if err := m.conn.Send(protocol.LogBatchMessage{
		Type:    "log_batch",
		BatchID: entry.BatchID,
		Epoch:   entry.Epoch,
		Entries: protoEntries,
	}); err != nil {
		log.Printf("[logtail] send error: %v (data in WAL)", err)
	} else {
		log.Printf("[logtail] batch sent: %s (%d entries)", entry.BatchID, len(protoEntries))
	}
}

// Run starts the batch sender loop. Blocks until ctx is cancelled.
// Each log entry is encrypted and persisted to an open batch file immediately.
// The batch is finalized and sent at each 10-minute wall-clock boundary.
func (m *Manager) Run(ctx context.Context) {
	// Wall-clock-aligned batch timer
	batchTimer := time.NewTimer(timeUntilNextLogBatch())
	defer batchTimer.Stop()

	posTicker := time.NewTicker(positionFlushInterval)
	defer posTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.flushOpenBatch()
			m.stopAllTailers()
			m.store.Flush()
			return

		case entry := <-m.entries:
			m.handleLogEntry(entry)

		case <-batchTimer.C:
			m.flushOpenBatch()
			batchTimer.Reset(timeUntilNextLogBatch())

		case <-m.flushCh:
			m.flushOpenBatch()

		case <-posTicker.C:
			if err := m.store.Flush(); err != nil {
				log.Printf("[logtail] position flush error: %v", err)
			}
		}
	}
}

// SendLive sends a single log entry immediately (live mode).
func (m *Manager) SendLive(entry LogEntry) {
	m.mu.RLock()
	enc := m.encryptor
	epoch := m.epoch
	m.mu.RUnlock()

	if enc == nil {
		return
	}

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return
	}

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		return
	}

	m.conn.Send(protocol.LiveLogMessage{
		Type:       "live_log",
		Epoch:      epoch,
		Timestamp:  entry.Timestamp,
		EncPayload: encrypted,
	})
}

func (m *Manager) stopAllTailers() {
	m.tailerMu.Lock()
	defer m.tailerMu.Unlock()

	for key, cancel := range m.tailers {
		cancel()
		delete(m.tailers, key)
	}
}

func sourceKey(cfg LogSourceConfig) string {
	if cfg.Type == "file" {
		return cfg.Type + ":" + cfg.Path
	}
	return cfg.Type + ":" + cfg.Label
}
