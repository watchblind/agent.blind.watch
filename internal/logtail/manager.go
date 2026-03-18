package logtail

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/watchblind/agent/internal/crypto"
	"github.com/watchblind/agent/internal/protocol"
	"github.com/watchblind/agent/internal/transport"
	"github.com/watchblind/agent/internal/wal"
)

const (
	// MaxBatchSize is the max entries per log batch before flushing.
	MaxBatchSize = 100
	// FlushInterval is the max time between log batch flushes.
	FlushInterval = 5 * time.Second
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
// Called when dashboard connects (pace change to live) to avoid stale data.
func (m *Manager) FlushNow() {
	select {
	case m.flushCh <- struct{}{}:
	default:
	}
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

// Run starts the batch sender loop. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	flushTicker := time.NewTicker(FlushInterval)
	defer flushTicker.Stop()

	posTicker := time.NewTicker(positionFlushInterval)
	defer posTicker.Stop()

	var batch []LogEntry

	for {
		select {
		case <-ctx.Done():
			// Flush remaining entries
			if len(batch) > 0 {
				m.sendBatch(batch)
			}
			m.stopAllTailers()
			m.store.Flush()
			return

		case entry := <-m.entries:
			batch = append(batch, entry)
			if len(batch) >= MaxBatchSize {
				m.sendBatch(batch)
				batch = nil
			}

		case <-flushTicker.C:
			if len(batch) > 0 {
				m.sendBatch(batch)
				batch = nil
			}

		case <-m.flushCh:
			if len(batch) > 0 {
				m.sendBatch(batch)
				batch = nil
			}

		case <-posTicker.C:
			if err := m.store.Flush(); err != nil {
				log.Printf("[logtail] position flush error: %v", err)
			}
		}
	}
}

func (m *Manager) sendBatch(entries []LogEntry) {
	m.mu.RLock()
	enc := m.encryptor
	epoch := m.epoch
	m.mu.RUnlock()

	if enc == nil {
		return
	}

	// Encrypt each entry individually
	protoEntries := make([]protocol.LogBatchEntry, 0, len(entries))
	for _, entry := range entries {
		plaintext, err := json.Marshal(entry)
		if err != nil {
			log.Printf("[logtail] marshal error: %v", err)
			continue
		}

		encrypted, err := enc.Encrypt(plaintext)
		if err != nil {
			log.Printf("[logtail] encrypt error: %v", err)
			continue
		}

		protoEntries = append(protoEntries, protocol.LogBatchEntry{
			Timestamp:  entry.Timestamp,
			EncPayload: encrypted,
		})
	}

	if len(protoEntries) == 0 {
		return
	}

	batchID := fmt.Sprintf("lb_%d_%s", time.Now().Unix(), m.agentID)

	// Persist to WAL
	walPayload, _ := json.Marshal(protoEntries)
	walEntry := wal.Entry{
		BatchID:    batchID,
		AgentID:    m.agentID,
		Epoch:      epoch,
		Timestamp:  time.Now().Unix(),
		EncPayload: string(walPayload),
	}
	if err := m.walLog.Append(walEntry); err != nil {
		log.Printf("[logtail] WAL append error: %v", err)
	}

	msg := protocol.LogBatchMessage{
		Type:    "log_batch",
		BatchID: batchID,
		Epoch:   epoch,
		Entries: protoEntries,
	}

	if err := m.conn.Send(msg); err != nil {
		log.Printf("[logtail] send error: %v (data in WAL)", err)
	} else {
		log.Printf("[logtail] batch sent: %s (%d entries)", batchID, len(protoEntries))
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
