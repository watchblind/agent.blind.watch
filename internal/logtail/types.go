package logtail

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// LogEntry represents a single log line captured by a tailer.
type LogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
	Source    string `json:"source"`
}

// LogSourceConfig describes a log source to tail.
type LogSourceConfig struct {
	Type  string   `json:"type"`            // "file" or "journald"
	Label string   `json:"label"`           // human-readable name
	Path  string   `json:"path,omitempty"`  // file path (type=file)
	Units []string `json:"units,omitempty"` // systemd units (type=journald)
}

// PositionStore persists file read positions to disk so tailing resumes
// after agent restart.
type PositionStore struct {
	path string

	mu        sync.Mutex
	positions map[string]int64
}

// NewPositionStore loads or creates a position store backed by a JSON file.
func NewPositionStore(path string) (*PositionStore, error) {
	ps := &PositionStore{
		path:      path,
		positions: make(map[string]int64),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ps, nil
		}
		return nil, fmt.Errorf("reading position store: %w", err)
	}

	if err := json.Unmarshal(data, &ps.positions); err != nil {
		// Corrupted file — start fresh
		ps.positions = make(map[string]int64)
	}

	return ps, nil
}

// Get returns the stored offset for a source key.
func (ps *PositionStore) Get(key string) int64 {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.positions[key]
}

// Set updates the offset for a source key.
func (ps *PositionStore) Set(key string, offset int64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.positions[key] = offset
}

// Flush persists all positions to disk.
func (ps *PositionStore) Flush() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	data, err := json.Marshal(ps.positions)
	if err != nil {
		return fmt.Errorf("marshaling positions: %w", err)
	}

	if err := os.WriteFile(ps.path, data, 0600); err != nil {
		return fmt.Errorf("writing position store: %w", err)
	}

	return nil
}
