package logtail

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

const (
	// pollInterval is how often the file tailer checks for new data.
	pollInterval = 250 * time.Millisecond
)

// Tailer reads new lines from a single log file, tracking position for resume.
type Tailer struct {
	cfg     LogSourceConfig
	entries chan<- LogEntry
	store   *PositionStore
	key     string
}

// NewTailer creates a file tailer for the given config.
func NewTailer(cfg LogSourceConfig, entries chan<- LogEntry, store *PositionStore) (*Tailer, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("file tailer requires a path")
	}

	// Verify the file exists
	if _, err := os.Stat(cfg.Path); err != nil {
		return nil, fmt.Errorf("stat %s: %w", cfg.Path, err)
	}

	return &Tailer{
		cfg:     cfg,
		entries: entries,
		store:   store,
		key:     "file:" + cfg.Path,
	}, nil
}

// Run tails the file until ctx is cancelled. Polls for new lines and sends
// them to the entries channel. Tracks file position via the PositionStore.
func (t *Tailer) Run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.readNewLines()
		}
	}
}

func (t *Tailer) readNewLines() {
	f, err := os.Open(t.cfg.Path)
	if err != nil {
		return // file may have been rotated; retry next tick
	}
	defer f.Close()

	// Check if file was truncated (log rotation)
	info, err := f.Stat()
	if err != nil {
		return
	}

	offset := t.store.Get(t.key)
	if info.Size() < offset {
		// File was truncated — start from beginning
		offset = 0
		log.Printf("[logtail] file truncated, resetting position: %s", t.cfg.Path)
	}

	if info.Size() == offset {
		return // no new data
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		t.entries <- LogEntry{
			Timestamp: time.Now().Unix(),
			Message:   line,
			Source:    t.cfg.Label,
		}
	}

	// Update position
	newOffset, _ := f.Seek(0, io.SeekCurrent)
	t.store.Set(t.key, newOffset)
}
