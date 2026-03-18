package logtail

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// JournaldTailer reads log entries from systemd journal via journalctl.
type JournaldTailer struct {
	cfg     LogSourceConfig
	entries chan<- LogEntry
	dataDir string
}

// NewJournaldTailer creates a journald tailer for the given config.
func NewJournaldTailer(cfg LogSourceConfig, entries chan<- LogEntry, dataDir string) (*JournaldTailer, error) {
	if len(cfg.Units) == 0 {
		return nil, fmt.Errorf("journald tailer requires at least one unit")
	}

	// Verify journalctl is available
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("journalctl not found: %w", err)
	}

	return &JournaldTailer{
		cfg:     cfg,
		entries: entries,
		dataDir: dataDir,
	}, nil
}

// Run tails the journal until ctx is cancelled.
func (jt *JournaldTailer) Run(ctx context.Context) {
	args := []string{
		"--follow",
		"--no-pager",
		"--output=short-iso",
		"--since=now",
	}
	for _, unit := range jt.cfg.Units {
		args = append(args, "--unit="+unit)
	}

	for {
		if err := jt.runJournalctl(ctx, args); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[logtail] journalctl exited: %v, restarting in 5s", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (jt *JournaldTailer) runJournalctl(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		jt.entries <- LogEntry{
			Timestamp: time.Now().Unix(),
			Message:   line,
			Source:    jt.cfg.Label,
		}
	}

	return cmd.Wait()
}
