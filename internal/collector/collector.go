package collector

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Metric struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Metric, error)
}

// ProcessProvider is optionally implemented by collectors that produce process lists.
type ProcessProvider interface {
	LastInfos() []ProcessInfo
}

// ProcessSnapshot is the per-process data included in each snapshot.
// Field names use snake_case JSON tags to match the dashboard's expected format.
type ProcessSnapshot struct {
	PID        int32   `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   float64 `json:"memory_mb"`
	User       string  `json:"user"`
}

type Snapshot struct {
	Metrics   []Metric          `json:"metrics"`
	Timestamp time.Time         `json:"timestamp"`
	Processes []ProcessSnapshot `json:"processes,omitempty"`
}

type Orchestrator struct {
	collectors []Collector
	mu         sync.RWMutex
	latest     *Snapshot
	listeners  []chan<- Snapshot
}

func NewOrchestrator() *Orchestrator {
	return &Orchestrator{}
}

func (o *Orchestrator) Register(c Collector) {
	o.collectors = append(o.collectors, c)
}

func (o *Orchestrator) Subscribe() <-chan Snapshot {
	ch := make(chan Snapshot, 8)
	o.mu.Lock()
	o.listeners = append(o.listeners, ch)
	o.mu.Unlock()
	return ch
}

func (o *Orchestrator) Latest() *Snapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.latest
}

func (o *Orchestrator) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Collect once immediately
	o.collect(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.collect(ctx)
		}
	}
}

func (o *Orchestrator) collect(ctx context.Context) {
	var all []Metric
	now := time.Now()

	for _, c := range o.collectors {
		metrics, err := c.Collect(ctx)
		if err != nil {
			fmt.Printf("[collector] %s error: %v\n", c.Name(), err)
			continue
		}
		all = append(all, metrics...)
	}

	// Extract process list from any collector that provides it
	var processes []ProcessSnapshot
	for _, c := range o.collectors {
		if pp, ok := c.(ProcessProvider); ok {
			for _, info := range pp.LastInfos() {
				processes = append(processes, ProcessSnapshot{
					PID:        info.PID,
					Name:       info.Name,
					CPUPercent: info.CPU,
					MemoryMB:   float64(info.MemRSS) / (1024 * 1024),
					User:       info.User,
				})
			}
		}
	}

	snap := Snapshot{
		Metrics:   all,
		Timestamp: now,
		Processes: processes,
	}

	o.mu.Lock()
	o.latest = &snap
	listeners := make([]chan<- Snapshot, len(o.listeners))
	copy(listeners, o.listeners)
	o.mu.Unlock()

	for _, ch := range listeners {
		select {
		case ch <- snap:
		default:
			// drop if listener is slow
		}
	}
}
