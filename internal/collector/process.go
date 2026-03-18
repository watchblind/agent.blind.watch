package collector

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// ProcessInfo holds per-process metrics similar to btop.
type ProcessInfo struct {
	PID     int32   `json:"pid"`
	Name    string  `json:"name"`
	Cmdline string  `json:"cmdline"`
	User    string  `json:"user"`
	Status  string  `json:"status"`
	CPU     float64 `json:"cpu_percent"`
	MemRSS  uint64  `json:"mem_rss"`
	MemVMS  uint64  `json:"mem_vms"`
	MemPct  float32 `json:"mem_percent"`
	Threads int32   `json:"threads"`
	IORead  uint64  `json:"io_read_bytes"`
	IOWrite uint64  `json:"io_write_bytes"`
}

type ProcessCollector struct {
	maxProcs    int
	prevCPU     map[int32]float64
	prevIORead  map[int32]uint64
	prevIOWrite map[int32]uint64
	prevTime    time.Time
	lastInfos   []ProcessInfo
}

func NewProcessCollector(maxProcs int) *ProcessCollector {
	if maxProcs <= 0 {
		maxProcs = 50
	}
	return &ProcessCollector{
		maxProcs:    maxProcs,
		prevCPU:     make(map[int32]float64),
		prevIORead:  make(map[int32]uint64),
		prevIOWrite: make(map[int32]uint64),
	}
}

func (c *ProcessCollector) Name() string { return "process" }

func (c *ProcessCollector) Collect(ctx context.Context) ([]Metric, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}

	infos := make([]ProcessInfo, 0, len(procs))

	for _, p := range procs {
		info := c.collectOne(ctx, p)
		if info != nil {
			infos = append(infos, *info)
		}
	}

	// Sort by CPU descending, take top N
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].CPU > infos[j].CPU
	})
	if len(infos) > c.maxProcs {
		infos = infos[:c.maxProcs]
	}

	// Store for snapshot inclusion
	c.lastInfos = infos

	now := time.Now()
	var metrics []Metric

	// Emit summary metrics
	var totalCPU float64
	var totalMem uint64
	for _, info := range infos {
		totalCPU += info.CPU
		totalMem += info.MemRSS
	}
	metrics = append(metrics, Metric{
		Name:      "process_count",
		Value:     float64(len(procs)),
		Timestamp: now,
	})

	return metrics, nil
}

// LastInfos returns the process list from the most recent Collect() call.
func (c *ProcessCollector) LastInfos() []ProcessInfo {
	return c.lastInfos
}

// CollectProcesses returns detailed process info for the dashboard.
func (c *ProcessCollector) CollectProcesses(ctx context.Context) []ProcessInfo {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil
	}

	infos := make([]ProcessInfo, 0, len(procs))
	for _, p := range procs {
		info := c.collectOne(ctx, p)
		if info != nil {
			infos = append(infos, *info)
		}
	}

	// Sort by CPU descending
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].CPU > infos[j].CPU
	})

	if len(infos) > c.maxProcs {
		infos = infos[:c.maxProcs]
	}

	// Track I/O for rate calculation
	newIORead := make(map[int32]uint64)
	newIOWrite := make(map[int32]uint64)
	for i := range infos {
		newIORead[infos[i].PID] = infos[i].IORead
		newIOWrite[infos[i].PID] = infos[i].IOWrite
	}
	c.prevIORead = newIORead
	c.prevIOWrite = newIOWrite
	c.prevTime = time.Now()

	return infos
}

func (c *ProcessCollector) collectOne(ctx context.Context, p *process.Process) *ProcessInfo {
	pid := p.Pid

	name, err := p.NameWithContext(ctx)
	if err != nil {
		return nil
	}

	cpuPct, _ := p.CPUPercentWithContext(ctx)

	memInfo, err := p.MemoryInfoWithContext(ctx)
	if err != nil {
		return nil
	}

	memPct, _ := p.MemoryPercentWithContext(ctx)

	status, _ := p.StatusWithContext(ctx)
	statusStr := ""
	if len(status) > 0 {
		statusStr = status[0]
	}

	user, err := p.UsernameWithContext(ctx)
	if err != nil || user == "" {
		// Fallback to numeric UID string when username lookup fails
		uids, uidErr := p.UidsWithContext(ctx)
		if uidErr == nil && len(uids) > 0 {
			user = fmt.Sprintf("%d", uids[0])
		}
	}

	threads, _ := p.NumThreadsWithContext(ctx)

	cmdline, _ := p.CmdlineWithContext(ctx)
	if len(cmdline) > 120 {
		cmdline = cmdline[:120]
	}

	var ioRead, ioWrite uint64
	ioCounters, err := p.IOCountersWithContext(ctx)
	if err == nil {
		ioRead = ioCounters.ReadBytes
		ioWrite = ioCounters.WriteBytes
	}

	return &ProcessInfo{
		PID:     pid,
		Name:    name,
		Cmdline: cmdline,
		User:    user,
		Status:  statusStr,
		CPU:     cpuPct,
		MemRSS:  memInfo.RSS,
		MemVMS:  memInfo.VMS,
		MemPct:  memPct,
		Threads: threads,
		IORead:  ioRead,
		IOWrite: ioWrite,
	}
}
