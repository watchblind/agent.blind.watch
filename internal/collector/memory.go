package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/mem"
)

type MemoryCollector struct{}

func NewMemoryCollector() *MemoryCollector {
	return &MemoryCollector{}
}

func (c *MemoryCollector) Name() string { return "memory" }

func (c *MemoryCollector) Collect(ctx context.Context) ([]Metric, error) {
	now := time.Now()

	v, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}

	return []Metric{
		{Name: "memory_total_bytes", Value: float64(v.Total), Timestamp: now},
		{Name: "memory_used_bytes", Value: float64(v.Used), Timestamp: now},
		{Name: "memory_available_bytes", Value: float64(v.Available), Timestamp: now},
		{Name: "memory_percent", Value: v.UsedPercent, Timestamp: now},
	}, nil
}
