package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
)

type CPUCollector struct{}

func NewCPUCollector() *CPUCollector {
	return &CPUCollector{}
}

func (c *CPUCollector) Name() string { return "cpu" }

func (c *CPUCollector) Collect(ctx context.Context) ([]Metric, error) {
	now := time.Now()

	// Total CPU percent (blocking call, ~200ms sample)
	totals, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return nil, fmt.Errorf("cpu total: %w", err)
	}

	var metrics []Metric
	if len(totals) > 0 {
		metrics = append(metrics, Metric{
			Name:      "cpu_percent",
			Value:     totals[0],
			Timestamp: now,
		})
	}

	// Per-core
	perCore, err := cpu.PercentWithContext(ctx, 0, true)
	if err != nil {
		return metrics, nil // return total even if per-core fails
	}

	for i, pct := range perCore {
		metrics = append(metrics, Metric{
			Name:      "cpu_core_percent",
			Value:     pct,
			Labels:    map[string]string{"core": fmt.Sprintf("%d", i)},
			Timestamp: now,
		})
	}

	return metrics, nil
}
