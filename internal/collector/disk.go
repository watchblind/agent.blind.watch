package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

type DiskCollector struct {
	prevCounters map[string]disk.IOCountersStat
	prevTime     time.Time
}

func NewDiskCollector() *DiskCollector {
	return &DiskCollector{
		prevCounters: make(map[string]disk.IOCountersStat),
	}
}

func (c *DiskCollector) Name() string { return "disk" }

func (c *DiskCollector) Collect(ctx context.Context) ([]Metric, error) {
	now := time.Now()
	var metrics []Metric

	// Disk usage per partition
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("disk partitions: %w", err)
	}

	for _, p := range partitions {
		usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			continue
		}
		labels := map[string]string{
			"mount":  p.Mountpoint,
			"device": p.Device,
			"fstype": p.Fstype,
		}
		metrics = append(metrics, Metric{
			Name:      "disk_usage_percent",
			Value:     usage.UsedPercent,
			Labels:    labels,
			Timestamp: now,
		})
		metrics = append(metrics, Metric{
			Name:      "disk_total_bytes",
			Value:     float64(usage.Total),
			Labels:    labels,
			Timestamp: now,
		})
		metrics = append(metrics, Metric{
			Name:      "disk_used_bytes",
			Value:     float64(usage.Used),
			Labels:    labels,
			Timestamp: now,
		})
	}

	// Disk I/O rates
	counters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return metrics, nil
	}

	if !c.prevTime.IsZero() {
		dt := now.Sub(c.prevTime).Seconds()
		if dt > 0 {
			for name, curr := range counters {
				prev, ok := c.prevCounters[name]
				if !ok {
					continue
				}
				labels := map[string]string{"device": name}
				metrics = append(metrics, Metric{
					Name:      "disk_read_bytes_per_sec",
					Value:     float64(curr.ReadBytes-prev.ReadBytes) / dt,
					Labels:    labels,
					Timestamp: now,
				})
				metrics = append(metrics, Metric{
					Name:      "disk_write_bytes_per_sec",
					Value:     float64(curr.WriteBytes-prev.WriteBytes) / dt,
					Labels:    labels,
					Timestamp: now,
				})
			}
		}
	}

	c.prevCounters = counters
	c.prevTime = now

	return metrics, nil
}
