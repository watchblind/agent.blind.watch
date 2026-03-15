package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/shirou/gopsutil/v4/net"
)

type NetworkCollector struct {
	prevCounters map[string]net.IOCountersStat
	prevTime     time.Time
}

func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{
		prevCounters: make(map[string]net.IOCountersStat),
	}
}

func (c *NetworkCollector) Name() string { return "network" }

func (c *NetworkCollector) Collect(ctx context.Context) ([]Metric, error) {
	now := time.Now()
	var metrics []Metric

	counters, err := net.IOCountersWithContext(ctx, true) // per-interface
	if err != nil {
		return nil, fmt.Errorf("network io: %w", err)
	}

	counterMap := make(map[string]net.IOCountersStat)
	for _, c := range counters {
		counterMap[c.Name] = c
	}

	if !c.prevTime.IsZero() {
		dt := now.Sub(c.prevTime).Seconds()
		if dt > 0 {
			for name, curr := range counterMap {
				prev, ok := c.prevCounters[name]
				if !ok {
					continue
				}
				labels := map[string]string{"interface": name}
				metrics = append(metrics, Metric{
					Name:      "net_bytes_sent_per_sec",
					Value:     float64(curr.BytesSent-prev.BytesSent) / dt,
					Labels:    labels,
					Timestamp: now,
				})
				metrics = append(metrics, Metric{
					Name:      "net_bytes_recv_per_sec",
					Value:     float64(curr.BytesRecv-prev.BytesRecv) / dt,
					Labels:    labels,
					Timestamp: now,
				})
			}
		}
	}

	c.prevCounters = counterMap
	c.prevTime = now

	return metrics, nil
}
