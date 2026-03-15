package collector

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// stubCollector returns fixed metrics for testing.
type stubCollector struct {
	name    string
	metrics []Metric
	calls   atomic.Int64
}

func (s *stubCollector) Name() string { return s.name }
func (s *stubCollector) Collect(_ context.Context) ([]Metric, error) {
	s.calls.Add(1)
	result := make([]Metric, len(s.metrics))
	for i, m := range s.metrics {
		m.Timestamp = time.Now()
		result[i] = m
	}
	return result, nil
}

// errorCollector always returns an error.
type errorCollector struct{ name string }

func (e *errorCollector) Name() string { return e.name }
func (e *errorCollector) Collect(_ context.Context) ([]Metric, error) {
	return nil, context.DeadlineExceeded
}

func TestOrchestratorCollectsOnStart(t *testing.T) {
	orch := NewOrchestrator()
	stub := &stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 42.0}},
	}
	orch.Register(stub)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 10*time.Second) // long interval — should still collect immediately

	// Wait a bit for the initial collection
	time.Sleep(100 * time.Millisecond)

	snap := orch.Latest()
	if snap == nil {
		t.Fatal("expected immediate collection on start")
	}
	if len(snap.Metrics) != 1 || snap.Metrics[0].Name != "cpu_percent" {
		t.Fatalf("unexpected metrics: %+v", snap.Metrics)
	}
}

func TestOrchestratorPollingInterval(t *testing.T) {
	orch := NewOrchestrator()
	stub := &stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 50.0}},
	}
	orch.Register(stub)

	ctx, cancel := context.WithTimeout(context.Background(), 550*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 200*time.Millisecond)

	// Wait for context to finish
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond) // let goroutine clean up

	// Initial + at least 2 ticks in 550ms with 200ms interval
	calls := stub.calls.Load()
	if calls < 3 {
		t.Fatalf("expected at least 3 collections in 550ms @ 200ms interval, got %d", calls)
	}
}

func TestOrchestratorSubscription(t *testing.T) {
	orch := NewOrchestrator()
	stub := &stubCollector{
		name:    "mem",
		metrics: []Metric{{Name: "memory_percent", Value: 65.0}},
	}
	orch.Register(stub)

	sub := orch.Subscribe()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 100*time.Millisecond)

	// Should receive at least one snapshot
	select {
	case snap := <-sub:
		if len(snap.Metrics) != 1 || snap.Metrics[0].Name != "memory_percent" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for subscription delivery")
	}
}

func TestOrchestratorMultipleSubscribers(t *testing.T) {
	orch := NewOrchestrator()
	stub := &stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 77.0}},
	}
	orch.Register(stub)

	sub1 := orch.Subscribe()
	sub2 := orch.Subscribe()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 100*time.Millisecond)

	// Both should receive
	for i, sub := range []<-chan Snapshot{sub1, sub2} {
		select {
		case snap := <-sub:
			if len(snap.Metrics) == 0 {
				t.Fatalf("subscriber %d got empty snapshot", i)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("subscriber %d timed out", i)
		}
	}
}

func TestOrchestratorSlowSubscriberDoesNotBlock(t *testing.T) {
	orch := NewOrchestrator()
	stub := &stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 50.0}},
	}
	orch.Register(stub)

	// Subscribe but never read — channel buffer (8) will fill up
	_ = orch.Subscribe()

	// Fast subscriber
	fast := orch.Subscribe()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 50*time.Millisecond) // fast polling

	// Fast subscriber should still get data even though slow one is backed up
	received := 0
	timeout := time.After(600 * time.Millisecond)
	for {
		select {
		case <-fast:
			received++
			if received >= 3 {
				return // success
			}
		case <-timeout:
			if received == 0 {
				t.Fatal("fast subscriber got nothing")
			}
			return
		}
	}
}

func TestOrchestratorMultipleCollectors(t *testing.T) {
	orch := NewOrchestrator()
	orch.Register(&stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 55.0}},
	})
	orch.Register(&stubCollector{
		name:    "mem",
		metrics: []Metric{{Name: "memory_percent", Value: 70.0}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 10*time.Second)
	time.Sleep(100 * time.Millisecond)

	snap := orch.Latest()
	if snap == nil {
		t.Fatal("expected snapshot")
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics from 2 collectors, got %d", len(snap.Metrics))
	}
}

func TestOrchestratorErrorCollectorDoesNotBreakOthers(t *testing.T) {
	orch := NewOrchestrator()
	orch.Register(&errorCollector{name: "broken"})
	orch.Register(&stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 60.0}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go orch.Run(ctx, 10*time.Second)
	time.Sleep(100 * time.Millisecond)

	snap := orch.Latest()
	if snap == nil {
		t.Fatal("expected snapshot despite erroring collector")
	}
	if len(snap.Metrics) != 1 {
		t.Fatalf("expected 1 metric (error collector skipped), got %d", len(snap.Metrics))
	}
	if snap.Metrics[0].Name != "cpu_percent" {
		t.Fatalf("expected cpu_percent from working collector, got %s", snap.Metrics[0].Name)
	}
}

func TestOrchestratorContextCancellation(t *testing.T) {
	orch := NewOrchestrator()
	stub := &stubCollector{
		name:    "cpu",
		metrics: []Metric{{Name: "cpu_percent", Value: 50.0}},
	}
	orch.Register(stub)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		orch.Run(ctx, 50*time.Millisecond)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	callsBefore := stub.calls.Load()

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after context cancellation")
	}

	// No more collections after cancel
	time.Sleep(200 * time.Millisecond)
	callsAfter := stub.calls.Load()
	if callsAfter > callsBefore+1 { // allow 1 in-flight
		t.Fatalf("expected no collections after cancel, got %d more", callsAfter-callsBefore)
	}
}
