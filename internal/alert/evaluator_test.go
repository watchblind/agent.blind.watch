package alert

import (
	"testing"
	"time"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/config"
)

func makeSnap(metrics ...collector.Metric) collector.Snapshot {
	return collector.Snapshot{
		Metrics:   metrics,
		Timestamp: time.Now(),
	}
}

func metric(name string, value float64) collector.Metric {
	return collector.Metric{
		Name:      name,
		Value:     value,
		Timestamp: time.Now(),
	}
}

func TestCheckThreshold(t *testing.T) {
	tests := []struct {
		value     float64
		operator  string
		threshold float64
		want      bool
	}{
		{91.0, ">", 90.0, true},
		{90.0, ">", 90.0, false},
		{90.0, ">=", 90.0, true},
		{89.0, ">=", 90.0, false},
		{5.0, "<", 10.0, true},
		{10.0, "<", 10.0, false},
		{10.0, "<=", 10.0, true},
		{11.0, "<=", 10.0, false},
		{42.0, "==", 42.0, true},
		{42.0, "==", 43.0, false},
		{42.0, "!=", 43.0, true},
		{42.0, "!=", 42.0, false},
		{50.0, "invalid", 50.0, false},
	}

	for _, tt := range tests {
		got := checkThreshold(tt.value, tt.operator, tt.threshold)
		if got != tt.want {
			t.Errorf("checkThreshold(%.1f, %q, %.1f) = %v, want %v",
				tt.value, tt.operator, tt.threshold, got, tt.want)
		}
	}
}

func TestEvaluatorFiringAfterDuration(t *testing.T) {
	rules := []config.AlertRule{{
		ID:              "test_cpu",
		Name:            "High CPU",
		Type:            "metric",
		Metric:          "cpu_percent",
		Operator:        ">",
		Threshold:       90.0,
		DurationSeconds: 0, // fire immediately after pending
	}}

	eval := NewEvaluator(rules)

	// First evaluation: goes to pending
	eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))

	state := eval.States().Get("test_cpu")
	if state == nil {
		t.Fatal("expected state to exist")
	}
	if state.Status != StatusPending {
		t.Errorf("expected PENDING, got %v", state.Status)
	}

	// Second evaluation: duration_seconds=0, so it fires
	eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))

	state = eval.States().Get("test_cpu")
	if state.Status != StatusFiring {
		t.Errorf("expected FIRING, got %v", state.Status)
	}

	// Check event was emitted
	select {
	case event := <-eval.Events():
		if event.Type != "firing" {
			t.Errorf("expected firing event, got %s", event.Type)
		}
		if event.RuleID != "test_cpu" {
			t.Errorf("expected rule_id test_cpu, got %s", event.RuleID)
		}
	default:
		t.Error("expected firing event to be emitted")
	}
}

func TestEvaluatorRecovery(t *testing.T) {
	rules := []config.AlertRule{{
		ID:              "test_cpu",
		Name:            "High CPU",
		Type:            "metric",
		Metric:          "cpu_percent",
		Operator:        ">",
		Threshold:       90.0,
		DurationSeconds: 0,
	}}

	eval := NewEvaluator(rules)

	// Trigger: pending → firing
	eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))

	// Drain firing event
	<-eval.Events()

	// Recover
	eval.Evaluate(makeSnap(metric("cpu_percent", 50.0)))

	state := eval.States().Get("test_cpu")
	if state.Status != StatusOK {
		t.Errorf("expected OK after recovery, got %v", state.Status)
	}

	select {
	case event := <-eval.Events():
		if event.Type != "recovered" {
			t.Errorf("expected recovered event, got %s", event.Type)
		}
	default:
		t.Error("expected recovered event")
	}
}

func TestEvaluatorPendingRecoveryNoEvent(t *testing.T) {
	// If alert is pending (not yet firing) and recovers, no event should be emitted
	rules := []config.AlertRule{{
		ID:              "test_mem",
		Name:            "High Memory",
		Type:            "metric",
		Metric:          "memory_percent",
		Operator:        ">",
		Threshold:       80.0,
		DurationSeconds: 60, // Long duration — won't fire quickly
	}}

	eval := NewEvaluator(rules)

	// Goes to pending
	eval.Evaluate(makeSnap(metric("memory_percent", 85.0)))

	state := eval.States().Get("test_mem")
	if state.Status != StatusPending {
		t.Fatalf("expected PENDING, got %v", state.Status)
	}

	// Recovers before firing
	eval.Evaluate(makeSnap(metric("memory_percent", 70.0)))

	state = eval.States().Get("test_mem")
	if state.Status != StatusOK {
		t.Errorf("expected OK, got %v", state.Status)
	}

	// No event should be emitted (wasn't firing)
	select {
	case event := <-eval.Events():
		t.Errorf("unexpected event: %+v", event)
	default:
		// Good — no event
	}
}

func TestEvaluatorIgnoresNonMetricRules(t *testing.T) {
	rules := []config.AlertRule{{
		ID:   "log_rule",
		Name: "Error Logs",
		Type: "log", // Not "metric"
	}}

	eval := NewEvaluator(rules)
	eval.Evaluate(makeSnap(metric("cpu_percent", 99.0)))

	if eval.States().Get("log_rule") != nil {
		t.Error("non-metric rule should not be evaluated")
	}
}

func TestEvaluatorIgnoresLabeledMetrics(t *testing.T) {
	rules := []config.AlertRule{{
		ID:              "test_cpu",
		Name:            "High CPU",
		Type:            "metric",
		Metric:          "cpu_percent",
		Operator:        ">",
		Threshold:       90.0,
		DurationSeconds: 0,
	}}

	eval := NewEvaluator(rules)

	// Labeled metric (per-core) should be ignored — only unlabeled (total) matches
	labeled := collector.Metric{
		Name:      "cpu_percent",
		Value:     99.0,
		Labels:    map[string]string{"core": "0"},
		Timestamp: time.Now(),
	}
	eval.Evaluate(makeSnap(labeled))

	if eval.States().Get("test_cpu") != nil {
		t.Error("labeled metric should not trigger alert rule")
	}
}

func TestEvaluatorMultipleRules(t *testing.T) {
	rules := []config.AlertRule{
		{
			ID: "cpu", Name: "CPU", Type: "metric",
			Metric: "cpu_percent", Operator: ">", Threshold: 90.0, DurationSeconds: 0,
		},
		{
			ID: "mem", Name: "Memory", Type: "metric",
			Metric: "memory_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		},
	}

	eval := NewEvaluator(rules)

	// Only CPU is high
	eval.Evaluate(makeSnap(
		metric("cpu_percent", 95.0),
		metric("memory_percent", 50.0),
	))
	eval.Evaluate(makeSnap(
		metric("cpu_percent", 95.0),
		metric("memory_percent", 50.0),
	))

	cpuState := eval.States().Get("cpu")
	memState := eval.States().Get("mem")

	if cpuState == nil || cpuState.Status != StatusFiring {
		t.Error("CPU should be FIRING")
	}
	if memState != nil && memState.Status != StatusOK {
		t.Errorf("Memory should be OK, got %v", memState.Status)
	}
}
