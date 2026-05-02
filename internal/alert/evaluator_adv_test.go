package alert

import (
	"testing"
	"time"

	"github.com/watchblind/agent/internal/config"
)

func TestFiringRequiresSustainedDuration(t *testing.T) {
	// Rule requires 2 seconds sustained breach before firing.
	rules := []config.AlertRule{{
		ID:              "cpu_sustained",
		Name:            "Sustained CPU",
		Type:            "metric",
		Metric:          "cpu_percent",
		Operator:        ">",
		Threshold:       80.0,
		DurationSeconds: 2,
	}}

	eval := NewEvaluator(rules)

	// First eval: goes pending
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0)))
	state := eval.States().Get("cpu_sustained")
	if state == nil || state.Status != StatusPending {
		t.Fatalf("expected PENDING, got %v", state)
	}

	// Immediately again: still pending (< 2s elapsed)
	eval.Evaluate(makeSnap(metric("cpu_percent", 91.0)))
	state = eval.States().Get("cpu_sustained")
	if state.Status != StatusPending {
		t.Fatalf("expected still PENDING, got %v", state.Status)
	}

	// No event should have been emitted yet
	select {
	case ev := <-eval.Events():
		t.Fatalf("unexpected event before duration met: %+v", ev)
	default:
	}

	// Wait past the duration threshold
	time.Sleep(2100 * time.Millisecond)

	// Evaluate again — now duration is met, should fire
	eval.Evaluate(makeSnap(metric("cpu_percent", 92.0)))
	state = eval.States().Get("cpu_sustained")
	if state.Status != StatusFiring {
		t.Fatalf("expected FIRING after sustained duration, got %v", state.Status)
	}

	select {
	case ev := <-eval.Events():
		if ev.Type != "firing" {
			t.Fatalf("expected firing event, got %s", ev.Type)
		}
	default:
		t.Fatal("expected firing event after sustained duration")
	}
}

func TestFiringDoesNotReEmit(t *testing.T) {
	// Once firing, continued breach should NOT emit more events.
	rules := []config.AlertRule{{
		ID: "cpu_no_spam", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}

	eval := NewEvaluator(rules)

	// Pending → Firing
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 91.0)))

	// Drain firing event
	select {
	case <-eval.Events():
	default:
		t.Fatal("expected initial firing event")
	}

	// Continue breaching — should stay Firing but emit nothing
	for i := 0; i < 5; i++ {
		eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))
	}

	select {
	case ev := <-eval.Events():
		t.Fatalf("should not re-emit while already firing: %+v", ev)
	default:
	}

	state := eval.States().Get("cpu_no_spam")
	if state.Status != StatusFiring {
		t.Fatalf("expected still FIRING, got %v", state.Status)
	}
}

func TestReTriggerAfterRecovery(t *testing.T) {
	// After recovery, a new breach should go through pending → firing again.
	rules := []config.AlertRule{{
		ID: "cpu_retrigger", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}

	eval := NewEvaluator(rules)

	// Fire
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0)))
	<-eval.Events() // drain firing

	// Recover
	eval.Evaluate(makeSnap(metric("cpu_percent", 50.0)))
	<-eval.Events() // drain recovered

	state := eval.States().Get("cpu_retrigger")
	if state.Status != StatusOK {
		t.Fatalf("expected OK after recovery, got %v", state.Status)
	}

	// New breach: should go pending again
	eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))
	state = eval.States().Get("cpu_retrigger")
	if state.Status != StatusPending {
		t.Fatalf("expected PENDING on re-trigger, got %v", state.Status)
	}

	// Fire again
	eval.Evaluate(makeSnap(metric("cpu_percent", 95.0)))
	state = eval.States().Get("cpu_retrigger")
	if state.Status != StatusFiring {
		t.Fatalf("expected FIRING on re-trigger, got %v", state.Status)
	}

	select {
	case ev := <-eval.Events():
		if ev.Type != "firing" {
			t.Fatalf("expected second firing event, got %s", ev.Type)
		}
	default:
		t.Fatal("expected re-trigger firing event")
	}
}

func TestMultipleRulesIndependent(t *testing.T) {
	// Two rules on different metrics should fire/recover independently.
	rules := []config.AlertRule{
		{
			ID: "cpu", Name: "CPU", Type: "metric",
			Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		},
		{
			ID: "mem", Name: "Memory", Type: "metric",
			Metric: "memory_percent", Operator: ">", Threshold: 70.0, DurationSeconds: 0,
		},
	}

	eval := NewEvaluator(rules)

	// Both breach
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0), metric("memory_percent", 80.0)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0), metric("memory_percent", 80.0)))

	// Both should fire
	events := drainEvents(eval, 2)
	if len(events) != 2 {
		t.Fatalf("expected 2 firing events, got %d", len(events))
	}

	// CPU recovers, memory stays
	eval.Evaluate(makeSnap(metric("cpu_percent", 50.0), metric("memory_percent", 85.0)))

	cpuState := eval.States().Get("cpu")
	memState := eval.States().Get("mem")
	if cpuState.Status != StatusOK {
		t.Fatalf("CPU should be OK, got %v", cpuState.Status)
	}
	if memState.Status != StatusFiring {
		t.Fatalf("Memory should still be FIRING, got %v", memState.Status)
	}

	// Drain CPU recovery event
	select {
	case ev := <-eval.Events():
		if ev.RuleID != "cpu" || ev.Type != "recovered" {
			t.Fatalf("expected cpu recovered, got %s %s", ev.RuleID, ev.Type)
		}
	default:
		t.Fatal("expected cpu recovery event")
	}
}

func TestMissingMetricDoesNotAffectState(t *testing.T) {
	// If a metric disappears from a snapshot, rule state should not change.
	rules := []config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}

	eval := NewEvaluator(rules)

	// Fire
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 90.0)))
	<-eval.Events()

	// Snapshot without cpu_percent — state should remain FIRING (metric just missing)
	eval.Evaluate(makeSnap(metric("memory_percent", 50.0)))

	state := eval.States().Get("cpu")
	if state.Status != StatusFiring {
		t.Fatalf("expected FIRING to persist when metric absent, got %v", state.Status)
	}
}

func TestAllOperators(t *testing.T) {
	operators := []struct {
		op        string
		value     float64
		threshold float64
		wantFire  bool
	}{
		{">", 91.0, 90.0, true},
		{">", 90.0, 90.0, false},
		{">=", 90.0, 90.0, true},
		{">=", 89.0, 90.0, false},
		{"<", 5.0, 10.0, true},
		{"<", 10.0, 10.0, false},
		{"<=", 10.0, 10.0, true},
		{"<=", 11.0, 10.0, false},
		{"==", 42.0, 42.0, true},
		{"==", 42.1, 42.0, false},
		{"!=", 42.0, 43.0, true},
		{"!=", 42.0, 42.0, false},
	}

	for _, tt := range operators {
		t.Run(tt.op, func(t *testing.T) {
			rules := []config.AlertRule{{
				ID: "op_test", Name: "Op Test", Type: "metric",
				Metric: "val", Operator: tt.op, Threshold: tt.threshold, DurationSeconds: 0,
			}}
			eval := NewEvaluator(rules)

			eval.Evaluate(makeSnap(metric("val", tt.value)))
			eval.Evaluate(makeSnap(metric("val", tt.value)))

			state := eval.States().Get("op_test")
			if tt.wantFire {
				if state == nil || state.Status != StatusFiring {
					t.Errorf("operator %s: value=%.1f threshold=%.1f expected FIRING", tt.op, tt.value, tt.threshold)
				}
			} else {
				if state != nil && state.Status == StatusFiring {
					t.Errorf("operator %s: value=%.1f threshold=%.1f should NOT fire", tt.op, tt.value, tt.threshold)
				}
			}
		})
	}
}

func TestEventChannelDropsWhenFull(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "flood", Name: "Flood", Type: "metric",
		Metric: "val", Operator: ">", Threshold: 0.0, DurationSeconds: 0,
	}}

	eval := NewEvaluator(rules)

	// Fill the event channel (capacity 64) without draining
	for i := 0; i < 100; i++ {
		eval.Evaluate(makeSnap(metric("val", 1.0)))
		// Reset to OK so it fires again
		eval.Evaluate(makeSnap(metric("val", -1.0)))
	}

	// Should not panic or block — events are silently dropped
	count := 0
	for {
		select {
		case <-eval.Events():
			count++
		default:
			goto done
		}
	}
done:
	// Channel capacity is 64, so we should have at most 64 events
	if count > 64 {
		t.Fatalf("expected at most 64 buffered events, got %d", count)
	}
}

// Regression test for the "email every duration_seconds" spam bug. With a
// configured recovery_seconds, a flapping metric must not re-emit firing
// events on every dip below threshold — the incident should remain open
// until the metric stays below threshold for a sustained recovery_seconds
// window.
func TestRecoveryDebounceSuppressesFlap(t *testing.T) {
	rules := []config.AlertRule{{
		ID:              "cpu_flap",
		Name:            "Flappy CPU",
		Type:            "metric",
		Metric:          "cpu_percent",
		Operator:        ">",
		Threshold:       1.0,
		DurationSeconds: 0, // fire on first breach
		RecoverySeconds: 60,
	}}

	eval := NewEvaluator(rules)

	// Initial fire.
	eval.Evaluate(makeSnap(metric("cpu_percent", 5.0)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 5.0))) // second sample to fire
	if ev := <-eval.Events(); ev.Type != "firing" {
		t.Fatalf("expected initial firing event, got %s", ev.Type)
	}

	// Brief dip below threshold — should enter RecoveryPending, NOT recover.
	eval.Evaluate(makeSnap(metric("cpu_percent", 0.5)))
	state := eval.States().Get("cpu_flap")
	if state.Status != StatusRecoveryPending {
		t.Fatalf("expected RECOVERY_PENDING after first dip, got %v", state.Status)
	}
	select {
	case ev := <-eval.Events():
		t.Fatalf("did not expect any event on first dip, got %s", ev.Type)
	default:
	}

	// Breach returns — should snap back to FIRING with no event.
	eval.Evaluate(makeSnap(metric("cpu_percent", 5.0)))
	state = eval.States().Get("cpu_flap")
	if state.Status != StatusFiring {
		t.Fatalf("expected FIRING after breach during debounce, got %v", state.Status)
	}
	select {
	case ev := <-eval.Events():
		t.Fatalf("did not expect any event when breach returns during debounce, got %s", ev.Type)
	default:
	}

	// Another dip + immediate breach — still no flap notification.
	eval.Evaluate(makeSnap(metric("cpu_percent", 0.5)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 5.0)))
	select {
	case ev := <-eval.Events():
		t.Fatalf("flap loop must not emit events, got %s", ev.Type)
	default:
	}
}

func TestNoRulesNoEvents(t *testing.T) {
	eval := NewEvaluator(nil)
	eval.Evaluate(makeSnap(metric("cpu_percent", 99.0)))

	select {
	case ev := <-eval.Events():
		t.Fatalf("no rules, expected no events: %+v", ev)
	default:
	}
}

func drainEvents(eval *Evaluator, max int) []AlertEvent {
	var events []AlertEvent
	for i := 0; i < max; i++ {
		select {
		case ev := <-eval.Events():
			events = append(events, ev)
		default:
			return events
		}
	}
	return events
}
