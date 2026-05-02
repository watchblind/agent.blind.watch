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

// ---------------------------------------------------------------------------
// UpdateRules — reconciliation behaviour while incidents are active.
// Each test below covers one branch of the diff in UpdateRules so a future
// change to a single branch can't silently break the others.
// ---------------------------------------------------------------------------

// fireAndDrain helps the tests by bringing a single rule to StatusFiring and
// consuming the firing event from the channel.
func fireAndDrain(t *testing.T, eval *Evaluator, ruleID, metricName string, value float64) {
	t.Helper()
	eval.Evaluate(makeSnap(metric(metricName, value)))
	eval.Evaluate(makeSnap(metric(metricName, value)))
	if ev := <-eval.Events(); ev.Type != "firing" || ev.RuleID != ruleID {
		t.Fatalf("expected firing for %s, got %s %s", ruleID, ev.Type, ev.RuleID)
	}
}

func TestUpdateRules_RemovedRuleEmitsRecoveryWhenFiring(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "cpu", "cpu_percent", 90)

	// Disable / delete the rule by removing it from the new rule set.
	eval.UpdateRules(nil)

	// Should emit a synthetic recovery so the dashboard's history closes.
	select {
	case ev := <-eval.Events():
		if ev.Type != "recovered" || ev.RuleID != "cpu" {
			t.Fatalf("expected recovered event for cpu, got %s %s", ev.Type, ev.RuleID)
		}
	default:
		t.Fatal("expected recovered event after rule removal")
	}

	// State row must be dropped so a re-added rule starts fresh.
	if s := eval.States().Get("cpu"); s != nil {
		t.Fatalf("expected state for cpu to be deleted, got %+v", s)
	}
}

func TestUpdateRules_RemovedRuleSilentWhenOK(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}
	eval := NewEvaluator(rules)

	// Trigger pending then recover to OK so state exists but is not firing.
	eval.Evaluate(makeSnap(metric("cpu_percent", 90)))
	eval.Evaluate(makeSnap(metric("cpu_percent", 90)))
	<-eval.Events() // drain firing
	eval.Evaluate(makeSnap(metric("cpu_percent", 50)))
	<-eval.Events() // drain recovered (instant: recoverySeconds=0)

	eval.UpdateRules(nil)

	select {
	case ev := <-eval.Events():
		t.Fatalf("did not expect recovered event for OK rule, got %+v", ev)
	default:
	}
}

func TestUpdateRules_MetricChangeEmitsRecoveryAndResets(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "rule1", Name: "Rule 1", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "rule1", "cpu_percent", 90)

	// Change the metric — completely different question.
	eval.UpdateRules([]config.AlertRule{{
		ID: "rule1", Name: "Rule 1", Type: "metric",
		Metric: "memory_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}})

	if ev := <-eval.Events(); ev.Type != "recovered" {
		t.Fatalf("expected recovered for metric change, got %s", ev.Type)
	}
	if s := eval.States().Get("rule1"); s != nil {
		t.Fatalf("expected state to be cleared after metric change, got %+v", s)
	}
}

func TestUpdateRules_OperatorChangeEmitsRecoveryAndResets(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "rule1", Name: "Rule 1", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "rule1", "cpu_percent", 90)

	// Flip operator from > to <.
	eval.UpdateRules([]config.AlertRule{{
		ID: "rule1", Name: "Rule 1", Type: "metric",
		Metric: "cpu_percent", Operator: "<", Threshold: 80.0, DurationSeconds: 0,
	}})

	if ev := <-eval.Events(); ev.Type != "recovered" {
		t.Fatalf("expected recovered for operator change, got %s", ev.Type)
	}
	if s := eval.States().Get("rule1"); s != nil {
		t.Fatalf("expected state cleared after operator change, got %+v", s)
	}
}

func TestUpdateRules_ThresholdRaisedRecoversWithoutDebounce(t *testing.T) {
	// User on vacation: incident fires, they raise the bar to silence it.
	rules := []config.AlertRule{{
		ID: "disk", Name: "Disk Full", Type: "metric",
		Metric: "memory_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		RecoverySeconds: 600, // long debounce — must be bypassed
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "disk", "memory_percent", 82)

	// Raise threshold above the current value.
	eval.UpdateRules([]config.AlertRule{{
		ID: "disk", Name: "Disk Full", Type: "metric",
		Metric: "memory_percent", Operator: ">", Threshold: 85.0, DurationSeconds: 0,
		RecoverySeconds: 600,
	}})

	select {
	case ev := <-eval.Events():
		if ev.Type != "recovered" {
			t.Fatalf("expected immediate recovered, got %s", ev.Type)
		}
		if ev.Threshold != 85.0 {
			t.Errorf("expected new threshold 85.0 in event, got %f", ev.Threshold)
		}
	default:
		t.Fatal("expected recovered event when threshold raised above current value")
	}

	if s := eval.States().Get("disk"); s == nil || s.Status != StatusOK {
		t.Fatalf("expected state to be StatusOK, got %+v", s)
	}
}

func TestUpdateRules_ThresholdLoweredButStillBreachingNoEvent(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "cpu", "cpu_percent", 90)

	// Tighten to 70 — still breaching, incident continues.
	eval.UpdateRules([]config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 70.0, DurationSeconds: 0,
	}})

	select {
	case ev := <-eval.Events():
		t.Fatalf("did not expect any event when still breaching, got %+v", ev)
	default:
	}
	if s := eval.States().Get("cpu"); s == nil || s.Status != StatusFiring {
		t.Fatalf("expected to remain FIRING, got %+v", s)
	}
	if s := eval.States().Get("cpu"); s.Threshold != 70.0 {
		t.Errorf("expected state.Threshold to track new threshold, got %f", s.Threshold)
	}
}

func TestUpdateRules_RaisedThresholdInRecoveryPendingClosesImmediately(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		RecoverySeconds: 60,
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "cpu", "cpu_percent", 90)

	// Drop value below threshold → debounce starts (no event yet).
	eval.Evaluate(makeSnap(metric("cpu_percent", 70)))
	if s := eval.States().Get("cpu"); s.Status != StatusRecoveryPending {
		t.Fatalf("expected RECOVERY_PENDING, got %v", s.Status)
	}

	// User raises threshold to 95 — clearly recovered, skip the wait.
	eval.UpdateRules([]config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 95.0, DurationSeconds: 0,
		RecoverySeconds: 60,
	}})

	if ev := <-eval.Events(); ev.Type != "recovered" {
		t.Fatalf("expected recovered event, got %s", ev.Type)
	}
	if s := eval.States().Get("cpu"); s.Status != StatusOK {
		t.Fatalf("expected OK after threshold-raised recovery, got %v", s.Status)
	}
}

func TestUpdateRules_NameAndChannelChangesAreSilent(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "cpu", Name: "Old Name", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		Channels: []string{"in-app"},
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "cpu", "cpu_percent", 90)

	eval.UpdateRules([]config.AlertRule{{
		ID: "cpu", Name: "New Name", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		Channels: []string{"in-app", "email"},
	}})

	select {
	case ev := <-eval.Events():
		t.Fatalf("name/channel changes must not emit events, got %+v", ev)
	default:
	}
	if s := eval.States().Get("cpu"); s == nil || s.Status != StatusFiring {
		t.Fatalf("expected to remain FIRING, got %+v", s)
	}
}

func TestUpdateRules_DurationChangesAreSilent(t *testing.T) {
	rules := []config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
		RecoverySeconds: 60,
	}}
	eval := NewEvaluator(rules)
	fireAndDrain(t, eval, "cpu", "cpu_percent", 90)

	eval.UpdateRules([]config.AlertRule{{
		ID: "cpu", Name: "CPU", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 30,
		RecoverySeconds: 120,
	}})

	select {
	case ev := <-eval.Events():
		t.Fatalf("duration changes must not emit events, got %+v", ev)
	default:
	}
}

func TestUpdateRules_NewRuleStartsFresh(t *testing.T) {
	eval := NewEvaluator(nil)
	eval.UpdateRules([]config.AlertRule{{
		ID: "fresh", Name: "Fresh", Type: "metric",
		Metric: "cpu_percent", Operator: ">", Threshold: 80.0, DurationSeconds: 0,
	}})
	// No state yet, no event yet.
	select {
	case ev := <-eval.Events():
		t.Fatalf("brand-new rule must not emit anything, got %+v", ev)
	default:
	}
	if s := eval.States().Get("fresh"); s != nil {
		t.Fatalf("expected no state for brand-new rule, got %+v", s)
	}

	// Now feed values and verify normal flow works.
	fireAndDrain(t, eval, "fresh", "cpu_percent", 90)
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
