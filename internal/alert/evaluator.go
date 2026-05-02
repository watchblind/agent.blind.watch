package alert

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/config"
)

type AlertEvent struct {
	RuleID          string
	RuleName        string
	Type            string // "firing" or "recovered"
	Metric          string
	Operator        string
	Threshold       float64
	Value           float64
	DurationSeconds int
	Message         string
	Time            time.Time
}

type Evaluator struct {
	mu     sync.RWMutex
	rules  []config.AlertRule
	states *StateTracker
	events chan AlertEvent
}

func NewEvaluator(rules []config.AlertRule) *Evaluator {
	return &Evaluator{
		rules:  rules,
		states: NewStateTracker(),
		events: make(chan AlertEvent, 64),
	}
}

func (e *Evaluator) Events() <-chan AlertEvent {
	return e.events
}

func (e *Evaluator) States() *StateTracker {
	return e.states
}

// UpdateRules replaces the alert rules at runtime (called when server pushes config).
func (e *Evaluator) UpdateRules(rules []config.AlertRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

func (e *Evaluator) Evaluate(snap collector.Snapshot) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	for _, rule := range rules {
		if rule.Type != "metric" {
			continue
		}
		e.evaluateMetricRule(rule, snap)
	}
}

func (e *Evaluator) evaluateMetricRule(rule config.AlertRule, snap collector.Snapshot) {
	var value float64
	found := false
	for _, m := range snap.Metrics {
		if m.Name == rule.Metric && len(m.Labels) == 0 {
			value = m.Value
			found = true
			break
		}
	}
	if !found {
		return
	}

	breached := checkThreshold(value, rule.Operator, rule.Threshold)
	now := time.Now()

	state := e.states.Get(rule.ID)
	if state == nil {
		state = &AlertState{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Status:   StatusOK,
		}
	}

	state.CurrentValue = value
	state.Threshold = rule.Threshold

	// Default the recovery window to the firing window so a single rule
	// edit still gives sensible hysteresis. Tests with DurationSeconds=0
	// pass through here as recovery_seconds=0 → instant recovery, matching
	// the old behaviour for that path.
	recoverySeconds := rule.RecoverySeconds
	if recoverySeconds <= 0 {
		recoverySeconds = rule.DurationSeconds
	}

	// Five-state machine. Once Firing, brief dips below threshold start a
	// recovery debounce instead of immediately ending the incident; only a
	// sustained recovery (recoverySeconds without a single breach) emits
	// "recovered" and lets the next breach fire a new incident. This is what
	// stops flapping rules from spamming notifications every
	// duration_seconds.
	switch {
	case breached && state.Status == StatusOK:
		state.Status = StatusPending
		state.FirstTriggered = now

	case breached && state.Status == StatusPending:
		if now.Sub(state.FirstTriggered) >= time.Duration(rule.DurationSeconds)*time.Second {
			state.Status = StatusFiring
			state.FiredAt = now
			e.emit(AlertEvent{
				RuleID:          rule.ID,
				RuleName:        rule.Name,
				Type:            "firing",
				Metric:          rule.Metric,
				Operator:        rule.Operator,
				Threshold:       rule.Threshold,
				Value:           value,
				DurationSeconds: rule.DurationSeconds,
				Message:         fmt.Sprintf("%s: %.1f %s %.1f for %ds", rule.Name, value, rule.Operator, rule.Threshold, rule.DurationSeconds),
				Time:            now,
			})
		}

	case breached && state.Status == StatusFiring:
		// Steady-state firing — no event, no state change.

	case breached && state.Status == StatusRecoveryPending:
		// A breach during recovery debounce means the incident never
		// actually recovered. Cancel debounce silently and stay Firing.
		state.Status = StatusFiring
		state.RecoveryStarted = time.Time{}

	case !breached && state.Status == StatusPending:
		// Hadn't fired yet — abort silently.
		state.Status = StatusOK
		state.FirstTriggered = time.Time{}

	case !breached && state.Status == StatusFiring:
		if recoverySeconds <= 0 {
			// No debounce configured — recover immediately. Preserves the
			// old single-snapshot-recovery behaviour for rules with
			// duration_seconds=0 (and the existing tests that rely on it).
			state.Status = StatusOK
			state.RecoveredAt = now
			state.FirstTriggered = time.Time{}
			state.RecoveryStarted = time.Time{}
			e.emit(AlertEvent{
				RuleID:          rule.ID,
				RuleName:        rule.Name,
				Type:            "recovered",
				Metric:          rule.Metric,
				Operator:        rule.Operator,
				Threshold:       rule.Threshold,
				Value:           value,
				DurationSeconds: rule.DurationSeconds,
				Message:         fmt.Sprintf("%s: recovered (%.1f)", rule.Name, value),
				Time:            now,
			})
		} else {
			// Start recovery debounce — do NOT emit yet. We only emit
			// "recovered" once the metric has stayed below threshold for
			// the full recovery_seconds window.
			state.Status = StatusRecoveryPending
			state.RecoveryStarted = now
		}

	case !breached && state.Status == StatusRecoveryPending:
		if now.Sub(state.RecoveryStarted) >= time.Duration(recoverySeconds)*time.Second {
			state.Status = StatusOK
			state.RecoveredAt = now
			state.FirstTriggered = time.Time{}
			state.RecoveryStarted = time.Time{}
			e.emit(AlertEvent{
				RuleID:          rule.ID,
				RuleName:        rule.Name,
				Type:            "recovered",
				Metric:          rule.Metric,
				Operator:        rule.Operator,
				Threshold:       rule.Threshold,
				Value:           value,
				DurationSeconds: rule.DurationSeconds,
				Message:         fmt.Sprintf("%s: recovered (%.1f)", rule.Name, value),
				Time:            now,
			})
		}
	}

	e.states.Set(rule.ID, state)
}

func (e *Evaluator) emit(event AlertEvent) {
	select {
	case e.events <- event:
	default:
		log.Printf("[alert] event dropped (channel full): rule=%s type=%s", event.RuleID, event.Type)
	}
}

func checkThreshold(value float64, operator string, threshold float64) bool {
	switch operator {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case "==":
		return value == threshold
	case "!=":
		return value != threshold
	default:
		return false
	}
}
