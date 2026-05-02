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

// UpdateRules replaces the alert rule set at runtime (called when the server
// pushes a fresh config). It also reconciles the per-rule state tracker
// against the new rules so an in-flight incident doesn't get into an
// inconsistent state when the operator edits the rule mid-incident:
//
//   - Rule removed (disabled / deleted / moved off this agent) — if the
//     previous state was Firing or RecoveryPending we emit a final
//     "recovered" event so the dashboard's history closes the incident,
//     then drop the state row.
//   - Breach condition (metric or operator) changed — the old state is no
//     longer comparable to the new question. Emit "recovered" for the old
//     incident if it was Firing/RecoveryPending, then drop state so the
//     new condition starts fresh from OK.
//   - Threshold-only change — re-check the last observed value against the
//     NEW threshold. If it still breaches, the incident continues
//     uninterrupted (no event). If it no longer breaches we emit
//     "recovered" immediately and skip the recovery debounce ("the user
//     raised the bar to snooze the incident").
//   - Anything else (name, channels, duration, recovery_seconds) — keep
//     state as-is; the new timings apply on the next transition.
func (e *Evaluator) UpdateRules(rules []config.AlertRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	oldRules := indexRulesByID(e.rules)
	newRules := indexRulesByID(rules)
	e.rules = rules

	now := time.Now()

	// 1. Rules that disappeared from the new set — close their incidents.
	for id, oldRule := range oldRules {
		if _, exists := newRules[id]; exists {
			continue
		}
		e.closeIncidentLocked(oldRule, now, "rule removed")
		e.states.Delete(id)
	}

	// 2. Rules that survived — reconcile changes to breach condition or
	//    threshold against the existing state.
	for id, newRule := range newRules {
		oldRule, existed := oldRules[id]
		if !existed {
			continue // new rule, no prior state to reconcile
		}
		conditionChanged := oldRule.Metric != newRule.Metric ||
			oldRule.Operator != newRule.Operator
		if conditionChanged {
			e.closeIncidentLocked(oldRule, now, "rule condition changed")
			e.states.Delete(id)
			continue
		}
		if oldRule.Threshold != newRule.Threshold {
			e.applyThresholdChangeLocked(oldRule, newRule, now)
			continue
		}
		// Name / channels / durations only — nothing to do; the new
		// duration_seconds and recovery_seconds will be picked up by the
		// next evaluateMetricRule call.
	}
}

// closeIncidentLocked emits a final "recovered" event for a rule that's
// being torn down, but only if there was actually an open incident
// (Firing / RecoveryPending) under the OLD definition. Caller must hold
// e.mu.
func (e *Evaluator) closeIncidentLocked(oldRule config.AlertRule, now time.Time, reason string) {
	state := e.states.Get(oldRule.ID)
	if state == nil {
		return
	}
	if state.Status != StatusFiring && state.Status != StatusRecoveryPending {
		return
	}
	e.emit(AlertEvent{
		RuleID:          oldRule.ID,
		RuleName:        oldRule.Name,
		Type:            "recovered",
		Metric:          oldRule.Metric,
		Operator:        oldRule.Operator,
		Threshold:       oldRule.Threshold,
		Value:           state.CurrentValue,
		DurationSeconds: oldRule.DurationSeconds,
		Message:         fmt.Sprintf("%s: %s", oldRule.Name, reason),
		Time:            now,
	})
}

// applyThresholdChangeLocked re-evaluates the existing state against the
// new threshold. If the last observed value still breaches we leave state
// alone (the incident continues, just with a stricter/looser bar). If it
// no longer breaches we close the incident immediately, bypassing the
// recovery debounce — the operator explicitly raised the threshold,
// there's nothing to debounce against. Caller must hold e.mu.
func (e *Evaluator) applyThresholdChangeLocked(oldRule, newRule config.AlertRule, now time.Time) {
	state := e.states.Get(newRule.ID)
	if state == nil {
		return
	}
	state.Threshold = newRule.Threshold

	if state.Status != StatusFiring && state.Status != StatusRecoveryPending {
		// Pending or OK — next evaluateMetricRule will reconcile naturally.
		e.states.Set(newRule.ID, state)
		return
	}

	stillBreached := checkThreshold(state.CurrentValue, newRule.Operator, newRule.Threshold)
	if stillBreached {
		// Incident continues under the new threshold. No event.
		e.states.Set(newRule.ID, state)
		return
	}

	state.Status = StatusOK
	state.RecoveredAt = now
	state.FirstTriggered = time.Time{}
	state.RecoveryStarted = time.Time{}
	e.states.Set(newRule.ID, state)

	e.emit(AlertEvent{
		RuleID:          newRule.ID,
		RuleName:        newRule.Name,
		Type:            "recovered",
		Metric:          newRule.Metric,
		Operator:        newRule.Operator,
		Threshold:       newRule.Threshold,
		Value:           state.CurrentValue,
		DurationSeconds: newRule.DurationSeconds,
		Message: fmt.Sprintf(
			"%s: threshold raised to %.1f, recovered",
			newRule.Name,
			newRule.Threshold,
		),
		Time: now,
	})
}

func indexRulesByID(rules []config.AlertRule) map[string]config.AlertRule {
	out := make(map[string]config.AlertRule, len(rules))
	for _, r := range rules {
		out[r.ID] = r
	}
	return out
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
