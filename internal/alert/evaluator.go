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
	RuleID   string
	RuleName string
	Type     string // "firing" or "recovered"
	Value    float64
	Message  string
	Time     time.Time
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

	switch {
	case breached && state.Status == StatusOK:
		// Start pending
		state.Status = StatusPending
		state.FirstTriggered = now

	case breached && state.Status == StatusPending:
		// Check if duration met
		if now.Sub(state.FirstTriggered) >= time.Duration(rule.DurationSeconds)*time.Second {
			state.Status = StatusFiring
			state.FiredAt = now
			e.emit(AlertEvent{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Type:     "firing",
				Value:    value,
				Message:  fmt.Sprintf("%s: %.1f %s %.1f for %ds", rule.Name, value, rule.Operator, rule.Threshold, rule.DurationSeconds),
				Time:     now,
			})
		}

	case !breached && (state.Status == StatusFiring || state.Status == StatusPending):
		// Recovered
		prevStatus := state.Status
		state.Status = StatusOK
		state.RecoveredAt = now
		state.FirstTriggered = time.Time{}
		if prevStatus == StatusFiring {
			e.emit(AlertEvent{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Type:     "recovered",
				Value:    value,
				Message:  fmt.Sprintf("%s: recovered (%.1f)", rule.Name, value),
				Time:     now,
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
