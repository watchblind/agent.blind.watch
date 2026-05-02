package alert

import (
	"sync"
	"time"
)

type AlertStatus int

const (
	StatusOK AlertStatus = iota
	StatusPending          // breaching, waiting for sustained duration before Firing
	StatusFiring           // actively firing (one ongoing incident)
	StatusRecoveryPending  // not breaching, waiting out the recovery window
)

func (s AlertStatus) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusPending:
		return "PENDING"
	case StatusFiring:
		return "FIRING"
	case StatusRecoveryPending:
		return "RECOVERY_PENDING"
	}
	return "UNKNOWN"
}

type AlertState struct {
	RuleID         string
	RuleName       string
	Status         AlertStatus
	CurrentValue   float64
	Threshold      float64
	FirstTriggered time.Time
	FiredAt        time.Time
	// When recovery debouncing started — i.e. the moment value last dipped
	// back below threshold while we were Firing. Only relevant in
	// StatusRecoveryPending; cleared on transition to OK or back to Firing.
	RecoveryStarted time.Time
	RecoveredAt     time.Time
}

type StateTracker struct {
	mu     sync.RWMutex
	states map[string]*AlertState
}

func NewStateTracker() *StateTracker {
	return &StateTracker{
		states: make(map[string]*AlertState),
	}
}

func (t *StateTracker) Get(ruleID string) *AlertState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.states[ruleID]
}

func (t *StateTracker) Set(ruleID string, state *AlertState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.states[ruleID] = state
}

// Delete drops the tracked state for a rule. Used by UpdateRules when a rule
// is removed or its breach condition changes — the existing state can no
// longer be reasoned about under the new question.
func (t *StateTracker) Delete(ruleID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, ruleID)
}

func (t *StateTracker) All() []*AlertState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]*AlertState, 0, len(t.states))
	for _, s := range t.states {
		result = append(result, s)
	}
	return result
}
