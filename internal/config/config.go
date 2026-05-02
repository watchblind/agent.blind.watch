package config

import (
	"fmt"
	"os"
	"runtime"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	AgentID string `toml:"agent_id"`
	OrgID   string `toml:"org_id"`
	Token   string `toml:"token"`
	APIURL  string `toml:"api_url"`

	Collection CollectionConfig `toml:"collection"`
	Alerts     AlertsConfig     `toml:"alerts"`
}

type CollectionConfig struct {
	MetricsIntervalSeconds int `toml:"metrics_interval_seconds"`
}

type AlertRule struct {
	ID              string   `toml:"id" json:"id"`
	Name            string   `toml:"name" json:"name"`
	Type            string   `toml:"type" json:"type"`
	Metric          string   `toml:"metric" json:"metric"`
	Operator        string   `toml:"operator" json:"operator"`
	Threshold       float64  `toml:"threshold" json:"threshold"`
	DurationSeconds int      `toml:"duration_seconds" json:"duration_seconds"`
	Channels        []string `toml:"channels" json:"channels"`
}

type AlertsConfig struct {
	Rules []AlertRule `toml:"rules"`
}

const maxAlertRules = 100

var validOperators = map[string]bool{
	">": true, ">=": true, "<": true, "<=": true, "==": true, "!=": true,
}

// ValidateRules checks that pushed alert rules are well-formed.
func ValidateRules(rules []AlertRule) error {
	if len(rules) > maxAlertRules {
		return fmt.Errorf("too many alert rules: %d (max %d)", len(rules), maxAlertRules)
	}
	for i, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("rule %d: missing id", i)
		}
		if r.Type != "metric" {
			return fmt.Errorf("rule %d (%s): unsupported type %q", i, r.ID, r.Type)
		}
		if !validOperators[r.Operator] {
			return fmt.Errorf("rule %d (%s): invalid operator %q", i, r.ID, r.Operator)
		}
		if r.DurationSeconds <= 0 {
			return fmt.Errorf("rule %d (%s): duration_seconds must be > 0", i, r.ID)
		}
		if r.Metric == "" {
			return fmt.Errorf("rule %d (%s): missing metric name", i, r.ID)
		}
	}
	return nil
}

func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\blind-watch\config.toml`
	}
	return "/etc/blind-watch/config.toml"
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Collection.MetricsIntervalSeconds <= 0 {
		cfg.Collection.MetricsIntervalSeconds = 1
	}

	return &cfg, nil
}
