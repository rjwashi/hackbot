// Package config loads hackbot configuration from an optional JSON file with
// environment-variable overrides.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the runtime configuration for the bot.
type Config struct {
	// Name is the bot's display name. Overridable via HACKBOT_NAME.
	Name string `json:"name"`
	// IntervalSeconds controls how often the bot loop ticks.
	// Overridable via HACKBOT_INTERVAL_SECONDS.
	IntervalSeconds int `json:"interval_seconds"`
	// PythonCmd is the interpreter used for Python helpers.
	// Overridable via HACKBOT_PYTHON_CMD.
	PythonCmd string `json:"python_cmd"`
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Name:            "hackbot",
		IntervalSeconds: 60,
		PythonCmd:       "python",
	}
}

// Load reads config from the JSON file at path (if non-empty) and applies
// environment-variable overrides. Missing files are not an error; only
// unreadable or malformed ones are.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	if v := os.Getenv("HACKBOT_NAME"); v != "" {
		cfg.Name = v
	}
	if v := os.Getenv("HACKBOT_INTERVAL_SECONDS"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.IntervalSeconds); err != nil {
			return cfg, fmt.Errorf("invalid HACKBOT_INTERVAL_SECONDS %q", v)
		}
	}
	if v := os.Getenv("HACKBOT_PYTHON_CMD"); v != "" {
		cfg.PythonCmd = v
	}

	return cfg, nil
}

// String returns a short human-readable summary.
func (c Config) String() string {
	return fmt.Sprintf("%s (tick every %ds)", c.Name, c.IntervalSeconds)
}
