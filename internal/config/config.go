// Package config loads hackbot configuration from an optional JSON file with
// environment-variable overrides.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

	// ---- nmap scanning (safety-gated) ----

	// EnableScan must be true before hackbot will run nmap at all.
	// Overridable via HACKBOT_ENABLE_SCAN (1/true/yes/on).
	EnableScan bool `json:"enable_scan"`
	// AllowedTargets is the allowlist of IPs/CIDRs hackbot may scan.
	// Overridable via HACKBOT_ALLOWED_TARGETS (comma-separated).
	AllowedTargets []string `json:"allowed_targets"`
	// NmapPath is the nmap binary. Overridable via HACKBOT_NMAP_PATH.
	NmapPath string `json:"nmap_path"`

	// ---- agent pipeline ----

	// LLMBaseURL is an OpenAI-compatible base URL (e.g. OpenCode Zen).
	// Overridable via HACKBOT_LLM_BASE_URL.
	LLMBaseURL string `json:"llm_base_url"`
	// LLMAPIKey authenticates to LLMBaseURL. Overridable via HACKBOT_LLM_API_KEY.
	LLMAPIKey string `json:"llm_api_key"`
	// LLMModel is the model ID. Overridable via HACKBOT_LLM_MODEL.
	LLMModel string `json:"llm_model"`
	// GitHubRepo (owner/name) receives auto-filed issues.
	// Overridable via HACKBOT_GITHUB_REPO.
	GitHubRepo string `json:"github_repo"`
}

// Default returns a Config populated with sensible defaults.
func Default() Config {
	return Config{
		Name:            "hackbot",
		IntervalSeconds: 60,
		PythonCmd:       "python",
		EnableScan:      false,
		NmapPath:        "nmap",
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
	if v := os.Getenv("HACKBOT_ENABLE_SCAN"); v != "" {
		cfg.EnableScan = parseBool(v)
	}
	if v := os.Getenv("HACKBOT_ALLOWED_TARGETS"); v != "" {
		cfg.AllowedTargets = splitList(v)
	}
	if v := os.Getenv("HACKBOT_NMAP_PATH"); v != "" {
		cfg.NmapPath = v
	}
	if v := os.Getenv("HACKBOT_LLM_BASE_URL"); v != "" {
		cfg.LLMBaseURL = v
	}
	if v := os.Getenv("HACKBOT_LLM_API_KEY"); v != "" {
		cfg.LLMAPIKey = v
	}
	if v := os.Getenv("HACKBOT_LLM_MODEL"); v != "" {
		cfg.LLMModel = v
	}
	if v := os.Getenv("HACKBOT_GITHUB_REPO"); v != "" {
		cfg.GitHubRepo = v
	}

	return cfg, nil
}

// String returns a short human-readable summary.
func (c Config) String() string {
	s := fmt.Sprintf("%s (tick every %ds)", c.Name, c.IntervalSeconds)
	if c.EnableScan {
		s += fmt.Sprintf(", scan=on targets=%v", c.AllowedTargets)
	} else {
		s += ", scan=off"
	}
	return s
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
