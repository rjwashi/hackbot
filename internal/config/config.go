// Package config loads hackbot configuration from an optional JSON file with
// environment-variable overrides. Env vars win over the file, so deployments can
// override without editing the file.
package config // importable as "config"

import ( // imports for this file
	"encoding/json" // decode the JSON config file
	"fmt"           // Errorf/Sprintf for messages
	"os"            // read the file and environment variables
	"strings"       // parse boolean/list env values
)

// Config holds the runtime configuration for the bot.
type Config struct { // one struct with JSON tags; env overrides applied after loading
	// Name is the bot's display name. Overridable via HACKBOT_NAME.
	Name string `json:"name"` // cosmetic label used in output
	// IntervalSeconds controls how often the bot loop ticks.
	// Overridable via HACKBOT_INTERVAL_SECONDS.
	IntervalSeconds int `json:"interval_seconds"` // seconds between bot loop iterations
	// PythonCmd is the interpreter used for Python helpers.
	// Overridable via HACKBOT_PYTHON_CMD.
	PythonCmd string `json:"python_cmd"` // e.g. "python" or "python3"

	// ---- nmap scanning (safety-gated) ----

	// EnableScan must be true before hackbot will run nmap at all.
	// Overridable via HACKBOT_ENABLE_SCAN (1/true/yes/on).
	EnableScan bool `json:"enable_scan"` // master switch; default false
	// AllowedTargets is the allowlist of IPs/CIDRs hackbot may scan.
	// Overridable via HACKBOT_ALLOWED_TARGETS (comma-separated).
	AllowedTargets []string `json:"allowed_targets"` // scanned only if a target falls inside one of these
	// NmapPath is the nmap binary. Overridable via HACKBOT_NMAP_PATH.
	NmapPath string `json:"nmap_path"` // default "nmap"

	// ---- agent pipeline ----

	// LLMBaseURL is an OpenAI-compatible base URL (e.g. OpenCode Zen).
	// Overridable via HACKBOT_LLM_BASE_URL.
	LLMBaseURL string `json:"llm_base_url"` // base URL without /chat/completions
	// LLMAPIKey authenticates to LLMBaseURL. Overridable via HACKBOT_LLM_API_KEY.
	LLMAPIKey string `json:"llm_api_key"` // bearer token; empty for local endpoints
	// LLMModel is the model ID. Overridable via HACKBOT_LLM_MODEL.
	LLMModel string `json:"llm_model"` // e.g. "step-5-preview-free"
	// GitHubRepo (owner/name) receives auto-filed issues.
	// Overridable via HACKBOT_GITHUB_REPO.
	GitHubRepo string `json:"github_repo"` // e.g. "rjwashi/hackbot"
}

// Default returns a Config populated with sensible defaults.
func Default() Config { // used as the starting point before file/env overrides
	return Config{
		Name:            "hackbot", // friendly default name
		IntervalSeconds: 60,        // default tick interval
		PythonCmd:       "python",  // assume python on PATH
		EnableScan:      false,     // SAFETY: never scan unless explicitly enabled
		NmapPath:        "nmap",    // assume nmap on PATH
	}
}

// Load reads config from the JSON file at path (if non-empty) and applies
// environment-variable overrides. Missing files are not an error; only
// unreadable or malformed ones are.
func Load(path string) (Config, error) { // main constructor
	cfg := Default() // start from defaults so absent fields keep their defaults

	if path != "" { // only read a file if a path was given
		data, err := os.ReadFile(path) // read the whole file
		if err != nil {                // missing/unreadable file is an error when explicitly requested
			return cfg, fmt.Errorf("read config %s: %w", path, err) // contextual error
		}
		if err := json.Unmarshal(data, &cfg); err != nil { // decode over the defaults
			return cfg, fmt.Errorf("parse config %s: %w", path, err) // malformed JSON
		}
	}

	if v := os.Getenv("HACKBOT_NAME"); v != "" { // env override for name...
		cfg.Name = v // ...only when set
	}
	if v := os.Getenv("HACKBOT_INTERVAL_SECONDS"); v != "" { // env override for interval...
		if _, err := fmt.Sscanf(v, "%d", &cfg.IntervalSeconds); err != nil { // parse an integer...
			return cfg, fmt.Errorf("invalid HACKBOT_INTERVAL_SECONDS %q", v) // ...and reject bad input
		}
	}
	if v := os.Getenv("HACKBOT_PYTHON_CMD"); v != "" { // env override for python interpreter
		cfg.PythonCmd = v
	}
	if v := os.Getenv("HACKBOT_ENABLE_SCAN"); v != "" { // env override for the scan switch
		cfg.EnableScan = parseBool(v) // accept 1/true/yes/on
	}
	if v := os.Getenv("HACKBOT_ALLOWED_TARGETS"); v != "" { // env override for the allowlist
		cfg.AllowedTargets = splitList(v) // split on commas, trim, drop blanks
	}
	if v := os.Getenv("HACKBOT_NMAP_PATH"); v != "" { // env override for the nmap binary
		cfg.NmapPath = v
	}
	if v := os.Getenv("HACKBOT_LLM_BASE_URL"); v != "" { // env override for LLM base URL
		cfg.LLMBaseURL = v
	}
	if v := os.Getenv("HACKBOT_LLM_API_KEY"); v != "" { // env override for LLM key
		cfg.LLMAPIKey = v
	}
	if v := os.Getenv("HACKBOT_LLM_MODEL"); v != "" { // env override for LLM model
		cfg.LLMModel = v
	}
	if v := os.Getenv("HACKBOT_GITHUB_REPO"); v != "" { // env override for the issue repo
		cfg.GitHubRepo = v
	}

	return cfg, nil // success
}

// String returns a short human-readable summary.
func (c Config) String() string { // shown by `hackbot hello`
	s := fmt.Sprintf("%s (tick every %ds)", c.Name, c.IntervalSeconds) // base summary
	if c.EnableScan {                                                  // reflect the safety state in the summary...
		s += fmt.Sprintf(", scan=on targets=%v", c.AllowedTargets) // ...showing the allowlist when on
	} else {
		s += ", scan=off" // ...or just "off"
	}
	return s // final summary
}

// parseBool interprets common truthy/falsey strings.
func parseBool(v string) bool { // tolerant env parsing
	switch strings.ToLower(strings.TrimSpace(v)) { // normalize case/space
	case "1", "true", "yes", "on": // recognized truthy values...
		return true // ...enable
	default: // anything else...
		return false // ...treated as disabled (safe default)
	}
}

// splitList splits a comma-separated env value into a trimmed, non-empty slice.
func splitList(v string) []string { // used for HACKBOT_ALLOWED_TARGETS
	var out []string                             // accumulator
	for _, part := range strings.Split(v, ",") { // split on commas
		if p := strings.TrimSpace(part); p != "" { // trim and skip blanks...
			out = append(out, p) // ...keep real entries
		}
	}
	return out // nil if nothing valid was provided
}
