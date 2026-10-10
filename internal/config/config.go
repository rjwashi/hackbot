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
	// NmapScripts lists NSE scripts to run when scanning. Nil means "use the
	// caller's default recon profile"; a non-nil empty list means "no scripts".
	// Overridable via HACKBOT_NMAP_SCRIPTS (comma-separated; "none" disables).
	NmapScripts []string `json:"nmap_scripts"` // e.g. ["banner","http-title"]
	// NmapScriptArgs is passed to nmap as --script-args (e.g. "vulscandb=cve.csv").
	// Overridable via HACKBOT_NMAP_SCRIPT_ARGS.
	NmapScriptArgs string `json:"nmap_script_args"` // optional NSE script arguments
	// VulscanDir is the directory holding vulscan.nse and its CSV databases.
	// Overridable via HACKBOT_VULSCAN_DIR.
	VulscanDir string `json:"vulscan_dir"` // used by the vulscan recon agent
	// VulscanDB selects a single vulscan database (e.g. "cve.csv").
	// Overridable via HACKBOT_VULSCAN_DB.
	VulscanDB string `json:"vulscan_db"` // passed to nmap as vulscandb=<name>

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

	// ---- CVE search (NVD) ----

	// NVDBaseURL overrides the NVD API endpoint (mirrors/tests).
	// Overridable via HACKBOT_NVD_BASE_URL.
	NVDBaseURL string `json:"nvd_base_url"` // default is the public NVD 2.0 endpoint
	// NVDAPIKey is an optional NIST NVD API key. Overridable via HACKBOT_NVD_API_KEY.
	NVDAPIKey string `json:"nvd_api_key"` // raises the NVD rate limit when set
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
	if v := os.Getenv("HACKBOT_NMAP_SCRIPTS"); v != "" { // env override for the NSE script list
		cfg.NmapScripts = parseScripts(v) // comma list, or "none"/"off" to disable
	}
	if v := os.Getenv("HACKBOT_NMAP_SCRIPT_ARGS"); v != "" { // env override for NSE script args
		cfg.NmapScriptArgs = v
	}
	if v := os.Getenv("HACKBOT_VULSCAN_DIR"); v != "" { // env override for the vulscan directory
		cfg.VulscanDir = v
	}
	if v := os.Getenv("HACKBOT_VULSCAN_DB"); v != "" { // env override for the vulscan database
		cfg.VulscanDB = v
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
	if v := os.Getenv("HACKBOT_NVD_BASE_URL"); v != "" { // env override for the NVD endpoint
		cfg.NVDBaseURL = v
	}
	if v := os.Getenv("HACKBOT_NVD_API_KEY"); v != "" { // env override for the NVD key
		cfg.NVDAPIKey = v
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

// parseScripts parses HACKBOT_NMAP_SCRIPTS. The values "none" or "off" select no
// scripts (returning an empty, non-nil slice so callers can tell that apart from
// an unset value); anything else is a comma-separated script list.
func parseScripts(v string) []string { // tolerant env parsing for script selection
	switch strings.ToLower(strings.TrimSpace(v)) { // normalize case/space
	case "none", "off": // explicit opt-out...
		return []string{} // ...a non-nil empty slice means "configured to run none"
	default: // otherwise...
		return splitList(v) // ...treat it as a comma-separated list
	}
}
