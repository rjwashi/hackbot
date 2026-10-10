package config // same package as config.go

import "testing" // the testing framework

// TestScanDefaults verifies the safety-oriented scan defaults.
func TestScanDefaults(t *testing.T) { // scan is opt-in
	cfg := Default()    // defaults
	if cfg.EnableScan { // scanning must be OFF by default (safety)...
		t.Error("scanning must be disabled by default")
	}
	if cfg.NmapPath != "nmap" { // the binary name should default sensibly
		t.Errorf("NmapPath = %q, want nmap", cfg.NmapPath)
	}
}

// TestEnableScanEnv verifies the truthy/falsey env parsing.
func TestEnableScanEnv(t *testing.T) { // env boolean parsing
	for _, v := range []string{"1", "true", "YES", "on"} { // each truthy spelling...
		t.Setenv("HACKBOT_ENABLE_SCAN", v) // ...set the env var
		cfg, err := Load("")               // load
		if err != nil {                    // must succeed
			t.Fatalf("Load: %v", err)
		}
		if !cfg.EnableScan { // truthy values must enable scanning
			t.Errorf("HACKBOT_ENABLE_SCAN=%q should enable scanning", v)
		}
	}
	t.Setenv("HACKBOT_ENABLE_SCAN", "0") // a falsey value...
	cfg, _ := Load("")                   // load
	if cfg.EnableScan {                  // ...must keep scanning off
		t.Error("HACKBOT_ENABLE_SCAN=0 should keep scanning disabled")
	}
}

// TestAllowedTargetsEnv verifies comma-separated parsing/trimming.
func TestAllowedTargetsEnv(t *testing.T) { // allowlist parsing
	t.Setenv("HACKBOT_ALLOWED_TARGETS", "192.168.1.0/24, 10.0.0.5 ,") // note spaces and a trailing comma
	cfg, err := Load("")                                              // load
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"192.168.1.0/24", "10.0.0.5"} // expected trimmed, non-empty entries
	if len(cfg.AllowedTargets) != len(want) {      // count must match
		t.Fatalf("AllowedTargets = %v, want %v", cfg.AllowedTargets, want)
	}
	for i := range want { // order/value must match
		if cfg.AllowedTargets[i] != want[i] {
			t.Errorf("AllowedTargets[%d] = %q, want %q", i, cfg.AllowedTargets[i], want[i])
		}
	}
}

// TestLLMAndRepoEnv verifies the agent-related env overrides.
func TestLLMAndRepoEnv(t *testing.T) { // env overrides
	t.Setenv("HACKBOT_LLM_BASE_URL", "https://example.test/v1") // LLM base URL
	t.Setenv("HACKBOT_LLM_API_KEY", "secret")                   // LLM key
	t.Setenv("HACKBOT_LLM_MODEL", "step-5-preview-free")        // model ID
	t.Setenv("HACKBOT_GITHUB_REPO", "rjwashi/hackbot")          // issue repo

	cfg, err := Load("") // load
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLMBaseURL != "https://example.test/v1" || cfg.LLMAPIKey != "secret" || // all four must be set...
		cfg.LLMModel != "step-5-preview-free" || cfg.GitHubRepo != "rjwashi/hackbot" { // ...to the override values
		t.Errorf("env overrides not applied: %+v", cfg)
	}
}

// TestJSONScanConfig verifies scan settings can come from the JSON file.
func TestJSONScanConfig(t *testing.T) { // JSON parsing for scan fields
	p := writeTemp(t, `{"enable_scan":true,"allowed_targets":["10.0.0.0/8"],"nmap_path":"C:/nmap/nmap.exe"}`) // JSON config
	cfg, err := Load(p)                                                                                       // load
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.EnableScan || len(cfg.AllowedTargets) != 1 || cfg.NmapPath != "C:/nmap/nmap.exe" { // all three applied
		t.Errorf("json config not applied: %+v", cfg)
	}
}
