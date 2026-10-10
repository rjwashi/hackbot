package config

import "testing"

func TestScanDefaults(t *testing.T) {
	cfg := Default()
	if cfg.EnableScan {
		t.Error("scanning must be disabled by default")
	}
	if cfg.NmapPath != "nmap" {
		t.Errorf("NmapPath = %q, want nmap", cfg.NmapPath)
	}
}

func TestEnableScanEnv(t *testing.T) {
	for _, v := range []string{"1", "true", "YES", "on"} {
		t.Setenv("HACKBOT_ENABLE_SCAN", v)
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !cfg.EnableScan {
			t.Errorf("HACKBOT_ENABLE_SCAN=%q should enable scanning", v)
		}
	}
	t.Setenv("HACKBOT_ENABLE_SCAN", "0")
	cfg, _ := Load("")
	if cfg.EnableScan {
		t.Error("HACKBOT_ENABLE_SCAN=0 should keep scanning disabled")
	}
}

func TestAllowedTargetsEnv(t *testing.T) {
	t.Setenv("HACKBOT_ALLOWED_TARGETS", "192.168.1.0/24, 10.0.0.5 ,")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"192.168.1.0/24", "10.0.0.5"}
	if len(cfg.AllowedTargets) != len(want) {
		t.Fatalf("AllowedTargets = %v, want %v", cfg.AllowedTargets, want)
	}
	for i := range want {
		if cfg.AllowedTargets[i] != want[i] {
			t.Errorf("AllowedTargets[%d] = %q, want %q", i, cfg.AllowedTargets[i], want[i])
		}
	}
}

func TestLLMAndRepoEnv(t *testing.T) {
	t.Setenv("HACKBOT_LLM_BASE_URL", "https://example.test/v1")
	t.Setenv("HACKBOT_LLM_API_KEY", "secret")
	t.Setenv("HACKBOT_LLM_MODEL", "step-5-preview-free")
	t.Setenv("HACKBOT_GITHUB_REPO", "rjwashi/hackbot")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LLMBaseURL != "https://example.test/v1" || cfg.LLMAPIKey != "secret" ||
		cfg.LLMModel != "step-5-preview-free" || cfg.GitHubRepo != "rjwashi/hackbot" {
		t.Errorf("env overrides not applied: %+v", cfg)
	}
}

func TestJSONScanConfig(t *testing.T) {
	p := writeTemp(t, `{"enable_scan":true,"allowed_targets":["10.0.0.0/8"],"nmap_path":"C:/nmap/nmap.exe"}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.EnableScan || len(cfg.AllowedTargets) != 1 || cfg.NmapPath != "C:/nmap/nmap.exe" {
		t.Errorf("json config not applied: %+v", cfg)
	}
}
