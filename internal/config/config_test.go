package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Name != "hackbot" {
		t.Errorf("Default().Name = %q, want %q", cfg.Name, "hackbot")
	}
	if cfg.IntervalSeconds == 0 {
		t.Error("Default().IntervalSeconds must be non-zero")
	}
	if cfg.PythonCmd == "" {
		t.Error("Default().PythonCmd must be non-empty")
	}
}

func TestLoadNoFileReturnsDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") error = %v", err)
	}
	if cfg.Name != "hackbot" {
		t.Errorf("Name = %q, want default", cfg.Name)
	}
}

func TestLoadJSON(t *testing.T) {
	p := writeTemp(t, `{"name":"testbot","interval_seconds":7,"python_cmd":"py"}`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Name != "testbot" || cfg.IntervalSeconds != 7 || cfg.PythonCmd != "py" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoadMalformedJSONFails(t *testing.T) {
	p := writeTemp(t, `{"name":`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestLoadMissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("HACKBOT_NAME", "envbot")
	t.Setenv("HACKBOT_INTERVAL_SECONDS", "12")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Name != "envbot" || cfg.IntervalSeconds != 12 {
		t.Errorf("env overrides not applied: %+v", cfg)
	}
}

func TestEnvOverrideInvalid(t *testing.T) {
	t.Setenv("HACKBOT_INTERVAL_SECONDS", "not-a-number")
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for invalid interval env var, got nil")
	}
}
