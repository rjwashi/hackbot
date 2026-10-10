package config // same package as config.go so tests exercise it directly

import ( // test imports
	"os"            // os.WriteFile to create temporary config files
	"path/filepath" // building portable temp file paths
	"testing"       // the testing framework
)

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, content string) string { // shared helper
	t.Helper()                                                      // mark as a helper so failures point at the caller
	dir := t.TempDir()                                              // per-test directory auto-cleaned by the framework
	p := filepath.Join(dir, "config.json")                          // the temp config path
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil { // write with owner-only perms...
		t.Fatalf("write temp config: %v", err) // ...fail the test on error
	}
	return p // return the path for Load
}

// TestDefault checks the baseline defaults.
func TestDefault(t *testing.T) { // defaults sanity
	cfg := Default()           // get defaults
	if cfg.Name != "hackbot" { // name default...
		t.Errorf("Default().Name = %q, want %q", cfg.Name, "hackbot") // ...must be "hackbot"
	}
	if cfg.IntervalSeconds == 0 { // interval must be set...
		t.Error("Default().IntervalSeconds must be non-zero") // ...else the tick is zero
	}
	if cfg.PythonCmd == "" { // interpreter must be set...
		t.Error("Default().PythonCmd must be non-empty") // ...else the Python bridge can't run
	}
}

// TestLoadNoFileReturnsDefault verifies an empty path yields defaults.
func TestLoadNoFileReturnsDefault(t *testing.T) { // no-file path
	cfg, err := Load("") // empty path
	if err != nil {      // must not error...
		t.Fatalf("Load(\"\") error = %v", err)
	}
	if cfg.Name != "hackbot" { // ...and keep defaults
		t.Errorf("Name = %q, want default", cfg.Name)
	}
}

// TestLoadJSON verifies all JSON fields decode.
func TestLoadJSON(t *testing.T) { // JSON parsing
	p := writeTemp(t, `{"name":"testbot","interval_seconds":7,"python_cmd":"py"}`) // write JSON
	cfg, err := Load(p)                                                            // load it
	if err != nil {                                                                // must succeed...
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Name != "testbot" || cfg.IntervalSeconds != 7 || cfg.PythonCmd != "py" { // ...with all fields set
		t.Errorf("unexpected config: %+v", cfg)
	}
}

// TestLoadMalformedJSONFails verifies bad JSON is rejected.
func TestLoadMalformedJSONFails(t *testing.T) { // error path
	p := writeTemp(t, `{"name":`)      // deliberately broken JSON
	if _, err := Load(p); err == nil { // must error...
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestLoadMissingFileFails verifies an explicitly requested but missing file errors.
func TestLoadMissingFileFails(t *testing.T) { // error path
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil { // path that doesn't exist...
		t.Fatal("expected error for missing file, got nil") // ...must error
	}
}

// TestEnvOverrides verifies env vars win over defaults.
func TestEnvOverrides(t *testing.T) { // env precedence
	t.Setenv("HACKBOT_NAME", "envbot")         // set name override (auto-restored after test)
	t.Setenv("HACKBOT_INTERVAL_SECONDS", "12") // set interval override
	cfg, err := Load("")                       // load with no file
	if err != nil {                            // must succeed
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Name != "envbot" || cfg.IntervalSeconds != 12 { // overrides must apply
		t.Errorf("env overrides not applied: %+v", cfg)
	}
}

// TestEnvOverrideInvalid verifies a non-numeric interval is rejected.
func TestEnvOverrideInvalid(t *testing.T) { // error path
	t.Setenv("HACKBOT_INTERVAL_SECONDS", "not-a-number") // invalid integer
	if _, err := Load(""); err == nil {                  // must error...
		t.Fatal("expected error for invalid interval env var, got nil")
	}
}
