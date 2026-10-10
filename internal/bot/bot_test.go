package bot

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rjwashi/hackbot/internal/config"
)

func testConfig() config.Config {
	return config.Config{Name: "testbot", IntervalSeconds: 1, PythonCmd: "python"}
}

func TestRunComplete(t *testing.T) {
	b := New(testConfig())
	if err := b.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunContextCanceledStopsPromptly(t *testing.T) {
	cfg := testConfig()
	cfg.IntervalSeconds = 3600 // long enough that only cancellation can finish it
	b := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := b.Run(ctx)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("unexpected error: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Run() did not stop promptly after cancellation: %v", time.Since(start))
	}
}

func TestRunPythonNoArgs(t *testing.T) {
	b := New(testConfig())
	if err := b.RunPython(context.Background(), nil); err == nil {
		t.Fatal("expected error for missing helper, got nil")
	}
}
