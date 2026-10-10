package bot // must be the same package as bot.go to access unexported symbols if needed

import ( // test file imports
	"context" // to create/cancel contexts for the cancellation test
	"strings" // strings.Contains to assert on error text
	"testing" // the Go testing framework
	"time"    // timing the cancellation promptness

	"github.com/rjwashi/hackbot/internal/config" // build a Config for the tests
)

// testConfig returns a config tuned for fast tests.
func testConfig() config.Config { // helper reused by all tests here
	return config.Config{Name: "testbot", IntervalSeconds: 1, PythonCmd: "python"} // 1s tick keeps tests quick
}

// TestRunComplete verifies a full cycle succeeds with a normal context.
func TestRunComplete(t *testing.T) { // happy path
	b := New(testConfig())                              // construct a Bot
	if err := b.Run(context.Background()); err != nil { // run one cycle...
		t.Fatalf("Run() error = %v", err) // ...and fail if it errors
	}
}

// TestRunContextCanceledStopsPromptly verifies cancellation is honored mid-tick.
func TestRunContextCanceledStopsPromptly(t *testing.T) { // cancellation behavior
	cfg := testConfig()        // start from defaults
	cfg.IntervalSeconds = 3600 // a long tick ensures only cancellation can finish the run
	b := New(cfg)              // build the bot

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond) // cancel after 100ms
	defer cancel()                                                                 // release timer resources
	start := time.Now()                                                            // record start to measure promptness
	err := b.Run(ctx)                                                              // run; should stop when the context expires
	if err == nil {                                                                // a cancelled run must return an error...
		t.Fatal("expected context cancellation error, got nil")
	}
	if !strings.Contains(err.Error(), "context") { // the error should mention context...
		t.Errorf("unexpected error: %v", err) // ...otherwise it's the wrong failure
	}
	if time.Since(start) > 2*time.Second { // it must stop well before the 3600s tick...
		t.Errorf("Run() did not stop promptly after cancellation: %v", time.Since(start)) // ...else the select is broken
	}
}

// TestRunPythonNoArgs verifies the helper-required argument is enforced.
func TestRunPythonNoArgs(t *testing.T) { // input validation
	b := New(testConfig())                                         // build a bot
	if err := b.RunPython(context.Background(), nil); err == nil { // no helper name...
		t.Fatal("expected error for missing helper, got nil") // ...must error
	}
}
