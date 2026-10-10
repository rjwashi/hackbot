// Package bot implements the core hackbot logic.
package bot // importable as "bot"

import ( // imports for this file
	"context" // cooperative cancellation for the loop and Python call
	"fmt"     // Printf/Errorf for output and errors
	"os/exec" // exec.CommandContext to run Python helpers
	"time"    // time.After for the loop tick delay

	"github.com/rjwashi/hackbot/internal/config" // the bot reads its settings from config
)

// Bot owns one run of hackbot's core loop, step by step.
type Bot struct { // holds the immutable config for a run
	cfg config.Config // captured settings
}

// New returns a Bot configured with cfg.
func New(cfg config.Config) *Bot { // constructor
	return &Bot{cfg: cfg} // store the config
}

// Run executes a single bot cycle: it honors context cancellation between
// steps. The steps are intentionally minimal until real features land.
func (b *Bot) Run(ctx context.Context) error { // the bot's main cycle
	steps := []func(context.Context) error{ // ordered list of steps...
		b.stepGreet, // 1) greet/log start
		b.stepTick,  // 2) wait for the configured interval (the "work")
		b.stepDone,  // 3) log completion
	}
	for _, s := range steps { // run each step in order
		if err := s(ctx); err != nil { // if a step fails or is cancelled...
			return err // ...stop immediately and propagate
		}
	}
	return nil // all steps succeeded
}

// stepGreet logs the bot's startup line.
func (b *Bot) stepGreet(ctx context.Context) error { // first step
	select { // check for cancellation before doing work
	case <-ctx.Done(): // context already cancelled...
		return ctx.Err() // ...report cancellation
	default: // otherwise proceed
		fmt.Printf("hackbot %q starting (tick %ds)\n", b.cfg.Name, b.cfg.IntervalSeconds) // startup log
		return nil                                                                        // done
	}
}

// stepTick waits one interval, then records the tick.
func (b *Bot) stepTick(ctx context.Context) error { // second step
	select { // wait, but stay cancellable
	case <-ctx.Done(): // cancelled during the wait...
		return ctx.Err() // ...return promptly
	case <-time.After(time.Duration(b.cfg.IntervalSeconds) * time.Second): // interval elapsed...
		// In a real bot this would poll an exchange, feed, or queue.
		// For the scaffold we just record a tick.
		fmt.Println("tick") // log the tick
		return nil          // done
	}
}

// stepDone logs the completion of a cycle.
func (b *Bot) stepDone(ctx context.Context) error { // third step
	select { // still check for cancellation
	case <-ctx.Done(): // cancelled...
		return ctx.Err() // ...report it
	default: // otherwise...
		fmt.Println("cycle complete") // ...log completion
		return nil                    // done
	}
}

// RunPython shells out to a Python helper, passing args through. This is the
// documented escape hatch for work that is easier in Python than Go.
func (b *Bot) RunPython(ctx context.Context, args []string) error { // Go->Python bridge
	if len(args) == 0 { // require a helper name...
		return fmt.Errorf("py: missing helper name (use: hackbot py <helper> [...args])") // ...else usage error
	}
	cmd := exec.CommandContext(ctx, b.cfg.PythonCmd, args...) // build the python process
	cmd.Dir = "pythontools"                                   // run from the helpers directory so relative module paths work
	out, err := cmd.CombinedOutput()                          // capture stdout+stderr
	if len(out) > 0 {                                         // forward any output...
		fmt.Print(string(out)) // ...verbatim to the user
	}
	return err // nil on success; non-nil (with output already shown) on failure
}
