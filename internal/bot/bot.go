// Package bot implements the core hackbot logic.
package bot

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/rjwashi/hackbot/internal/config"
)

// Bot owns one run of hackbot's core loop, step by step.
type Bot struct {
	cfg config.Config
}

// New returns a Bot configured with cfg.
func New(cfg config.Config) *Bot {
	return &Bot{cfg: cfg}
}

// Run executes a single bot cycle: it honors context cancellation between
// steps. The steps are intentionally minimal until real features land.
func (b *Bot) Run(ctx context.Context) error {
	steps := []func(context.Context) error{
		b.stepGreet,
		b.stepTick,
		b.stepDone,
	}
	for _, s := range steps {
		if err := s(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bot) stepGreet(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		fmt.Printf("hackbot %q starting (tick %ds)\n", b.cfg.Name, b.cfg.IntervalSeconds)
		return nil
	}
}

func (b *Bot) stepTick(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(b.cfg.IntervalSeconds) * time.Second):
		// In a real bot this would poll an exchange, feed, or queue.
		// For the scaffold we just record a tick.
		fmt.Println("tick")
		return nil
	}
}

func (b *Bot) stepDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		fmt.Println("cycle complete")
		return nil
	}
}

// RunPython shells out to a Python helper, passing args through. This is the
// documented escape hatch for work that is easier in Python than Go.
func (b *Bot) RunPython(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("py: missing helper name (use: hackbot py <helper> [...args])")
	}
	cmd := exec.CommandContext(ctx, b.cfg.PythonCmd, args...)
	cmd.Dir = "pythontools"
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		fmt.Print(string(out))
	}
	return err
}
