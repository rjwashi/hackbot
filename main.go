// Command hackbot is the entry point for the hackbot project.
//
// hackbot is a Go-first bot project. Go owns the core bot logic; anything Go
// cannot do cleanly (or quickly) is delegated to small Python helpers under
// pythontools/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/rjwashi/hackbot/internal/bot"
	"github.com/rjwashi/hackbot/internal/config"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `hackbot - a Go-first bot with Python helpers

Usage:
  hackbot <command> [flags]

Commands:
  hello          Print a greeting
  run            Run the bot once (loads config, executes bot steps)
  py             Run a Python helper (demonstrates the Go->Python escape hatch)
  version        Print version
  help           Show this help

Flags (apply to all commands):
  -config PATH   Path to a JSON config file (optional)
`

func main() {
	configPath := flag.String("config", "", "path to JSON config file (optional)")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if len(flag.Args()) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hackbot: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	var runErr error

	switch flag.Arg(0) {
	case "hello":
		fmt.Printf("Hello from hackbot! (config: %s)\n", cfg.String())
	case "run":
		runErr = bot.New(cfg).Run(ctx)
	case "py":
		runErr = bot.New(cfg).RunPython(ctx, flag.Args()[1:])
	case "version":
		fmt.Println(version)
	case "help":
		flag.Usage()
	default:
		runErr = fmt.Errorf("unknown command %q", flag.Arg(0))
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "hackbot: %v\n", runErr)
		os.Exit(1)
	}
}
