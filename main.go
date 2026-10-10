// Command hackbot is the entry point for the hackbot project.
//
// hackbot is a Go-first bot project. Go owns the core bot logic; anything Go
// cannot do cleanly (or quickly) is delegated to small Python helpers under
// pythontools/.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rjwashi/hackbot/internal/agent"
	"github.com/rjwashi/hackbot/internal/bot"
	"github.com/rjwashi/hackbot/internal/config"
	"github.com/rjwashi/hackbot/internal/nmap"
	"github.com/rjwashi/hackbot/internal/scan"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `hackbot - a Go-first bot with Python helpers

Usage:
  hackbot <command> [args]

Commands:
  hello                     Print a greeting
  run                       Run the bot once (loads config, executes bot steps)
  py <helper> [args...]     Run a Python helper (Go->Python escape hatch)
  version                   Print version
  help                      Show this help

  nmap parse   <file>       Parse an nmap XML file and list hosts/ports
  nmap analyze <file>       Parse + rule-based risk report
  nmap scan    <target>     Run a GUARDED nmap scan, then analyze
  nmap pipeline <file>      Full pipeline: analyze [+ llm] [+ issues]

Common flags:
  -config PATH              Path to a JSON config file (optional)
  -json                     Machine-readable JSON output (nmap commands)

nmap pipeline flags:
  -llm                      Ask the configured LLM to explain/prioritize
  -issues                   File GitHub issues for findings
  -dry-run                  Do not actually create issues (default true)
  -repo owner/name          Override the target repo for issues
  -min-severity S           Minimum severity to file (info|low|medium|high|critical)
  -max-issues N             Max issues per run (default 10)

Safety: scanning is disabled unless enable_scan is true AND the target is in
allowed_targets. Only scan systems you own or are explicitly authorized to test.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "hello", "run", "py", "nmap":
		err = runCommand(command, args)
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q (try: hackbot help)", command)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "hackbot: %v\n", err)
		os.Exit(1)
	}
}

func runCommand(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to JSON config file (optional)")
	asJSON := fs.Bool("json", false, "JSON output")

	// nmap pipeline flags (ignored by other commands).
	useLLM := fs.Bool("llm", false, "use the configured LLM")
	createIssues := fs.Bool("issues", false, "file GitHub issues for findings")
	dryRun := fs.Bool("dry-run", true, "do not actually create issues")
	repo := fs.String("repo", "", "owner/name for issues (overrides config)")
	minSeverity := fs.String("min-severity", "high", "minimum severity for issues")
	maxIssues := fs.Int("max-issues", 10, "max issues per run")

	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	switch command {
	case "hello":
		fmt.Printf("Hello from hackbot! (config: %s)\n", cfg.String())
		return nil
	case "run":
		return bot.New(cfg).Run(context.Background())
	case "py":
		return bot.New(cfg).RunPython(context.Background(), fs.Args())
	case "nmap":
		return runNmap(cfg, fs.Args(), nmapFlags{
			json:        *asJSON,
			useLLM:      *useLLM,
			issues:      *createIssues,
			dryRun:      *dryRun,
			repo:        *repo,
			minSeverity: *minSeverity,
			maxIssues:   *maxIssues,
		})
	}
	return nil
}

type nmapFlags struct {
	json        bool
	useLLM      bool
	issues      bool
	dryRun      bool
	repo        string
	minSeverity string
	maxIssues   int
}

func runNmap(cfg config.Config, args []string, fl nmapFlags) error {
	if len(args) < 1 {
		return fmt.Errorf("nmap: missing subcommand (parse|analyze|scan|pipeline)")
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "parse":
		if len(rest) < 1 {
			return fmt.Errorf("nmap parse: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0])
		if err != nil {
			return err
		}
		if fl.json {
			return printJSON(nmapSummary(sc))
		}
		printScan(sc)
		return nil

	case "analyze":
		if len(rest) < 1 {
			return fmt.Errorf("nmap analyze: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0])
		if err != nil {
			return err
		}
		findings := nmap.Analyze(sc)
		if fl.json {
			return printJSON(findings)
		}
		printFindings(findings)
		return nil

	case "scan":
		if len(rest) < 1 {
			return fmt.Errorf("nmap scan: missing <target>")
		}
		scanner := scan.New(scan.Options{
			NmapPath:       cfg.NmapPath,
			Enable:         cfg.EnableScan,
			AllowedTargets: cfg.AllowedTargets,
		}, nil)
		sc, err := scanner.Scan(context.Background(), rest[0])
		if err != nil {
			return err
		}
		findings := nmap.Analyze(sc)
		if fl.json {
			return printJSON(findings)
		}
		printScan(sc)
		printFindings(findings)
		return nil

	case "pipeline":
		if len(rest) < 1 {
			return fmt.Errorf("nmap pipeline: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0])
		if err != nil {
			return err
		}
		sev, err := parseSeverity(fl.minSeverity)
		if err != nil {
			return err
		}
		rep, err := agent.Run(context.Background(), sc, agent.Options{
			UseLLM:       fl.useLLM,
			CreateIssues: fl.issues,
			DryRun:       fl.dryRun,
			Repo:         firstNonEmpty(fl.repo, cfg.GitHubRepo),
			MinSeverity:  sev,
			MaxIssues:    fl.maxIssues,
			LLM: agent.LLMClient{
				BaseURL: cfg.LLMBaseURL,
				APIKey:  cfg.LLMAPIKey,
				Model:   cfg.LLMModel,
			},
			Log: func(s string) { fmt.Fprintln(os.Stderr, "hackbot:", s) },
		})
		if err != nil {
			return err
		}
		if fl.json {
			return printJSONIndent(rep)
		}
		fmt.Print(rep.Summary())
		return nil

	default:
		return fmt.Errorf("nmap: unknown subcommand %q", sub)
	}
}

func printScan(sc *nmap.Scan) {
	up := sc.UpHosts()
	fmt.Printf("nmap %s: %d host(s), %d up\n", sc.Version, len(sc.Hosts), len(up))
	for _, h := range up {
		fmt.Printf("  %s\n", h.Label())
		for _, p := range h.OpenPorts() {
			svc := p.Service.Name
			banner := strings.TrimSpace(strings.Join([]string{p.Service.Product, p.Service.Version}, " "))
			if banner != "" {
				svc = fmt.Sprintf("%s (%s)", svc, banner)
			}
			fmt.Printf("    %d/%s open  %s\n", p.Number, p.Protocol, svc)
		}
	}
}

func printFindings(findings []nmap.Finding) {
	if len(findings) == 0 {
		fmt.Println("no findings")
		return
	}
	counts := nmap.Counts(findings)
	fmt.Printf("%d finding(s)", len(findings))
	for _, sev := range []nmap.Severity{nmap.SevCritical, nmap.SevHigh, nmap.SevMedium, nmap.SevLow, nmap.SevInfo} {
		if counts[sev] > 0 {
			fmt.Printf("  %s:%d", sev, counts[sev])
		}
	}
	fmt.Println()
	for _, f := range findings {
		fmt.Printf("  %s\n", f.String())
	}
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

type portSummary struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type hostSummary struct {
	Label     string        `json:"label"`
	Address   string        `json:"address,omitempty"`
	Hostnames []string      `json:"hostnames,omitempty"`
	Status    string        `json:"status"`
	OpenPorts []portSummary `json:"open_ports,omitempty"`
}

type scanSummary struct {
	Scanner   string        `json:"scanner"`
	Version   string        `json:"version"`
	Args      string        `json:"args,omitempty"`
	HostsUp   int           `json:"hosts_up"`
	HostsDown int           `json:"hosts_down"`
	Hosts     []hostSummary `json:"hosts"`
}

func nmapSummary(sc *nmap.Scan) scanSummary {
	s := scanSummary{
		Scanner:   sc.Scanner,
		Version:   sc.Version,
		Args:      sc.Args,
		HostsUp:   len(sc.UpHosts()),
		HostsDown: len(sc.Hosts) - len(sc.UpHosts()),
	}
	for _, h := range sc.Hosts {
		hs := hostSummary{
			Label:     h.Label(),
			Address:   h.PrimaryAddress(),
			Hostnames: h.Hostnames,
			Status:    h.Status,
		}
		for _, p := range h.OpenPorts() {
			hs.OpenPorts = append(hs.OpenPorts, portSummary{
				Port:     p.Number,
				Protocol: p.Protocol,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			})
		}
		s.Hosts = append(s.Hosts, hs)
	}
	return s
}

func printJSONIndent(v interface{ JSON() ([]byte, error) }) error {
	data, err := v.JSON()
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func parseSeverity(s string) (nmap.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return nmap.SevInfo, nil
	case "low":
		return nmap.SevLow, nil
	case "medium", "med":
		return nmap.SevMedium, nil
	case "high":
		return nmap.SevHigh, nil
	case "critical", "crit":
		return nmap.SevCritical, nil
	default:
		return nmap.SevInfo, fmt.Errorf("invalid severity %q", s)
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// reorderArgs moves flags (and their values) ahead of positional arguments.
//
// The stdlib flag package stops at the first non-flag token, which would make
// flags placed after a subcommand/file (e.g. "pipeline scan.xml -issues") be
// silently ignored. Reordering lets users put flags anywhere.
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			return append(flags, positional...)
		case strings.HasPrefix(a, "-") && a != "-":
			flags = append(flags, a)
			if strings.Contains(a, "=") {
				continue
			}
			name := strings.TrimLeft(a, "-")
			if f := fs.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
					if i+1 < len(args) {
						flags = append(flags, args[i+1])
						i++
					}
				}
			}
		default:
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}
