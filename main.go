// Command hackbot is the entry point for the hackbot project.
//
// hackbot is a Go-first bot project. Go owns the core bot logic; anything Go
// cannot do cleanly (or quickly) is delegated to small Python helpers under
// pythontools/.
package main // package main makes this an executable

import ( // imports for the whole CLI
	"context"       // background context for one-shot commands
	"encoding/json" // JSON output for nmap commands
	"errors"        // errors.Is to special-case canceled contexts
	"flag"          // stdlib flag parsing for subcommand flags
	"fmt"           // printing and error formatting
	"os"            // args, exit codes, stderr
	"strings"       // arg/severity/string helpers

	"github.com/rjwashi/hackbot/internal/agent"  // the pipeline
	"github.com/rjwashi/hackbot/internal/bot"    // the core bot loop + Python bridge
	"github.com/rjwashi/hackbot/internal/config" // configuration loading
	"github.com/rjwashi/hackbot/internal/nmap"   // XML parsing + analysis
	"github.com/rjwashi/hackbot/internal/scan"   // guarded scanning
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev" // default for local builds

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
` // end of usage text

func main() { // program entry point
	if len(os.Args) < 2 { // no command given...
		fmt.Fprint(os.Stderr, usage) // ...print usage to stderr...
		os.Exit(2)                   // ...and exit with the conventional "usage" code
	}

	command := os.Args[1] // first arg is the command
	args := os.Args[2:]   // remaining args belong to the command

	var err error    // captured command error
	switch command { // dispatch on the command name
	case "hello", "run", "py", "nmap": // commands that load config and parse flags
		err = runCommand(command, args)
	case "version", "-v", "--version": // version has no config/flags
		fmt.Println(version)
	case "help", "-h", "--help": // help prints usage to stdout
		fmt.Print(usage)
	default: // unknown command
		err = fmt.Errorf("unknown command %q (try: hackbot help)", command)
	}

	if err != nil && !errors.Is(err, context.Canceled) { // report errors, but treat cancellation as a clean stop
		fmt.Fprintf(os.Stderr, "hackbot: %v\n", err) // show the error...
		os.Exit(1)                                   // ...and exit non-zero
	}
}

// runCommand parses flags and dispatches to hello/run/py/nmap.
func runCommand(command string, args []string) error { // shared preamble
	fs := flag.NewFlagSet(command, flag.ContinueOnError)                      // per-command flag set; returns errors instead of exiting
	cfgPath := fs.String("config", "", "path to JSON config file (optional)") // optional config file
	asJSON := fs.Bool("json", false, "JSON output")                           // machine-readable output toggle

	// nmap pipeline flags (ignored by other commands).
	useLLM := fs.Bool("llm", false, "use the configured LLM")                       // enable LLM stage
	createIssues := fs.Bool("issues", false, "file GitHub issues for findings")     // enable actions stage
	dryRun := fs.Bool("dry-run", true, "do not actually create issues")             // SAFETY: default true
	repo := fs.String("repo", "", "owner/name for issues (overrides config)")       // repo override
	minSeverity := fs.String("min-severity", "high", "minimum severity for issues") // filing threshold
	maxIssues := fs.Int("max-issues", 10, "max issues per run")                     // per-run cap

	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }      // give the flag set our usage text
	if err := fs.Parse(reorderArgs(fs, args)); err != nil { // parse flags anywhere on the line
		return err // propagate parse errors
	}

	cfg, err := config.Load(*cfgPath) // load config (defaults + file + env)
	if err != nil {
		return err
	}

	switch command { // dispatch after common setup
	case "hello": // simple greeting
		fmt.Printf("Hello from hackbot! (config: %s)\n", cfg.String()) // show config summary
		return nil
	case "run": // one bot cycle
		return bot.New(cfg).Run(context.Background())
	case "py": // Python escape hatch
		return bot.New(cfg).RunPython(context.Background(), fs.Args()) // pass remaining args to the helper
	case "nmap": // nmap subcommands
		return runNmap(cfg, fs.Args(), nmapFlags{ // collect relevant flags
			json:        *asJSON,       // JSON output
			useLLM:      *useLLM,       // LLM stage
			issues:      *createIssues, // actions stage
			dryRun:      *dryRun,       // dry-run safety
			repo:        *repo,         // repo override
			minSeverity: *minSeverity,  // threshold
			maxIssues:   *maxIssues,    // cap
		})
	}
	return nil // unreachable
}

// nmapFlags carries the nmap-related flags into runNmap.
type nmapFlags struct { // small struct keeps runNmap's signature tidy
	json        bool   // emit JSON
	useLLM      bool   // run LLM stage
	issues      bool   // run actions stage
	dryRun      bool   // dry-run issue creation
	repo        string // repo override
	minSeverity string // filing threshold
	maxIssues   int    // issue cap
}

// runNmap dispatches the parse/analyze/scan/pipeline subcommands.
func runNmap(cfg config.Config, args []string, fl nmapFlags) error { // nmap entry point
	if len(args) < 1 { // need a subcommand...
		return fmt.Errorf("nmap: missing subcommand (parse|analyze|scan|pipeline)") // ...else error
	}
	sub := args[0]   // the subcommand name
	rest := args[1:] // its arguments

	switch sub { // dispatch
	case "parse": // parse and list hosts/ports
		if len(rest) < 1 { // need a file...
			return fmt.Errorf("nmap parse: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0]) // read + parse XML
		if err != nil {
			return err
		}
		if fl.json { // JSON mode...
			return printJSON(nmapSummary(sc)) // ...emit a serializable summary
		}
		printScan(sc) // human mode
		return nil

	case "analyze": // rules-only risk report
		if len(rest) < 1 {
			return fmt.Errorf("nmap analyze: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0]) // parse
		if err != nil {
			return err
		}
		findings := nmap.Analyze(sc) // analyze
		if fl.json {                 // JSON mode
			return printJSON(findings)
		}
		printFindings(findings) // human mode
		return nil

	case "scan": // guarded live scan
		if len(rest) < 1 {
			return fmt.Errorf("nmap scan: missing <target>")
		}
		scanner := scan.New(scan.Options{ // build a scanner from config (safety gates included)
			NmapPath:       cfg.NmapPath,       // nmap binary
			Enable:         cfg.EnableScan,     // master switch (default false)
			AllowedTargets: cfg.AllowedTargets, // allowlist
		}, nil) // nil runner => real ExecRunner
		sc, err := scanner.Scan(context.Background(), rest[0]) // guarded scan
		if err != nil {
			return err
		}
		findings := nmap.Analyze(sc) // analyze results
		if fl.json {                 // JSON mode
			return printJSON(findings)
		}
		printScan(sc)           // show what was found
		printFindings(findings) // and the risk report
		return nil

	case "pipeline": // full modular pipeline on an existing file
		if len(rest) < 1 {
			return fmt.Errorf("nmap pipeline: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0]) // parse input
		if err != nil {
			return err
		}
		sev, err := parseSeverity(fl.minSeverity) // convert threshold string
		if err != nil {
			return err
		}
		rep, err := agent.Run(context.Background(), sc, agent.Options{ // run the pipeline
			UseLLM:       fl.useLLM,                              // stage 1 toggle
			CreateIssues: fl.issues,                              // stage 2 toggle
			DryRun:       fl.dryRun,                              // safety default true
			Repo:         firstNonEmpty(fl.repo, cfg.GitHubRepo), // flag overrides config
			MinSeverity:  sev,                                    // filing threshold
			MaxIssues:    fl.maxIssues,                           // cap
			LLM: agent.LLMClient{ // LLM settings from config
				BaseURL: cfg.LLMBaseURL,
				APIKey:  cfg.LLMAPIKey,
				Model:   cfg.LLMModel,
			},
			Log: func(s string) { fmt.Fprintln(os.Stderr, "hackbot:", s) }, // progress to stderr
		})
		if err != nil {
			return err
		}
		if fl.json { // JSON mode
			return printJSONIndent(rep) // Report has a JSON() method
		}
		fmt.Print(rep.Summary()) // human mode
		return nil

	default: // unknown subcommand
		return fmt.Errorf("nmap: unknown subcommand %q", sub)
	}
}

// printScan prints a human summary of a parsed scan.
func printScan(sc *nmap.Scan) { // used by parse and scan
	up := sc.UpHosts()                                                             // only show reachable hosts
	fmt.Printf("nmap %s: %d host(s), %d up\n", sc.Version, len(sc.Hosts), len(up)) // headline
	for _, h := range up {                                                         // one block per up host
		fmt.Printf("  %s\n", h.Label())   // host label
		for _, p := range h.OpenPorts() { // list open ports
			svc := p.Service.Name                                                                          // start with the service name
			banner := strings.TrimSpace(strings.Join([]string{p.Service.Product, p.Service.Version}, " ")) // "product version"
			if banner != "" {                                                                              // if we detected a product/version...
				svc = fmt.Sprintf("%s (%s)", svc, banner) // ...show it in parentheses
			}
			fmt.Printf("    %d/%s open  %s\n", p.Number, p.Protocol, svc) // port line
		}
	}
}

// printFindings prints a human summary of findings with a severity tally.
func printFindings(findings []nmap.Finding) { // used by analyze and scan
	if len(findings) == 0 { // nothing found...
		fmt.Println("no findings") // ...say so
		return
	}
	counts := nmap.Counts(findings)                                                                                  // tally by severity
	fmt.Printf("%d finding(s)", len(findings))                                                                       // headline count
	for _, sev := range []nmap.Severity{nmap.SevCritical, nmap.SevHigh, nmap.SevMedium, nmap.SevLow, nmap.SevInfo} { // worst first
		if counts[sev] > 0 { // only show severities present
			fmt.Printf("  %s:%d", sev, counts[sev]) // e.g. "CRITICAL:2"
		}
	}
	fmt.Println()                // end the headline line
	for _, f := range findings { // then each finding
		fmt.Printf("  %s\n", f.String()) // Finding.String() renders the detail block
	}
}

// printJSON marshals any value to indented JSON and prints it.
func printJSON(v any) error { // used for scan summary and findings
	data, err := json.MarshalIndent(v, "", "  ") // two-space indent
	if err != nil {
		return err
	}
	fmt.Println(string(data)) // print with trailing newline
	return nil
}

// portSummary is the JSON shape for an open port.
type portSummary struct { // used only for output
	Port     int    `json:"port"`              // port number
	Protocol string `json:"protocol"`          // tcp/udp
	Service  string `json:"service"`           // service name
	Product  string `json:"product,omitempty"` // detected product
	Version  string `json:"version,omitempty"` // detected version
}

// hostSummary is the JSON shape for a host.
type hostSummary struct { // used only for output
	Label     string        `json:"label"`                // display label
	Address   string        `json:"address,omitempty"`    // primary address
	Hostnames []string      `json:"hostnames,omitempty"`  // reverse-DNS names
	Status    string        `json:"status"`               // up/down
	OpenPorts []portSummary `json:"open_ports,omitempty"` // open ports
}

// scanSummary is the JSON shape for a whole scan.
type scanSummary struct { // used only for output
	Scanner   string        `json:"scanner"`        // scanner name
	Version   string        `json:"version"`        // nmap version
	Args      string        `json:"args,omitempty"` // recorded command line
	HostsUp   int           `json:"hosts_up"`       // reachable count
	HostsDown int           `json:"hosts_down"`     // unreachable count
	Hosts     []hostSummary `json:"hosts"`          // per-host details
}

// nmapSummary converts a parsed scan into its serializable form.
func nmapSummary(sc *nmap.Scan) scanSummary { // used by `nmap parse -json`
	s := scanSummary{ // start with top-level fields
		Scanner:   sc.Scanner,                        // scanner
		Version:   sc.Version,                        // version
		Args:      sc.Args,                           // command line
		HostsUp:   len(sc.UpHosts()),                 // up count
		HostsDown: len(sc.Hosts) - len(sc.UpHosts()), // down count
	}
	for _, h := range sc.Hosts { // convert each host
		hs := hostSummary{
			Label:     h.Label(),          // label
			Address:   h.PrimaryAddress(), // address
			Hostnames: h.Hostnames,        // names
			Status:    h.Status,           // up/down
		}
		for _, p := range h.OpenPorts() { // convert each open port
			hs.OpenPorts = append(hs.OpenPorts, portSummary{
				Port:     p.Number,          // number
				Protocol: p.Protocol,        // tcp/udp
				Service:  p.Service.Name,    // service
				Product:  p.Service.Product, // product
				Version:  p.Service.Version, // version
			})
		}
		s.Hosts = append(s.Hosts, hs) // add the host
	}
	return s // final summary
}

// printJSONIndent prints a value that knows how to render itself as JSON.
func printJSONIndent(v interface{ JSON() ([]byte, error) }) error { // used by the pipeline
	data, err := v.JSON() // delegate to the value's JSON() method
	if err != nil {
		return err
	}
	fmt.Println(string(data)) // print with trailing newline
	return nil
}

// parseSeverity converts a CLI severity string into a nmap.Severity.
func parseSeverity(s string) (nmap.Severity, error) { // used by pipeline
	switch strings.ToLower(strings.TrimSpace(s)) { // normalize input
	case "info": // informational
		return nmap.SevInfo, nil
	case "low": // low
		return nmap.SevLow, nil
	case "medium", "med": // medium (with shorthand)
		return nmap.SevMedium, nil
	case "high": // high
		return nmap.SevHigh, nil
	case "critical", "crit": // critical (with shorthand)
		return nmap.SevCritical, nil
	default: // unknown value
		return nmap.SevInfo, fmt.Errorf("invalid severity %q", s) // error
	}
}

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(vals ...string) string { // used to let flags override config
	for _, v := range vals { // check each candidate...
		if strings.TrimSpace(v) != "" { // ...returning the first non-blank
			return v
		}
	}
	return "" // all blank
}

// reorderArgs moves flags (and their values) ahead of positional arguments.
//
// The stdlib flag package stops at the first non-flag token, which would make
// flags placed after a subcommand/file (e.g. "pipeline scan.xml -issues") be
// silently ignored. Reordering lets users put flags anywhere.
func reorderArgs(fs *flag.FlagSet, args []string) []string { // returns a parse-safe ordering
	var flags, positional []string   // two buckets
	for i := 0; i < len(args); i++ { // walk the args once
		a := args[i] // current token
		switch {
		case a == "--": // explicit end-of-flags marker...
			positional = append(positional, args[i+1:]...) // ...everything after is positional
			return append(flags, positional...)            // return the merged ordering
		case strings.HasPrefix(a, "-") && a != "-": // a flag (but not a bare "-", often meaning stdin)
			flags = append(flags, a)      // keep the flag token
			if strings.Contains(a, "=") { // "-flag=value" already contains its value...
				continue // ...so nothing more to consume
			}
			name := strings.TrimLeft(a, "-")    // strip leading dashes to look up the flag
			if f := fs.Lookup(name); f != nil { // only consume a value if the flag is known
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() { // non-boolean flags take a value
					if i+1 < len(args) { // if a value token exists...
						flags = append(flags, args[i+1]) // ...move it into the flags bucket
						i++                              // ...and skip it
					}
				}
			}
		default: // positional token
			positional = append(positional, a) // keep in order
		}
	}
	return append(flags, positional...) // flags first, then positionals
}
