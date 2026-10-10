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
	"path/filepath" // join vulscan script paths
	"strings"       // arg/severity/string helpers

	"github.com/rjwashi/hackbot/internal/agent"   // the pipeline
	"github.com/rjwashi/hackbot/internal/bot"     // the core bot loop + Python bridge
	"github.com/rjwashi/hackbot/internal/config"  // configuration loading
	"github.com/rjwashi/hackbot/internal/cve"     // CVE search (NVD) agent
	"github.com/rjwashi/hackbot/internal/nmap"    // XML parsing + analysis
	"github.com/rjwashi/hackbot/internal/scan"    // guarded scanning
	"github.com/rjwashi/hackbot/internal/vulscan" // vulscan (VulDB) recon agent
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
  agents                    List the available agents (see agents flags below)
  help                      Show this help

  nmap parse   <file>       Parse an nmap XML file and list hosts/ports
  nmap analyze <file>       Parse + rule-based risk report
  nmap recon   <file>       Parse + list NSE script (recon) results
  nmap vulscan <file>       Parse + list vulscan (VulDB) vulnerability matches
  nmap scan    <target>     Run a GUARDED nmap scan, then analyze + recon
  nmap pipeline <file>      Full pipeline: analyze [+ llm] [+ issues]

  cve categories            List CVE search categories
  cve search <category>     Search NVD for CVEs in a category (xss, sqli, rce, ...)
  cve keyword <text>        Free-text CVE search
  cve scan <nmap.xml>       Search CVEs for software nmap detected

Common flags:
  -config PATH              Path to a JSON config file (optional)
  -json                     Machine-readable JSON output (nmap commands)

nmap scan flags:
  -scripts LIST             NSE scripts to run (default: safe recon set; "none" disables)
  -script-args STR          Extra args passed to nmap --script-args
  -vulscan                  Add vulscan (VulDB) recon to the scan

nmap pipeline flags:
  -llm                      Ask the configured LLM to explain/prioritize
  -issues                   File GitHub issues for findings
  -dry-run                  Do not actually create issues (default true)
  -repo owner/name          Override the target repo for issues
  -min-severity S           Minimum severity to file (info|low|medium|high|critical)
  -max-issues N             Max issues per run (default 10)

cve flags:
  -limit N                  Max CVE results to show (default 20)
  -min-score X              Only CVEs with CVSS >= X

agents flags:
  -format FMT               Output format: text (default), markdown, json, skill
  -name NAME                Agent name for -format skill

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
	case "hello", "run", "py", "nmap", "cve", "agents": // commands that load config and parse flags
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

	// nmap scan (NSE recon) flags.
	scripts := fs.String("scripts", "", "NSE scripts for nmap scan (comma list; default recon set)") // recon scripts
	scriptArgs := fs.String("script-args", "", "extra args for nmap --script-args")                  // script arguments
	addVulscan := fs.Bool("vulscan", false, "add vulscan (VulDB) recon to the scan")                 // vulscan toggle

	// cve (CVE search) flags.
	limit := fs.Int("limit", 20, "max CVE results to show")              // display cap
	minScore := fs.Float64("min-score", 0, "minimum CVSS score to show") // score floor

	// agents flags.
	agentFormat := fs.String("format", "text", "agents output format: text|markdown|json|skill") // listing format
	agentName := fs.String("name", "", "agent name for -format skill")                           // skill target

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
	case "agents": // list the available agents
		return printAgents(*agentFormat, *agentName)
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
			scripts:     *scripts,      // NSE scripts
			scriptArgs:  *scriptArgs,   // script args
			vulscan:     *addVulscan,   // vulscan toggle
		})
	case "cve": // CVE search subcommands
		return runCVE(cfg, fs.Args(), cveFlags{ // collect flags
			json:     *asJSON,   // JSON output
			limit:    *limit,    // result cap
			minScore: *minScore, // score floor
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
	scripts     string // comma-separated NSE scripts for `nmap scan`
	scriptArgs  string // value for nmap --script-args
	vulscan     bool   // add vulscan to the scan's script list
}

// runNmap dispatches the parse/analyze/recon/scan/pipeline subcommands.
func runNmap(cfg config.Config, args []string, fl nmapFlags) error { // nmap entry point
	if len(args) < 1 { // need a subcommand...
		return fmt.Errorf("nmap: missing subcommand (parse|analyze|recon|vulscan|scan|pipeline)") // ...else error
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

	case "recon": // NSE script results only
		if len(rest) < 1 { // need a file...
			return fmt.Errorf("nmap recon: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0]) // read + parse XML
		if err != nil {
			return err
		}
		items := nmap.Recon(sc) // flatten NSE script output
		if fl.json {            // JSON mode
			return printJSON(items)
		}
		printRecon(items) // human mode
		return nil

	case "vulscan": // vulscan (VulDB) matches only
		if len(rest) < 1 { // need a file...
			return fmt.Errorf("nmap vulscan: missing <file>")
		}
		sc, err := nmap.ParseFile(rest[0]) // read + parse XML
		if err != nil {
			return err
		}
		results := vulscan.Parse(sc) // parse vulscan output
		if fl.json {                 // JSON mode
			return printJSON(results)
		}
		fmt.Print(vulscan.Summary(sc)) // human mode
		return nil

	case "scan": // guarded live scan
		if len(rest) < 1 {
			return fmt.Errorf("nmap scan: missing <target>")
		}
		scriptsList := resolveScripts(fl.scripts, cfg.NmapScripts) // NSE scripts
		if fl.vulscan {                                            // optionally add vulscan...
			scriptsList = appendUnique(scriptsList, vulscanScriptPath(cfg.VulscanDir)) // ...to the list
		}
		scanner := scan.New(scan.Options{ // build a scanner from config (safety gates included)
			NmapPath:       cfg.NmapPath,                                                                               // nmap binary
			Enable:         cfg.EnableScan,                                                                             // master switch (default false)
			AllowedTargets: cfg.AllowedTargets,                                                                         // allowlist
			Scripts:        scriptsList,                                                                                // NSE recon scripts
			ScriptArgs:     withVulscanDB(firstNonEmpty(fl.scriptArgs, cfg.NmapScriptArgs), fl.vulscan, cfg.VulscanDB), // --script-args
		}, nil) // nil runner => real ExecRunner
		sc, err := scanner.Scan(context.Background(), rest[0]) // guarded scan
		if err != nil {
			return err
		}
		findings := nmap.Analyze(sc) // analyze results
		if fl.json {                 // JSON mode
			return printJSON(findings)
		}
		printScan(sc)                  // show what was found
		printFindings(findings)        // and the risk report
		printRecon(nmap.Recon(sc))     // and any NSE recon output
		fmt.Print(vulscan.Summary(sc)) // and any vulscan matches
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

// cveFlags carries the CVE-search flags into runCVE.
type cveFlags struct { // keeps runCVE's signature tidy
	json     bool    // emit JSON
	limit    int     // max results to show
	minScore float64 // minimum CVSS score to show
}

// runCVE dispatches the categories/search/keyword/scan subcommands.
func runCVE(cfg config.Config, args []string, fl cveFlags) error { // CVE entry point
	if len(args) < 1 { // need a subcommand...
		return fmt.Errorf("cve: missing subcommand (categories|search|keyword|scan)") // ...else error
	}
	sub := args[0]   // the subcommand
	rest := args[1:] // its arguments

	searcher := &cve.NVDClient{BaseURL: cfg.NVDBaseURL, APIKey: cfg.NVDAPIKey} // NVD data source
	cveAgent := &cve.Agent{                                                    // the search agent
		Searcher: searcher,                                                  // data source
		Limit:    fl.limit,                                                  // display cap
		MinScore: fl.minScore,                                               // score floor
		Log:      func(s string) { fmt.Fprintln(os.Stderr, "hackbot:", s) }, // progress to stderr
	}
	ctx := context.Background() // one-shot command context

	switch sub { // dispatch
	case "categories": // list the built-in categories
		printCVECategories()
		return nil

	case "search": // search one category
		if len(rest) < 1 { // need a category...
			return fmt.Errorf("cve search: missing <category> (try: %s)", strings.Join(cve.CategoryNames(), ", "))
		}
		rep, err := cveAgent.SearchCategory(ctx, rest[0]) // run the search
		if err != nil {
			return err
		}
		return emitCVEReport(rep, fl.json) // render

	case "keyword": // free-text search
		if len(rest) < 1 {
			return fmt.Errorf("cve keyword: missing <text>")
		}
		rep, err := cveAgent.SearchKeyword(ctx, strings.Join(rest, " ")) // join words into one phrase
		if err != nil {
			return err
		}
		return emitCVEReport(rep, fl.json)

	case "scan": // derive queries from an nmap file
		if len(rest) < 1 {
			return fmt.Errorf("cve scan: missing <nmap.xml>")
		}
		sc, err := nmap.ParseFile(rest[0]) // parse the scan
		if err != nil {
			return err
		}
		rep, err := cveAgent.SearchScan(ctx, sc) // search for the detected software
		if err != nil {
			return err
		}
		return emitCVEReport(rep, fl.json)

	default: // unknown subcommand
		return fmt.Errorf("cve: unknown subcommand %q", sub)
	}
}

// emitCVEReport prints a CVE report as JSON or human text.
func emitCVEReport(rep *cve.Report, asJSON bool) error { // shared renderer
	if asJSON { // JSON mode
		return printJSON(rep)
	}
	fmt.Print(rep.Summary()) // human mode
	return nil
}

// printCVECategories lists the built-in CVE categories.
func printCVECategories() { // used by `cve categories`
	fmt.Printf("%d categories:\n", len(cve.Categories)) // headline
	for _, c := range cve.Categories {                  // one row per category
		fmt.Printf("  %-22s %-9s %s\n", c.Name, c.CWE, c.Description) // name, CWE, description
	}
}

// vulscanScriptPath returns the NSE script path/name for vulscan.
//
// When VulscanDir is configured we point nmap at the script file directly;
// otherwise we rely on vulscan being installed under nmap's scripts directory
// (the documented install) as "vulscan/vulscan.nse".
func vulscanScriptPath(dir string) string { // used by `nmap scan -vulscan`
	if strings.TrimSpace(dir) != "" { // an explicit directory wins...
		return filepath.Join(dir, "vulscan.nse") // ...e.g. /opt/vulscan/vulscan.nse
	}
	return "vulscan/vulscan.nse" // documented default install location
}

// appendUnique appends s to list unless it is already present.
func appendUnique(list []string, s string) []string { // keeps the script list clean
	for _, v := range list { // scan existing entries...
		if v == s { // ...and skip duplicates
			return list
		}
	}
	return append(list, s) // add the new entry
}

// withVulscanDB adds vulscandb=<db> to the script args when vulscan is on.
func withVulscanDB(args string, enabled bool, db string) string { // builds --script-args
	if !enabled || strings.TrimSpace(db) == "" { // nothing to add...
		return args // ...leave the args unchanged
	}
	kv := "vulscandb=" + strings.TrimSpace(db) // the vulscan argument
	if strings.TrimSpace(args) == "" {         // no existing args...
		return kv // ...use just the vulscan arg
	}
	return args + "," + kv // otherwise append it
}

// agentInfo describes one available agent for `hackbot agents` and the docs.
//
// The registry below is the single source of truth: the CLI listing, the
// Markdown catalog in docs/agents.md, the README snapshot, and (later) OpenCode
// skills are all derived from it, and a test fails if the docs drift.
type agentInfo struct { // one row in the registry
	Name        string   `json:"name"`        // short agent name; doubles as the planned skill id
	Command     string   `json:"command"`     // invocation without the leading "hackbot"
	Description string   `json:"description"` // one-line summary (also the future skill description)
	Triggers    []string `json:"triggers"`    // phrases that should invoke this agent/skill later
}

// agents is the registry of security agents the CLI exposes.
var agents = []agentInfo{ // listed by `hackbot agents`
	{
		Name:        "nmap-analyze",
		Command:     "nmap analyze <file>",
		Description: "Rule-based exposure report from an nmap XML file (flags risky open services)",
		Triggers:    []string{"analyze an nmap scan for risky exposed services", "review an nmap XML file for security issues"},
	},
	{
		Name:        "nmap-recon",
		Command:     "nmap recon <file>",
		Description: "NSE script reconnaissance: banners, titles, headers, keys",
		Triggers:    []string{"list NSE script output from an nmap scan", "pull banners and service details from nmap XML"},
	},
	{
		Name:        "nmap-vulscan",
		Command:     "nmap vulscan <file>",
		Description: "Potential (unconfirmed) VulDB matches from vulscan NSE output",
		Triggers:    []string{"interpret vulscan output", "find potential vulnerabilities in an nmap scan"},
	},
	{
		Name:        "nmap-pipeline",
		Command:     "nmap pipeline <file> [-llm] [-issues]",
		Description: "Full pipeline: analyze + recon + vulscan [+ LLM] [+ issues]",
		Triggers:    []string{"run the full nmap analysis pipeline", "explain and file issues for nmap findings"},
	},
	{
		Name:        "cve-category",
		Command:     "cve search <category>",
		Description: "Search NVD for CVEs by category (xss, sqli, rce, ...), worst-first",
		Triggers:    []string{"find CVEs for a vulnerability category", "search for XSS or SQL injection CVEs"},
	},
	{
		Name:        "cve-keyword",
		Command:     "cve keyword <text>",
		Description: "Free-text CVE search across NVD",
		Triggers:    []string{"search CVEs by keyword or product name", "look up a CVE by free text"},
	},
	{
		Name:        "cve-scan",
		Command:     "cve scan <nmap.xml>",
		Description: "Find CVEs for the software nmap fingerprinted",
		Triggers:    []string{"find CVEs for the software in an nmap scan", "correlate nmap services with known CVEs"},
	},
}

// Markers delimit the generated agent listings inside the docs, so a test can
// verify they stay in sync with the registry above. Keep these strings in sync
// with docs/agents.md and README.md.
const (
	agentTableBegin = "<!-- BEGIN AGENTS TABLE (generated by `hackbot agents -format markdown`) -->"
	agentTableEnd   = "<!-- END AGENTS TABLE -->"
	agentsSnapBegin = "<!-- BEGIN AGENTS (generated by `hackbot agents`) -->"
	agentsSnapEnd   = "<!-- END AGENTS -->"
)

// agentsText renders the plain-text listing printed by `hackbot agents` and
// snapshotted in the README.
func agentsText() string { // keep the README snapshot in sync via the test
	var b strings.Builder                        // accumulate the listing
	fmt.Fprintf(&b, "%d agents:\n", len(agents)) // headline count
	for _, a := range agents {                   // one row per agent
		fmt.Fprintf(&b, "  %-14s %-40s %s\n", a.Name, a.Command, a.Description)
	}
	return b.String() // finished listing
}

// agentsMarkdown renders the catalog as a Markdown table (used in docs).
func agentsMarkdown() string { // keep docs/agents.md in sync via the test
	var b strings.Builder                                 // accumulate the table
	b.WriteString("| Agent | Command | What it does |\n") // header row
	b.WriteString("| --- | --- | --- |\n")                // separator row
	for _, a := range agents {                            // one table row per agent
		fmt.Fprintf(&b, "| `%s` | `hackbot %s` | %s |\n", a.Name, a.Command, a.Description)
	}
	return b.String() // finished table
}

// agentsJSON renders the registry as indented JSON.
func agentsJSON() (string, error) { // used by `-format json`
	data, err := json.MarshalIndent(agents, "", "  ") // pretty-print the registry
	if err != nil {                                   // practically unreachable, but handle it
		return "", err
	}
	return string(data) + "\n", nil // trailing newline for shells
}

// agentSkill renders an OpenCode SKILL.md scaffold for one agent.
//
// Skills are built later; this scaffold captures the name, description,
// triggers, and command so authoring is mostly filling in examples and notes.
func agentSkill(a agentInfo) string { // used by `agents -format skill -name <agent>`
	var b strings.Builder                                                                     // accumulate the scaffold
	fmt.Fprintf(&b, "---\nname: %s\ndescription: %s. Use when the user asks to %s.\n---\n\n", // YAML frontmatter
		a.Name, a.Description, strings.Join(a.Triggers, "; "))
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", a.Name, a.Description)                 // title + summary
	fmt.Fprintf(&b, "## Command\n\n```bash\nhackbot %s\n```\n\n", a.Command) // canonical invocation
	b.WriteString("## Notes\n\n")                                            // authoring checklist
	b.WriteString("- TODO: document inputs, outputs, and when NOT to use this agent.\n")
	b.WriteString("- TODO: add worked examples against `internal/nmap/testdata/sample.xml`.\n")
	b.WriteString("- Scanning requires `enable_scan=true` and a target inside `allowed_targets`; issue filing defaults to dry-run.\n")
	return b.String() // finished scaffold
}

// agentNames returns the registered agent names, comma-separated.
func agentNames() string { // used in error messages
	names := make([]string, 0, len(agents)) // accumulator
	for _, a := range agents {              // collect names in registry order
		names = append(names, a.Name)
	}
	return strings.Join(names, ", ") // "a, b, c"
}

// findAgent looks up an agent by name (case-insensitive).
func findAgent(name string) (agentInfo, bool) { // used by `-format skill`
	for _, a := range agents { // linear scan (tiny N)
		if strings.EqualFold(a.Name, strings.TrimSpace(name)) {
			return a, true
		}
	}
	return agentInfo{}, false // not found
}

// printAgents lists the available agents in the requested format.
func printAgents(format, name string) error { // used by `hackbot agents`
	switch strings.ToLower(strings.TrimSpace(format)) { // normalize the format
	case "", "text": // default human listing
		fmt.Print(agentsText())
	case "markdown", "md": // docs table
		fmt.Print(agentsMarkdown())
	case "json": // machine-readable registry
		s, err := agentsJSON()
		if err != nil {
			return err
		}
		fmt.Print(s)
	case "skill": // SKILL.md scaffold for one agent
		if strings.TrimSpace(name) == "" { // need a target agent...
			return fmt.Errorf("agents: -format skill needs -name <agent> (one of: %s)", agentNames())
		}
		a, ok := findAgent(name) // look it up
		if !ok {                 // unknown agent...
			return fmt.Errorf("agents: unknown agent %q (one of: %s)", name, agentNames())
		}
		fmt.Print(agentSkill(a)) // print the scaffold
	default: // unknown format
		return fmt.Errorf("agents: unknown -format %q (text|markdown|json|skill)", format)
	}
	return nil // success
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
			if len(p.Scripts) > 0 {                                       // if NSE scripts ran on this port...
				fmt.Printf("      scripts: %s\n", scriptIDs(p.Scripts)) // ...list their ids compactly
			}
		}
	}
}

// scriptIDs joins script ids into a comma-separated list for display.
func scriptIDs(scripts []nmap.Script) string { // small display helper
	ids := make([]string, 0, len(scripts)) // collect ids in order
	for _, s := range scripts {            // walk the scripts...
		ids = append(ids, s.ID) // ...keeping each id
	}
	return strings.Join(ids, ", ") // "banner, http-title"
}

// printRecon prints the NSE script results gathered from a scan.
func printRecon(items []nmap.ReconItem) { // used by recon and scan
	if len(items) == 0 { // nothing gathered...
		fmt.Println("no NSE script results") // ...say so plainly
		return
	}
	fmt.Printf("%d recon item(s)\n", len(items)) // headline count
	for _, it := range items {                   // one block per item
		fmt.Printf("  %s\n", it.String()) // ReconItem.String() renders the detail
	}
}

// printFindings prints a human summary of findings with a severity tally.
func printFindings(findings []nmap.Finding) { // used by analyze and scan
	if len(findings) == 0 { // nothing found...
		fmt.Println("no findings") // ...say so plainly
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
	Port     int           `json:"port"`              // port number
	Protocol string        `json:"protocol"`          // tcp/udp
	Service  string        `json:"service"`           // service name
	Product  string        `json:"product,omitempty"` // detected product
	Version  string        `json:"version,omitempty"` // detected version
	Scripts  []nmap.Script `json:"scripts,omitempty"` // NSE script results, if any
}

// hostSummary is the JSON shape for a host.
type hostSummary struct { // used only for output
	Label     string        `json:"label"`                // display label
	Address   string        `json:"address,omitempty"`    // primary address
	Hostnames []string      `json:"hostnames,omitempty"`  // reverse-DNS names
	Status    string        `json:"status"`               // up/down
	OpenPorts []portSummary `json:"open_ports,omitempty"` // open ports
	Scripts   []nmap.Script `json:"scripts,omitempty"`    // host-level NSE scripts
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
			Scripts:   h.Scripts,          // host-level NSE scripts
		}
		for _, p := range h.OpenPorts() { // convert each open port
			hs.OpenPorts = append(hs.OpenPorts, portSummary{
				Port:     p.Number,          // number
				Protocol: p.Protocol,        // tcp/udp
				Service:  p.Service.Name,    // service
				Product:  p.Service.Product, // product
				Version:  p.Service.Version, // version
				Scripts:  p.Scripts,         // port-level NSE scripts
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

// resolveScripts decides which NSE scripts a scan should run.
//
// Precedence: an explicit -scripts flag wins; otherwise a configured
// nmap_scripts value is used; otherwise the built-in safe recon profile. The
// flag values "none"/"off" (or a configured empty list) disable scripts.
func resolveScripts(flagValue string, configured []string) []string { // used by `nmap scan`
	if strings.TrimSpace(flagValue) != "" { // an explicit flag always wins...
		return parseScriptList(flagValue) // ...parsed as a comma list
	}
	if configured != nil { // a configured value (even empty) overrides the default...
		return configured // ...so an empty list can disable scripts
	}
	return scan.ReconScripts // fall back to the built-in safe recon profile
}

// parseScriptList parses a comma-separated -scripts value.
func parseScriptList(v string) []string { // mirrors config.parseScripts for CLI values
	switch strings.ToLower(strings.TrimSpace(v)) { // normalize case/space
	case "none", "off": // explicit disable...
		return []string{} // ...a non-nil empty slice means "run no scripts"
	default: // otherwise...
		var out []string                             // accumulate non-empty entries
		for _, part := range strings.Split(v, ",") { // split on commas
			if p := strings.TrimSpace(part); p != "" { // trim and drop blanks
				out = append(out, p) // keep real entries
			}
		}
		return out // the parsed list (may be nil if the value was only commas)
	}
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
