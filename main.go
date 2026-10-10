// Command hackbot is the entry point for the hackbot project.
//
// hackbot is a Go-first bot project. Go owns the core bot logic; anything Go
// cannot do cleanly (or quickly) is delegated to small Python helpers under
// pythontools/.
package main // package main makes this an executable

import ( // imports for the whole CLI
	"context"       // background context for one-shot commands
	"embed"         // embed the WSTG checklist Markdown files
	"encoding/json" // JSON output for nmap commands
	"errors"        // errors.Is to special-case canceled contexts
	"flag"          // stdlib flag parsing for subcommand flags
	"fmt"           // printing and error formatting
	"io/fs"         // fs.SkipDir + fs.DirEntry for the layout walk
	"os"            // args, exit codes, stderr
	"path/filepath" // join vulscan script paths and walk the repo tree
	"sort"          // deterministic repo layout ordering
	"strings"       // arg/severity/string helpers
	"time"          // web check timeouts

	"github.com/rjwashi/hackbot/internal/agent"   // the pipeline
	"github.com/rjwashi/hackbot/internal/bot"     // the core bot loop + Python bridge
	"github.com/rjwashi/hackbot/internal/config"  // configuration loading
	"github.com/rjwashi/hackbot/internal/cve"     // CVE search (NVD) agent
	"github.com/rjwashi/hackbot/internal/nmap"    // XML parsing + analysis
	"github.com/rjwashi/hackbot/internal/ops"     // recon + content-discovery engine
	"github.com/rjwashi/hackbot/internal/scan"    // guarded scanning
	"github.com/rjwashi/hackbot/internal/vulscan" // vulscan (VulDB) recon agent
	"github.com/rjwashi/hackbot/internal/wstg"    // WSTG web-security-testing checklists
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev" // default for local builds

// checklistsDir is where the WSTG checklist Markdown files live in the repo.
const checklistsDir = "src/agent_files" // used by the `web` command

// checklistsFS embeds the WSTG checklist Markdown files so the web-security
// agents work from any directory without the source tree on disk.
//
//go:embed src/agent_files/*.md
var checklistsFS embed.FS // embedded checklist filesystem

const usage = `hackbot - a Go-first bot with Python helpers

Usage:
  hackbot <command> [args]

Commands:
  hello                     Print a greeting
  run                       Run the bot once (loads config, executes bot steps)
  py <helper> [args...]     Run a Python helper (Go->Python escape hatch)
  version                   Print version
  agents                    List the available agents (see agents flags below)
  layout                    Print the repository layout (full paths)
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

  web list                  List WSTG web-security-testing categories
  web show <category>       Show one WSTG category's test checklist
  web tools [category]      List the free/open-source tools for a category
  web plan <category>       Map each test to a free tool or manual guidance
  web run <category> <tgt>  Run guarded checks (dry-run by default)

  recon list                List recon/OSINT tasks (subdomains, dns, ports, ...)
  recon chains              List recon pipelines (e.g. footprint)
  recon tools [group]       List the free recon tools
  recon plan                Show every recon task and its command
  recon <task> <target>     Run a recon task (dry-run by default)
  recon footprint <target>  Chain: subfinder subdomains -> httpx live probe

  discover list             List content-discovery tasks
  discover chains           List discovery pipelines (none yet)
  discover tools [group]    List the free content-discovery tools
  discover plan             Show every discovery task and its command
  discover <task> <target>  Run a discovery task (dry-run by default)

  secrets list              List secret-scanning tasks (scan, history, verify, entropy)
  secrets tools [group]     List the free secret scanners
  secrets plan              Show every secrets task and its command
  secrets <task> <path>     Run a secret scan on a local path (dry-run by default)

  deps list                 List dependency/SBOM tasks (vulns, sbom, grype, osv)
  deps tools [group]        List the free dependency/SBOM tools
  deps plan                 Show every deps task and its command
  deps <task> <path>        Run a dependency/SBOM scan on a local path (dry-run by default)

Common flags:
  -config PATH              Path to a JSON config file (optional)
  -json                     Machine-readable JSON output (nmap commands)

web run flags:
  -dry-run                  Do not execute tools (default true; pass -dry-run=false)
  -timeout DURATION         Per-check timeout (default 60s)
  -scheme SCHEME            URL scheme used to build {url} (default https)
  -test ID                  Run only one WSTG test id (e.g. WSTG-INJT-05)

recon/discover/secrets/deps flags:
  -dry-run                  Do not execute tools (default true; pass -dry-run=false)
  -timeout DURATION         Per-task timeout (default 60s)
  -scheme SCHEME            URL scheme used to build {url} (default https)
  -wordlist PATH            Wordlist for content discovery (default: SecLists common.txt)

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
allowed_targets (IPs/CIDRs) or allowed_domains (names); local tools (secrets/deps)
additionally require the path to be inside allowed_paths. Only scan systems you
own or are explicitly authorized to test.
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
	case "hello", "run", "py", "nmap", "cve", "agents", "layout", "web", "recon", "discover", "secrets", "deps": // commands that load config and parse flags
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

	// web (WSTG) flags.
	webTimeout := fs.Duration("timeout", 60*time.Second, "per-check timeout for web run") // bound each tool
	webScheme := fs.String("scheme", "https", "URL scheme for web run (https|http)")      // target URL scheme
	webTest := fs.String("test", "", "only run this WSTG test id (web run)")              // single-capability filter

	// recon/discover flags.
	wordlist := fs.String("wordlist", "", "wordlist path for content discovery") // discovery wordlist override

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
	case "layout": // print the repository layout (full paths)
		root := "."                     // default to the current directory
		if a := fs.Args(); len(a) > 0 { // allow an explicit directory
			root = a[0]
		}
		return printLayout(root)
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
	case "web": // WSTG web-security-testing agents
		return runWeb(cfg, fs.Args(), webFlags{ // pass config + web flags
			json:    *asJSON,     // JSON output
			dryRun:  *dryRun,     // dry-run default true (no traffic)
			timeout: *webTimeout, // per-check timeout
			scheme:  *webScheme,  // target URL scheme
			test:    *webTest,    // optional single-test filter
		})
	case "recon": // OSINT reconnaissance agents
		return runOps(cfg, ops.ReconCatalog(), fs.Args(), opsFlags{ // recon catalog
			json:     *asJSON,                                                     // JSON output
			dryRun:   *dryRun,                                                     // dry-run default true
			timeout:  *webTimeout,                                                 // per-task timeout
			scheme:   *webScheme,                                                  // URL scheme
			wordlist: firstNonEmpty(*wordlist, cfg.Wordlist, ops.DefaultWordlist), // wordlist (unused by recon but harmless)
		})
	case "discover": // content-discovery agents
		return runOps(cfg, ops.DiscoveryCatalog(), fs.Args(), opsFlags{ // discovery catalog
			json:     *asJSON,                                                     // JSON output
			dryRun:   *dryRun,                                                     // dry-run default true
			timeout:  *webTimeout,                                                 // per-task timeout
			scheme:   *webScheme,                                                  // URL scheme
			wordlist: firstNonEmpty(*wordlist, cfg.Wordlist, ops.DefaultWordlist), // wordlist resolution
		})
	case "secrets": // local secret-scanning agents
		return runOps(cfg, ops.SecretsCatalog(), fs.Args(), opsFlags{ // secrets catalog (path targets)
			json:    *asJSON,     // JSON output
			dryRun:  *dryRun,     // dry-run default true
			timeout: *webTimeout, // per-task timeout
			scheme:  *webScheme,  // URL scheme (unused by path catalogs, harmless)
		})
	case "deps": // dependency / SBOM agents
		return runOps(cfg, ops.DepsCatalog(), fs.Args(), opsFlags{ // deps catalog (path targets)
			json:    *asJSON,     // JSON output
			dryRun:  *dryRun,     // dry-run default true
			timeout: *webTimeout, // per-task timeout
			scheme:  *webScheme,  // URL scheme (unused by path catalogs, harmless)
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

// webFlags carries the WSTG flags into runWeb.
//
// WHY a struct: runWeb grew from a single bool (JSON) into several knobs, and a
// struct keeps the call site readable and easy to extend without churning the
// signature again. Alternative considered: pass the *flag.FlagSet directly, but
// that couples runWeb to CLI parsing and makes it harder to unit test.
type webFlags struct {
	json    bool          // emit JSON (machine-readable)
	dryRun  bool          // render commands but send nothing (SECURITY: default true)
	timeout time.Duration // per-check timeout (a hung tool must not hang the run)
	scheme  string        // URL scheme used to build {url} (https by default)
	test    string        // optional single-test filter for `web run`
}

// runWeb dispatches the WSTG web-security-testing agents.
//
// Subcommands:
//
//	web list                    list the 12 categories (default)
//	web show <category>         print one category's test checklist
//	web tools [category]        list the free/open-source tools
//	web plan <category>         map every test to a tool or manual guidance
//	web run <category> <target> run the automatable checks (guarded, dry-run default)
//
// WHY these five verbs: they mirror the user's mental model of the feature —
// see the checklist, see the free tooling, see the plan, then (carefully) run it.
// WHY a bare `web <category>` also works: it is the most common thing to type,
// so accepting it avoids a papercut; it simply forwards to `show`.
//
// The category may be a slug (injection), code (WSTG-INJT), human name
// (Injection), or file name (Injection.md); wstg.Find normalizes all four.
func runWeb(cfg config.Config, args []string, fl webFlags) error { // used by `hackbot web`
	checklists, err := wstg.Load(checklistsFS, checklistsDir) // load the embedded checklist files
	if err != nil {                                           // embedded files should always load
		return err
	}
	sub := "" // the subcommand (lowercased); empty means "list"
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}
	switch sub { // dispatch
	case "", "list": // catalog of categories
		if fl.json { // JSON mode
			return printJSON(checklists)
		}
		fmt.Print(wstg.List(checklists)) // human catalog
		return nil
	case "show": // show one checklist
		if len(args) < 2 { // need a category...
			return fmt.Errorf("web show: missing <category> (try: hackbot web list)") // ...else error
		}
		return showWebChecklist(checklists, args[1], fl.json) // render it
	case "tools": // list the free tooling
		return runWebTools(checklists, args[1:], fl)
	case "plan": // map tests to tools/manual steps
		return runWebPlan(checklists, args[1:], fl)
	case "run": // guarded execution
		return runWebChecks(cfg, checklists, args[1:], fl)
	default: // bare category is a convenience for `show`
		return showWebChecklist(checklists, args[0], fl.json)
	}
}

// showWebChecklist prints one category's checklist as text or JSON.
//
// WHY this is separate from runWeb: keeping it tiny makes the happy path obvious
// and lets both `show` and the bare-category shortcut share exactly one code path.
func showWebChecklist(checklists []wstg.Checklist, query string, asJSON bool) error { // used by `web show`
	c, ok := wstg.Find(checklists, query) // look up the checklist
	if !ok {                              // unknown category...
		return fmt.Errorf("web: unknown category %q (try: hackbot web list)", query) // ...error with a hint
	}
	if asJSON { // JSON mode
		return printJSON(c)
	}
	fmt.Print(c.Summary()) // human mode
	return nil
}

// runWebTools lists the free tool catalog, or one category's toolset.
//
// WHY show the whole catalog by default: a first-time user wants to know what
// hackbot can drive before picking a category. The per-category view is the
// focused follow-up. Alternative considered: only expose per-category, but then
// there is no single place to learn install commands for all tools.
func runWebTools(checklists []wstg.Checklist, rest []string, fl webFlags) error { // used by `web tools`
	if len(rest) == 0 { // whole catalog
		tools := wstg.Tools() // sorted catalog
		if fl.json {          // JSON mode
			return printJSON(tools)
		}
		fmt.Printf("%d free/open-source tools:\n", len(tools)) // headline
		for _, t := range tools {                              // one row per tool
			fmt.Printf("  %-12s %-14s %-16s %s\n", t.Key, t.Name, t.License, t.URL)
			if t.Install != "" { // install hint, when known
				fmt.Printf("      install: %s\n", t.Install)
			}
		}
		return nil
	}
	c, ok := wstg.Find(checklists, rest[0]) // a category was named
	if !ok {                                // unknown category...
		return fmt.Errorf("web tools: unknown category %q (try: hackbot web list)", rest[0])
	}
	tools := wstg.ToolsFor(c.Slug) // the curated toolset
	if fl.json {                   // JSON mode
		return printJSON(tools)
	}
	fmt.Printf("%s (%s): %d free tool(s)\n", c.Category, c.Code, len(tools)) // headline
	for _, t := range tools {                                                // one row per tool
		fmt.Printf("  %-12s %-14s %s\n", t.Key, t.Name, t.URL)
	}
	fmt.Printf("reference: %s\n", wstg.WSTGBaseURL) // OWASP WSTG (free reference)
	return nil
}

// runWebPlan maps every test in a category to a tool or manual guidance.
//
// WHY render placeholders (no target): a plan is reference material, not an
// action. Showing "{url}"/"{host}" keeps it honest about where a target goes and
// avoids implying traffic was sent. Pass a target to `web run` to fill them in.
// Alternative considered: require a target for `plan`, but that would make the
// most useful reference view depend on having a live target.
func runWebPlan(checklists []wstg.Checklist, rest []string, fl webFlags) error { // used by `web plan`
	if len(rest) < 1 { // need a category...
		return fmt.Errorf("web plan: missing <category> (try: hackbot web list)")
	}
	c, ok := wstg.Find(checklists, rest[0]) // look up the checklist
	if !ok {                                // unknown category...
		return fmt.Errorf("web plan: unknown category %q (try: hackbot web list)", rest[0])
	}
	steps := wstg.Plan(c, fl.scheme, "") // render with placeholders (no target yet)
	if fl.json {                         // JSON mode
		return printJSON(steps)
	}
	auto := 0                 // count automated capabilities
	for _, s := range steps { // tally
		if s.Automated {
			auto++
		}
	}
	fmt.Printf("%s (%s): %d tests, %d automated\n", c.Category, c.Code, len(steps), auto) // headline
	for _, s := range steps {                                                             // one step per test
		if s.Automated { // automated: show the tool + command template
			fmt.Printf("  [auto] %-13s %-44s %s\n", s.TestID, s.Name, s.Command)
			continue
		}
		fmt.Printf("  [man ] %-13s %-44s %s\n", s.TestID, s.Name, s.Manual) // manual: show guidance
	}
	return nil
}

// runWebChecks runs a category's automatable checks against a target.
//
// SECURITY: real execution requires the same two gates as nmap scanning
// (enable_scan plus an allowed_targets match). We check them here as well as in
// the runner so the CLI can print a precise, actionable message; the runner
// still enforces them as the authoritative guard, so a caller that bypasses the
// CLI cannot skip safety. WHY not gate dry-run too: a dry-run sends nothing, so
// requiring configuration first would block the most useful "what would you do?"
// preview. The banner makes the dry-run state explicit so it can't be confused
// with a real run.
func runWebChecks(cfg config.Config, checklists []wstg.Checklist, rest []string, fl webFlags) error { // used by `web run`
	if len(rest) < 2 { // need a category and a target...
		return fmt.Errorf("web run: usage: web run <category> <target> (dry-run by default)")
	}
	c, ok := wstg.Find(checklists, rest[0]) // look up the category
	if !ok {                                // unknown category...
		return fmt.Errorf("web run: unknown category %q (try: hackbot web list)", rest[0])
	}
	target := rest[1]                     // the target (IP or CIDR in the allowlist)
	checks := wstg.ChecksFor(c.Slug)      // automatable capabilities
	if strings.TrimSpace(fl.test) != "" { // -test narrows to one test id...
		checks = nil                                   // ...reset the list
		for _, ck := range wstg.CheckByTest(fl.test) { // and keep only matching checks in this category
			if ck.Slug == c.Slug {
				checks = append(checks, ck)
			}
		}
	}
	if len(checks) == 0 { // nothing automatable here...
		return fmt.Errorf("web run: no automated checks for %s (see: hackbot web plan %s)", c.Slug, c.Slug)
	}
	if !fl.dryRun { // REAL runs enforce the safety gates up front for a clear message
		if !cfg.EnableScan { // master switch?
			return fmt.Errorf("web run: %w", wstg.ErrWebDisabled) // explain how to enable
		}
		if !scan.InScope(target, cfg.AllowedTargets) { // allowlist?
			return fmt.Errorf("web run: target %q is not in allowed_targets; refusing to run", target) // refuse
		}
	}
	names := map[string]string{} // test id -> name, for reporting
	for _, t := range c.Tests {  // index the checklist names
		names[t.ID] = t.Name
	}
	runner := wstg.NewRunner(wstg.RunnerOptions{ // assemble the guarded runner
		Enable:         cfg.EnableScan,                                            // master switch
		AllowedTargets: cfg.AllowedTargets,                                        // allowlist
		DryRun:         fl.dryRun,                                                 // dry-run default true
		Timeout:        fl.timeout,                                                // per-check timeout
		Scheme:         fl.scheme,                                                 // URL scheme
		Log:            func(s string) { fmt.Fprintln(os.Stderr, "hackbot:", s) }, // progress to stderr
	})
	results := runner.RunChecks(context.Background(), checks, func(ck wstg.Check) string { return names[ck.TestID] }, target)
	if fl.json { // JSON mode
		return printJSON(results)
	}
	if fl.dryRun { // make the safety state explicit
		fmt.Println("dry-run: no traffic sent (pass -dry-run=false to execute)")
	}
	okCount := 0 // tally successes
	for _, r := range results {
		status := "ok" // default label
		switch {       // choose a label
		case r.DryRun: // dry-run rows
			status = "dry"
		case !r.OK: // failures
			status = "error"
		default: // successes
			okCount++
		}
		fmt.Printf("  [%s] %-13s %s\n", status, r.TestID, r.Command) // one line per check
		if r.Output != "" {                                          // show captured output, indented
			for _, line := range strings.Split(r.Output, "\n") { // line by line
				fmt.Printf("      %s\n", line)
			}
		}
		if r.Error != "" { // show tool errors
			fmt.Printf("      error: %s\n", r.Error)
		}
	}
	if !fl.dryRun { // summarize real runs
		fmt.Printf("%d/%d check(s) completed without error\n", okCount, len(results))
	}
	return nil
}

// opsFlags carries the recon/discover flags into runOps.
//
// WHY a separate struct (rather than reusing webFlags): the new families share
// dry-run/timeout/scheme with `web`, but they add a wordlist and drop the WSTG
// test filter. A dedicated struct keeps each command's contract explicit.
type opsFlags struct {
	json     bool          // emit JSON
	dryRun   bool          // render commands but send nothing (SECURITY: default true)
	timeout  time.Duration // per-task timeout
	scheme   string        // URL scheme used to build {url}
	wordlist string        // resolved wordlist path (flag > config > default)
}

// runOps dispatches the recon/discover agents against a catalog.
//
// Subcommands:
//
//	<cmd> list               list the tasks (default)
//	<cmd> chains             list the multi-step pipelines (e.g. footprint)
//	<cmd> tools [group]      list the free tools, or one group's tools
//	<cmd> plan [task]        show every task (or one) with its command
//	<cmd> <task> <target>    run a task (guarded, dry-run default)
//	<cmd> <chain> <target>   run a chain (guarded, dry-run default)
//	<cmd> run <task> <target>  explicit run form
//
// WHY the bare `<task> <target>` form: it is the common case, so we accept it
// directly (like `web <category>`), while `run` stays available for scripts that
// want an explicit verb. A chain key is accepted in the same position, so
// `recon footprint example.com` works without a special verb.
func runOps(cfg config.Config, cat *ops.Catalog, args []string, fl opsFlags) error { // used by recon/discover/secrets/deps
	sub := "" // subcommand (lowercased); empty means "list"
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}
	switch sub { // dispatch
	case "", "list": // task catalog
		if fl.json { // JSON mode
			return printJSON(cat.Tasks())
		}
		fmt.Print(opsList(cat))
		return nil
	case "tasks", "show": // alias for list (kept tiny on purpose)
		if fl.json {
			return printJSON(cat.Tasks())
		}
		fmt.Print(opsList(cat))
		return nil
	case "chains": // multi-step pipelines
		return runOpsChains(cat, fl)
	case "tools": // free tooling
		return runOpsTools(cat, args[1:], fl)
	case "plan": // rendered commands
		return runOpsPlan(cat, args[1:], fl)
	case "run": // explicit run form
		if len(args) < 3 { // need <task|chain> <target>
			return fmt.Errorf("%s run: usage: %s run <task> <target> (dry-run by default)", cat.Name, cat.Name)
		}
		if ch, ok := cat.ChainByKey(args[1]); ok { // a chain can also be run explicitly
			return runOpsChain(cfg, cat, ch, args[2], fl)
		}
		return runOpsTask(cfg, cat, args[1], args[2], fl)
	default: // bare <task|chain> <target>
		if len(args) < 2 { // a task needs a target
			return fmt.Errorf("%s: usage: %s <task> <target> (try: hackbot %s list)", cat.Name, cat.Name, cat.Name)
		}
		if ch, ok := cat.ChainByKey(args[0]); ok { // a chain key takes precedence here
			return runOpsChain(cfg, cat, ch, args[1], fl)
		}
		return runOpsTask(cfg, cat, args[0], args[1], fl)
	}
}

// runOpsChains lists a catalog's multi-step pipelines (its `chains` subcommand).
func runOpsChains(cat *ops.Catalog, fl opsFlags) error { // used by `<cmd> chains`
	chains := cat.Chains() // declared order
	if len(chains) == 0 {  // not every catalog has chains yet
		fmt.Printf("%s: no chains defined\n", cat.Name)
		return nil
	}
	if fl.json {
		return printJSON(chains)
	}
	fmt.Printf("%s: %d chain(s)\n", cat.Name, len(chains))
	for _, ch := range chains { // one line per chain
		fmt.Printf("  %-12s %-40s %d step(s)\n", ch.Key, ch.Name, len(ch.Steps))
		if ch.Note != "" {
			fmt.Printf("      %s\n", ch.Note)
		}
	}
	return nil
}

// opsList renders a catalog's tasks as a short catalog.
func opsList(cat *ops.Catalog) string { // used by `<cmd> list`
	tasks := cat.Tasks()                                // declared order
	var b strings.Builder                               // accumulate text
	fmt.Fprintf(&b, "%s - %s\n", cat.Name, cat.Summary) // headline
	fmt.Fprintf(&b, "%d tasks:\n", len(tasks))          // count
	for _, t := range tasks {                           // one line per task
		tool, _ := cat.ToolByKey(t.ToolKey) // resolve the tool for display
		fmt.Fprintf(&b, "  %-12s %-26s [%s]\n", t.Key, t.Name, tool.Name)
	}
	return b.String()
}

// runOpsTools lists the free tool catalog, or one group's tools.
func runOpsTools(cat *ops.Catalog, rest []string, fl opsFlags) error { // used by `<cmd> tools`
	if len(rest) == 0 { // whole catalog
		tools := cat.Tools() // sorted
		if fl.json {
			return printJSON(tools)
		}
		fmt.Printf("%d free/open-source tools:\n", len(tools))
		for _, t := range tools {
			fmt.Printf("  %-12s %-16s %-16s %s\n", t.Key, t.Name, t.License, t.URL)
			if t.Install != "" {
				fmt.Printf("      install: %s\n", t.Install)
			}
		}
		return nil
	}
	group := strings.ToLower(rest[0]) // a group was named
	tools := cat.ToolsFor(group)      // resolve it
	if len(tools) == 0 {              // unknown group...
		return fmt.Errorf("%s tools: unknown group %q (groups: %s)", cat.Name, rest[0], strings.Join(cat.GroupNames(), ", "))
	}
	if fl.json {
		return printJSON(tools)
	}
	fmt.Printf("%s: tools for %q:\n", cat.Name, group)
	for _, t := range tools {
		fmt.Printf("  %-12s %-16s %s\n", t.Key, t.Name, t.URL)
	}
	return nil
}

// runOpsPlan shows each task and the command it would run (placeholders intact).
func runOpsPlan(cat *ops.Catalog, rest []string, fl opsFlags) error { // used by `<cmd> plan`
	steps := cat.Plan(fl.scheme, "", fl.wordlist) // template render (no target)
	if len(rest) > 0 {                            // optional single-task filter
		key := strings.ToLower(rest[0])
		var filtered []ops.PlanStep
		for _, s := range steps {
			if strings.EqualFold(s.TaskKey, key) {
				filtered = append(filtered, s)
			}
		}
		if len(filtered) == 0 { // unknown task...
			return fmt.Errorf("%s plan: unknown task %q (try: hackbot %s list)", cat.Name, rest[0], cat.Name)
		}
		steps = filtered
	}
	if fl.json {
		return printJSON(steps)
	}
	fmt.Printf("%s: %d task(s)\n", cat.Name, len(steps))
	for _, s := range steps {
		fmt.Printf("  %-12s %-26s %s\n", s.TaskKey, s.Name, s.Command)
	}
	return nil
}

// runOpsTask runs one task against a target with the same two safety gates as
// scanning, chosen by the catalog's kind: enable_scan must be true, and the
// target must be inside the matching allowlist (allowed_paths for a KindPath
// catalog, otherwise allowed_targets/allowed_domains). We pre-check here for a
// precise message; the runner enforces the same rules authoritatively via the
// shared ops.CheckScope. Dry-run needs neither gate because it sends nothing.
func runOpsTask(cfg config.Config, cat *ops.Catalog, taskKey, target string, fl opsFlags) error { // used by `<cmd> <task>`
	task, ok := cat.TaskByKey(taskKey) // look up the task
	if !ok {                           // unknown task...
		return fmt.Errorf("%s: unknown task %q (try: hackbot %s list)", cat.Name, taskKey, cat.Name)
	}
	if !fl.dryRun { // real runs enforce the gates up front
		if !cfg.EnableScan { // master switch
			return fmt.Errorf("%s: %w", cat.Name, ops.ErrDisabled)
		}
		if err := ops.CheckScope(cat.Kind, target, cfg.AllowedTargets, cfg.AllowedDomains, cfg.AllowedPaths); err != nil { // kind-aware allowlist
			return fmt.Errorf("%s: %w", cat.Name, err)
		}
	}
	runner := ops.New(cat, ops.Options{ // assemble the guarded runner
		Enable:         cfg.EnableScan,
		AllowedTargets: cfg.AllowedTargets,
		AllowedDomains: cfg.AllowedDomains,
		AllowedPaths:   cfg.AllowedPaths,
		DryRun:         fl.dryRun,
		Timeout:        fl.timeout,
		Scheme:         fl.scheme,
		Wordlist:       fl.wordlist,
		Log:            func(s string) { fmt.Fprintln(os.Stderr, "hackbot:", s) },
	})
	res, err := runner.Run(context.Background(), task, target) // execute (or preview)
	if err != nil {
		return err
	}
	if fl.json { // JSON mode
		return printJSON(res)
	}
	if fl.dryRun { // make the safety state explicit
		fmt.Println("dry-run: no traffic sent (pass -dry-run=false to execute)")
	}
	status := "ok" // default label
	switch {       // choose a label
	case res.DryRun:
		status = "dry"
	case !res.OK:
		status = "error"
	}
	fmt.Printf("  [%s] %-12s %s\n", status, res.Task, res.Command) // one line per task
	if res.Output != "" {                                          // show captured output, indented
		for _, line := range strings.Split(res.Output, "\n") {
			fmt.Printf("      %s\n", line)
		}
	}
	if res.Error != "" { // show tool errors
		fmt.Printf("      error: %s\n", res.Error)
	}
	return nil
}

// runOpsChain runs a multi-step pipeline against one target, applying exactly the
// same two gates as runOpsTask (enable_scan plus the kind-appropriate allowlist).
// The up-front check mirrors the runner so the operator gets a clear message; the
// runner re-checks authoritatively. Each step's output is shown indented, and a
// step fed from the previous one is labeled so a dry-run clearly shows the flow.
func runOpsChain(cfg config.Config, cat *ops.Catalog, ch ops.Chain, target string, fl opsFlags) error { // used by `<cmd> <chain>`
	if !fl.dryRun { // real runs enforce the gates up front
		if !cfg.EnableScan { // master switch
			return fmt.Errorf("%s: %w", cat.Name, ops.ErrDisabled)
		}
		if err := ops.CheckScope(cat.Kind, target, cfg.AllowedTargets, cfg.AllowedDomains, cfg.AllowedPaths); err != nil { // kind-aware allowlist
			return fmt.Errorf("%s: %w", cat.Name, err)
		}
	}
	runner := ops.New(cat, ops.Options{ // assemble the guarded runner
		Enable:         cfg.EnableScan,
		AllowedTargets: cfg.AllowedTargets,
		AllowedDomains: cfg.AllowedDomains,
		AllowedPaths:   cfg.AllowedPaths,
		DryRun:         fl.dryRun,
		Timeout:        fl.timeout,
		Scheme:         fl.scheme,
		Wordlist:       fl.wordlist,
		Log:            func(s string) { fmt.Fprintln(os.Stderr, "hackbot:", s) },
	})
	results, err := runner.RunChain(context.Background(), ch, target) // execute (or preview) every step
	if err != nil {
		return err
	}
	if fl.json { // JSON mode
		return printJSON(results)
	}
	if fl.dryRun { // make the safety state explicit
		fmt.Println("dry-run: no traffic sent (pass -dry-run=false to execute)")
	}
	fmt.Printf("%s: chain %q (%d step(s))\n", cat.Name, ch.Key, len(results)) // headline
	for _, res := range results {                                             // one block per step, in order
		status := "ok" // default label
		switch {       // choose a label
		case res.DryRun:
			status = "dry"
		case !res.OK:
			status = "error"
		}
		feed := "" // stdin annotation
		if res.Stdin {
			feed = " (stdin <- previous)" // this step consumed the previous step's output
		}
		fmt.Printf("  [%s] %-12s %s%s\n", status, res.Task, res.Command, feed)
		if res.Output != "" { // show captured output, indented
			for _, line := range strings.Split(res.Output, "\n") {
				fmt.Printf("      %s\n", line)
			}
		}
		if res.Error != "" { // show tool errors
			fmt.Printf("      error: %s\n", res.Error)
		}
	}
	return nil
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
	// Web Security Testing (OWASP WSTG) agents. One per checklist file under
	// src/agent_files/; a test fails if a checklist has no matching agent.
	{
		Name:        "web-information-gathering",
		Command:     "web show information-gathering",
		Description: "OWASP WSTG information gathering checklist (WSTG-INFO)",
		Triggers:    []string{"run the web information gathering checklist", "enumerate a web app's attack surface"},
	},
	{
		Name:        "web-config-management",
		Command:     "web show config-management",
		Description: "OWASP WSTG configuration/deployment testing checklist (WSTG-CONF)",
		Triggers:    []string{"run the web configuration testing checklist", "check security headers and platform configuration"},
	},
	{
		Name:        "web-identity-management",
		Command:     "web show identity-management",
		Description: "OWASP WSTG identity management checklist (WSTG-IDNT)",
		Triggers:    []string{"run the identity management testing checklist", "review registration and account provisioning"},
	},
	{
		Name:        "web-authentication",
		Command:     "web show authentication",
		Description: "OWASP WSTG authentication testing checklist (WSTG-ATHN)",
		Triggers:    []string{"run the authentication testing checklist", "test login and credential handling"},
	},
	{
		Name:        "web-authorization",
		Command:     "web show authorization",
		Description: "OWASP WSTG authorization testing checklist (WSTG-ATHZ)",
		Triggers:    []string{"run the authorization testing checklist", "test access control and IDOR"},
	},
	{
		Name:        "web-session-management",
		Command:     "web show session-management",
		Description: "OWASP WSTG session management checklist (WSTG-SESS)",
		Triggers:    []string{"run the session management testing checklist", "test cookies, sessions, and CSRF"},
	},
	{
		Name:        "web-injection",
		Command:     "web show injection",
		Description: "OWASP WSTG injection testing checklist (WSTG-INJT)",
		Triggers:    []string{"run the injection testing checklist", "test for XSS, SQLi, and other injection flaws"},
	},
	{
		Name:        "web-error-handling",
		Command:     "web show error-handling",
		Description: "OWASP WSTG error handling testing checklist (WSTG-ERRH)",
		Triggers:    []string{"run the error handling testing checklist", "check for stack traces and verbose errors"},
	},
	{
		Name:        "web-weak-cryptography",
		Command:     "web show weak-cryptography",
		Description: "OWASP WSTG weak cryptography testing checklist (WSTG-CRYP)",
		Triggers:    []string{"run the weak cryptography testing checklist", "test TLS and cryptographic primitives"},
	},
	{
		Name:        "web-business-logic",
		Command:     "web show business-logic",
		Description: "OWASP WSTG business logic testing checklist (WSTG-BUSL)",
		Triggers:    []string{"run the business logic testing checklist", "test workflows and abuse cases"},
	},
	{
		Name:        "web-client-side",
		Command:     "web show client-side",
		Description: "OWASP WSTG client-side testing checklist (WSTG-CLNT)",
		Triggers:    []string{"run the client-side testing checklist", "test DOM XSS and browser storage"},
	},
	{
		Name:        "web-api-testing",
		Command:     "web show api-testing",
		Description: "OWASP WSTG API testing checklist (WSTG-APIT)",
		Triggers:    []string{"run the API testing checklist", "test REST and GraphQL APIs"},
	},
	// Recon/OSINT agents (family: `recon`). Each maps to one runnable task in the
	// ops recon catalog; a drift test keeps them aligned with that catalog.
	{
		Name:        "recon-subdomains",
		Command:     "recon subdomains <target>",
		Description: "Passive subdomain enumeration with subfinder (OSINT)",
		Triggers:    []string{"enumerate subdomains for a domain", "discover an attack surface from public sources"},
	},
	{
		Name:        "recon-dns",
		Command:     "recon dns <target>",
		Description: "Bulk DNS resolution with dnsx",
		Triggers:    []string{"resolve DNS records for a domain", "check which hostnames are live"},
	},
	{
		Name:        "recon-ports",
		Command:     "recon ports <target>",
		Description: "Fast common-port scan with naabu",
		Triggers:    []string{"scan common ports on a host", "quick port discovery"},
	},
	{
		Name:        "recon-services",
		Command:     "recon services <target>",
		Description: "Service/version inventory with nmap",
		Triggers:    []string{"fingerprint services on a host", "identify versions of exposed services"},
	},
	{
		Name:        "recon-http",
		Command:     "recon http <target>",
		Description: "HTTP probe (status, title, tech) with httpx",
		Triggers:    []string{"probe a web target's status and technologies", "identify the tech stack of a site"},
	},
	{
		Name:        "recon-whois",
		Command:     "recon whois <target>",
		Description: "WHOIS registration/ownership lookup (OSINT)",
		Triggers:    []string{"look up domain ownership", "whois a domain"},
	},
	{
		Name:        "recon-urls",
		Command:     "recon urls <target>",
		Description: "Fetch known URLs from public archives with gau (OSINT)",
		Triggers:    []string{"find historical URLs for a domain", "discover old endpoints from archives"},
	},
	// Content-discovery agents (family: `discover`). Each maps to one runnable
	// task in the ops discovery catalog.
	{
		Name:        "discover-dirs",
		Command:     "discover dirs <target>",
		Description: "Directory discovery with ffuf",
		Triggers:    []string{"brute-force directories on a web server", "find hidden paths"},
	},
	{
		Name:        "discover-files",
		Command:     "discover files <target>",
		Description: "File discovery with gobuster",
		Triggers:    []string{"find files and directories on a web server", "gobuster a target"},
	},
	{
		Name:        "discover-extensions",
		Command:     "discover extensions <target>",
		Description: "Extension brute force (backups, scripts) with gobuster",
		Triggers:    []string{"find backup or script files by extension", "look for .bak/.old files"},
	},
	{
		Name:        "discover-vhosts",
		Command:     "discover vhosts <target>",
		Description: "Virtual host discovery by fuzzing the Host header with ffuf",
		Triggers:    []string{"find virtual hosts on an IP", "fuzz the Host header"},
	},
	{
		Name:        "discover-params",
		Command:     "discover params <target>",
		Description: "Hidden parameter discovery with ffuf",
		Triggers:    []string{"find hidden query parameters", "discover unlinked parameters"},
	},
	// Recon pipeline agent: a whole chain in one command.
	{
		Name:        "recon-footprint",
		Command:     "recon footprint <target>",
		Description: "Chain: enumerate subdomains with subfinder, then probe them with httpx",
		Triggers:    []string{"map a domain's live attack surface in one step", "find live subdomains and their tech stack"},
	},
	// Secrets-scanning agents (family: `secrets`). KindPath: these read a local
	// directory and are gated by allowed_paths, not the network allowlists.
	{
		Name:        "secrets-scan",
		Command:     "secrets scan <path>",
		Description: "Scan a working tree for secrets with gitleaks",
		Triggers:    []string{"scan a checkout for hardcoded secrets", "find API keys in a directory"},
	},
	{
		Name:        "secrets-history",
		Command:     "secrets history <path>",
		Description: "Scan a git repository's full history for secrets with gitleaks",
		Triggers:    []string{"find secrets left in git history", "audit a repo's past commits for credentials"},
	},
	{
		Name:        "secrets-verify",
		Command:     "secrets verify <path>",
		Description: "Scan and verify live secrets with trufflehog",
		Triggers:    []string{"check whether found secrets are still active", "verify leaked credentials"},
	},
	{
		Name:        "secrets-entropy",
		Command:     "secrets entropy <path>",
		Description: "High-recall entropy/pattern secret baseline with detect-secrets",
		Triggers:    []string{"catch unknown secret formats by entropy", "baseline a repository for secrets"},
	},
	// Dependency / SBOM agents (family: `deps`). Also KindPath (local project).
	{
		Name:        "deps-vulns",
		Command:     "deps vulns <path>",
		Description: "Dependency/OS vulnerability scan with trivy",
		Triggers:    []string{"find vulnerable dependencies in a project", "scan a directory for known CVEs"},
	},
	{
		Name:        "deps-sbom",
		Command:     "deps sbom <path>",
		Description: "Generate a CycloneDX SBOM with syft",
		Triggers:    []string{"produce a software bill of materials", "generate an SBOM for a project"},
	},
	{
		Name:        "deps-grype",
		Command:     "deps grype <path>",
		Description: "Directory vulnerability scan with grype",
		Triggers:    []string{"scan lockfiles and packages with grype", "cross-check dependencies against another database"},
	},
	{
		Name:        "deps-osv",
		Command:     "deps osv <path>",
		Description: "Dependency scan against the OSV database with osv-scanner",
		Triggers:    []string{"query OSV for dependency vulnerabilities", "scan manifests with Google's OSV database"},
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
	layoutBegin     = "<!-- BEGIN LAYOUT (generated by `hackbot layout`) -->"
	layoutEnd       = "<!-- END LAYOUT -->"
)

// agentsText renders the plain-text listing printed by `hackbot agents` and
// snapshotted in the README.
func agentsText() string { // keep the README snapshot in sync via the test
	var b strings.Builder                        // accumulate the listing
	fmt.Fprintf(&b, "%d agents:\n", len(agents)) // headline count
	for _, a := range agents {                   // one row per agent
		fmt.Fprintf(&b, "  %-26s %-40s %s\n", a.Name, a.Command, a.Description)
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

// layoutRootName is the stable label used as the root of the generated layout.
// It is fixed (not taken from the working directory) so the README reads as a
// tree and the sync test is deterministic on any machine.
const layoutRootName = "hackbot" // shown as the root of every generated path

// layoutSkipDirs are directory names excluded from the generated layout. These
// mirror the ignored directories in .gitignore so build output and caches are
// never listed.
var layoutSkipDirs = map[string]bool{ // checked by name at every directory
	".git": true, "bin": true, "dist": true, "build": true,
	"node_modules": true, "vendor": true,
	"__pycache__": true, ".pytest_cache": true, ".venv": true, "venv": true, "env": true,
	".vscode": true, ".idea": true, "secrets": true,
}

// layoutSkipFiles reports whether a file is excluded from the generated layout,
// mirroring the ignored files in .gitignore.
func layoutSkipFiles(name string) bool { // checked by name for every file
	switch name { // exact-name matches
	case ".DS_Store", "Thumbs.db", ".env", "coverage.out":
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) { // extension matches (build output, caches)
	case ".exe", ".test", ".out", ".pyc", ".pyo", ".so", ".bak", ".tmp", ".local":
		return true
	}
	return false // include everything else
}

// repoLayout returns every directory and file under root as a full path, rooted
// at layoutRootName and sorted. Directories end with "/".
func repoLayout(root string) ([]string, error) { // used by `hackbot layout`
	var entries []string                                                              // accumulated full paths
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { // walk the tree
		if err != nil { // propagate walk errors
			return err
		}
		rel, rerr := filepath.Rel(root, path) // path relative to root
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel) // normalize separators to "/" for portability
		if rel == "." {             // skip the root itself
			return nil
		}
		if d.IsDir() { // a directory...
			if layoutSkipDirs[d.Name()] { // ...that should be ignored?
				return fs.SkipDir // don't descend and don't list it
			}
			entries = append(entries, layoutRootName+"/"+rel+"/") // record with trailing slash
			return nil
		}
		if layoutSkipFiles(d.Name()) { // ignored file...
			return nil // ...skip it
		}
		entries = append(entries, layoutRootName+"/"+rel) // record the file
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(entries) // deterministic order regardless of walk order
	return entries, nil
}

// layoutText renders the repository layout as text (one full path per line).
func layoutText(root string) (string, error) { // used by `hackbot layout` and the test
	entries, err := repoLayout(root) // collect the paths
	if err != nil {
		return "", err
	}
	var b strings.Builder       // accumulate the listing
	for _, e := range entries { // one path per line
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// printLayout writes the repository layout to stdout.
func printLayout(root string) error { // used by `hackbot layout`
	out, err := layoutText(root) // build the listing
	if err != nil {
		return err
	}
	fmt.Print(out) // print it
	return nil
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
