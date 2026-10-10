package skillsec // same package as the code under test

import ( // imports for this file
	"context"       // cancel and bound every probe
	"errors"        // errors.As against exec.ExitError for exit codes
	"fmt"           // Errorf for contextual failures
	"io/fs"         // walk the skill directory in the built-in scanner
	"os"            // open files the built-in scanner reads
	"os/exec"       // exec.LookPath to resolve probes, ExitError to read exit codes
	"path/filepath" // clean and join paths in the built-in scanner
	"regexp"        // compile each search probe's pattern
	"sort"          // deterministic ordering of skipped-probe notes
	"strings"       // trim and join captured output
	"time"          // default probe timeout

	"github.com/rjwashi/hackbot/internal/ops"  // ErrDisabled and CheckScope: the shared gate
	"github.com/rjwashi/hackbot/internal/scan" // CommandRunner seam so tests inject a fake
)

// Verdict is a rubric check's outcome after every probe has run.
type Verdict string // one word per check, so reports scan cleanly

const (
	// VerdictPass: every automated probe ran and found no violation.
	VerdictPass Verdict = "PASS"
	// VerdictFail: a probe found the violation the rubric forbids.
	VerdictFail Verdict = "FAIL"
	// VerdictReview: evidence exists but the rubric reserves judgment for a person.
	VerdictReview Verdict = "REVIEW"
	// VerdictManual: the check cannot be automated and needs human judgment.
	VerdictManual Verdict = "MANUAL"
	// VerdictSkip: every probe for this check was unavailable (tool not installed).
	VerdictSkip Verdict = "SKIP"
	// VerdictError: a probe failed to run for a reason that is not a verdict.
	VerdictError Verdict = "ERROR"
	// VerdictDry: a dry run rendered the command but executed nothing.
	VerdictDry Verdict = "DRY"
)

// ProbeResult is one probe's own outcome inside a check's result.
type ProbeResult struct { // what one probe did
	Kind    ProbeKind `json:"kind"`             // search | exec | manual
	Tool    string    `json:"tool"`             // binary that ran, or builtin-search
	Command string    `json:"command"`          // the command line, copyable
	Verdict Verdict   `json:"verdict"`          // this probe's own outcome
	Output  string    `json:"output,omitempty"` // captured stdout+stderr, trimmed
	Error   string    `json:"error,omitempty"`  // why it could not run
	Note    string    `json:"note,omitempty"`   // why this probe answers the check
}

// Result is one rubric check's outcome, with every probe that produced it.
type Result struct { // one row per rubric row
	Rubric   string        `json:"rubric"`   // slug of the rubric the check came from
	CheckID  string        `json:"check"`    // e.g. "3.8"
	Test     string        `json:"test"`     // the check's question
	Evidence string        `json:"evidence"` // the evidence the rubric asks for
	Verdict  Verdict       `json:"verdict"`  // aggregated across the probes below
	Probes   []ProbeResult `json:"probes"`   // the probes, in execution order
}

// Options configures a guarded evaluation run.
type Options struct { // everything Run needs to be safe and testable
	Enable       bool                         // master switch; false refuses real runs
	AllowedPaths []string                     // path allowlist for the target directory
	DryRun       bool                         // render commands, execute nothing
	Timeout      time.Duration                // per-probe deadline; 0 means the default
	Runner       scan.CommandRunner           // process seam; nil means scan.ExecRunner
	LookPath     func(string) (string, error) // PATH resolver; nil means exec.LookPath
	Log          func(string)                 // progress sink; nil discards
}

// defaults fills in the seams and limits a caller left unset, so Run is always
// usable directly and tests only override what they care about.
func (o *Options) defaults() { // called at the top of Run
	if o.Runner == nil { // no injected runner...
		o.Runner = scan.ExecRunner{} // ...so run real processes
	}
	if o.LookPath == nil { // no injected resolver...
		o.LookPath = exec.LookPath // ...so resolve against the real PATH
	}
	if o.Timeout <= 0 { // no deadline supplied...
		o.Timeout = 60 * time.Second // ...so no probe can hang a report
	}
	if o.Log == nil { // no progress sink...
		o.Log = func(string) {} // ...so logging is silently dropped
	}
}

// avail reports whether a binary is on PATH, for searchCommandLine.
func (o *Options) avail(toolKey string) bool { // helper shared by plan and run
	tools := ToolCatalog()  // the catalog knows each tool's binary
	t, ok := tools[toolKey] // look the tool up
	if !ok {                // unknown key...
		return false // ...is simply not available
	}
	_, err := o.LookPath(t.Bin) // resolve the binary
	return err == nil           // present only when it resolves
}

// ErrNoTarget is returned when a rubric is run without a directory to evaluate.
var ErrNoTarget = errors.New("skillsec: no skill directory given (usage: hackbot skill run <rubric> <path>)")

// Run evaluates one rubric against a local skill directory and returns one
// Result per rubric check, in rubric order.
//
// Safety: a real run (anything not marked DryRun) is refused unless scanning is
// enabled and the target resolves inside the configured path allowlist, using
// the same shared ops.CheckScope gate as every other active capability. Dry runs
// need neither, because they send nothing and touch nothing. The gate is checked
// here, inside Run, rather than only in the CLI, so a new caller cannot bypass it.
func Run(ctx context.Context, r Rubric, target string, opts Options) ([]Result, error) { // one rubric, one directory
	target = strings.TrimSpace(target) // tolerate stray whitespace
	if target == "" {                  // no directory to evaluate...
		return nil, ErrNoTarget // ...so refuse with the usage line
	}
	opts.defaults()   // fill unset seams and limits
	if !opts.DryRun { // real runs enforce both gates up front...
		if !opts.Enable { // master switch?
			return nil, ops.ErrDisabled
		}
		if err := ops.CheckScope(ops.KindPath, target, nil, nil, opts.AllowedPaths); err != nil { // path allowlist
			return nil, err
		}
	}
	results := make([]Result, 0, len(r.Checks)) // one row per check
	for _, c := range r.Checks {                // preserve rubric order
		select { // respect cancellation between checks
		case <-ctx.Done(): // the caller gave up...
			return results, ctx.Err() // ...report what finished
		default: // keep going
		}
		rule, ok := RuleFor(r.Slug, c.ID) // look the check's probes up
		if !ok {                          // a rubric row with no registered probes...
			results = append(results, Result{ // ...is reported honestly, not silently
				Rubric: r.Slug, CheckID: c.ID, Test: c.Test, Evidence: c.Evidence,
				Verdict: VerdictManual,
				Probes: []ProbeResult{{Kind: ProbeManual, Verdict: VerdictManual,
					Note: "no automated probe is registered for this check"}},
			})
			continue // next check
		}
		res := Result{Rubric: r.Slug, CheckID: c.ID, Test: c.Test, Evidence: c.Evidence} // seed the row
		for _, p := range rule.Probes {                                                  // run each probe for this check
			if opts.DryRun { // a dry run renders instead of executing...
				res.Probes = append(res.Probes, renderProbe(p, target, opts)) // ...so nothing is started
				continue                                                      // next probe
			}
			res.Probes = append(res.Probes, runProbe(ctx, p, target, opts))
		}
		if opts.DryRun { // no probe ran, so there is no evidence to aggregate...
			res.Verdict = VerdictDry // ...and the row says so plainly
		} else {
			res.Verdict = aggregate(res.Probes) // one verdict for the whole check
		}
		results = append(results, res) // collect
	}
	return results, nil // the report
}

// renderProbe produces what a dry run shows: the command that WOULD run for a
// probe, with no execution and no filesystem access. Manual probes render their
// instruction instead, because that is what a dry run of a manual check should
// display.
func renderProbe(p Probe, target string, opts Options) ProbeResult { // dry-run rendering
	pr := ProbeResult{Kind: p.Kind, Verdict: VerdictDry, Note: p.Note} // seed it
	subs := map[string]string{}                                        // path only when given, so {path} stays visible
	if strings.TrimSpace(target) != "" {                               // the operator supplied a directory...
		subs["path"] = strings.TrimSpace(target) // ...so substitute it everywhere
	}
	switch p.Kind { // render by kind
	case ProbeManual: // the human instruction, verbatim
		pr.Output = p.Manual
	case ProbeSearch: // the preferred search command
		if p.GoOnly { // the pattern the built-in scanner must handle...
			pr.Tool, pr.Command = builtinSearchTool, builtinCommand(p.Pattern, target) // ...show that
			break
		}
		pr.Tool, pr.Command = searchCommandLine(p.Pattern, target, opts.avail) // pick and render
	case ProbeExec: // the external command
		tools := ToolCatalog()    // need the binary
		t, ok := tools[p.ToolKey] // look it up
		if !ok {                  // unknown tool...
			pr.Error = fmt.Sprintf("unknown tool %q", p.ToolKey) // ...say so
			return pr
		}
		pr.Tool = t.Bin                                      // the binary
		pr.Command = joinCmd(t.Bin, ExpandAll(p.Args, subs)) // the rendered command
	}
	return pr // the rendered probe
}

// runProbe dispatches one probe by kind. It never returns a zero-value result:
// every probe ends with a verdict and an explanation of how it got there.
func runProbe(ctx context.Context, p Probe, target string, opts Options) ProbeResult { // one probe
	switch p.Kind { // choose by probe kind
	case ProbeManual: // a check no static evidence can settle
		return ProbeResult{Kind: ProbeManual, Verdict: VerdictManual, Note: p.Note, Output: p.Manual}
	case ProbeSearch: // grep the skill's files for a pattern
		return runSearch(ctx, p, target, opts)
	case ProbeExec: // run an external tool for real
		return runExec(ctx, p, target, opts)
	default: // an unregistered kind is a programming error, not a user error
		return ProbeResult{Kind: p.Kind, Verdict: VerdictError,
			Error: fmt.Sprintf("unknown probe kind %q", p.Kind), Note: p.Note}
	}
}

// runSearch finds the first available search tool and runs the pattern through
// it, falling back to an in-process scan when neither ripgrep nor grep exists so
// a bare machine still gets a real answer instead of a SKIP.
func runSearch(ctx context.Context, p Probe, target string, opts Options) ProbeResult { // search probe
	if p.GoOnly { // the pattern's syntax is Go-only (e.g. \x{...} escapes)...
		return runBuiltinSearch(ctx, p, target, builtinCommand(p.Pattern, target), opts) // ...scan in-process always
	}
	toolKey, command := searchCommandLine(p.Pattern, target, opts.avail) // pick a tool and render
	if toolKey == builtinSearchTool {                                    // nothing installed...
		return runBuiltinSearch(ctx, p, target, command, opts) // ...so scan in-process
	}
	tools := ToolCatalog()                                          // need the binary name
	bin := tools[toolKey].Bin                                       // resolve it
	subs := map[string]string{"pattern": p.Pattern, "path": target} // real values
	args := make([]string, 0, len(searchOrder[0].Args))             // room for the args
	for _, s := range searchOrder {                                 // find the matching template
		if s.ToolKey == toolKey { // the one we chose
			for _, a := range s.Args { // substitute each argument
				args = append(args, Expand(a, subs))
			}
			break // template found
		}
	}
	rctx, cancel := withTimeout(ctx, opts.Timeout)                                      // bound this probe
	defer cancel()                                                                      // release the timer when the probe ends
	out, err := opts.Runner.Run(rctx, bin, args...)                                     // execute for real
	pr := ProbeResult{Kind: ProbeSearch, Tool: toolKey, Command: command, Note: p.Note} // seed
	pr.Output = trimOutput(string(out))                                                 // capture evidence
	code, isExit := exitStatus(err)                                                     // classify the error
	switch {                                                                            // judge the probe
	case err != nil && !isExit: // the process never started...
		pr.Verdict, pr.Error = VerdictError, err.Error() // ...so this is an error, not a verdict
		return pr
	case err != nil && code >= 2: // grep/rg exit 2 for a real failure...
		pr.Verdict, pr.Error = VerdictError, trimOutput(string(out)) // ...not a match
		return pr
	}
	pr.Verdict = judgeSearch(p.Expect, code == 0) // 0 means a match was found
	return pr
}

// runBuiltinSearch scans the skill's files in-process with the same regex the
// external tools would have used, so results do not depend on what is installed.
// It splits the file into lines before matching, which is what makes ^, $ and .
// behave exactly as they do under grep and ripgrep.
func runBuiltinSearch(ctx context.Context, p Probe, target, command string, opts Options) ProbeResult { // fallback
	pr := ProbeResult{Kind: ProbeSearch, Tool: builtinSearchTool, Command: command, Note: p.Note} // seed
	matches, err := builtinSearch(ctx, p.Pattern, target)                                         // scan
	if err != nil {                                                                               // a missing directory or unreadable file...
		pr.Verdict, pr.Error = VerdictError, err.Error() // ...is an error, not a verdict
		return pr
	}
	pr.Output = matches                               // what the scan found
	pr.Verdict = judgeSearch(p.Expect, matches != "") // empty means no match
	return pr
}

// runExec resolves an external tool and runs it for real. A tool that is not
// installed reports SKIP with its install hint rather than failing the check,
// because "not evaluated" and "evaluated and clean" must never look alike.
func runExec(ctx context.Context, p Probe, target string, opts Options) ProbeResult { // exec probe
	tools := ToolCatalog()    // need the binary and hint
	t, ok := tools[p.ToolKey] // look the tool up
	if !ok {                  // unknown tool key...
		return ProbeResult{Kind: ProbeExec, Tool: p.ToolKey, Verdict: VerdictError,
			Error: fmt.Sprintf("unknown tool %q", p.ToolKey), Note: p.Note}
	}
	command := joinCmd(t.Bin, ExpandAll(p.Args, map[string]string{"path": target})) // render it
	pr := ProbeResult{Kind: ProbeExec, Tool: t.Bin, Command: command, Note: p.Note} // seed
	if _, err := opts.LookPath(t.Bin); err != nil {                                 // not installed...
		pr.Verdict = VerdictSkip                                          // ...not evaluated
		pr.Error = fmt.Sprintf("%s not installed (%s)", t.Bin, t.Install) // with a way to fix it
		return pr
	}
	args := ExpandAll(p.Args, map[string]string{"path": target}) // real arguments
	rctx, cancel := withTimeout(ctx, opts.Timeout)               // bound this probe
	defer cancel()                                               // release the timer when the probe ends
	out, err := opts.Runner.Run(rctx, t.Bin, args...)            // execute for real
	pr.Output = trimOutput(string(out))                          // capture evidence
	code, isExit := exitStatus(err)                              // classify the error
	if err != nil && !isExit {                                   // never started...
		pr.Verdict, pr.Error = VerdictError, err.Error() // ...an error, not a verdict
		return pr
	}
	switch p.Expect { // judge by the probe's declared expectation
	case ExpectExit0: // non-zero exit means the check failed
		if err == nil { // clean exit...
			pr.Verdict = VerdictPass // ...so the check holds
		} else if isExit && code >= 2 { // a tool-level failure, not a finding...
			pr.Verdict, pr.Error = VerdictError, pr.Output // ...reported as an error
		} else { // a genuine non-zero result (unsigned commit, leaked key)...
			pr.Verdict = VerdictFail // ...is a finding
		}
	case ExpectReview: // evidence for a person, whatever the exit code
		pr.Verdict = VerdictReview
	default: // ExpectNone/ExpectSome on an exec probe: judge by found/not-found
		pr.Verdict = judgeSearch(p.Expect, err == nil)
	}
	return pr
}

// judgeSearch turns "did the pattern match" into a verdict for the two
// pattern-shaped expectations. ExpectExit0 and ExpectReview are handled by the
// exec path, because only a real process has an exit code to reason about.
func judgeSearch(exp Expectation, found bool) Verdict { // shared by search probes
	switch exp { // which question was asked
	case ExpectSome: // evidence must be present...
		if found { // ...and it is
			return VerdictPass
		}
		return VerdictFail // missing evidence is a finding
	default: // ExpectNone: a violation must be absent...
		if found { // ...but it is present
			return VerdictFail
		}
		return VerdictPass // clean
	}
}

// aggregate collapses per-probe verdicts into the check's single verdict.
//
// Precedence runs worst-first so a report can never look greener than the work
// behind it: a real FAIL beats everything, an ERROR beats a REVIEW, and a check
// with at least one clean probe reads PASS even when a supplementary probe was
// unavailable (the CLI says which tools did not run). Only when no probe
// produced any verdict does the row read SKIP, which is the honest answer.
func aggregate(probes []ProbeResult) Verdict { // one verdict per check
	if len(probes) == 0 { // nothing to judge...
		return VerdictSkip // ...so nothing was evaluated
	}
	seen := map[Verdict]bool{} // which verdicts appeared
	for _, p := range probes { // scan every probe
		seen[p.Verdict] = true // record it
	}
	for _, v := range []Verdict{ // worst first...
		VerdictFail, VerdictError, VerdictReview, VerdictManual, VerdictPass,
	} {
		if seen[v] { // the worst verdict present wins
			return v
		}
	}
	return VerdictSkip // only reached when every probe was skipped
}

// PlanStep is one line of `skill plan`: what would run for one rubric check.
type PlanStep struct { // what a check would do
	CheckID   string `json:"check"`             // e.g. "3.8"
	Test      string `json:"test"`              // the check's question
	Evidence  string `json:"evidence"`          // the evidence the rubric asks for
	Automated bool   `json:"automated"`         // true when a probe exists
	Tool      string `json:"tool,omitempty"`    // binary, when automated
	Command   string `json:"command,omitempty"` // the command line, when automated
	Manual    string `json:"manual,omitempty"`  // the human instruction, when manual
	Note      string `json:"note,omitempty"`    // why this probe answers the check
}

// Plan renders what `skill run` would execute for each check of a rubric,
// without touching the filesystem. With an empty target the {path} placeholder
// is left in the command, so the plan reads as a template to fill in.
func Plan(r Rubric, target string, opts Options) []PlanStep { // used by `skill plan`
	opts.defaults()                             // fill the seams so tool availability is real
	steps := make([]PlanStep, 0, len(r.Checks)) // one step per check
	for _, c := range r.Checks {                // preserve rubric order
		step := PlanStep{CheckID: c.ID, Test: c.Test, Evidence: c.Evidence} // seed
		rule, ok := RuleFor(r.Slug, c.ID)                                   // look the probes up
		if !ok || len(rule.Probes) == 0 {                                   // nothing registered...
			step.Manual = "Review manually: no automated probe is registered for this check."
			steps = append(steps, step) // ...so the plan says so
			continue
		}
		var cmdParts, toolParts, noteParts []string // every probe's rendering
		allManual := true                           // assume every probe is human-driven
		subs := map[string]string{}                 // path only when given, so {path} stays visible
		if strings.TrimSpace(target) != "" {        // the operator supplied a directory...
			subs["path"] = strings.TrimSpace(target) // ...so substitute it everywhere
		}
		for _, p := range rule.Probes { // walk every probe for the check
			noteParts = append(noteParts, p.Note) // carry each rationale through
			switch p.Kind {                       // render by kind
			case ProbeManual: // a human instruction, not a command
				cmdParts = append(cmdParts, p.Manual) // the instruction itself
			case ProbeSearch: // grep-style probe
				allManual = false // this probe would really run
				if p.GoOnly {     // the pattern only the built-in scanner understands...
					toolParts = append(toolParts, builtinSearchTool)
					cmdParts = append(cmdParts, builtinCommand(p.Pattern, target)) // ...show that
					continue
				}
				toolKey, command := searchCommandLine(p.Pattern, target, opts.avail) // pick and render
				toolParts = append(toolParts, toolKey)                               // record
				cmdParts = append(cmdParts, command)
			case ProbeExec: // external tool
				allManual = false                                                                   // this probe would really run
				tools := ToolCatalog()                                                              // need the binary
				toolParts = append(toolParts, tools[p.ToolKey].Bin)                                 // resolve it
				cmdParts = append(cmdParts, joinCmd(tools[p.ToolKey].Bin, ExpandAll(p.Args, subs))) // render
			}
		}
		step.Note = strings.Join(noteParts, " ") // the check's combined rationale
		if allManual {                           // nothing would actually execute...
			step.Manual = strings.Join(cmdParts, " ") // ...so the plan is the guidance
		} else { // at least one probe runs...
			step.Automated = true                                   // ...mark it automated
			step.Tool = strings.Join(uniqueStrings(toolParts), "+") // every binary involved
			step.Command = strings.Join(cmdParts, " ; ")            // every command, in order
		}
		steps = append(steps, step) // collect
	}
	return steps // the plan
}

// uniqueStrings de-duplicates a string slice while preserving first-seen order.
func uniqueStrings(in []string) []string { // helper for multi-probe plan rows
	seen := map[string]bool{} // already kept?
	var out []string          // result
	for _, s := range in {    // walk the input...
		if seen[s] { // ...skipping repeats
			continue
		}
		seen[s] = true       // record it
		out = append(out, s) // keep it
	}
	return out // de-duplicated
}

// ExpandAll substitutes every placeholder in an argument list.
func ExpandAll(args []string, subs map[string]string) []string { // helper for exec probes
	out := make([]string, 0, len(args)) // one output slot per argument
	for _, a := range args {            // walk the template
		out = append(out, Expand(a, subs)) // substituting as we go
	}
	return out // substituted
}

// exitStatus classifies an error from CommandRunner.Run: an exit code when the
// process ran and returned one, and false when it never started at all.
func exitStatus(err error) (int, bool) { // used by the search and exec paths
	if err == nil { // success...
		return 0, true // ...which is exit code zero
	}
	var ee *exec.ExitError // a process that ran and returned non-zero
	if errors.As(err, &ee) {
		return ee.ExitCode(), true // the real exit code
	}
	return -1, false // anything else never produced an exit code
}

// withTimeout derives a per-probe context so one hung tool cannot stall a report.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) { // bounded run
	return context.WithTimeout(ctx, d) // the caller's deadline still wins if sooner
}

// trimOutput strips trailing whitespace from captured output so reports do not
// carry blank lines, while keeping the evidence itself intact.
func trimOutput(s string) string { // used by every probe path
	s = strings.TrimSpace(s) // drop surrounding whitespace
	const max = 8 << 10      // 8 KiB of evidence is plenty for one probe
	if len(s) > max {        // a runaway match set...
		s = s[:max] + "\n... output truncated" // ...is cut, and says so
	}
	return s // reportable evidence
}

// builtinSearch walks a skill directory and returns matches formatted the way
// ripgrep and grep format them (path:line:text), so evidence looks the same
// whichever tool produced it.
func builtinSearch(ctx context.Context, pattern, target string) (string, error) { // in-process scanner
	re, err := regexp.Compile("(?i)" + pattern) // case-insensitive, like the -i flag
	if err != nil {                             // a malformed pattern is a bug...
		return "", fmt.Errorf("skillsec: bad pattern: %w", err) // ...reported as such
	}
	st, err := os.Stat(target) // what are we scanning?
	if err != nil {            // a path that does not exist...
		return "", err // ...is a real error
	}
	var (
		matches []string // accumulated "path:line:text" lines
		lines   int      // how many matches so far, for the cap
	)
	emit := func(rel, line string, no int) { // append one match
		if lines >= 200 { // stop growing after 200 matches...
			return // ...so one noisy file cannot flood the report
		}
		lines++ // count it
		matches = append(matches, fmt.Sprintf("%s:%d:%s", rel, no, line))
	}
	readFile := func(path, rel string) error { // scan one file
		select { // respect cancellation per file
		case <-ctx.Done(): // the caller gave up...
			return ctx.Err() // ...so stop walking
		default: // keep going
		}
		f, err := os.Open(path) // open the candidate
		if err != nil {         // unreadable file...
			return nil // ...is skipped rather than failing the whole scan
		}
		defer f.Close()                        // release the handle
		info, err := f.Stat()                  // how big is it?
		if err != nil || info.Size() > 4<<20 { // oversized or unstattable...
			return nil // ...skip it; skill files are small
		}
		data, err := os.ReadFile(path) // read the whole file
		if err != nil {                // a race or permission problem...
			return nil // ...is not worth failing over
		}
		if indexByte(data, 0) >= 0 { // NUL bytes mean binary...
			return nil // ...and ripgrep skips those too
		}
		no := 0                                                  // running line number
		for _, line := range strings.Split(string(data), "\n") { // split like grep does
			no++                      // the next line
			if re.MatchString(line) { // the pattern hits this line...
				emit(rel, strings.TrimRight(line, "\r"), no) // ...record it
			}
		}
		return nil // this file is done
	}
	if !st.IsDir() { // a single file target...
		if err := readFile(target, filepath.Base(target)); err != nil { // scan it directly
			return "", err
		}
		return strings.Join(matches, "\n"), nil // whatever it yielded
	}
	err = filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error { // walk
		if err != nil { // an unreadable entry...
			return nil // ...is skipped
		}
		if d.IsDir() { // a directory entry
			if d.Name() == ".git" { // never read VCS internals...
				return fs.SkipDir // ...they are not part of the skill
			}
			return nil // otherwise descend
		}
		if !d.Type().IsRegular() { // sockets, pipes and devices are not skills...
			return nil // ...so skip them
		}
		rel, rerr := filepath.Rel(target, path) // how should this path print?
		if rerr != nil {                        // an odd path...
			rel = path // ...print it whole
		}
		return readFile(path, filepath.ToSlash(rel)) // scan it
	})
	if err != nil { // the walk itself failed...
		return "", err // ...surface it
	}
	return strings.Join(matches, "\n"), nil // the evidence, ripgrep-style
}

// indexByte is bytes.IndexByte, inlined so the scanner needs no extra import.
func indexByte(b []byte, c byte) int { // find one byte
	for i, v := range b { // walk the buffer
		if v == c { // a hit...
			return i // ...at this offset
		}
	}
	return -1 // not present
}

// SkippedTools lists, for a set of probe results, which external tools were
// missing, so a report can say what did not run without burying the verdict.
func SkippedTools(probes []ProbeResult) []string { // used by the CLI summary
	var out []string           // accumulated binary names
	for _, p := range probes { // every probe...
		if p.Verdict == VerdictSkip && p.Tool != "" && p.Tool != builtinSearchTool { // ...unavailable
			out = append(out, p.Tool) // record the binary
		}
	}
	sort.Strings(out) // deterministic
	return out        // de-duplicated by the caller if it cares
}
