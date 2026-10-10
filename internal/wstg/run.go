// This file adds the guarded execution layer for the WSTG capabilities.
//
// Safety model (mirrors internal/scan): checks are DISABLED by default and, when
// enabled, a target is only touched if it falls within the configured allowlist.
// A dry-run mode renders the exact commands without sending any traffic, and it
// is the default at the CLI. Arguments come from a fixed template (see
// capability.go), so user input is never interpolated into a shell.
package wstg // same package as wstg.go

import ( // imports for this file
	"context" // lets callers cancel a long-running check
	"errors"  // errors.New for the disabled sentinel
	"fmt"     // Errorf for contextual errors
	"strings" // building the human-readable command line
	"time"    // per-check timeouts

	"github.com/rjwashi/hackbot/internal/scan" // reuse the guarded InScope + CommandRunner seam
)

// ErrWebDisabled is returned when checks are attempted without enabling scans.
var ErrWebDisabled = errors.New("web checks are disabled (set enable_scan=true and allowed_targets)") // sentinel for errors.Is

// RunnerOptions configures a Runner. The zero value is safe: dry-run, no tools.
type RunnerOptions struct { // all inputs the runner needs, injected for testability
	Enable         bool               // master switch; must be true to actually run a check
	AllowedTargets []string           // IPs/CIDRs that may be touched (the allowlist)
	DryRun         bool               // when true, render commands but send nothing
	Timeout        time.Duration      // per-check timeout; defaults to 60s
	Scheme         string             // URL scheme for {url}; defaults to "https"
	Runner         scan.CommandRunner // process runner seam; defaults to the real one
	Log            func(string)       // optional progress sink (stderr)
}

// Runner executes curated checks against explicitly allowlisted targets.
type Runner struct { // holds the resolved options
	opts RunnerOptions // copied and defaulted in NewRunner
}

// NewRunner applies safe defaults and returns a Runner.
func NewRunner(opts RunnerOptions) *Runner { // constructor
	if opts.Timeout <= 0 { // allow callers to omit the timeout...
		opts.Timeout = 60 * time.Second // ...and get a sane one
	}
	if opts.Scheme == "" { // allow callers to omit the scheme...
		opts.Scheme = "https" // ...and default to https
	}
	if opts.Runner == nil { // allow callers to omit the runner...
		opts.Runner = scan.ExecRunner{} // ...and get the real process runner
	}
	return &Runner{opts: opts} // assemble
}

// Result is the outcome of one check.
type Result struct { // serializable for `web run -json`
	TestID  string `json:"test_id"`          // checklist test id
	Name    string `json:"name"`             // checklist test name
	Tool    string `json:"tool"`             // display name of the tool
	Command string `json:"command"`          // exact command line (dry-run or executed)
	DryRun  bool   `json:"dry_run"`          // true when nothing was executed
	OK      bool   `json:"ok"`               // true when the tool ran without error
	Output  string `json:"output,omitempty"` // combined stdout+stderr (trimmed)
	Error   string `json:"error,omitempty"`  // error text, when the tool failed
}

// Run executes one check against target.
//
// In dry-run mode it never touches the network and does not require the enable
// switch. In real mode it refuses unless checks are enabled and target is inside
// the allowlist. Tool failures are returned inside Result.Error, not as an error,
// so one failing tool does not abort a whole category run.
func (r *Runner) Run(ctx context.Context, c Check, testName, target string) (Result, error) { // guarded entry point
	tool, ok := ToolByKey(c.ToolKey) // resolve the tool first
	if !ok {                         // an unknown tool key is a programming error...
		return Result{}, fmt.Errorf("web: unknown tool %q for %s", c.ToolKey, c.TestID) // ...refuse
	}
	target = strings.TrimSpace(target) // normalize the target
	if target == "" {                  // a check always needs a target...
		return Result{}, fmt.Errorf("web: missing <target>") // ...else refuse
	}
	if !r.opts.DryRun { // only REAL runs need the safety gates...
		if !r.opts.Enable { // hard gate #1: the master switch
			return Result{}, ErrWebDisabled // refuse before doing anything
		}
		if !scan.InScope(target, r.opts.AllowedTargets) { // hard gate #2: the allowlist
			return Result{}, fmt.Errorf("target %q is not in the configured allowlist; refusing to run", target) // refuse
		}
	}
	url := r.opts.Scheme + "://" + target           // build the URL for {url}
	args := RenderArgs(c.Args, url, target, target) // substitute placeholders
	res := Result{                                  // seed the result
		TestID:  c.TestID,                                               // checklist id
		Name:    testName,                                               // checklist name
		Tool:    tool.Name,                                              // tool display name
		Command: strings.Join(append([]string{tool.Bin}, args...), " "), // exact command line
		DryRun:  r.opts.DryRun,                                          // remember whether we ran
	}
	if r.opts.DryRun { // dry-run: stop before executing...
		return res, nil // ...and hand back the command
	}
	tctx, cancel := context.WithTimeout(ctx, r.opts.Timeout) // bound the check
	defer cancel()                                           // always release
	if r.opts.Log != nil {                                   // progress, when asked
		r.opts.Log("running: " + res.Command)
	}
	out, err := r.opts.Runner.Run(tctx, tool.Bin, args...) // execute the tool (no shell)
	res.Output = strings.TrimSpace(string(out))            // capture combined output
	if err != nil {                                        // a tool failure is evidence, not a crash
		res.Error = err.Error() // record it
		return res, nil         // return the result (OK stays false)
	}
	res.OK = true // success
	return res, nil
}

// RunChecks runs several checks in order and returns their results.
func (r *Runner) RunChecks(ctx context.Context, list []Check, nameFor func(Check) string, target string) []Result { // used by `web run`
	out := make([]Result, 0, len(list)) // accumulate results
	for _, c := range list {            // one result per check
		res, err := r.Run(ctx, c, nameFor(c), target) // run it
		if err != nil {                               // a safety/usage error aborts the batch
			out = append(out, Result{TestID: c.TestID, Name: nameFor(c), Tool: c.ToolKey, Error: err.Error()})
			return out // stop on the first hard error
		}
		out = append(out, res) // keep the result
	}
	return out // all results
}
