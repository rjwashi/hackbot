// This file is the guarded executor for ops tasks. It is the ONLY place that
// starts a process for recon/discovery, mirroring internal/wstg/run.go so both
// families share one safety story: disabled by default, dry-run by default at the
// CLI, and allowlist-checked (IPs and domains) before anything runs.
package ops // same package as ops.go

import ( // imports for this file
	"context" // cancellation for long-running tools
	"fmt"     // Errorf for contextual errors
	"strings" // trimming output and building command lines
	"time"    // per-task timeout

	"github.com/rjwashi/hackbot/internal/scan" // CommandRunner + TargetInScope
)

// ErrDisabled is returned when a real run is attempted without enable_scan.
//
// We reuse scan.ErrDisabled (same underlying value) so callers can treat every
// "scanning is off" case identically with errors.Is, regardless of which agent
// family raised it.
var ErrDisabled = scan.ErrDisabled // shared sentinel

// Options configures a Runner. The zero value is safe: dry-run, no execution.
type Options struct { // all inputs injected for testability
	Enable         bool               // master switch; required for a real run
	AllowedTargets []string           // IP/CIDR allowlist
	AllowedDomains []string           // domain allowlist (recon)
	AllowedPaths   []string           // local path allowlist (secrets/deps)
	DryRun         bool               // render commands but send nothing
	Timeout        time.Duration      // per-task timeout; defaults to 60s
	Scheme         string             // URL scheme for {url}; defaults to "https"
	Wordlist       string             // wordlist path; defaults to DefaultWordlist
	Runner         scan.CommandRunner // process seam; defaults to the real one
	Log            func(string)       // optional progress sink
}

// Result is the outcome of one task.
type Result struct { // serializable for `-json`
	Task    string `json:"task"`             // task id
	Name    string `json:"name"`             // task name
	Tool    string `json:"tool"`             // tool display name
	Command string `json:"command"`          // exact command line
	DryRun  bool   `json:"dry_run"`          // true when nothing executed
	Stdin   bool   `json:"stdin,omitempty"`  // true when this step was fed the previous step's output
	OK      bool   `json:"ok"`               // true when the tool exited cleanly
	Output  string `json:"output,omitempty"` // combined stdout+stderr (trimmed)
	Error   string `json:"error,omitempty"`  // error text when the tool failed
}

// Runner executes ops tasks against allowlisted targets.
type Runner struct { // holds a catalog + resolved options
	cat  *Catalog // tools/tasks definition
	opts Options  // resolved options
}

// New applies safe defaults and returns a Runner bound to a catalog.
func New(cat *Catalog, opts Options) *Runner { // constructor
	if opts.Timeout <= 0 { // allow callers to omit the timeout...
		opts.Timeout = 60 * time.Second // ...and get a sane one
	}
	if opts.Scheme == "" { // allow callers to omit the scheme...
		opts.Scheme = "https" // ...and default to https
	}
	if opts.Wordlist == "" { // allow callers to omit the wordlist...
		opts.Wordlist = DefaultWordlist // ...and use the free SecLists default
	}
	if opts.Runner == nil { // allow callers to omit the runner...
		opts.Runner = scan.ExecRunner{} // ...and get the real process runner
	}
	return &Runner{cat: cat, opts: opts} // assemble
}

// Run executes one task against target.
//
// Dry-run never touches the network and does not require the enable switch (a
// preview should work before configuration). A real run refuses unless scanning
// is enabled and the target is inside the IP or domain allowlist. A tool failure
// is reported in Result.Error, not returned as a hard error, so one missing tool
// does not abort a batch.
func (r *Runner) Run(ctx context.Context, t Task, target string) (Result, error) { // guarded entry point
	tool, ok := r.cat.ToolByKey(t.ToolKey) // resolve the tool
	if !ok {                               // unknown tool key is a programming error
		return Result{}, fmt.Errorf("ops: unknown tool %q for task %s", t.ToolKey, t.Key)
	}
	target = strings.TrimSpace(target) // normalize
	if target == "" {                  // every task needs a target
		return Result{}, fmt.Errorf("ops: missing <target>")
	}
	if !r.opts.DryRun { // only REAL runs enforce the gates
		if !r.opts.Enable { // master switch
			return Result{}, ErrDisabled
		}
		if err := CheckScope(r.cat.Kind, target, r.opts.AllowedTargets, r.opts.AllowedDomains, r.opts.AllowedPaths); err != nil { // kind-aware allowlist
			return Result{}, err
		}
	}
	wl := r.opts.Wordlist                               // effective wordlist
	subs := Subs(r.cat.Kind, r.opts.Scheme, target, wl) // placeholder values
	args := Render(t.Args, subs)                        // rendered argv
	res := Result{                                      // seed the result
		Task:    t.Key,
		Name:    t.Name,
		Tool:    tool.Name,
		Command: strings.Join(append([]string{tool.Bin}, args...), " "),
		DryRun:  r.opts.DryRun,
	}
	if r.opts.DryRun { // dry-run: stop before executing
		return res, nil
	}
	tctx, cancel := context.WithTimeout(ctx, r.opts.Timeout) // bound the task
	defer cancel()                                           // always release
	if r.opts.Log != nil {                                   // progress, when asked
		r.opts.Log("running: " + res.Command)
	}
	out, err := r.opts.Runner.Run(tctx, tool.Bin, args...) // execute (no shell)
	res.Output = strings.TrimSpace(string(out))            // capture output
	if err != nil {                                        // tool failure is evidence
		res.Error = err.Error()
		return res, nil
	}
	res.OK = true // success
	return res, nil
}

// RunAll runs several tasks in order, stopping only on a hard safety error.
func (r *Runner) RunAll(ctx context.Context, tasks []Task, target string) []Result { // used by batch runs
	out := make([]Result, 0, len(tasks)) // accumulate
	for _, t := range tasks {            // one result per task
		res, err := r.Run(ctx, t, target)
		if err != nil { // a safety/usage error aborts the batch
			out = append(out, Result{Task: t.Key, Name: t.Name, Tool: t.ToolKey, Error: err.Error()})
			return out
		}
		out = append(out, res)
	}
	return out
}

// RunChain executes a multi-step pipeline against one target.
//
// Safety: a chain is gated exactly like a single task — a real run requires
// enable_scan and one in-scope target. Because every step shares the same target
// we check the scope ONCE up front (and resolve every task/tool first, so a
// malformed chain fails before anything runs). A step may feed the previous
// step's raw stdout into its stdin (FeedPrevious); that needs the underlying
// runner to implement scan.StdinRunner, and we say so plainly instead of
// silently running a step with no input.
//
// Failure policy: a tool error ends the chain and the results gathered so far are
// returned. That is deliberate — in a pipeline a failed step usually makes every
// later step meaningless, and stopping avoids emitting a wall of follow-on
// errors. (A future variant could continue independent steps; nothing here needs
// that yet.)
func (r *Runner) RunChain(ctx context.Context, ch Chain, target string) ([]Result, error) { // used by `<cmd> <chain>`
	target = strings.TrimSpace(target) // normalize
	if target == "" {                  // every chain needs a target
		return nil, fmt.Errorf("ops: missing <target>")
	}
	if len(ch.Steps) == 0 { // a chain with no steps is a definition bug
		return nil, fmt.Errorf("ops: chain %q has no steps", ch.Key)
	}

	// Resolve every step's task and tool up front, and validate the pipe wiring,
	// so an invalid chain never half-runs.
	type resolved struct { // one prepared step
		task Task      // the task
		tool Tool      // its tool
		step ChainStep // the original step (for Args override / FeedPrevious)
	}
	steps := make([]resolved, 0, len(ch.Steps)) // prepared steps
	needsStdin := false                         // does any step read the previous output?
	for i, st := range ch.Steps {               // walk declared order
		t, ok := r.cat.TaskByKey(st.TaskKey) // resolve the task
		if !ok {                             // unknown task is a definition bug
			return nil, fmt.Errorf("ops: chain %q references unknown task %q", ch.Key, st.TaskKey)
		}
		tool, ok := r.cat.ToolByKey(t.ToolKey) // resolve its tool
		if !ok {                               // unknown tool is a definition bug
			return nil, fmt.Errorf("ops: task %q references unknown tool %q", t.Key, t.ToolKey)
		}
		if st.FeedPrevious { // a step that reads the previous output...
			if i == 0 { // ...cannot be first
				return nil, fmt.Errorf("ops: chain %q step 1 cannot read previous output", ch.Key)
			}
			needsStdin = true // remember we will need a stdin-capable runner
		}
		steps = append(steps, resolved{task: t, tool: tool, step: st}) // keep it
	}

	// One safety gate for the whole chain (same target throughout).
	if !r.opts.DryRun { // dry-run sends nothing and needs no configuration
		if !r.opts.Enable { // master switch
			return nil, ErrDisabled
		}
		if err := CheckScope(r.cat.Kind, target, r.opts.AllowedTargets, r.opts.AllowedDomains, r.opts.AllowedPaths); err != nil {
			return nil, err
		}
	}

	var stdinRunner scan.StdinRunner                    // the stdin-capable runner, if any
	if sr, ok := r.opts.Runner.(scan.StdinRunner); ok { // opportunistic type assertion
		stdinRunner = sr
	}
	if !r.opts.DryRun && needsStdin && stdinRunner == nil { // we cannot satisfy the chain
		return nil, fmt.Errorf("ops: runner cannot pipe stdin for chain %q", ch.Key)
	}

	subs := Subs(r.cat.Kind, r.opts.Scheme, target, r.opts.Wordlist) // placeholders
	out := make([]Result, 0, len(steps))                             // accumulated results
	var prev []byte                                                  // previous step's raw stdout
	for _, rs := range steps {                                       // run each step in order
		args := rs.task.Args       // default to the task's template
		if len(rs.step.Args) > 0 { // a step may override (e.g. drop -u to read stdin)
			args = rs.step.Args
		}
		rendered := Render(args, subs) // fill placeholders
		res := Result{                 // seed the result
			Task:    rs.task.Key,
			Name:    rs.task.Name,
			Tool:    rs.tool.Name,
			Command: strings.Join(append([]string{rs.tool.Bin}, rendered...), " "),
			DryRun:  r.opts.DryRun,
			Stdin:   rs.step.FeedPrevious,
		}
		if r.opts.DryRun { // preview only
			out = append(out, res)
			continue
		}
		tctx, cancel := context.WithTimeout(ctx, r.opts.Timeout) // bound the step
		if r.opts.Log != nil {                                   // progress, when asked
			r.opts.Log("running: " + res.Command)
		}
		var ( // result of the child process
			o   []byte
			err error
		)
		if rs.step.FeedPrevious { // feed the previous output on stdin
			o, err = stdinRunner.RunStdin(tctx, prev, rs.tool.Bin, rendered...)
		} else { // ordinary run
			o, err = r.opts.Runner.Run(tctx, rs.tool.Bin, rendered...)
		}
		cancel()                                  // release the timeout context
		res.Output = strings.TrimSpace(string(o)) // capture (trimmed) output
		if err != nil {                           // a failed step ends the chain
			res.Error = err.Error()
			out = append(out, res)
			return out, nil
		}
		res.OK = true // success
		prev = o      // keep raw stdout for the next step
		out = append(out, res)
	}
	return out, nil
}
