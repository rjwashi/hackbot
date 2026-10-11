// This file is the guarded executor for logic probes: the ONLY place that starts
// a process (curl) for this family. It mirrors internal/wstg/run.go and
// internal/skillsec/run.go so every active capability shares one safety story:
// disabled by default, dry-run by default at the CLI, and allowlist-checked
// (IPs/domains) before any real request. Tool failures are captured as evidence
// rather than hard errors, so one unreachable endpoint still yields a report.
package logic // same package as logic.go

import ( // imports for the runner
	"context" // cancellation and per-request deadlines
	"fmt"     // Errorf for hard/usage errors
	"strings" // placeholders, trimming, and command rendering
	"sync"    // parallel step fan-out
	"time"    // default timeout

	"github.com/rjwashi/hackbot/internal/ops"  // ErrDisabled and CheckScope: the shared gates
	"github.com/rjwashi/hackbot/internal/scan" // CommandRunner seam so tests inject a fake
)

// Options configures a probe run. The zero value is safe: dry-run, no requests.
type Options struct { // all inputs injected for testability
	Enable         bool               // master switch; required to actually send requests
	AllowedTargets []string           // IP/CIDR allowlist
	AllowedDomains []string           // domain allowlist
	DryRun         bool               // when true, render commands but send nothing
	Timeout        time.Duration      // per-request timeout; defaults to 60s
	Scheme         string             // URL scheme for {url}; defaults to "https"
	Path           string             // endpoint override for {path}; defaults to the probe's
	Token          string             // bearer token added as an Authorization header
	Header         string             // one extra "Name: value" header on every request
	Runner         scan.CommandRunner // process runner seam; defaults to the real one
	Log            func(string)       // optional progress sink (stderr)
}

// defaults fills the seams and limits a caller left unset, so Run is always
// usable directly and tests only override what they care about.
func (o *Options) defaults() { // called at the top of Run
	if o.Timeout <= 0 { // no deadline supplied...
		o.Timeout = defaultTimeout // ...so no request can hang a report
	}
	if o.Scheme == "" { // no scheme supplied...
		o.Scheme = "https" // ...so URLs are built securely
	}
	if o.Runner == nil { // no injected runner...
		o.Runner = scan.ExecRunner{} // ...so run real processes
	}
	if o.Log == nil { // no progress sink...
		o.Log = func(string) {} // ...so logging is silently dropped
	}
}

// effectivePath picks the path substituted into {path}: the operator's -path
// when given, otherwise the probe's curated default.
func effectivePath(o Options, p Probe) string { // one resolution rule
	if strings.TrimSpace(o.Path) != "" { // the operator chose an endpoint
		return strings.TrimSpace(o.Path) // use it
	}
	return p.DefaultPath // otherwise the probe's curated default
}

// curlArgs builds the argv for one request: curl with fixed flags, the step's
// method/path/headers/body, and the probe's token/header additions. The target
// and every value it substitutes travel as single elements — never a shell.
func curlArgs(o Options, p Probe, target string, st Step, id string) []string { // argv builder
	path := render(st.Path, map[string]string{"path": effectivePath(o, p), "id": id}) // fill {path}/{id}
	base := "{url}"                                                                   // plan/placeholder form
	if strings.TrimSpace(target) != "" {                                              // a real run has a target...
		base = o.Scheme + "://" + target // ...so build the concrete URL
	}
	args := []string{ // fixed curl preamble, status line at the end
		"-sS", "-k", "-o", "-", "-w", "\n%{http_code}\n", // body then the HTTP status
		"-X", st.Method, // the step's HTTP method
	}
	for _, h := range st.Headers { // per-step headers
		args = append(args, "-H", h)
	}
	if o.Token != "" { // bearer token for authenticated probes
		args = append(args, "-H", "Authorization: Bearer "+o.Token)
	}
	if strings.TrimSpace(o.Header) != "" { // operator-supplied extra header
		args = append(args, "-H", strings.TrimSpace(o.Header))
	}
	if strings.TrimSpace(st.Body) != "" { // the request body, if any
		args = append(args, "--data-binary", render(st.Body, map[string]string{"id": id}))
	}
	return append(args, base+path) // the request URL closes the argv
}

// Plan renders every command a probe would send, without touching the network.
// Placeholders stay visible until a target exists, exactly like `web plan`.
func Plan(p Probe, o Options) []PlanStep { // used by `logic plan`
	o.defaults()                 // snap the seams so availability is real
	cmds := make([]string, 0, 4) // one command per step x id (parallel once)
	for _, st := range p.Steps { // walk the probe's steps
		ids := st.IDs      // fan-out values
		if len(ids) == 0 { // a single-call step...
			ids = []string{""} // ...runs once with no id
		}
		n := st.Count // repeats
		if n < 1 {    // a zero count means the default
			n = 1
		}
		shown := n       // how many to render (parallel batches repeat once)
		if st.Parallel { // a parallel burst is one command
			shown = 1
		}
		for _, id := range ids { // one row per id
			for k := 0; k < shown; k++ { // render repeats (parallel batches once)
				argv := curlArgs(o, p, "", st, id) // render with placeholders
				cmds = append(cmds, "curl "+strings.Join(argv, " "))
			}
		}
	}
	return []PlanStep{ // one plan row for the probe
		{
			Probe: p.Key, Name: p.Name, Category: p.Category, Tests: p.Tests,
			Like: p.Like, Commands: trimOmitted(cmds),
		},
	}
}

// Run executes one probe against an allowlisted target.
//
// Dry-run renders the commands and never touches the network, and does not need
// the enable switch (a preview should work before configuration). A real run
// refuses unless scanning is enabled and the target is inside the IP or domain
// allowlist. A transport failure makes the whole probe ERROR rather than a
// (misleading) verdict, because FOUND/CLEAN/UNVERIFIED all assume the probe ran.
func Run(ctx context.Context, p Probe, target string, o Options) (Result, error) { // guarded entry point
	target = strings.TrimSpace(target) // normalize the target
	if target == "" {                  // a probe always needs a target...
		return Result{}, fmt.Errorf("logic: missing <target>") // ...else refuse
	}
	if len(p.Steps) == 0 { // a probe with no steps is a definition bug
		return Result{}, fmt.Errorf("logic: probe %q has no steps", p.Key)
	}
	if p.Judge == nil { // every probe must know how to classify
		return Result{}, fmt.Errorf("logic: probe %q has no judge", p.Key)
	}
	o.defaults()   // snap the seams
	if !o.DryRun { // REAL runs enforce the gates up front
		if !o.Enable { // master switch
			return Result{}, ops.ErrDisabled // refuse before doing anything
		}
		if err := ops.CheckScope(ops.KindHost, target, o.AllowedTargets, o.AllowedDomains, nil); err != nil { // allowlist
			return Result{}, err
		}
	}
	res := Result{ // seed the result
		Probe: p.Key, Name: p.Name, Category: p.Category, Tests: p.Tests,
		DryRun: o.DryRun,
	}
	for _, st := range p.Steps { // render every step into commands
		ids := st.IDs
		if len(ids) == 0 {
			ids = []string{""}
		}
		n := st.Count
		if n < 1 {
			n = 1
		}
		shown := n
		if st.Parallel {
			shown = 1 // a parallel burst renders as one command
		}
		for _, id := range ids {
			for k := 0; k < shown; k++ {
				argv := curlArgs(o, p, target, st, id)
				res.Commands = append(res.Commands, "curl "+strings.Join(argv, " "))
			}
		}
	}
	res.Commands = trimOmitted(res.Commands) // keep only what would run
	if o.DryRun {                            // dry-run: stop before executing
		res.Verdict = VerdictDry // say so plainly
		return res, nil
	}
	responses := make([]Response, 0, 8) // accumulate the exchanges
	for _, st := range p.Steps {        // one step at a time
		ids := st.IDs
		if len(ids) == 0 {
			ids = []string{""}
		}
		n := st.Count
		if n < 1 {
			n = 1
		}
		for _, id := range ids { // one id at a time
			if st.Parallel { // fire the repeats concurrently...
				rs := runParallel(ctx, o, p, target, st, id, n) // ...one burst
				responses = append(responses, rs...)
				continue
			}
			for k := 0; k < n; k++ { // sequential repeats...
				rs := runOne(ctx, o, p, target, st, id, k+1)
				responses = append(responses, rs)
			}
		}
	}
	res.Responses = responses     // keep every exchange
	failed := 0                   // tally transport errors
	for _, r := range responses { // count the failures
		if r.Err != "" {
			failed++
		}
	}
	if len(responses) == 0 || failed == len(responses) { // nothing completed...
		res.Verdict = VerdictError // ...so the probe cannot produce a verdict
		res.Reason = "every request failed (connection, TLS, or tool error); see responses"
		res.Evidence = statusReport(p.Key, responses) // numbered evidence
		return res, nil
	}
	res.Verdict, res.Reason = p.Judge(responses) // the pure classifier decides
	res.Evidence = statusReport(p.Key, responses)
	return res, nil
}

// runOne executes a single request and parses its response.
func runOne(ctx context.Context, o Options, p Probe, target string, st Step, id string, idx int) Response { // one exchange
	argv := curlArgs(o, p, target, st, id)              // the argv
	o.Log("running: curl " + strings.Join(argv, " "))   // progress, when asked
	rctx, cancel := context.WithTimeout(ctx, o.Timeout) // bound this request
	defer cancel()                                      // always release
	out, err := o.Runner.Run(rctx, "curl", argv...)     // execute (no shell)
	r := parseResponse(out, err)                        // turn output into a response
	r.Step, r.ID, r.Index = st.Label, id, idx           // attach identity
	return r
}

// runParallel fires count identical requests concurrently and collects them in
// index order, so a race probe's report is deterministic even though the
// requests are not.
func runParallel(ctx context.Context, o Options, p Probe, target string, st Step, id string, count int) []Response { // race burst
	out := make([]Response, count) // one slot per request, pre-sized
	var wg sync.WaitGroup          // wait for every goroutine
	for i := 0; i < count; i++ {   // spawn one goroutine per repeat
		wg.Add(1)          // track it
		go func(idx int) { // fire in its own goroutine
			defer wg.Done()                                     // signal completion
			out[idx] = runOne(ctx, o, p, target, st, id, idx+1) // write to its own slot (no lock needed)
		}(i)
	}
	wg.Wait()  // block until every request finished
	return out // deterministic order
}
