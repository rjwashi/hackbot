package logic // same package as the code under test

import ( // test imports
	"context" // pass a context to Run
	"errors"  // errors.Is for the disabled sentinel
	"strings" // assertions on rendered commands and reasons
	"testing" // the testing framework

	"github.com/rjwashi/hackbot/internal/ops" // the shared gates under test
)

// fakeRunner records the commands it is asked to run and returns canned output.
type fakeRunner struct { // implements scan.CommandRunner
	calls [][]string // every command, as [name, args...]
	out   []byte     // canned combined output
	err   error      // canned error
}

// Run satisfies scan.CommandRunner and records the call.
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) { // fake process
	f.calls = append(f.calls, append([]string{name}, args...)) // record it
	return f.out, f.err                                        // return the canned result
}

// TestCatalogValid verifies every shipped probe is internally consistent.
func TestCatalogValid(t *testing.T) { // guards probes.go
	seen := map[string]bool{}     // key uniqueness
	for _, p := range Catalog() { // walk the catalog
		if p.Key == "" || p.Name == "" || p.Category == "" { // identity required
			t.Errorf("probe missing key/name/category: %+v", p)
		}
		if seen[p.Key] { // keys double as CLI/agent slugs
			t.Errorf("duplicate probe key %q", p.Key)
		}
		seen[p.Key] = true     // remember
		if len(p.Tests) == 0 { // every probe anchors to a WSTG test
			t.Errorf("probe %q has no WSTG tests", p.Key)
		}
		if p.Judge == nil { // every probe must classify its evidence
			t.Errorf("probe %q has no judge", p.Key)
		}
		if len(p.Steps) == 0 { // every probe must actually send requests
			t.Errorf("probe %q has no steps", p.Key)
		}
		for _, st := range p.Steps { // step invariants
			if st.Method == "" || st.Path == "" { // a step needs a method and path
				t.Errorf("probe %q has an incomplete step: %+v", p.Key, st)
			}
			if !strings.Contains(st.Path, "{path}") { // anchoring to the endpoint
				t.Errorf("probe %q step %q path %q lacks {path}", p.Key, st.Label, st.Path)
			}
			if st.Count < 0 { // no negative repetition counts
				t.Errorf("probe %q step %q has negative count", p.Key, st.Label)
			}
		}
	}
}

// TestCatalogCountController is a pinned count so an accidental catalog rewrite
// (or a lost probe) is caught instead of silently changing the CLI surface.
func TestCatalogCountController(t *testing.T) { // drift guard
	if got := len(Catalog()); got != 11 { // the shipped set
		t.Errorf("Catalog() = %d probes, want 11 (update this test when the set changes deliberately)", got)
	}
}

// TestDryRun verifies a dry run renders commands and executes nothing.
func TestDryRun(t *testing.T) { // safe preview
	fake := &fakeRunner{}                                         // should never be called
	p, _ := ByKey("workflow")                                     // a known probe
	res, err := Run(context.Background(), p, "10.0.0.1", Options{ // dry run
		DryRun: true, Runner: fake,
	})
	if err != nil { // dry-run must not error
		t.Fatalf("Run: %v", err)
	}
	if res.Verdict != VerdictDry { // the verdict says so
		t.Errorf("verdict = %q, want DRY", res.Verdict)
	}
	if len(fake.calls) != 0 { // no process may run
		t.Errorf("runner was called: %v", fake.calls)
	}
	if len(res.Commands) == 0 { // commands must have been rendered
		t.Error("no commands rendered")
	}
	for _, c := range res.Commands { // every command is curl, argv-safe
		if !strings.HasPrefix(c, "curl ") { // curl is the delivery
			t.Errorf("command %q is not a curl invocation", c)
		}
		if strings.Contains(c, "|") || strings.Contains(c, ";") || strings.Contains(c, "$(") { // no shell constructs
			t.Errorf("command %q contains shell metacharacters", c)
		}
	}
}

// TestDisabled verifies a real run without the enable switch is refused.
func TestDisabled(t *testing.T) { // operations gate
	p, _ := ByKey("workflow")                                   // any probe
	_, err := Run(context.Background(), p, "10.0.0.1", Options{ // NOT enabled
		DryRun: false, Runner: &fakeRunner{},
	})
	if !errors.Is(err, ops.ErrDisabled) { // the shared, testable sentinel
		t.Fatalf("err = %v, want ops.ErrDisabled", err)
	}
}

// TestOutOfScope verifies the allowlist gate refuses non-allowlisted targets.
func TestOutOfScope(t *testing.T) { // network gate
	p, _ := ByKey("workflow")                                       // any probe
	_, err := Run(context.Background(), p, "203.0.113.42", Options{ // outside the list
		Enable: true, DryRun: false, Runner: &fakeRunner{},
		AllowedTargets: []string{"10.0.0.0/8"}, // a different range
	})
	if err == nil { // refusal expected
		t.Fatal("err = nil, want a scope error")
	}
}

// TestDisabledTargetBlank verifies a missing target is refused before anything.
func TestMissingTarget(t *testing.T) { // usage guard
	p, _ := ByKey("workflow")                                           // any probe
	_, err := Run(context.Background(), p, "  ", Options{DryRun: true}) // blank target
	if err == nil {                                                     // refusal expected
		t.Fatal("err = nil, want a missing-target error")
	}
}

// TestExecuteHappyPath drives a probe through the fake runner and checks that
// the response parser and the verdict pipeline agree with a canned exchange.
func TestExecuteHappyPath(t *testing.T) { // end-to-end with a canned 200
	fake := &fakeRunner{out: []byte("<html>ok</html>\n200\n")}    // HTTP 200 + body
	p, _ := ByKey("workflow")                                     // 2xx means FOUND
	res, err := Run(context.Background(), p, "10.0.0.1", Options{ // real run
		Enable: true, DryRun: false, Runner: fake,
		AllowedTargets: []string{"10.0.0.1"}, // in scope
	})
	if err != nil { // nothing should have refused it
		t.Fatalf("Run: %v", err)
	}
	if res.Verdict != VerdictFound { // direct 2xx is the workflow finding
		t.Errorf("verdict = %q, want FOUND (%s)", res.Verdict, res.Reason)
	}
	if len(fake.calls) != 1 { // exactly one request was sent
		t.Errorf("runner called %d times, want 1", len(fake.calls))
	}
	if n := len(res.Evidence); n != 1 { // numbered evidence exists
		t.Errorf("evidence = %d lines, want 1", n)
	}
	want := "curl -sS -k -o - -w" // the rendered command is curl with the status trailer
	found := false
	for _, c := range res.Commands {
		if strings.Contains(c, want) && strings.Contains(c, "10.0.0.1") { // executable + correct target
			found = true
		}
	}
	if !found { // the command must reference the real target
		t.Errorf("no command referenced the target: %v", res.Commands)
	}
}

// TestAllRequestsFail verifies a probe whose requests all error reports ERROR
// instead of a misleading verdict.
func TestAllRequestsFail(t *testing.T) { // transport failure != verdict
	fake := &fakeRunner{err: errors.New("connection refused")}    // nothing completes
	p, _ := ByKey("workflow")                                     // any probe
	res, err := Run(context.Background(), p, "10.0.0.1", Options{ // real run
		Enable: true, DryRun: false, Runner: fake,
		AllowedTargets: []string{"10.0.0.1"},
	})
	if err != nil { // refused runs must still deliver a report
		t.Fatalf("Run: %v", err)
	}
	if res.Verdict != VerdictError { // the honest outcome
		t.Errorf("verdict = %q, want ERROR", res.Verdict)
	}
	if len(res.Responses) == 0 || res.Responses[0].Err == "" { // the failure is recorded
		t.Errorf("responses = %+v, want a recorded transport error", res.Responses)
	}
}

// TestRenderIDOR checks the id fan-out renders one command per id, each carrying
// a substituted {id}.
func TestRenderIDOR(t *testing.T) { // placeholders substituted per id
	p, _ := ByKey("idor")                                         // sequential ids
	res, err := Run(context.Background(), p, "10.0.0.1", Options{ // dry run
		DryRun: true, Runner: &fakeRunner{},
	})
	if err != nil { // dry-run must not error
		t.Fatalf("Run: %v", err)
	}
	if len(p.Steps[0].IDs) != 5 { // the catalog yields five ids
		t.Fatalf("idor steps ids = %v, want 5", p.Steps[0].IDs)
	}
	if len(res.Commands) != 5 { // one command per id
		t.Errorf("commands = %d, want 5", len(res.Commands))
	}
	if !strings.Contains(strings.Join(res.Commands, " "), "/api/object/5") { // last id rendered
		t.Errorf("commands missing the /api/object/5 call: %v", res.Commands)
	}
}

// TestParseResponse covers the parser's edge cases: a clean status line, a
// status line plus body, an odd (non-status) trailer, and a tool error.
func TestParseResponse(t *testing.T) { // parser edges
	cases := []struct { // table of inputs
		name string // case label
		out  []byte // combined output
		err  error  // tool error
		want string // expected status ("" = none)
		body string // expected body
	}{
		{"empty", []byte(""), nil, "", ""},
		{"status only", []byte("\n200\n"), nil, "200", ""},
		{"body then status", []byte("<html>hi</html>\n302\n"), nil, "302", "<html>hi</html>"},
		{"no status trailer", []byte("curl: (7) Failed to connect\n"), nil, "", "curl: (7) Failed to connect"},
		{"tool error", []byte(""), errors.New("exit status 7"), "", ""},
	}
	for _, tc := range cases { // walk the table
		r := parseResponse(tc.out, tc.err) // run it
		if r.Status != tc.want {           // the parsed status
			t.Errorf("%s: status = %q, want %q", tc.name, r.Status, tc.want)
		}
		if r.Body != tc.body { // the parsed body
			t.Errorf("%s: body = %q, want %q", tc.name, r.Body, tc.body)
		}
	}
}

// classify is a tiny helper for the judge tests below.
func classify(p Probe, rs []Response) (Verdict, string) { // judge shim
	return p.Judge(rs) // pure classifier call
}

// TestJudgeRules pins the classifier outcomes for the representative cases of
// every probe: the FOUND signal, the CLEAN counter-signal, and the honest
// UNVERIFIED default where the evidence cannot settle the class.
func TestJudgeRules(t *testing.T) { // classifiers, table-driven
	ok := Response{Status: "200"}                  // a normal success
	forb := Response{Status: "403"}                // a refusal
	srv := Response{Status: "500"}                 // a server error
	redir := Response{Status: "302"}               // a redirect
	diff := Response{Status: "200", Body: "other"} // same status, different body

	cases := []struct { // table of probe x responses -> expected verdict
		name  string     // case label
		probe string     // probe key
		rs    []Response // the synthetic exchanges
		want  Verdict    // expected verdict
	}{
		{"race divergent", "race", []Response{ok, ok, diff}, VerdictFound},
		{"race identical", "race", []Response{ok, ok, ok}, VerdictUnverified},
		{"ratelimit 429", "ratelimit", []Response{{Status: "429"}}, VerdictClean},
		{"ratelimit throttle msg", "ratelimit", []Response{{Status: "200", Body: "Too many requests, try again later"}}, VerdictClean},
		{"ratelimit no lockout", "ratelimit", []Response{ok, ok, ok}, VerdictFound},
		{"workflow direct 2xx", "workflow", []Response{ok}, VerdictFound},
		{"workflow gated", "workflow", []Response{forb}, VerdictClean},
		{"workflow redirected", "workflow", []Response{redir}, VerdictUnverified},
		{"idor different objects", "idor", []Response{ok, ok, diff}, VerdictFound},
		{"idor same object", "idor", []Response{ok, ok, ok}, VerdictUnverified},
		{"idor one refused", "idor", []Response{ok, ok, forb}, VerdictClean},
		{"privesc flip", "privesc", []Response{forb, ok}, VerdictFound},
		{"privesc stays closed", "privesc", []Response{forb, forb, forb}, VerdictClean},
		{"privesc open baseline", "privesc", []Response{ok, ok}, VerdictUnverified},
		{"authz flip", "authz-bypass", []Response{forb, ok, forb, forb, forb}, VerdictFound},
		{"authz stays closed", "authz-bypass", []Response{forb, forb, forb, forb, forb}, VerdictClean},
		{"error disclosure trace", "error-disclosure", []Response{ok, {Status: "200", Body: "at foo.bar(Bar.java:12)"}}, VerdictFound},
		{"error disclosure clean 4xx", "error-disclosure", []Response{ok, forb, forb, forb}, VerdictClean},
		{"error disclosure silent 5xx", "error-disclosure", []Response{ok, srv}, VerdictUnverified},
		{"payment accepted", "payment-integrity", []Response{ok}, VerdictFound},
		{"payment rejected", "payment-integrity", []Response{forb}, VerdictClean},
		{"upload accepted", "upload-type", []Response{ok, ok}, VerdictFound},
		{"upload rejected", "upload-type", []Response{forb, forb}, VerdictClean},
		{"mass-assignment echoed", "mass-assignment", []Response{{Status: "200", Body: `{"role":"admin"}`}}, VerdictFound},
		{"mass-assignment rejected", "mass-assignment", []Response{forb}, VerdictClean},
		{"graphql introspected", "graphql-args", []Response{{Status: "200", Body: `{"data":{"__schema":{}}}`}, ok}, VerdictFound},
		{"graphql refused", "graphql-args", []Response{forb, forb}, VerdictClean},
	}
	for _, tc := range cases { // walk the table
		p, ok := ByKey(tc.probe) // the probe under test
		if !ok {                 // a bad key is a test bug
			t.Fatalf("unknown probe %q", tc.probe)
		}
		got, _ := classify(p, tc.rs) // classify the synthetic evidence
		if got != tc.want {          // the pinned outcome
			t.Errorf("%s: verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestTimeoutDefaults verifies the runner applies sane defaults so tests and
// callers cannot accidentally send unbounded requests.
func TestTimeoutDefaults(t *testing.T) { // seam defaults
	o := Options{}           // the zero value
	o.defaults()             // fill the seams
	if o.Scheme != "https" { // secure by default
		t.Errorf("scheme = %q, want https", o.Scheme)
	}
	if o.Timeout <= 0 { // never unbounded
		t.Error("timeout not defaulted")
	}
}
