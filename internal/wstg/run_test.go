package wstg // same package as the code under test

import ( // test imports
	"context" // pass a context to Run
	"errors"  // errors.Is for the disabled sentinel
	"testing" // the testing framework
	"time"    // a short timeout for tests
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

// TestRunnerDryRun verifies dry-run renders a command and executes nothing.
func TestRunnerDryRun(t *testing.T) { // safe preview
	fake := &fakeRunner{}                                                      // should never be called
	r := NewRunner(RunnerOptions{DryRun: true, Runner: fake, Scheme: "https"}) // dry-run, not enabled
	ck := CheckByTest("WSTG-INJT-05")[0]                                       // a known check
	res, err := r.Run(context.Background(), ck, "SQL Injection", "10.0.0.1")   // run (dry)
	if err != nil {                                                            // dry-run must not error
		t.Fatalf("Run: %v", err)
	}
	if !res.DryRun || res.OK { // dry-run flag set, nothing executed
		t.Errorf("result = %+v", res)
	}
	if len(fake.calls) != 0 { // no process may run
		t.Errorf("runner was called: %v", fake.calls)
	}
	if res.Command == "" || res.Tool == "" { // command rendered
		t.Errorf("empty command: %+v", res)
	}
}

// TestRunnerDisabled verifies a real run is refused without enable_scan.
func TestRunnerDisabled(t *testing.T) { // master switch
	fake := &fakeRunner{}
	r := NewRunner(RunnerOptions{Enable: false, DryRun: false, Runner: fake}) // enabled? no
	ck := CheckByTest("WSTG-INJT-05")[0]
	if _, err := r.Run(context.Background(), ck, "SQL Injection", "10.0.0.1"); !errors.Is(err, ErrWebDisabled) { // must refuse
		t.Fatalf("err = %v, want ErrWebDisabled", err)
	}
	if len(fake.calls) != 0 { // nothing may run
		t.Errorf("runner was called: %v", fake.calls)
	}
}

// TestRunnerOutOfScope verifies the allowlist gate.
func TestRunnerOutOfScope(t *testing.T) { // allowlist
	fake := &fakeRunner{}
	r := NewRunner(RunnerOptions{Enable: true, DryRun: false, AllowedTargets: []string{"10.0.0.0/24"}, Runner: fake})
	ck := CheckByTest("WSTG-INJT-05")[0]
	if _, err := r.Run(context.Background(), ck, "SQL Injection", "192.168.1.1"); err == nil { // out of scope must error
		t.Fatal("expected an out-of-scope error")
	}
	if len(fake.calls) != 0 { // nothing may run
		t.Errorf("runner was called: %v", fake.calls)
	}
}

// TestRunnerExecutes verifies an in-scope, enabled run reaches the tool.
func TestRunnerExecutes(t *testing.T) { // happy path
	fake := &fakeRunner{out: []byte("boom\n")} // canned output
	r := NewRunner(RunnerOptions{Enable: true, DryRun: false, AllowedTargets: []string{"10.0.0.1"}, Runner: fake, Timeout: time.Second})
	ck := CheckByTest("WSTG-INJT-05")[0] // sqlmap check
	res, err := r.Run(context.Background(), ck, "SQL Injection", "10.0.0.1")
	if err != nil { // must succeed
		t.Fatalf("Run: %v", err)
	}
	if !res.OK || res.Output != "boom" { // output captured
		t.Errorf("result = %+v", res)
	}
	if len(fake.calls) != 1 { // exactly one call
		t.Fatalf("calls = %v", fake.calls)
	}
	if fake.calls[0][0] != "sqlmap" { // the right binary
		t.Errorf("binary = %q", fake.calls[0][0])
	}
	joined := "" // find the target argument
	for _, a := range fake.calls[0] {
		joined += a + " "
	}
	if !contains(joined, "https://10.0.0.1") { // target rendered into args
		t.Errorf("args = %v", fake.calls[0])
	}
}

// TestRunnerToolError verifies a tool failure is returned as evidence.
func TestRunnerToolError(t *testing.T) { // tool missing or failed
	fake := &fakeRunner{out: []byte("not found"), err: errors.New("exit status 127")}
	r := NewRunner(RunnerOptions{Enable: true, DryRun: false, AllowedTargets: []string{"10.0.0.1"}, Runner: fake})
	ck := CheckByTest("WSTG-INJT-05")[0]
	res, err := r.Run(context.Background(), ck, "SQL Injection", "10.0.0.1")
	if err != nil { // not a hard error
		t.Fatalf("Run: %v", err)
	}
	if res.OK || res.Error == "" || res.Output != "not found" { // failure recorded
		t.Errorf("result = %+v", res)
	}
}

// TestRunChecks verifies a batch runs in order.
func TestRunChecks(t *testing.T) { // batch helper
	fake := &fakeRunner{out: []byte("x")}
	r := NewRunner(RunnerOptions{DryRun: true, Runner: fake})
	list := ChecksFor("injection") // sqlmap + dalfox + commix
	names := func(c Check) string { return c.TestID }
	got := r.RunChecks(context.Background(), list, names, "10.0.0.1")
	if len(got) != len(list) { // one result per check
		t.Fatalf("results = %d, want %d", len(got), len(list))
	}
	for i, res := range got { // order preserved
		if res.TestID != list[i].TestID {
			t.Errorf("result %d = %s, want %s", i, res.TestID, list[i].TestID)
		}
	}
}

// contains reports whether s contains sub (small local helper for the tests).
func contains(s, sub string) bool { // avoids importing strings here
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
