package scan // same package as scan.go

import ( // test imports
	"context"       // pass a context to Scan
	"errors"        // errors.Is for the sentinel check
	"os"            // read the shared fixture
	"path/filepath" // build the fixture path portably
	"strings"       // string assertions
	"testing"       // the testing framework
)

// fakeRunner records the command it received and returns canned output.
type fakeRunner struct { // test double for CommandRunner
	gotName string   // captured binary name
	gotArgs []string // captured args
	out     []byte   // canned stdout
	err     error    // canned error
}

// Run implements CommandRunner, capturing inputs and returning the canned result.
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) { // interface method
	f.gotName = name    // record the binary
	f.gotArgs = args    // record the args
	return f.out, f.err // return the canned output/error
}

// sampleXML loads the fixture XML bytes.
func sampleXML(t *testing.T) []byte { // shared helper
	t.Helper()                                                                      // mark as helper
	data, err := os.ReadFile(filepath.Join("..", "nmap", "testdata", "sample.xml")) // read fixture from the sibling package
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	return data // return raw bytes
}

// TestScanDisabledByDefault verifies the master switch blocks scanning.
func TestScanDisabledByDefault(t *testing.T) { // safety gate #1
	s := New(Options{NmapPath: "nmap"}, &fakeRunner{})                                        // scanner with Enable unset (false)
	if _, err := s.Scan(context.Background(), "192.168.1.10"); !errors.Is(err, ErrDisabled) { // must return the sentinel
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

// TestScanRefusesOutOfScope verifies the allowlist blocks scanning.
func TestScanRefusesOutOfScope(t *testing.T) { // safety gate #2
	fr := &fakeRunner{out: sampleXML(t)} // fake runner that would succeed if called
	s := New(Options{
		Enable:         true,                       // enabled...
		AllowedTargets: []string{"192.168.1.0/24"}, // ...but this allowlist...
	}, fr)

	_, err := s.Scan(context.Background(), "10.0.0.5")             // ...does not include this target
	if err == nil || !strings.Contains(err.Error(), "allowlist") { // must be refused with an allowlist error
		t.Fatalf("expected allowlist refusal, got %v", err)
	}
	if fr.gotName != "" { // the critical safety assertion: nmap must NOT have run...
		t.Fatal("nmap must not be invoked for an out-of-scope target") // ...before the scope check
	}
}

// TestScanInScopeBuildsArgsAndParses verifies the happy path.
func TestScanInScopeBuildsArgsAndParses(t *testing.T) { // allowed scan
	fr := &fakeRunner{out: sampleXML(t)} // fake runner returns valid XML
	s := New(Options{
		NmapPath:       "nmap",                     // binary
		Enable:         true,                       // enabled
		AllowedTargets: []string{"192.168.1.0/24"}, // target is in scope
		ExtraArgs:      []string{"-T4"},            // extra flags
	}, fr)

	scan, err := s.Scan(context.Background(), "192.168.1.10") // run
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(scan.Hosts) != 3 { // parsing happened
		t.Errorf("parsed hosts = %d, want 3", len(scan.Hosts))
	}
	if fr.gotName != "nmap" { // correct binary
		t.Errorf("ran %q, want nmap", fr.gotName)
	}
	joined := strings.Join(fr.gotArgs, " ")                                     // join args for substring checks
	if !strings.Contains(joined, "-oX -") || !strings.Contains(joined, "-sV") { // required flags present
		t.Errorf("args missing expected flags: %v", fr.gotArgs)
	}
	if fr.gotArgs[len(fr.gotArgs)-1] != "192.168.1.10" { // target must be the LAST arg
		t.Errorf("target must be last arg, got %v", fr.gotArgs)
	}
}

// TestScanPropagatesNmapError verifies nmap failures surface with context.
func TestScanPropagatesNmapError(t *testing.T) { // error path
	fr := &fakeRunner{out: []byte("nmap: command failed"), err: errors.New("exit status 1")} // simulate failure
	s := New(Options{Enable: true, AllowedTargets: []string{"192.168.1.0/24"}}, fr)          // in-scope
	_, err := s.Scan(context.Background(), "192.168.1.10")                                   // run
	if err == nil || !strings.Contains(err.Error(), "run nmap") {                            // error must be wrapped with "run nmap"
		t.Fatalf("expected run error, got %v", err)
	}
}

// TestInScope covers the allowlist matching rules.
func TestInScope(t *testing.T) { // table-driven scope tests
	allowed := []string{"192.168.1.0/24", "10.10.10.5"} // mixed CIDR + literal IP

	cases := []struct { // table of target/expected
		target string // input
		want   bool   // expected result
	}{
		{"192.168.1.10", true},    // inside allowed CIDR
		{"192.168.1.255", true},   // top of allowed CIDR
		{"192.168.2.1", false},    // outside CIDR
		{"10.10.10.5", true},      // exact literal match
		{"10.10.10.6", false},     // not the literal, not in a CIDR
		{"192.168.1.0/25", true},  // narrower CIDR contained in allowed /24
		{"192.168.0.0/16", false}, // broader CIDR -> refusing prevents scope widening
		{"gateway.local", false},  // hostnames are refused
		{"", false},               // empty refused
		{"not-an-ip", false},      // garbage refused
	}
	for _, c := range cases { // run each case
		if got := InScope(c.target, allowed); got != c.want { // compare
			t.Errorf("InScope(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

// TestInScopeEmptyAllowlist verifies an empty allowlist allows nothing.
func TestInScopeEmptyAllowlist(t *testing.T) { // fail-closed behavior
	if InScope("127.0.0.1", nil) { // with no allowlist...
		t.Error("empty allowlist must allow nothing") // ...nothing is in scope
	}
}
