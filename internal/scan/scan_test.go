package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	gotName string
	gotArgs []string
	out     []byte
	err     error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.gotName = name
	f.gotArgs = args
	return f.out, f.err
}

func sampleXML(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "nmap", "testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	return data
}

func TestScanDisabledByDefault(t *testing.T) {
	s := New(Options{NmapPath: "nmap"}, &fakeRunner{})
	if _, err := s.Scan(context.Background(), "192.168.1.10"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

func TestScanRefusesOutOfScope(t *testing.T) {
	fr := &fakeRunner{out: sampleXML(t)}
	s := New(Options{
		Enable:         true,
		AllowedTargets: []string{"192.168.1.0/24"},
	}, fr)

	_, err := s.Scan(context.Background(), "10.0.0.5")
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("expected allowlist refusal, got %v", err)
	}
	if fr.gotName != "" {
		t.Fatal("nmap must not be invoked for an out-of-scope target")
	}
}

func TestScanInScopeBuildsArgsAndParses(t *testing.T) {
	fr := &fakeRunner{out: sampleXML(t)}
	s := New(Options{
		NmapPath:       "nmap",
		Enable:         true,
		AllowedTargets: []string{"192.168.1.0/24"},
		ExtraArgs:      []string{"-T4"},
	}, fr)

	scan, err := s.Scan(context.Background(), "192.168.1.10")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(scan.Hosts) != 3 {
		t.Errorf("parsed hosts = %d, want 3", len(scan.Hosts))
	}
	if fr.gotName != "nmap" {
		t.Errorf("ran %q, want nmap", fr.gotName)
	}
	joined := strings.Join(fr.gotArgs, " ")
	if !strings.Contains(joined, "-oX -") || !strings.Contains(joined, "-sV") {
		t.Errorf("args missing expected flags: %v", fr.gotArgs)
	}
	if fr.gotArgs[len(fr.gotArgs)-1] != "192.168.1.10" {
		t.Errorf("target must be last arg, got %v", fr.gotArgs)
	}
}

func TestScanPropagatesNmapError(t *testing.T) {
	fr := &fakeRunner{out: []byte("nmap: command failed"), err: errors.New("exit status 1")}
	s := New(Options{Enable: true, AllowedTargets: []string{"192.168.1.0/24"}}, fr)
	_, err := s.Scan(context.Background(), "192.168.1.10")
	if err == nil || !strings.Contains(err.Error(), "run nmap") {
		t.Fatalf("expected run error, got %v", err)
	}
}

func TestInScope(t *testing.T) {
	allowed := []string{"192.168.1.0/24", "10.10.10.5"}

	cases := []struct {
		target string
		want   bool
	}{
		{"192.168.1.10", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},
		{"10.10.10.5", true},
		{"10.10.10.6", false},
		{"192.168.1.0/25", true},  // contained in allowed /24
		{"192.168.0.0/16", false}, // broader than allowed /24
		{"gateway.local", false},  // hostnames refused
		{"", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := InScope(c.target, allowed); got != c.want {
			t.Errorf("InScope(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestInScopeEmptyAllowlist(t *testing.T) {
	if InScope("127.0.0.1", nil) {
		t.Error("empty allowlist must allow nothing")
	}
}
