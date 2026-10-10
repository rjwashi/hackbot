package nmap

import (
	"encoding/json"
	"testing"
)

func TestAnalyzeRanksCriticalFirst(t *testing.T) {
	findings := Analyze(loadSample(t))
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}

	// Sample data includes Docker API (2375, critical) and Redis (6379, critical).
	if findings[0].Severity != SevCritical {
		t.Errorf("first finding severity = %s, want CRITICAL", findings[0].Severity)
	}

	// Severity must be non-increasing.
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Severity < findings[i].Severity {
			t.Fatalf("findings not sorted at %d: %s before %s",
				i, findings[i-1].Severity, findings[i].Severity)
		}
	}
}

func TestAnalyzeFlagsKnownRiskyPorts(t *testing.T) {
	findings := Analyze(loadSample(t))

	wantPorts := map[int]Severity{
		2375: SevCritical,
		6379: SevCritical,
		3306: SevHigh,
	}
	got := map[int]Severity{}
	for _, f := range findings {
		got[f.Port] = f.Severity
	}
	for port, sev := range wantPorts {
		if got[port] != sev {
			t.Errorf("port %d severity = %s, want %s", port, got[port], sev)
		}
	}
}

func TestAnalyzeIncludesDetectedBanner(t *testing.T) {
	findings := Analyze(loadSample(t))
	for _, f := range findings {
		if f.Port == 2375 {
			if want := "Docker 24.0.5"; !contains(f.Detail, want) {
				t.Errorf("port 2375 detail %q should include %q", f.Detail, want)
			}
			return
		}
	}
	t.Fatal("no finding for port 2375")
}

func TestAnalyzeSkipsDownHostsAndClosedPorts(t *testing.T) {
	findings := Analyze(loadSample(t))
	for _, f := range findings {
		if f.Port == 8080 {
			t.Error("closed port 8080 should not produce a finding")
		}
		if f.Host == "192.168.1.99" {
			t.Error("down host should not produce findings")
		}
	}
}

func TestAnalyzeNilScan(t *testing.T) {
	if got := Analyze(nil); got != nil {
		t.Errorf("Analyze(nil) = %v, want nil", got)
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SevInfo: "INFO", SevLow: "LOW", SevMedium: "MEDIUM",
		SevHigh: "HIGH", SevCritical: "CRITICAL",
	}
	for sev, want := range cases {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSeverityMarshalJSON(t *testing.T) {
	b, err := json.Marshal(SevHigh)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"HIGH"` {
		t.Errorf("Severity JSON = %s, want \"HIGH\"", b)
	}
}
