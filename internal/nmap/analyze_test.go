package nmap // same package as analyze.go

import ( // test imports
	"encoding/json" // to test Severity JSON marshaling
	"testing"       // the testing framework
)

// TestAnalyzeRanksCriticalFirst verifies findings are sorted worst-first.
func TestAnalyzeRanksCriticalFirst(t *testing.T) { // ordering
	findings := Analyze(loadSample(t)) // analyze the fixture
	if len(findings) == 0 {            // must produce findings
		t.Fatal("expected findings")
	}

	// Sample data includes Docker API (2375, critical) and Redis (6379, critical).
	if findings[0].Severity != SevCritical { // the top finding must be critical
		t.Errorf("first finding severity = %s, want CRITICAL", findings[0].Severity)
	}

	for i := 1; i < len(findings); i++ { // severity must be non-increasing across the list
		if findings[i-1].Severity < findings[i].Severity { // a later finding worse than an earlier one...
			t.Fatalf("findings not sorted at %d: %s before %s", // ...is a sort bug
				i, findings[i-1].Severity, findings[i].Severity)
		}
	}
}

// TestAnalyzeFlagsKnownRiskyPorts verifies specific port->severity mappings.
func TestAnalyzeFlagsKnownRiskyPorts(t *testing.T) { // rule mapping
	findings := Analyze(loadSample(t)) // analyze fixture

	wantPorts := map[int]Severity{ // expected severities for ports present in the fixture
		2375: SevCritical, // Docker API
		6379: SevCritical, // Redis
		3306: SevHigh,     // MySQL
	}
	got := map[int]Severity{}    // collect actual severities by port
	for _, f := range findings { // walk findings...
		got[f.Port] = f.Severity // ...indexing by port
	}
	for port, sev := range wantPorts { // compare each expectation
		if got[port] != sev {
			t.Errorf("port %d severity = %s, want %s", port, got[port], sev)
		}
	}
}

// TestAnalyzeIncludesDetectedBanner verifies product/version text is appended.
func TestAnalyzeIncludesDetectedBanner(t *testing.T) { // banner enrichment
	findings := Analyze(loadSample(t)) // analyze fixture
	for _, f := range findings {       // find the Docker finding...
		if f.Port == 2375 { // ...the one for port 2375
			if want := "Docker 24.0.5"; !contains(f.Detail, want) { // detail must mention the detected product/version
				t.Errorf("port 2375 detail %q should include %q", f.Detail, want)
			}
			return // done once found
		}
	}
	t.Fatal("no finding for port 2375") // fixture changed unexpectedly
}

// TestAnalyzeSkipsDownHostsAndClosedPorts verifies exclusions.
func TestAnalyzeSkipsDownHostsAndClosedPorts(t *testing.T) { // filtering
	findings := Analyze(loadSample(t)) // analyze fixture
	for _, f := range findings {       // inspect every finding
		if f.Port == 8080 { // closed port...
			t.Error("closed port 8080 should not produce a finding") // ...must not appear
		}
		if f.Host == "192.168.1.99" { // down host...
			t.Error("down host should not produce findings") // ...must not appear
		}
	}
}

// TestAnalyzeNilScan verifies nil is handled gracefully.
func TestAnalyzeNilScan(t *testing.T) { // defensive
	if got := Analyze(nil); got != nil { // nil in -> nil out
		t.Errorf("Analyze(nil) = %v, want nil", got)
	}
}

// TestSeverityString verifies every severity label.
func TestSeverityString(t *testing.T) { // String() mapping
	cases := map[Severity]string{ // expected labels
		SevInfo: "INFO", SevLow: "LOW", SevMedium: "MEDIUM",
		SevHigh: "HIGH", SevCritical: "CRITICAL",
	}
	for sev, want := range cases { // check each
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}

// contains is a tiny substring helper (avoids importing strings just for this).
func contains(s, sub string) bool { // used above
	for i := 0; i+len(sub) <= len(s); i++ { // slide the window across s
		if s[i:i+len(sub)] == sub { // compare the slice with sub...
			return true // ...return on match
		}
	}
	return false // no match
}

// TestSeverityMarshalJSON verifies severity serializes as its label string.
func TestSeverityMarshalJSON(t *testing.T) { // JSON shape
	b, err := json.Marshal(SevHigh) // marshal one severity
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"HIGH"` { // must be the quoted string, not the int 3
		t.Errorf("Severity JSON = %s, want \"HIGH\"", b)
	}
}
