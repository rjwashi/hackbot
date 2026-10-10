package vulscan // same package as vulscan.go

import ( // test imports
	"path/filepath" // build the fixture path
	"strings"       // string assertions
	"testing"       // the testing framework

	"github.com/rjwashi/hackbot/internal/nmap" // the scan type
)

// loadScan parses the shared nmap fixture.
func loadScan(t *testing.T) *nmap.Scan { // shared helper
	t.Helper()                                                                       // mark as a helper for cleaner failures
	sc, err := nmap.ParseFile(filepath.Join("..", "nmap", "testdata", "sample.xml")) // parse the fixture
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return sc // parsed scan
}

// TestParseFixture verifies vulscan output is located and parsed from a scan.
func TestParseFixture(t *testing.T) { // happy path against sample.xml
	results := Parse(loadScan(t)) // parse
	if len(results) != 1 {        // the fixture has exactly one vulscan script (redis)
		t.Fatalf("results = %d, want 1", len(results))
	}
	r := results[0]                                                                                // the single result
	if r.Host != "192.168.1.50" || r.Port != 6379 || r.Protocol != "tcp" || r.Service != "redis" { // target fields
		t.Errorf("result target = %+v", r)
	}
	if len(r.Matches) != 3 { // three entries in the fixture output
		t.Fatalf("matches = %d, want 3", len(r.Matches))
	}
	if r.Matches[0].ID != "CVE-2022-0543" || r.Matches[0].Title != "Redis Lua sandbox escape" { // first row parsed
		t.Errorf("first match = %+v", r.Matches[0])
	}
	var sawOSVDB bool // non-CVE ids must also be preserved
	for _, m := range r.Matches {
		if m.ID == "OSVDB-100500" {
			sawOSVDB = true
		}
	}
	if !sawOSVDB {
		t.Errorf("expected OSVDB-100500 in %+v", r.Matches)
	}
}

// TestCVEsFiltersAndSorts verifies only canonical CVEs are returned, sorted.
func TestCVEsFiltersAndSorts(t *testing.T) { // CVE extraction
	got := CVEs(loadScan(t)) // extract
	if len(got) != 2 {       // OSVDB must be filtered out
		t.Fatalf("CVEs = %v, want 2", got)
	}
	if got[0] != "CVE-2022-0543" || got[1] != "CVE-2023-28856" { // sorted ascending
		t.Errorf("CVEs = %v", got)
	}
}

// TestParsePipesAndLabel verifies tolerance of nmap text-output pipes/labels.
func TestParsePipesAndLabel(t *testing.T) { // text-mode looks like "| vulscan:" then "| [id] ..."
	const x = `<nmaprun scanner="nmap" version="7.94"><host><status state="up"/>` + // root + host
		`<address addr="10.0.0.1" addrtype="ipv4"/><ports>` + // address + ports
		`<port protocol="tcp" portid="80"><state state="open"/>` + // open port
		`<service name="http"/>` + // service
		`<script id="vulscan" output="| vulscan: &#10;| [CVE-2020-1234] Example issue&#10;|_"/>` + // piped output
		`</port></ports></host></nmaprun>` // close
	sc, err := nmap.Parse(strings.NewReader(x)) // parse
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	results := Parse(sc)                                   // parse vulscan output
	if len(results) != 1 || len(results[0].Matches) != 1 { // one match expected
		t.Fatalf("results = %+v", results)
	}
	if results[0].Matches[0].ID != "CVE-2020-1234" { // id recovered despite pipes/label
		t.Errorf("match = %+v", results[0].Matches[0])
	}
}

// TestFindings verifies matches become MEDIUM-severity nmap findings.
func TestFindings(t *testing.T) { // pipeline conversion
	findings := Findings(loadScan(t)) // convert
	if len(findings) != 3 {           // one finding per match
		t.Fatalf("findings = %d, want 3", len(findings))
	}
	for _, f := range findings { // every finding must be potential/MEDIUM
		if f.Severity != nmap.SevMedium {
			t.Errorf("severity = %v, want MEDIUM", f.Severity)
		}
		if f.Host == "" || !strings.Contains(f.Title, "vulscan") {
			t.Errorf("finding = %+v", f)
		}
	}
}

// TestNilAndSummary verifies nil-safety and the empty summary.
func TestNilAndSummary(t *testing.T) { // edge cases
	if got := Parse(nil); got != nil { // nil scan -> nil
		t.Errorf("Parse(nil) = %v, want nil", got)
	}
	if got := CVEs(nil); got != nil { // nil scan -> nil
		t.Errorf("CVEs(nil) = %v, want nil", got)
	}
	if HasVulscan(&nmap.Scan{}) { // empty scan has no vulscan
		t.Error("HasVulscan(empty) = true")
	}
	if !HasVulscan(loadScan(t)) { // fixture does have vulscan
		t.Error("HasVulscan(fixture) = false")
	}
	if got := Summary(&nmap.Scan{}); !strings.Contains(got, "no vulscan results") { // empty summary
		t.Errorf("Summary(empty) = %q", got)
	}
}
