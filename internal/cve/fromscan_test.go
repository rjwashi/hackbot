package cve // same package as fromscan.go

import ( // test imports
	"context"       // pass contexts
	"path/filepath" // build the fixture path
	"testing"       // the testing framework

	"github.com/rjwashi/hackbot/internal/nmap" // the scan type
)

// loadScan parses the shared nmap fixture.
func loadScan(t *testing.T) *nmap.Scan { // shared helper
	t.Helper()                                                                       // mark as helper
	sc, err := nmap.ParseFile(filepath.Join("..", "nmap", "testdata", "sample.xml")) // parse fixture
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return sc // parsed scan
}

// TestQueriesFromScan verifies software phrases are derived from open ports.
func TestQueriesFromScan(t *testing.T) { // query derivation
	qs := QueriesFromScan(loadScan(t)) // derive
	if len(qs) == 0 {
		t.Fatal("expected queries")
	}
	var found bool         // did we find the nginx phrase?
	for _, q := range qs { // walk queries
		if q.Keyword == "nginx 1.24.0" {
			found = true
		}
	}
	if !found { // nginx is open+fp'd in the fixture
		t.Errorf("queries = %+v", qs)
	}
}

// TestSearchScanMergesAndDedupes verifies merging, de-duping, filtering, capping.
func TestSearchScanMergesAndDedupes(t *testing.T) { // scan merge
	fs := &fakeSearcher{result: Result{Total: 2, CVEs: []CVE{ // same CVE returned per product
		{ID: "CVE-A", Score: 9.8, Severity: "CRITICAL"},
		{ID: "CVE-A", Score: 9.8, Severity: "CRITICAL"},
		{ID: "CVE-B", Score: 1.0, Severity: "LOW"},
	}}}
	a := &Agent{Searcher: fs, Limit: 20, MinScore: 5.0} // filter below 5.0
	rep, err := a.SearchScan(context.Background(), loadScan(t))
	if err != nil {
		t.Fatalf("SearchScan: %v", err)
	}
	if rep.Category != "scan" { // marker category
		t.Errorf("category = %q", rep.Category)
	}
	if len(rep.Results) != 1 || rep.Results[0].ID != "CVE-A" { // deduped + filtered
		t.Errorf("results = %+v", rep.Results)
	}
	if len(fs.got) == 0 || len(fs.got) > maxScanQueries { // query count capped
		t.Errorf("query count = %d, want 1..%d", len(fs.got), maxScanQueries)
	}
}

// TestSearchScanNoSoftware verifies a scan with no fingerprints is handled.
func TestSearchScanNoSoftware(t *testing.T) { // empty case
	a := &Agent{Searcher: &fakeSearcher{}}               // agent
	sc := &nmap.Scan{Hosts: []nmap.Host{{Status: "up"}}} // up host, no ports
	rep, err := a.SearchScan(context.Background(), sc)
	if err != nil {
		t.Fatalf("SearchScan: %v", err)
	}
	if len(rep.Results) != 0 { // nothing to report
		t.Errorf("expected no results, got %+v", rep.Results)
	}
}
