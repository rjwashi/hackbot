package cve // same package as cve.go

import ( // test imports
	"context" // pass contexts to the agent
	"strings" // string assertions
	"testing" // the testing framework
)

// fakeSearcher is a scripted Searcher used across the cve tests.
type fakeSearcher struct { // test double for the Searcher seam
	got    []Query // recorded queries
	result Result  // canned result
	err    error   // canned error
}

// Search records the query and returns the canned result.
func (f *fakeSearcher) Search(_ context.Context, q Query) (Result, error) { // interface method
	f.got = append(f.got, q) // record
	return f.result, f.err   // return canned result
}

// TestCategoryByName verifies names, case, whitespace, and aliases resolve.
func TestCategoryByName(t *testing.T) { // category lookup
	for _, name := range []string{"xss", "XSS", " cross-site-scripting "} { // spellings that should all hit xss
		c, ok := CategoryByName(name) // look up
		if !ok || c.Name != "xss" {   // must resolve to xss
			t.Errorf("CategoryByName(%q) = %+v ok=%v", name, c, ok)
		}
	}
	if _, ok := CategoryByName("definitely-not-real"); ok { // unknown must fail
		t.Error("expected unknown category to fail")
	}
	if len(CategoryNames()) != len(Categories) { // names cover the whole catalog
		t.Errorf("CategoryNames len = %d, want %d", len(CategoryNames()), len(Categories))
	}
}

// TestSearchCategoryRanksAndFilters verifies query mapping, filtering, sorting.
func TestSearchCategoryRanksAndFilters(t *testing.T) { // agent happy path
	fs := &fakeSearcher{result: Result{Total: 100, CVEs: []CVE{ // canned records, out of order
		{ID: "CVE-2", Score: 5.0}, // passes the 4.0 floor
		{ID: "CVE-1", Score: 9.8}, // highest
		{ID: "CVE-3", Score: 3.0}, // filtered out
	}}}
	a := &Agent{Searcher: fs, Limit: 20, MinScore: 4.0} // agent under test
	rep, err := a.SearchCategory(context.Background(), "xss")
	if err != nil {
		t.Fatalf("SearchCategory: %v", err)
	}
	if rep.Query != "CWE-79" { // category maps to its CWE
		t.Errorf("query = %q, want CWE-79", rep.Query)
	}
	if rep.Total != 100 { // total from the source is preserved
		t.Errorf("total = %d, want 100", rep.Total)
	}
	if len(rep.Results) != 2 || rep.Results[0].ID != "CVE-1" || rep.Results[1].ID != "CVE-2" { // filtered + worst-first
		t.Errorf("results = %+v", rep.Results)
	}
	if len(fs.got) != 1 || fs.got[0].CWE != "CWE-79" { // searcher received the CWE query
		t.Errorf("searcher query = %+v", fs.got)
	}
}

// TestSearchCategoryUnknown verifies unknown categories error clearly.
func TestSearchCategoryUnknown(t *testing.T) { // error path
	a := &Agent{Searcher: &fakeSearcher{}}                                     // agent
	if _, err := a.SearchCategory(context.Background(), "bogus"); err == nil { // bogus category...
		t.Error("expected error for unknown category") // ...must error
	}
}

// TestSearchKeywordEmpty verifies blank keywords are rejected.
func TestSearchKeywordEmpty(t *testing.T) { // error path
	a := &Agent{Searcher: &fakeSearcher{}}                                  // agent
	if _, err := a.SearchKeyword(context.Background(), "   "); err == nil { // blank...
		t.Error("expected error for empty keyword") // ...must error
	}
}

// TestSeverityFromScore verifies CVSS banding.
func TestSeverityFromScore(t *testing.T) { // helper
	cases := map[float64]string{9.8: "CRITICAL", 7.5: "HIGH", 5.0: "MEDIUM", 2.0: "LOW", 0: "UNKNOWN"}
	for score, want := range cases { // each band
		if got := SeverityFromScore(score); got != want {
			t.Errorf("SeverityFromScore(%v) = %q, want %q", score, got, want)
		}
	}
}

// TestReportSummaryAndString verifies the human renderers.
func TestReportSummaryAndString(t *testing.T) { // output helpers
	rep := &Report{Category: "xss", Query: "CWE-79", Total: 5, Results: []CVE{{ // one result
		ID: "CVE-1", Score: 9.8, Severity: "CRITICAL", Description: "a long\n  description", References: []string{"https://x"},
	}}}
	s := rep.Summary()                                        // render
	if !strings.Contains(s, "xss (CWE-79): showing 1 of 5") { // headline
		t.Errorf("summary headline = %q", s)
	}
	if !strings.Contains(s, "[CRITICAL 9.8]") || !strings.Contains(s, "https://x") { // detail + reference
		t.Errorf("summary detail = %q", s)
	}
}
