package cve // same package as nvd.go

import ( // test imports
	"context"           // pass contexts to Search
	"net/http"          // status codes
	"net/http/httptest" // in-process NVD server
	"strings"           // query/error assertions
	"testing"           // the testing framework
)

// TestNVDSearchParsesResponse verifies request shape and response mapping.
func TestNVDSearchParsesResponse(t *testing.T) { // client happy path
	var gotPath, gotKey, gotQuery string                                                      // captured request details
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // fake NVD
		gotPath = r.URL.Path                                                    // record path
		gotKey = r.Header.Get("apiKey")                                         // record key header
		gotQuery = r.URL.RawQuery                                               // record query string
		w.Header().Set("Content-Type", "application/json")                      // JSON content type
		_, _ = w.Write([]byte(`{"totalResults":1,"vulnerabilities":[{"cve":{` + // canned payload
			`"id":"CVE-2023-1","published":"2023-01-01T00:00:00.000",` +
			`"descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"english text"}],` +
			`"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}]},` +
			`"weaknesses":[{"description":[{"lang":"en","value":"CWE-79"}]},{"description":[{"lang":"en","value":"CWE-79"}]}],` +
			`"references":[{"url":"https://a"},{"url":""}]}}]}`))
	}))
	defer srv.Close() // stop the server

	c := &NVDClient{BaseURL: srv.URL, APIKey: "k"}                              // client under test
	res, err := c.Search(context.Background(), Query{CWE: "CWE-79", Limit: 10}) // search
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if gotPath != "/" { // path preserved
		t.Errorf("path = %q", gotPath)
	}
	if gotKey != "k" { // apiKey header sent
		t.Errorf("apiKey header = %q, want k", gotKey)
	}
	if !strings.Contains(gotQuery, "cweId=CWE-79") || !strings.Contains(gotQuery, "resultsPerPage=10") { // params encoded
		t.Errorf("query = %q", gotQuery)
	}
	if res.Total != 1 || len(res.CVEs) != 1 { // mapping produced one record
		t.Fatalf("res = %+v", res)
	}
	got := res.CVEs[0] // the record
	if got.ID != "CVE-2023-1" || got.Description != "english text" || got.Score != 9.8 || got.Severity != "CRITICAL" {
		t.Errorf("cve = %+v", got)
	}
	if len(got.CWEs) != 1 || got.CWEs[0] != "CWE-79" { // CWEs de-duped
		t.Errorf("cwes = %v", got.CWEs)
	}
	if len(got.References) != 1 || got.References[0] != "https://a" { // empty ref dropped
		t.Errorf("refs = %v", got.References)
	}
}

// TestNVDSearchNon200Error verifies non-200 responses surface usefully.
func TestNVDSearchNon200Error(t *testing.T) { // error path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // failing NVD
		w.WriteHeader(http.StatusForbidden) // 403 (rate limited)
		_, _ = w.Write([]byte("slow down"))
	}))
	defer srv.Close()

	c := &NVDClient{BaseURL: srv.URL} // client
	_, err := c.Search(context.Background(), Query{Keyword: "x"})
	if err == nil || !strings.Contains(err.Error(), "NVD returned") { // must mention the status
		t.Fatalf("expected status error, got %v", err)
	}
}

// TestNVDSearchKeywordParam verifies keyword requests encode the phrase.
func TestNVDSearchKeywordParam(t *testing.T) { // keyword path
	var gotQuery string                                                                       // captured query
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // fake NVD
		gotQuery = r.URL.RawQuery                                         // record
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`)) // empty result
	}))
	defer srv.Close()

	c := &NVDClient{BaseURL: srv.URL}                                                         // client
	if _, err := c.Search(context.Background(), Query{Keyword: "nginx 1.24.0"}); err != nil { // search
		t.Fatalf("Search: %v", err)
	}
	if !strings.Contains(gotQuery, "keywordSearch=nginx+1.24.0") { // encoded keyword
		t.Errorf("keyword query = %q", gotQuery)
	}
}
