package agent // same package as the pipeline

import ( // test imports
	"context"           // pass contexts to Run
	"encoding/json"     // validate JSON output
	"net/http"          // status codes in the fake server
	"net/http/httptest" // spin up an in-process LLM server
	"strings"           // string assertions
	"testing"           // the testing framework

	"github.com/rjwashi/hackbot/internal/nmap" // findings types
)

// sampleScan parses the shared nmap fixture.
func sampleScan(t *testing.T) *nmap.Scan { // shared helper
	t.Helper()                                                 // mark as helper
	scan, err := nmap.ParseFile("../nmap/testdata/sample.xml") // fixture lives in the sibling nmap package
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return scan // return parsed scan
}

// fakeIssueCreator records created issue titles.
type fakeIssueCreator struct { // test double for IssueCreator
	created []string // titles of issues "created"
}

// CreateIssue records the title and returns a fake URL.
func (f *fakeIssueCreator) CreateIssue(_ context.Context, _ string, title, _ string, _ []string) (string, error) { // interface method
	f.created = append(f.created, title)               // record
	return "https://example.test/issues/" + title, nil // return a deterministic URL
}

// TestRunAnalyzeOnly verifies the default pipeline only analyzes.
func TestRunAnalyzeOnly(t *testing.T) { // defaults
	rep, err := Run(context.Background(), sampleScan(t), Options{}) // run with everything off
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.HostsUp != 2 || rep.HostsDown != 1 { // host counts from the fixture
		t.Errorf("host counts = up %d down %d, want 2/1", rep.HostsUp, rep.HostsDown)
	}
	if len(rep.Findings) == 0 { // analysis must run by default
		t.Fatal("expected findings")
	}
	if len(rep.Recon) == 0 { // recon must populate from the fixture's NSE scripts
		t.Fatal("expected recon items")
	}
	if len(rep.Vulscan) == 0 { // vulscan matches must populate from the fixture
		t.Fatal("expected vulscan results")
	}
	if rep.Narrative != "" || len(rep.Issues) != 0 { // optional stages must be off
		t.Error("LLM/issues should be off by default")
	}
}

// TestRunLLMSkippedWhenUnconfigured verifies a graceful skip (not an error).
func TestRunLLMSkippedWhenUnconfigured(t *testing.T) { // graceful degradation
	rep, err := Run(context.Background(), sampleScan(t), Options{UseLLM: true}) // ask for LLM with no config
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Narrative != "" { // no narrative produced
		t.Error("narrative should be empty when LLM unconfigured")
	}
	if len(rep.Skipped) == 0 || !strings.Contains(rep.Skipped[0], "LLM") { // a skip note must explain why
		t.Errorf("expected an LLM-skipped note, got %v", rep.Skipped)
	}
}

// TestRunLLMUsesEndpoint verifies the HTTP request shape and response parsing.
func TestRunLLMUsesEndpoint(t *testing.T) { // LLM happy path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // fake LLM
		if r.URL.Path != "/chat/completions" { // correct endpoint...
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" { // ...and correct auth
			t.Errorf("auth header = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{ // return a canned chat response
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": "Prioritize the Docker API exposure first."}},
			},
		})
	}))
	defer srv.Close() // stop the server after the test

	rep, err := Run(context.Background(), sampleScan(t), Options{ // run with the fake endpoint
		UseLLM: true,
		LLM:    LLMClient{BaseURL: srv.URL, APIKey: "test-key", Model: "test-model"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(rep.Narrative, "Docker API") { // narrative must carry the model's text
		t.Errorf("narrative = %q", rep.Narrative)
	}
}

// TestRunLLMErrorsOnBadStatus verifies non-200 responses surface as errors.
func TestRunLLMErrorsOnBadStatus(t *testing.T) { // error path
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // fake failing LLM
		w.WriteHeader(http.StatusUnauthorized)                                                          // 401
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": "no auth"}}) // error body
	}))
	defer srv.Close()

	_, err := Run(context.Background(), sampleScan(t), Options{ // run
		UseLLM: true,
		LLM:    LLMClient{BaseURL: srv.URL, Model: "m"},
	})
	if err == nil || !strings.Contains(err.Error(), "llm") { // must error mentioning llm
		t.Fatalf("expected llm error, got %v", err)
	}
}

// TestRunCreatesIssuesAboveMinSeverity verifies threshold filtering.
func TestRunCreatesIssuesAboveMinSeverity(t *testing.T) { // actions stage
	creator := &fakeIssueCreator{}                                // recording fake
	rep, err := Run(context.Background(), sampleScan(t), Options{ // run with issues enabled
		CreateIssues: true,
		Repo:         "rjwashi/hackbot",
		MinSeverity:  nmap.SevHigh, // only HIGH and above
		Issues:       creator,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Issues) == 0 { // some issues should be reported
		t.Fatal("expected issues to be reported")
	}
	// Sample has exactly two CRITICAL and one HIGH -> 3 issues at SevHigh.
	if len(creator.created) != 3 { // assert the exact count
		t.Errorf("created %d issues, want 3: %v", len(creator.created), creator.created)
	}
}

// TestRunCapsIssueCount verifies the per-run cap.
func TestRunCapsIssueCount(t *testing.T) { // cap enforcement
	creator := &fakeIssueCreator{}                                // recording fake
	rep, err := Run(context.Background(), sampleScan(t), Options{ // run with a cap of 1
		CreateIssues: true,
		Repo:         "rjwashi/hackbot",
		MinSeverity:  nmap.SevInfo, // allow everything, so the cap is what limits us
		MaxIssues:    1,
		Issues:       creator,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(creator.created) != 1 { // exactly one created
		t.Errorf("created %d issues, want 1", len(creator.created))
	}
	if len(rep.Skipped) == 0 { // and a note that we stopped
		t.Error("expected a cap notice")
	}
}

// TestRunDryRunDoesNotCallCreator verifies dry-run never hits the real creator.
func TestRunDryRunDoesNotCallCreator(t *testing.T) { // safety default
	creator := &fakeIssueCreator{}                                // recording fake that must NOT be called
	var logs []string                                             // capture dry-run log lines
	rep, err := Run(context.Background(), sampleScan(t), Options{ // dry-run on
		CreateIssues: true,
		Repo:         "rjwashi/hackbot",
		MinSeverity:  nmap.SevCritical,
		DryRun:       true, // the important flag
		Issues:       creator,
		Log:          func(s string) { logs = append(logs, s) }, // capture logs
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(creator.created) != 0 { // the real creator must be untouched
		t.Error("dry-run must not call the real creator")
	}
	if len(rep.Issues) == 0 || !strings.Contains(rep.Issues[0], "dry-run") { // reports must be marked dry-run
		t.Errorf("expected dry-run issue entries, got %v", rep.Issues)
	}
}

// TestRunIssuesSkippedWithoutRepo verifies missing repo is a graceful skip.
func TestRunIssuesSkippedWithoutRepo(t *testing.T) { // graceful degradation
	rep, err := Run(context.Background(), sampleScan(t), Options{CreateIssues: true}) // no Repo set
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Skipped) == 0 || !strings.Contains(strings.Join(rep.Skipped, " "), "repo") { // a skip note mentioning repo
		t.Errorf("expected repo-skipped note, got %v", rep.Skipped)
	}
}

// TestReportJSONAndSummary verifies both output renderers work.
func TestReportJSONAndSummary(t *testing.T) { // output helpers
	rep, err := Run(context.Background(), sampleScan(t), Options{}) // analysis-only report
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := rep.JSON() // JSON renderer
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !json.Valid(data) { // must be valid JSON
		t.Error("report JSON is not valid")
	}
	if !strings.Contains(rep.Summary(), "findings") { // summary renderer must mention findings
		t.Error("summary missing findings line")
	}
	if !strings.Contains(rep.Summary(), "recon") { // and the recon section
		t.Error("summary missing recon section")
	}
	if !strings.Contains(rep.Summary(), "vulscan") { // and the vulscan section
		t.Error("summary missing vulscan section")
	}
}

// TestRunNilScan verifies nil input is rejected.
func TestRunNilScan(t *testing.T) { // defensive
	if _, err := Run(context.Background(), nil, Options{}); err == nil { // nil scan...
		t.Fatal("expected error for nil scan") // ...must error
	}
}
