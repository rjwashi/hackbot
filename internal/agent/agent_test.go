package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rjwashi/hackbot/internal/nmap"
)

func sampleScan(t *testing.T) *nmap.Scan {
	t.Helper()
	scan, err := nmap.ParseFile("../nmap/testdata/sample.xml")
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	return scan
}

type fakeIssueCreator struct {
	created []string
}

func (f *fakeIssueCreator) CreateIssue(_ context.Context, _ string, title, _ string, _ []string) (string, error) {
	f.created = append(f.created, title)
	return "https://example.test/issues/" + title, nil
}

func TestRunAnalyzeOnly(t *testing.T) {
	rep, err := Run(context.Background(), sampleScan(t), Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.HostsUp != 2 || rep.HostsDown != 1 {
		t.Errorf("host counts = up %d down %d, want 2/1", rep.HostsUp, rep.HostsDown)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if rep.Narrative != "" || len(rep.Issues) != 0 {
		t.Error("LLM/issues should be off by default")
	}
}

func TestRunLLMSkippedWhenUnconfigured(t *testing.T) {
	rep, err := Run(context.Background(), sampleScan(t), Options{UseLLM: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Narrative != "" {
		t.Error("narrative should be empty when LLM unconfigured")
	}
	if len(rep.Skipped) == 0 || !strings.Contains(rep.Skipped[0], "LLM") {
		t.Errorf("expected an LLM-skipped note, got %v", rep.Skipped)
	}
}

func TestRunLLMUsesEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("auth header = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": "Prioritize the Docker API exposure first."}},
			},
		})
	}))
	defer srv.Close()

	rep, err := Run(context.Background(), sampleScan(t), Options{
		UseLLM: true,
		LLM:    LLMClient{BaseURL: srv.URL, APIKey: "test-key", Model: "test-model"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(rep.Narrative, "Docker API") {
		t.Errorf("narrative = %q", rep.Narrative)
	}
}

func TestRunLLMErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": "no auth"}})
	}))
	defer srv.Close()

	_, err := Run(context.Background(), sampleScan(t), Options{
		UseLLM: true,
		LLM:    LLMClient{BaseURL: srv.URL, Model: "m"},
	})
	if err == nil || !strings.Contains(err.Error(), "llm") {
		t.Fatalf("expected llm error, got %v", err)
	}
}

func TestRunCreatesIssuesAboveMinSeverity(t *testing.T) {
	creator := &fakeIssueCreator{}
	rep, err := Run(context.Background(), sampleScan(t), Options{
		CreateIssues: true,
		Repo:         "rjwashi/hackbot",
		MinSeverity:  nmap.SevHigh,
		Issues:       creator,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Issues) == 0 {
		t.Fatal("expected issues to be reported")
	}
	// Sample has exactly two CRITICAL and one HIGH -> 3 issues at SevHigh.
	if len(creator.created) != 3 {
		t.Errorf("created %d issues, want 3: %v", len(creator.created), creator.created)
	}
}

func TestRunCapsIssueCount(t *testing.T) {
	creator := &fakeIssueCreator{}
	rep, err := Run(context.Background(), sampleScan(t), Options{
		CreateIssues: true,
		Repo:         "rjwashi/hackbot",
		MinSeverity:  nmap.SevInfo,
		MaxIssues:    1,
		Issues:       creator,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(creator.created) != 1 {
		t.Errorf("created %d issues, want 1", len(creator.created))
	}
	if len(rep.Skipped) == 0 {
		t.Error("expected a cap notice")
	}
}

func TestRunDryRunDoesNotCallCreator(t *testing.T) {
	creator := &fakeIssueCreator{}
	var logs []string
	rep, err := Run(context.Background(), sampleScan(t), Options{
		CreateIssues: true,
		Repo:         "rjwashi/hackbot",
		MinSeverity:  nmap.SevCritical,
		DryRun:       true,
		Issues:       creator,
		Log:          func(s string) { logs = append(logs, s) },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(creator.created) != 0 {
		t.Error("dry-run must not call the real creator")
	}
	if len(rep.Issues) == 0 || !strings.Contains(rep.Issues[0], "dry-run") {
		t.Errorf("expected dry-run issue entries, got %v", rep.Issues)
	}
}

func TestRunIssuesSkippedWithoutRepo(t *testing.T) {
	rep, err := Run(context.Background(), sampleScan(t), Options{CreateIssues: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Skipped) == 0 || !strings.Contains(strings.Join(rep.Skipped, " "), "repo") {
		t.Errorf("expected repo-skipped note, got %v", rep.Skipped)
	}
}

func TestReportJSONAndSummary(t *testing.T) {
	rep, err := Run(context.Background(), sampleScan(t), Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, err := rep.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !json.Valid(data) {
		t.Error("report JSON is not valid")
	}
	if !strings.Contains(rep.Summary(), "findings") {
		t.Error("summary missing findings line")
	}
}

func TestRunNilScan(t *testing.T) {
	if _, err := Run(context.Background(), nil, Options{}); err == nil {
		t.Fatal("expected error for nil scan")
	}
}
