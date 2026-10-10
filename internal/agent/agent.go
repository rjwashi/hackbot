// Package agent turns nmap scans into a modular pipeline:
//
//	parse -> rule-based risk report -> optional LLM explanation -> optional actions
//
// Each stage is independently toggleable and safe by default (LLM off, issues
// off, and issue creation defaults to dry-run).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/rjwashi/hackbot/internal/nmap"
)

// Options controls which pipeline stages run.
type Options struct {
	UseLLM       bool
	CreateIssues bool
	DryRun       bool   // when creating issues, log instead of calling gh
	Repo         string // owner/name for issue creation
	MinSeverity  nmap.Severity
	MaxIssues    int // cap issues per run (0 = default 10)
	LLM          LLMClient
	Issues       IssueCreator // required when CreateIssues && !DryRun
	Log          func(string)
}

// Report is the result of running the pipeline.
type Report struct {
	HostsUp   int            `json:"hosts_up"`
	HostsDown int            `json:"hosts_down"`
	Findings  []nmap.Finding `json:"findings"`
	Narrative string         `json:"narrative,omitempty"`
	Issues    []string       `json:"issues,omitempty"`
	Skipped   []string       `json:"skipped,omitempty"`
}

// Run executes the pipeline against an already-parsed scan.
func Run(ctx context.Context, scan *nmap.Scan, opts Options) (*Report, error) {
	if scan == nil {
		return nil, fmt.Errorf("agent: nil scan")
	}
	if opts.Log == nil {
		opts.Log = func(string) {}
	}
	if opts.MaxIssues <= 0 {
		opts.MaxIssues = 10
	}

	rep := &Report{
		HostsUp:   len(scan.UpHosts()),
		HostsDown: len(scan.Hosts) - len(scan.UpHosts()),
		Findings:  nmap.Analyze(scan),
	}

	// Stage: LLM explanation.
	if opts.UseLLM {
		if !opts.LLM.Configured() {
			rep.Skipped = append(rep.Skipped, "LLM explanation skipped: "+ErrLLMNotConfigured.Error())
		} else {
			opts.Log("asking LLM to explain and prioritize findings...")
			narrative, err := opts.LLM.Complete(ctx, buildPrompt(rep))
			if err != nil {
				return nil, fmt.Errorf("agent: llm stage: %w", err)
			}
			rep.Narrative = narrative
		}
	}

	// Stage: actions (create issues), bounded by severity and count.
	if opts.CreateIssues {
		if opts.Repo == "" {
			rep.Skipped = append(rep.Skipped, "issue creation skipped: no repo configured (set HACKBOT_GITHUB_REPO)")
		} else {
			creator := opts.Issues
			if opts.DryRun || creator == nil {
				creator = DryRunIssueCreator{Log: opts.Log}
			}
			created := 0
			for _, f := range rep.Findings {
				if f.Severity < opts.MinSeverity {
					continue
				}
				if created >= opts.MaxIssues {
					rep.Skipped = append(rep.Skipped,
						fmt.Sprintf("issue creation capped at %d; remaining findings not filed", opts.MaxIssues))
					break
				}
				url, err := creator.CreateIssue(ctx, opts.Repo, issueTitle(f), issueBody(f),
					[]string{"nmap", strings.ToLower(f.Severity.String())})
				if err != nil {
					return nil, fmt.Errorf("agent: create issue: %w", err)
				}
				if url != "" {
					rep.Issues = append(rep.Issues, url)
				} else {
					rep.Issues = append(rep.Issues, "(dry-run) "+issueTitle(f))
				}
				created++
			}
		}
	}

	return rep, nil
}

// buildPrompt renders the findings into a compact prompt for the LLM.
func buildPrompt(rep *Report) string {
	var b strings.Builder
	b.WriteString("You are a defensive security assistant. Summarize the following nmap findings.\n")
	b.WriteString("Rank risks, explain the business impact briefly, and give concrete remediation steps.\n")
	b.WriteString("Do not invent vulnerabilities beyond the evidence below.\n\n")
	fmt.Fprintf(&b, "Hosts up: %d, hosts down: %d. Findings: %d\n\n", rep.HostsUp, rep.HostsDown, len(rep.Findings))
	for _, f := range rep.Findings {
		where := f.Host
		if f.Port > 0 {
			where = fmt.Sprintf("%s:%d/%s", f.Host, f.Port, f.Protocol)
		}
		fmt.Fprintf(&b, "- [%s] %s (%s): %s %s\n", f.Severity, where, f.Service, f.Title, f.Detail)
	}
	return b.String()
}

// Summary returns a human-readable report.
func (r *Report) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "nmap pipeline: %d hosts up, %d down, %d findings\n", r.HostsUp, r.HostsDown, len(r.Findings))
	fmt.Fprintf(&b, "%s\n", severityLine(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %s\n", f.String())
	}
	if r.Narrative != "" {
		b.WriteString("\n--- LLM analysis ---\n")
		b.WriteString(r.Narrative)
		b.WriteString("\n")
	}
	if len(r.Issues) > 0 {
		b.WriteString("\n--- issues ---\n")
		for _, i := range r.Issues {
			fmt.Fprintf(&b, "  %s\n", i)
		}
	}
	if len(r.Skipped) > 0 {
		b.WriteString("\n--- skipped ---\n")
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "  %s\n", s)
		}
	}
	return b.String()
}

// JSON returns the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func severityLine(findings []nmap.Finding) string {
	counts := nmap.Counts(findings)
	var parts []string
	order := []nmap.Severity{nmap.SevCritical, nmap.SevHigh, nmap.SevMedium, nmap.SevLow, nmap.SevInfo}
	sort.SliceStable(order, func(i, j int) bool { return order[i] > order[j] })
	for _, sev := range order {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", sev, counts[sev]))
		}
	}
	if len(parts) == 0 {
		return "severity: none"
	}
	return "severity: " + strings.Join(parts, " ")
}
