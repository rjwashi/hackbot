// Package agent turns nmap scans into a modular pipeline:
//
//	parse -> rule-based risk report -> optional LLM explanation -> optional actions
//
// Each stage is independently toggleable and safe by default (LLM off, issues
// off, and issue creation defaults to dry-run).
package agent // importable as "agent"

import ( // imports for this file
	"context"       // pipeline stages accept a context for cancellation
	"encoding/json" // Report.JSON marshals the report
	"fmt"           // Errorf/Sprintf/Fprintf for messages and rendering
	"sort"          // ordering severities when rendering the summary line
	"strings"       // Builder + Join/ToLower for text assembly

	"github.com/rjwashi/hackbot/internal/nmap" // the findings we operate on
)

// Options controls which pipeline stages run.
type Options struct { // everything the pipeline needs, injected for testability
	UseLLM       bool          // run the LLM explanation stage
	CreateIssues bool          // run the actions stage
	DryRun       bool          // when creating issues, log instead of calling gh
	Repo         string        // owner/name for issue creation
	MinSeverity  nmap.Severity // minimum severity to file an issue for
	MaxIssues    int           // cap issues per run (0 = default 10)
	LLM          LLMClient     // the chat client (used only when UseLLM)
	Issues       IssueCreator  // required when CreateIssues && !DryRun
	Log          func(string)  // progress sink (usually stderr); nil means discard
}

// Report is the result of running the pipeline.
type Report struct { // field tags give a clean JSON shape for `-json`
	HostsUp   int              `json:"hosts_up"`            // reachable hosts
	HostsDown int              `json:"hosts_down"`          // unreachable hosts
	Findings  []nmap.Finding   `json:"findings"`            // ranked risk findings
	Recon     []nmap.ReconItem `json:"recon,omitempty"`     // NSE script reconnaissance
	Narrative string           `json:"narrative,omitempty"` // LLM explanation, if any
	Issues    []string         `json:"issues,omitempty"`    // created issue URLs (or dry-run notes)
	Skipped   []string         `json:"skipped,omitempty"`   // reasons stages were skipped
}

// Run executes the pipeline against an already-parsed scan.
func Run(ctx context.Context, scan *nmap.Scan, opts Options) (*Report, error) { // main entry point
	if scan == nil { // defensive: no scan means nothing to do
		return nil, fmt.Errorf("agent: nil scan")
	}
	if opts.Log == nil { // ensure Log is always callable...
		opts.Log = func(string) {} // ...by substituting a no-op
	}
	if opts.MaxIssues <= 0 { // apply the default cap when unset/nonsensical
		opts.MaxIssues = 10
	}

	rep := &Report{ // seed the report with host counts and the risk findings
		HostsUp:   len(scan.UpHosts()),                   // reachable hosts
		HostsDown: len(scan.Hosts) - len(scan.UpHosts()), // the remainder were down
		Findings:  nmap.Analyze(scan),                    // rule-based analysis
		Recon:     nmap.Recon(scan),                      // NSE script reconnaissance
	}

	// Stage: LLM explanation.
	if opts.UseLLM { // only when explicitly requested
		if !opts.LLM.Configured() { // but configured? if not, skip gracefully...
			rep.Skipped = append(rep.Skipped, "LLM explanation skipped: "+ErrLLMNotConfigured.Error()) // ...record why
		} else { // otherwise call the model
			opts.Log("asking LLM to explain and prioritize findings...") // progress note
			narrative, err := opts.LLM.Complete(ctx, buildPrompt(rep))   // send the findings
			if err != nil {                                              // a real failure aborts the pipeline...
				return nil, fmt.Errorf("agent: llm stage: %w", err) // ...with context
			}
			rep.Narrative = narrative // store the explanation
		}
	}

	// Stage: actions (create issues), bounded by severity and count.
	if opts.CreateIssues { // only when explicitly requested
		if opts.Repo == "" { // need a target repo...
			rep.Skipped = append(rep.Skipped, "issue creation skipped: no repo configured (set HACKBOT_GITHUB_REPO)") // ...else skip
		} else { // we have a repo
			creator := opts.Issues             // start with the caller-provided creator
			if opts.DryRun || creator == nil { // dry-run (default) OR no real creator provided...
				creator = DryRunIssueCreator{Log: opts.Log} // ...use the safe no-op creator
			}
			created := 0                     // count how many issues we've handled this run
			for _, f := range rep.Findings { // consider findings worst-first (already sorted)
				if f.Severity < opts.MinSeverity { // below the filing threshold...
					continue // ...skip
				}
				if created >= opts.MaxIssues { // hit the cap...
					rep.Skipped = append(rep.Skipped, // ...record that we stopped
						fmt.Sprintf("issue creation capped at %d; remaining findings not filed", opts.MaxIssues))
					break // stop the loop
				}
				url, err := creator.CreateIssue(ctx, opts.Repo, issueTitle(f), issueBody(f), // file/emit the issue
					[]string{"nmap", strings.ToLower(f.Severity.String())}) // labels: "nmap" + lowercase severity
				if err != nil { // a real creation error aborts the pipeline...
					return nil, fmt.Errorf("agent: create issue: %w", err) // ...with context
				}
				if url != "" { // a real URL means gh created it
					rep.Issues = append(rep.Issues, url) // record the URL
				} else { // empty URL means dry-run
					rep.Issues = append(rep.Issues, "(dry-run) "+issueTitle(f)) // record the preview
				}
				created++ // count this one
			}
		}
	}

	return rep, nil // success
}

// buildPrompt renders the findings into a compact prompt for the LLM.
func buildPrompt(rep *Report) string { // pure function; keeps prompting testable
	var b strings.Builder                                                                                            // efficient concatenation
	b.WriteString("You are a defensive security assistant. Summarize the following nmap findings.\n")                // role
	b.WriteString("Rank risks, explain the business impact briefly, and give concrete remediation steps.\n")         // task
	b.WriteString("Do not invent vulnerabilities beyond the evidence below.\n\n")                                    // grounding constraint
	fmt.Fprintf(&b, "Hosts up: %d, hosts down: %d. Findings: %d\n\n", rep.HostsUp, rep.HostsDown, len(rep.Findings)) // context line
	for _, f := range rep.Findings {                                                                                 // one bullet per finding
		where := f.Host // target label...
		if f.Port > 0 { // ...with port when present
			where = fmt.Sprintf("%s:%d/%s", f.Host, f.Port, f.Protocol)
		}
		fmt.Fprintf(&b, "- [%s] %s (%s): %s %s\n", f.Severity, where, f.Service, f.Title, f.Detail) // compact bullet
	}
	if len(rep.Recon) > 0 { // include NSE output when present...
		b.WriteString("\nRecon (NSE script output):\n") // ...under its own heading
		for _, r := range rep.Recon {                   // one bullet per recon item
			fmt.Fprintf(&b, "- [%s] %s: %s\n", r.Script, r.Host, strings.ReplaceAll(r.Output, "\n", " ")) // flatten newlines
		}
	}
	return b.String() // the final prompt
}

// Summary returns a human-readable report.
func (r *Report) Summary() string { // used by the CLI when -json is absent
	var b strings.Builder                                                                                          // accumulate the text
	fmt.Fprintf(&b, "nmap pipeline: %d hosts up, %d down, %d findings\n", r.HostsUp, r.HostsDown, len(r.Findings)) // headline
	fmt.Fprintf(&b, "%s\n", severityLine(r.Findings))                                                              // "severity: CRITICAL:2 HIGH:1" line
	for _, f := range r.Findings {                                                                                 // one indented block per finding
		fmt.Fprintf(&b, "  %s\n", f.String()) // Finding.String() renders the two-line block
	}
	if len(r.Recon) > 0 { // only if NSE scripts produced output
		b.WriteString("\n--- recon ---\n") // section header
		for _, it := range r.Recon {       // one block per recon item
			fmt.Fprintf(&b, "  %s\n", it.String()) // ReconItem.String() renders the detail
		}
	}
	if r.Narrative != "" { // only if the LLM stage ran
		b.WriteString("\n--- LLM analysis ---\n") // section header
		b.WriteString(r.Narrative)                // the explanation
		b.WriteString("\n")                       // trailing newline for spacing
	}
	if len(r.Issues) > 0 { // only if the actions stage ran
		b.WriteString("\n--- issues ---\n") // section header
		for _, i := range r.Issues {        // list each issue (URL or dry-run preview)
			fmt.Fprintf(&b, "  %s\n", i)
		}
	}
	if len(r.Skipped) > 0 { // surface any skipped-stage notes
		b.WriteString("\n--- skipped ---\n") // section header
		for _, s := range r.Skipped {        // one line per reason
			fmt.Fprintf(&b, "  %s\n", s)
		}
	}
	return b.String() // the assembled report
}

// JSON returns the report as indented JSON.
func (r *Report) JSON() ([]byte, error) { // used by the CLI when -json is set
	return json.MarshalIndent(r, "", "  ") // two-space indentation for readability
}

// severityLine builds the "severity: CRITICAL:2 HIGH:1" summary.
func severityLine(findings []nmap.Finding) string { // helper for Summary
	counts := nmap.Counts(findings)                                                                     // tally by severity
	var parts []string                                                                                  // accumulate "LABEL:n" parts
	order := []nmap.Severity{nmap.SevCritical, nmap.SevHigh, nmap.SevMedium, nmap.SevLow, nmap.SevInfo} // worst first
	sort.SliceStable(order, func(i, j int) bool { return order[i] > order[j] })                         // keep worst-first ordering explicit
	for _, sev := range order {                                                                         // iterate severities worst to best
		if counts[sev] > 0 { // only mention severities that occurred
			parts = append(parts, fmt.Sprintf("%s:%d", sev, counts[sev])) // e.g. "CRITICAL:2"
		}
	}
	if len(parts) == 0 { // no findings at all...
		return "severity: none" // ...say so plainly
	}
	return "severity: " + strings.Join(parts, " ") // join the parts
}
