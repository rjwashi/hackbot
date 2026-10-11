// Package logic hosts the guarded logic-bug probes: small, hand-authored HTTP
// probe sequences that poke an application's state machine (workflows, roles,
// object references, limits, integrity) and return an evidence-backed verdict.
//
// WHY a separate package from wstg: injection-class checks (sqlmap, dalfox)
// are one tool per test, so wstg models a check as a single tool + argument
// template. A logic bug rarely has a scanner; it needs a SEQUENCE of requests
// (baseline vs. tampered, or N parallel repeats) and a classifier that turns
// the observed responses into FOUND / CLEAN / UNVERIFIED. This package models
// that shape while reusing the exact same safety story as every other active
// capability: dry-run by default, enable_scan + allowlist before any real
// request, and no user input ever interpolated into a shell (curl argv is
// assembled as a string slice, target and bodies pass as single elements).
//
// Verdict vocabulary is the one skillsec already uses, so a future Validator
// Bot can cross-confirm these rows exactly like it would a rubric check.
package logic

import ( // imports for the model, renderers, and parsers
	"crypto/sha256" // short body hashes for diffing responses
	"encoding/hex"  // hex-encode those hashes
	"fmt"           // Errorf for usage/scope-refusal messages
	"regexp"        // the three-digit HTTP status matcher
	"strings"       // trimming, joining, and placeholder rendering
	"time"          // default per-request timeout
)

// Verdict is a probe's outcome after its steps ran.
type Verdict string // one word per probe, so reports scan cleanly

const (
	// VerdictFound: the observed evidence is consistent with the bug class.
	VerdictFound Verdict = "FOUND"
	// VerdictClean: a counter-signal (e.g. a 403 or a lockout) is clearly present.
	VerdictClean Verdict = "CLEAN"
	// VerdictUnverified: the probe ran but the evidence cannot settle the class.
	VerdictUnverified Verdict = "UNVERIFIED"
	// VerdictError: every request failed for a reason that is not a verdict.
	VerdictError Verdict = "ERROR"
	// VerdictDry: a dry run rendered the commands but executed nothing.
	VerdictDry Verdict = "DRY"
)

// Step is one request pattern inside a probe: a fixed method, path, headers,
// body, and optional repetition. IDs lets a step fan out over values (for
// object-reference probes); Count+Parallel provides the race/limit shapes.
type Step struct { // one request shape
	Label    string   // what this step is probing
	Method   string   // GET / POST / PUT / DELETE / ...
	Path     string   // path template; may contain {path} and {id}
	IDs      []string // values substituted for {id}; empty means one call
	Headers  []string // extra "Name: value" headers
	Body     string   // request body template; may contain {id}
	Count    int      // repeats per id (1 by default)
	Parallel bool     // fire the repeats concurrently (race probes)
}

// Response is what one executed request produced.
type Response struct { // one exchange
	Step   string `json:"step"`             // owning step label
	ID     string `json:"id,omitempty"`     // the {id} value used, when any
	Index  int    `json:"index"`            // repeat number for this step
	Status string `json:"status,omitempty"` // HTTP status code ("200"), or "" on transport error
	Body   string `json:"body,omitempty"`   // response body, trimmed and capped
	Err    string `json:"error,omitempty"`  // transport/tool error, when the request failed
}

// Evidence is one numbered line of the report a probe produced.
type Evidence struct { // line-numbered, like skillsec evidence
	Line int    `json:"line"` // 1-based position in the report
	Text string `json:"text"` // the evidence itself
}

// Probe is one logic-bug agent: a name, its WSTG anchor, the requests it sends,
// and the pure classifier that turns the responses into a verdict.
type Probe struct { // one micro-scoped agent
	Key         string                             `json:"key"`            // slug (race, idor, ...)
	Name        string                             `json:"name"`           // human name
	Category    string                             `json:"category"`       // WSTG checklist slug (business-logic, ...)
	Tests       []string                           `json:"tests"`          // WSTG test ids this probe answers
	Steps       []Step                             `json:"steps"`          // the requests, in order
	DefaultPath string                             `json:"default_path"`   // the {path} used when -path is not given
	Like        string                             `json:"like,omitempty"` // one line: what evidence triggers FOUND
	Note        string                             `json:"note,omitempty"` // caveats / how to customize
	Judge       func([]Response) (Verdict, string) `json:"-"` // pure classifier (not serialized)
}

// Result is one probe run: the verdict, the reason, and the evidence.
type Result struct { // serializable for `logic run -json`
	Probe     string     `json:"probe"`               // probe key
	Name      string     `json:"name"`                // probe name
	Category  string     `json:"category"`            // WSTG slug
	Tests     []string   `json:"tests"`               // WSTG test ids
	Verdict   Verdict    `json:"verdict"`             // aggregate outcome
	Reason    string     `json:"reason,omitempty"`    // why the verdict was chosen
	DryRun    bool       `json:"dry_run"`             // true when nothing executed
	Commands  []string   `json:"commands,omitempty"`  // the rendered curl lines (dry-run/plan)
	Responses []Response `json:"responses,omitempty"` // the exchanges, in order
	Evidence  []Evidence `json:"evidence,omitempty"`  // numbered report lines
}

// PlanStep is one line of `logic plan`: what a probe would send.
type PlanStep struct { // what a probe would do
	Probe    string   `json:"probe"`          // probe key
	Name     string   `json:"name"`           // probe name
	Category string   `json:"category"`       // WSTG slug
	Tests    []string `json:"tests"`          // WSTG test ids
	Like     string   `json:"like,omitempty"` // what evidence triggers FOUND
	Commands []string `json:"commands"`       // the rendered curl commands
}

// Proxy defaults and shared helpers ---------------------------------------------.

// defaultTimeout bounds a single request when the caller set no timeout.
const defaultTimeout = 60 * time.Second

// maxBody caps stored response bodies so one huge reply cannot flood a report.
const maxBody = 8 << 10

// statusPattern matches a bare three-digit HTTP status code.
var statusPattern = regexp.MustCompile(`^[1-5][0-9][0-9]$`)

// render substitutes {path} and {id} in a template, leaving unknown
// placeholders literal so a plan shows them as such.
func render(t string, subs map[string]string) string { // small template filler
	for k, v := range subs { // apply each known substitution...
		t = strings.ReplaceAll(t, "{"+k+"}", v)
	}
	return t
}

// bodyHash returns a short stable hash of a response body for diffing.
func bodyHash(b string) string { // e.g. "ab12cd34"
	sum := sha256.Sum256([]byte(b))       // full hash...
	return hex.EncodeToString(sum[:])[:8] // ...shortened for display
}

// httpStatusPrefix reports whether a status code starts with a digit group.
func httpStatusPrefix(s, p string) bool { // e.g. ("200", "2") == true
	return len(s) >= 1 && strings.HasPrefix(s, p)
}

// statusReport builds one evidence line per response, numbered like skillsec.
func statusReport(probe string, rs []Response) []Evidence { // numbered evidence
	out := make([]Evidence, 0, len(rs)) // one line per exchange
	for i, r := range rs {              // walk the responses
		label := r.Step // step label names the line
		if r.ID != "" { // an id-based step shows which value was used
			label += " (id=" + r.ID + ")"
		}
		if r.Index > 1 { // a repeated step shows which repeat
			label += fmt.Sprintf(" #%d", r.Index)
		}
		text := label // start the text
		switch {      // describe the outcome
		case r.Err != "": // the request never completed
			text += " transport error: " + r.Err
		case r.Status == "": // no usable status (odd output)
			text += " no status parsed"
		default: // the normal, interesting case
			text += " HTTP " + r.Status
			if r.Body != "" { // a body worth diffing
				text += " (hash " + bodyHash(r.Body) + ")"
			}
		}
		out = append(out, Evidence{Line: i + 1, Text: text}) // numbered
	}
	return out // finished report
}

// parseResponse turns a tool's combined output into a Response. The curl
// template ends with -w "\n%{http_code}\n", so the LAST non-empty line is the
// status code when the exchange completed; anything else is treated as a
// transport error rather than guessed at.
func parseResponse(out []byte, err error) Response { // one exchange
	r := Response{} // seed
	if err != nil { // the tool could not complete the request
		r.Err = err.Error() // record it
	}
	s := strings.TrimSuffix(string(out), "\n") // drop the trailing newline
	lines := strings.Split(s, "\n")            // split like a transcript
	last := ""                                 // the last non-empty line
	for i := len(lines) - 1; i >= 0; i-- {     // scan from the end
		if strings.TrimSpace(lines[i]) != "" { // first non-empty from the back
			last = strings.TrimSpace(lines[i])
			break
		}
	}
	if statusPattern.MatchString(last) { // a real status code...
		r.Status = last                                                 // ...remember it
		r.Body = maxCap(strings.TrimSpace(strings.TrimSuffix(s, last))) // everything before it, trimmed
		return r
	}
	if last != "" { // a non-status "last line" is transport noise
		if r.Err == "" { // keep the tool's own error if there is one
			r.Err = last
		}
	}
	r.Body = maxCap(strings.TrimSpace(s)) // keep whatever the tool returned
	return r
}

// maxCap trims a body/excerpt to a reportable size.
func maxCap(s string) string { // evidence cap
	if len(s) > maxBody { // a runaway reply...
		return s[:maxBody] + "\n... output truncated" // ...is cut, and says so
	}
	return s // small enough to keep whole
}

// trimOmitted removes empty commands from a rendering list.
func trimOmitted(in []string) []string { // display helper
	out := make([]string, 0, len(in)) // accumulate
	for _, s := range in {            // walk the inputs
		if strings.TrimSpace(s) != "" { // blanks carry no information
			out = append(out, s)
		}
	}
	return out // the meaningful commands
}
