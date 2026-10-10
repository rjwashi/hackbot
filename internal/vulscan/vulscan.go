// Package vulscan interprets output from scipag/vulscan, an Nmap Scripting
// Engine (NSE) script that matches fingerprinted services against offline VulDB
// databases (CVE, Exploit-DB, OSVDB, SecurityFocus, and more).
//
// vulscan is a recon aid, not a confirmation engine: a match means the detected
// product/version appears in a vulnerability database, not that the target is
// definitely exploitable. Findings are therefore surfaced at MEDIUM severity
// and labelled "potential", so they inform a human without being treated as
// confirmed and auto-filed.
package vulscan // importable as "vulscan"

import ( // imports for this file
	"fmt"     // Sprintf for the human-readable summary
	"regexp"  // parse the "[<id>] <title>" lines vulscan prints
	"sort"    // deterministic ordering of results and CVE ids
	"strings" // line cleaning and prefix checks

	"github.com/rjwashi/hackbot/internal/nmap" // the scan we read NSE output from
)

// ScriptID is the NSE script id nmap records for vulscan output.
const ScriptID = "vulscan" // matches `<script id="vulscan" ...>`

// scriptIDPrefix matches the id plus path-style variants such as "vulscan.nse".
const scriptIDPrefix = "vulscan" // used for a tolerant prefix match

var ( // compiled once at package init
	// matchLine matches vulscan's default output line: "[<id>] <title>".
	matchLine = regexp.MustCompile(`^\[([^\]]+)\]\s*(.*)$`)
	// cveID matches a canonical CVE id, e.g. "CVE-2022-0543".
	cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// Match is one vulnerability entry reported by vulscan.
type Match struct { // one "[id] title" row
	ID    string `json:"id"`              // the bracketed database id (CVE, OSVDB, ...)
	Title string `json:"title,omitempty"` // the human-readable title after the id
	Line  string `json:"line,omitempty"`  // the cleaned source line, kept for provenance
}

// Result is vulscan output for one host/port pair.
type Result struct { // one group of matches for a target
	Host     string  `json:"host"`               // host label (name + address)
	Port     int     `json:"port,omitempty"`     // port number; 0 for host-level output
	Protocol string  `json:"protocol,omitempty"` // tcp/udp
	Service  string  `json:"service,omitempty"`  // detected service name
	Matches  []Match `json:"matches"`            // the matched vulnerabilities
	Raw      string  `json:"raw,omitempty"`      // the raw script output text
}

// IsVulscan reports whether a script is vulscan (or a path variant of it).
func IsVulscan(s nmap.Script) bool { // tolerant so "vulscan.nse" also matches
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.ID)), scriptIDPrefix)
}

// HasVulscan reports whether a scan contains any vulscan output.
func HasVulscan(scan *nmap.Scan) bool { // convenience for callers deciding whether to show a section
	return len(Parse(scan)) > 0 // Parse already ignores scans with no vulscan results
}

// Parse extracts every vulscan result from a scan, in deterministic order.
func Parse(scan *nmap.Scan) []Result { // main entry point
	if scan == nil { // defensive: callers and tests may pass nil
		return nil // nothing to parse
	}
	var out []Result               // accumulator
	for _, h := range scan.Hosts { // walk every host (vulscan usually only runs on up hosts)
		label := h.Label()            // precompute the display label once
		for _, s := range h.Scripts { // host-level vulscan output (uncommon but possible)
			if !IsVulscan(s) { // ignore non-vulscan scripts
				continue
			}
			if ms := parseScript(s); len(ms) > 0 { // parse only when there are matches
				out = append(out, Result{Host: label, Matches: ms, Raw: s.Output}) // host-level result
			}
		}
		for _, p := range h.Ports { // port-level vulscan output (the normal case)
			for _, s := range p.Scripts { // examine each script on the port
				if !IsVulscan(s) { // ignore non-vulscan scripts
					continue
				}
				if ms := parseScript(s); len(ms) > 0 { // parse when matches exist
					out = append(out, Result{ // port-level result
						Host:     label,          // host label
						Port:     p.Number,       // port number
						Protocol: p.Protocol,     // tcp/udp
						Service:  p.Service.Name, // detected service
						Matches:  ms,             // parsed matches
						Raw:      s.Output,       // raw output for provenance
					})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { // keep output stable across runs
		if out[i].Host != out[j].Host { // first by host...
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port // ...then by port
	})
	return out // parsed results
}

// parseScript parses one vulscan script's output into de-duplicated matches.
func parseScript(s nmap.Script) []Match { // shared by host- and port-level output
	var ms []Match                        // accumulator
	seen := map[string]bool{}             // de-duplicate identical rows
	for _, line := range scriptLines(s) { // consider every line
		m, ok := parseLine(line) // parse the line
		if !ok {                 // skip headings/blank lines
			continue
		}
		key := m.ID + "\x00" + m.Title // de-dupe on id+title
		if seen[key] {                 // already have it...
			continue // ...skip
		}
		seen[key] = true   // remember
		ms = append(ms, m) // collect
	}
	return ms // matches for this script
}

// scriptLines returns the text lines of a vulscan script, from its output text
// and (as a fallback) from any structured <elem> values.
func scriptLines(s nmap.Script) []string { // handles both string and table output
	var lines []string                     // accumulator
	if strings.TrimSpace(s.Output) != "" { // the normal case: a text block
		lines = append(lines, strings.Split(s.Output, "\n")...) // split on newlines
	}
	if len(lines) == 0 { // no text output means vulscan returned structured data
		lines = append(lines, elemValues(s)...) // fall back to <elem> values
	}
	return lines // candidate lines
}

// elemValues flattens all <elem> values inside a script (recursing tables).
func elemValues(s nmap.Script) []string { // used only when Output is empty
	var vals []string           // accumulator
	for _, e := range s.Elems { // direct fields
		vals = append(vals, e.Value)
	}
	for _, t := range s.Tables { // then nested tables
		vals = append(vals, tableValues(t)...)
	}
	return vals // flattened values
}

// tableValues recursively flattens <elem> values inside a table.
func tableValues(t nmap.ScriptTable) []string { // recursive helper for elemValues
	var vals []string           // accumulator
	for _, e := range t.Elems { // this table's rows
		vals = append(vals, e.Value)
	}
	for _, n := range t.Tables { // any nested tables
		vals = append(vals, tableValues(n)...)
	}
	return vals // flattened values
}

// parseLine extracts a Match from one vulscan output line, or reports false.
func parseLine(line string) (Match, bool) { // one "[id] title" row
	l := cleanLine(line)                               // strip nmap pipes/labels
	if l == "" || strings.EqualFold(l, ScriptID+":") { // skip blanks and the "vulscan:" label
		return Match{}, false
	}
	m := matchLine.FindStringSubmatch(l) // apply the "[id] title" pattern
	if m == nil {                        // not a result line
		return Match{}, false
	}
	id := strings.TrimSpace(m[1]) // the bracketed id
	if id == "" {                 // guard against "[] title"
		return Match{}, false
	}
	return Match{ID: id, Title: strings.TrimSpace(m[2]), Line: l}, true // success
}

// cleanLine strips nmap's text-output pipes and a leading script label.
func cleanLine(line string) string { // makes the parser tolerant of -oN-style text
	l := strings.TrimSpace(line)            // trim surrounding space
	l = strings.TrimPrefix(l, "|_")         // NSE's last-line marker
	l = strings.TrimPrefix(l, "|")          // NSE's continuation marker
	l = strings.TrimSpace(l)                // trim again after removing pipes
	l = strings.TrimPrefix(l, ScriptID+":") // drop the leading "vulscan:" label
	return strings.TrimSpace(l)             // final trim
}

// CVEs returns the unique CVE ids found by vulscan, sorted.
func CVEs(scan *nmap.Scan) []string { // used by summaries and future enrichment
	seen := map[string]bool{}       // de-duplicate
	var out []string                // accumulator
	for _, r := range Parse(scan) { // walk all results
		for _, m := range r.Matches { // and their matches
			id := strings.ToUpper(m.ID)             // normalize case
			if cveID.MatchString(id) && !seen[id] { // keep only canonical CVEs
				seen[id] = true       // remember
				out = append(out, id) // collect
			}
		}
	}
	sort.Strings(out) // stable order
	return out        // unique CVE ids
}

// Findings converts vulscan matches into MEDIUM-severity nmap findings.
//
// MEDIUM (rather than HIGH) reflects that a database match is potential, not
// confirmed, and keeps these out of the default high-severity issue threshold.
func Findings(scan *nmap.Scan) []nmap.Finding { // plugs vulscan into the pipeline
	var findings []nmap.Finding     // accumulator
	for _, r := range Parse(scan) { // walk results
		for _, m := range r.Matches { // and matches
			title := "Potential vulnerability (vulscan): " + m.ID // headline
			detail := "vulscan matched the detected service against an offline vulnerability database. " +
				"This is not a confirmed exploit; verify the product version and the advisory." // guidance
			if m.Title != "" { // include the database title when present
				detail += " Advisory: " + m.Title
			}
			findings = append(findings, nmap.Finding{ // one finding per match
				Host:     r.Host,         // host
				Port:     r.Port,         // port (0 for host-level)
				Protocol: r.Protocol,     // tcp/udp
				Service:  r.Service,      // service
				Severity: nmap.SevMedium, // potential, not confirmed
				Title:    title,          // headline
				Detail:   detail,         // guidance + advisory
			})
		}
	}
	return findings // converted findings
}

// Summary renders a short human report of vulscan results.
func Summary(scan *nmap.Scan) string { // used by the CLI
	results := Parse(scan) // parse once
	if len(results) == 0 { // nothing found...
		return "no vulscan results\n" // ...say so plainly
	}
	total := 0 // count matches across groups
	for _, r := range results {
		total += len(r.Matches)
	}
	var b strings.Builder                                                              // accumulate text
	fmt.Fprintf(&b, "%d vulscan result group(s), %d match(es)\n", len(results), total) // headline
	for _, r := range results {                                                        // one block per target
		target := r.Host // host...
		if r.Port > 0 {  // ...with port when present
			target = fmt.Sprintf("%s:%d/%s", r.Host, r.Port, r.Protocol)
		}
		if r.Service != "" { // include the service name when known
			target += " (" + r.Service + ")"
		}
		fmt.Fprintf(&b, "  %s\n", target) // target line
		for _, m := range r.Matches {     // then each match
			if m.Title != "" { // with title when present
				fmt.Fprintf(&b, "    [%s] %s\n", m.ID, m.Title)
			} else { // otherwise just the id
				fmt.Fprintf(&b, "    [%s]\n", m.ID)
			}
		}
	}
	return b.String() // assembled report
}
