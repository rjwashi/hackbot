// Package cve searches public vulnerability databases for CVEs by category
// (for example XSS, SQL injection, or remote code execution).
//
// It is intentionally read-only and defensive: it only queries public
// vulnerability databases (today the NIST NVD REST API) and never touches a
// target. A "category" is a friendly name mapped to a CWE identifier plus
// optional keywords, so the same search is reproducible run to run.
package cve // importable as "cve"

import ( // imports for this file
	"context" // cancels in-flight HTTP searches
	"fmt"     // Errorf/Sprintf for messages
	"sort"    // deterministic ranking of results
	"strings" // joining/trimming when building queries and summaries
)

// Category describes a family of vulnerabilities to search for.
type Category struct { // one row of the built-in catalog
	Name        string   // short, stable, lowercase name used on the CLI and in JSON
	CWE         string   // primary CWE id to filter on, e.g. "CWE-79"
	Keywords    []string // fallback keyword terms when no CWE is set
	Description string   // one-line explanation shown by `cve categories`
}

// Categories is the built-in catalog of searchable vulnerability categories.
//
// CWEs are preferred over free text because they are stable, precise, and map
// cleanly onto NVD's cweId filter. Keywords are only used when a category has
// no representative CWE.
var Categories = []Category{ // ordered roughly from most to least severe impact
	{Name: "rce", CWE: "CWE-94", Keywords: []string{"remote code execution"}, Description: "Remote code execution / code injection"},
	{Name: "command-injection", CWE: "CWE-78", Keywords: []string{"OS command injection"}, Description: "OS command injection"},
	{Name: "sqli", CWE: "CWE-89", Keywords: []string{"SQL injection"}, Description: "SQL injection"},
	{Name: "xss", CWE: "CWE-79", Keywords: []string{"cross-site scripting"}, Description: "Cross-site scripting (XSS)"},
	{Name: "xxe", CWE: "CWE-611", Keywords: []string{"XML external entity"}, Description: "XML external entity (XXE) injection"},
	{Name: "ssrf", CWE: "CWE-918", Keywords: []string{"server-side request forgery"}, Description: "Server-side request forgery (SSRF)"},
	{Name: "deserialization", CWE: "CWE-502", Keywords: []string{"deserialization"}, Description: "Unsafe deserialization"},
	{Name: "path-traversal", CWE: "CWE-22", Keywords: []string{"path traversal", "directory traversal"}, Description: "Path / directory traversal"},
	{Name: "lfi", CWE: "CWE-98", Keywords: []string{"file inclusion"}, Description: "Local / remote file inclusion (LFI/RFI)"},
	{Name: "buffer-overflow", CWE: "CWE-787", Keywords: []string{"buffer overflow"}, Description: "Out-of-bounds write / buffer overflow"},
	{Name: "memory-corruption", CWE: "CWE-119", Keywords: []string{"memory corruption"}, Description: "Memory corruption"},
	{Name: "auth-bypass", CWE: "CWE-287", Keywords: []string{"authentication bypass"}, Description: "Improper authentication / auth bypass"},
	{Name: "privilege-escalation", CWE: "CWE-269", Keywords: []string{"privilege escalation"}, Description: "Improper privilege management / privesc"},
	{Name: "csrf", CWE: "CWE-352", Keywords: []string{"cross-site request forgery"}, Description: "Cross-site request forgery (CSRF)"},
	{Name: "open-redirect", CWE: "CWE-601", Keywords: []string{"open redirect"}, Description: "URL redirection / open redirect"},
	{Name: "info-disclosure", CWE: "CWE-200", Keywords: []string{"information disclosure"}, Description: "Information exposure / disclosure"},
	{Name: "dos", CWE: "CWE-400", Keywords: []string{"denial of service"}, Description: "Resource exhaustion / denial of service"},
}

// categoryAliases lets a few common spellings map onto canonical names.
var categoryAliases = map[string]string{ // consulted by CategoryByName
	"remote":                 "rce",
	"remote-exploit":         "rce",
	"remote-code-execution":  "rce",
	"code-execution":         "rce",
	"os-command-injection":   "command-injection",
	"sql":                    "sqli",
	"sql-injection":          "sqli",
	"cross-site-scripting":   "xss",
	"traversal":              "path-traversal",
	"directory-traversal":    "path-traversal",
	"file-inclusion":         "lfi",
	"auth":                   "auth-bypass",
	"privesc":                "privilege-escalation",
	"infoleak":               "info-disclosure",
	"information-disclosure": "info-disclosure",
	"memory":                 "memory-corruption",
	"denial-of-service":      "dos",
}

// CategoryByName finds a category by name or alias, case-insensitively.
func CategoryByName(name string) (Category, bool) { // used by the CLI and Agent
	key := strings.ToLower(strings.TrimSpace(name)) // normalize the input
	if alias, ok := categoryAliases[key]; ok {      // translate an alias...
		key = alias // ...to its canonical name
	}
	for _, c := range Categories { // then look it up
		if c.Name == key {
			return c, true // found
		}
	}
	return Category{}, false // unknown category
}

// CategoryNames returns the catalog's names in their declared order.
func CategoryNames() []string { // used in help and error messages
	names := make([]string, 0, len(Categories)) // preallocate
	for _, c := range Categories {              // copy each name
		names = append(names, c.Name)
	}
	return names // ordered list
}

// CVE is one vulnerability record normalized across data sources.
type CVE struct { // the subset we display and rank on
	ID          string   `json:"id"`                   // e.g. "CVE-2023-1234"
	Description string   `json:"description"`          // English summary
	Score       float64  `json:"cvss_score,omitempty"` // best available CVSS base score
	Severity    string   `json:"severity,omitempty"`   // CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
	Vector      string   `json:"vector,omitempty"`     // CVSS vector string
	CWEs        []string `json:"cwes,omitempty"`       // associated CWE ids
	Published   string   `json:"published,omitempty"`  // publication date (as reported)
	References  []string `json:"references,omitempty"` // reference URLs
}

// Report is the result of one category or keyword search.
type Report struct { // serialized directly by the CLI with -json
	Category string `json:"category"` // category name, or "keyword"/"scan"
	Query    string `json:"query"`    // the CWE/keyword actually searched
	Total    int    `json:"total"`    // total matches the source reported
	Results  []CVE  `json:"results"`  // ranked, filtered results
}

// Query is a single search request handed to a Searcher.
type Query struct { // source-agnostic request shape
	CWE     string // filter by CWE id (preferred)
	Keyword string // free-text keyword (used when CWE is empty)
	Limit   int    // requested page size
}

// Result is what a Searcher returns: the total match count plus one page.
type Result struct { // lets Report expose "showing N of TOTAL"
	Total int   // total matches reported by the source
	CVEs  []CVE // one page of normalized records
}

// Searcher is the data-source seam so the agent can be tested without network.
type Searcher interface { // implemented by NVDClient; fakes used in tests
	Search(ctx context.Context, q Query) (Result, error) // one query, one page
}

// Agent orchestrates category searches, filtering, and ranking.
type Agent struct { // the "CVE agent" the CLI drives
	Searcher Searcher     // required; the vulnerability data source
	Limit    int          // max results to return (0 = 20)
	MinScore float64      // drop CVEs below this CVSS score (0 = keep all)
	Log      func(string) // optional progress sink
}

// defaultLimit is used when Agent.Limit is unset.
const defaultLimit = 20 // results shown by default

// SearchCategory looks up a category and searches for its CVEs.
func (a *Agent) SearchCategory(ctx context.Context, name string) (*Report, error) { // CLI: cve search <category>
	cat, ok := CategoryByName(name) // resolve the friendly name
	if !ok {                        // unknown category...
		return nil, fmt.Errorf("cve: unknown category %q (try: %s)", name, strings.Join(CategoryNames(), ", ")) // helpful error
	}
	q := a.queryFor(cat) // build the source query
	if a.Log != nil {    // progress note when requested
		a.Log(fmt.Sprintf("searching NVD for %s (%s)...", cat.Name, queryLabel(q)))
	}
	res, err := a.Searcher.Search(ctx, q) // ask the source
	if err != nil {                       // propagate failures
		return nil, err
	}
	return &Report{ // assemble the ranked report
		Category: cat.Name,         // category name
		Query:    queryLabel(q),    // the CWE/keyword used
		Total:    res.Total,        // total matches at the source
		Results:  a.rank(res.CVEs), // filtered + sorted + capped
	}, nil
}

// SearchKeyword runs a free-text search across all of NVD.
func (a *Agent) SearchKeyword(ctx context.Context, keyword string) (*Report, error) { // CLI: cve keyword <text>
	keyword = strings.TrimSpace(keyword) // normalize
	if keyword == "" {                   // nothing to search for...
		return nil, fmt.Errorf("cve: empty keyword") // ...is an error
	}
	if a.Log != nil {
		a.Log("searching NVD for keyword " + keyword + "...")
	}
	res, err := a.Searcher.Search(ctx, Query{Keyword: keyword, Limit: a.fetchLimit()}) // query
	if err != nil {
		return nil, err
	}
	return &Report{ // assemble
		Category: "keyword",
		Query:    keyword,
		Total:    res.Total,
		Results:  a.rank(res.CVEs),
	}, nil
}

// queryFor maps a category onto a source query.
func (a *Agent) queryFor(cat Category) Query { // CWE wins over keywords
	if cat.CWE != "" { // prefer the precise CWE filter
		return Query{CWE: cat.CWE, Limit: a.fetchLimit()}
	}
	kw := "" // fall back to the first keyword
	if len(cat.Keywords) > 0 {
		kw = cat.Keywords[0]
	}
	return Query{Keyword: kw, Limit: a.fetchLimit()}
}

// fetchLimit decides how many records to pull before client-side filtering.
//
// NVD cannot sort by CVSS score, so we fetch a larger pool (a few times the
// display limit) and then filter/sort locally.
func (a *Agent) fetchLimit() int { // per-request page size
	limit := a.Limit // configured display limit
	if limit <= 0 {
		limit = defaultLimit // default
	}
	fetch := limit * 5 // aim for a useful pool...
	if fetch < 50 {    // ...but never fewer than 50...
		fetch = 50
	}
	if fetch > 200 { // ...and never more than 200 (keeps responses small)
		fetch = 200
	}
	return fetch
}

// rank filters by score, sorts worst-first, and caps to the display limit.
func (a *Agent) rank(cves []CVE) []CVE { // shared by all Agent searches
	out := make([]CVE, 0, len(cves)) // filtered slice
	for _, c := range cves {         // drop anything under the score floor
		if c.Score >= a.MinScore {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { // worst-first, then by id for stability
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	limit := a.Limit // display cap
	if limit <= 0 {
		limit = defaultLimit
	}
	if len(out) > limit { // truncate
		out = out[:limit]
	}
	return out // final ranked results
}

// queryLabel renders a query for display.
func queryLabel(q Query) string { // used in Report.Query and logs
	if q.CWE != "" {
		return q.CWE
	}
	return q.Keyword
}

// Summary renders a human-readable report for the CLI.
func (r *Report) Summary() string { // used when -json is absent
	var b strings.Builder                                                                        // accumulate text
	fmt.Fprintf(&b, "%s (%s): showing %d of %d\n", r.Category, r.Query, len(r.Results), r.Total) // headline
	if len(r.Results) == 0 {                                                                     // empty result set...
		b.WriteString("  no matching CVEs\n") // ...say so
		return b.String()
	}
	for _, c := range r.Results { // one block per CVE
		fmt.Fprintf(&b, "  %s\n", c.String()) // CVE.String() renders detail
	}
	return b.String()
}

// String renders one CVE as a short two-line block.
func (c CVE) String() string { // used by Report.Summary
	sev := c.Severity // severity label
	if sev == "" {
		sev = "UNKNOWN"
	}
	desc := strings.Join(strings.Fields(c.Description), " ") // collapse whitespace/newlines
	if len(desc) > 200 {                                     // keep blocks readable
		desc = desc[:197] + "..."
	}
	head := fmt.Sprintf("%s  [%s %.1f]  %s", c.ID, sev, c.Score, desc) // first line
	if len(c.References) > 0 {                                         // second line: first reference
		head += "\n      " + c.References[0]
	}
	return head
}

// SeverityFromScore maps a CVSS base score to a label.
func SeverityFromScore(score float64) string { // used when a source omits a label
	switch { // standard CVSS v3 bands
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
