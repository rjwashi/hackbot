// This file connects nmap results to CVE search: it derives software queries
// from fingerprinted services and merges the matching CVEs into one report.
package cve // same package as cve.go

import ( // imports for this file
	"context" // cancels the per-product searches
	"sort"    // deterministic query ordering
	"strings" // building search phrases

	"github.com/rjwashi/hackbot/internal/nmap" // the scan we read software from
)

// maxScanQueries caps how many distinct software queries `cve scan` issues, to
// stay friendly to NVD's rate limit.
const maxScanQueries = 5 // plenty for a typical host's open services

// QueriesFromScan derives CVE keyword queries from the software nmap detected.
//
// Only open ports on hosts that are up are considered. Each unique
// "product version" becomes one keyword query.
func QueriesFromScan(scan *nmap.Scan) []Query { // used by SearchScan
	if scan == nil { // defensive
		return nil
	}
	seen := map[string]bool{}          // de-duplicate phrases
	var out []Query                    // result
	for _, h := range scan.UpHosts() { // reachable hosts only
		for _, p := range h.OpenPorts() { // open ports only
			kw := productVersion(p.Service) // build "product version"
			if kw == "" || seen[kw] {       // skip blanks and repeats
				continue
			}
			seen[kw] = true                                  // remember
			out = append(out, Query{Keyword: kw, Limit: 20}) // one query per unique product
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Keyword < out[j].Keyword }) // stable order
	return out                                                                            // the queries
}

// productVersion builds a search phrase from a detected service.
func productVersion(s nmap.Service) string { // helper for QueriesFromScan
	var parts []string                      // collect product then version
	if strings.TrimSpace(s.Product) != "" { // product, when detected
		parts = append(parts, strings.TrimSpace(s.Product))
	}
	if strings.TrimSpace(s.Version) != "" { // version, when detected
		parts = append(parts, strings.TrimSpace(s.Version))
	}
	return strings.Join(parts, " ") // e.g. "nginx 1.24.0"
}

// SearchScan searches NVD for each piece of software nmap detected and merges
// the results into one ranked report. It caps the number of queries and
// de-duplicates CVEs that match more than one product.
func (a *Agent) SearchScan(ctx context.Context, scan *nmap.Scan) (*Report, error) { // CLI: cve scan <file>
	queries := QueriesFromScan(scan) // derive software queries
	if len(queries) == 0 {           // nothing to look up...
		return &Report{Category: "scan", Query: "(no software detected)"}, nil // ...return an empty report
	}
	if len(queries) > maxScanQueries { // respect the rate-limit cap
		queries = queries[:maxScanQueries]
	}
	var all []CVE               // accumulate matches
	var used []string           // record which products we searched
	total := 0                  // sum of totals reported by the source
	for _, q := range queries { // search each product
		q.Limit = a.fetchLimit() // use the larger fetch pool
		if a.Log != nil {        // progress note
			a.Log("searching NVD for " + q.Keyword + "...")
		}
		res, err := a.Searcher.Search(ctx, q) // query
		if err != nil {
			return nil, err // propagate
		}
		total += res.Total             // add to the grand total
		all = append(all, res.CVEs...) // collect records
		used = append(used, q.Keyword) // remember the phrase
	}
	return &Report{ // assemble one merged report
		Category: "scan",                   // marker
		Query:    strings.Join(used, ", "), // products searched
		Total:    total,                    // grand total
		Results:  a.rank(dedupeCVEs(all)),  // de-dupe, filter, rank, cap
	}, nil
}

// dedupeCVEs keeps the first record seen for each CVE id.
func dedupeCVEs(in []CVE) []CVE { // used by SearchScan
	seen := map[string]bool{}      // de-dupe set
	out := make([]CVE, 0, len(in)) // result
	for _, c := range in {         // walk records
		if c.ID == "" || seen[c.ID] { // skip blanks and repeats
			continue
		}
		seen[c.ID] = true    // remember
		out = append(out, c) // collect
	}
	return out // de-duplicated records
}
