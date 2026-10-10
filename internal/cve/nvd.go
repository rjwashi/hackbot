// This file implements the default Searcher: a read-only client for the NIST
// National Vulnerability Database (NVD) 2.0 REST API.
//
// NVD is free and needs no API key, though a key raises the rate limit from 5
// to 50 requests per 30 seconds. We only ever issue GET requests.
package cve // same package as cve.go

import ( // imports for this file
	"context"       // request cancellation
	"encoding/json" // decode NVD JSON
	"fmt"           // Errorf for contextual errors
	"io"            // read and bound the response body
	"net/http"      // the HTTP client
	"net/url"       // build query parameters safely (encoding)
	"sort"          // sort CWE ids for stable output
	"strings"       // string helpers for parsing
	"time"          // request timeout
)

// DefaultNVDURL is the public NIST NVD 2.0 CVE API endpoint.
const DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0" // overridable for tests/mirrors

// NVDClient searches the NIST National Vulnerability Database.
type NVDClient struct { // satisfies the Searcher interface
	BaseURL string       // API endpoint; empty means DefaultNVDURL
	APIKey  string       // optional; sent as the "apiKey" header
	HTTP    *http.Client // optional; defaults to a 30s-timeout client
}

// Search runs one NVD query and normalizes the response.
func (c *NVDClient) Search(ctx context.Context, q Query) (Result, error) { // Searcher implementation
	base := c.BaseURL // choose the endpoint
	if base == "" {
		base = DefaultNVDURL
	}
	u, err := url.Parse(base) // parse so we can attach query parameters
	if err != nil {
		return Result{}, fmt.Errorf("cve: bad NVD base url %q: %w", base, err)
	}
	params := u.Query() // start from any params already in the URL
	if q.CWE != "" {    // prefer the precise CWE filter...
		params.Set("cweId", q.CWE) // ...NVD's cweId parameter
	}
	if q.Keyword != "" && q.CWE == "" { // otherwise fall back to a keyword
		params.Set("keywordSearch", q.Keyword)
	}
	if q.Limit > 0 { // bound the page size
		params.Set("resultsPerPage", fmt.Sprintf("%d", q.Limit))
	}
	u.RawQuery = params.Encode() // encode safely

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) // build the request
	if err != nil {
		return Result{}, fmt.Errorf("cve: build NVD request: %w", err)
	}
	req.Header.Set("Accept", "application/json") // ask for JSON
	if c.APIKey != "" {                          // include the key when configured...
		req.Header.Set("apiKey", c.APIKey) // ...to raise the rate limit
	}

	client := c.HTTP // pick the client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second} // default with a timeout
	}
	resp, err := client.Do(req) // perform the request
	if err != nil {
		return Result{}, fmt.Errorf("cve: NVD request: %w", err)
	}
	defer resp.Body.Close()                                 // always release the body
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // read up to 8 MiB
	if resp.StatusCode != http.StatusOK {                   // non-200 is an error...
		return Result{}, fmt.Errorf("cve: NVD returned %s: %s", resp.Status, snippet(body)) // ...with a body hint
	}

	var parsed nvdResponse // decode
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Result{}, fmt.Errorf("cve: decode NVD response: %w", err)
	}
	out := Result{Total: parsed.TotalResults}  // carry the total match count
	for _, v := range parsed.Vulnerabilities { // normalize each record
		out.CVEs = append(out.CVEs, v.CVE.toCVE())
	}
	return out, nil // done
}

// nvdResponse mirrors the top level of the NVD 2.0 JSON payload.
type nvdResponse struct { // only the fields we use
	TotalResults    int       `json:"totalResults"`    // total matches available
	Vulnerabilities []nvdVuln `json:"vulnerabilities"` // this page of records
}

// nvdVuln wraps one vulnerability entry.
type nvdVuln struct { // NVD nests the record under "cve"
	CVE nvdCVE `json:"cve"` // the CVE record
}

// nvdCVE mirrors the fields of a single CVE record.
type nvdCVE struct { // subset of the NVD schema
	ID           string         `json:"id"`           // CVE id
	Published    string         `json:"published"`    // publication timestamp
	Descriptions []nvdLang      `json:"descriptions"` // localized descriptions
	Metrics      nvdMetrics     `json:"metrics"`      // CVSS metrics
	Weaknesses   []nvdWeakness  `json:"weaknesses"`   // CWE mappings
	References   []nvdReference `json:"references"`   // external links
}

// nvdLang is a localized string (lang + value).
type nvdLang struct { // used by descriptions and CWE descriptions
	Lang  string `json:"lang"`  // e.g. "en"
	Value string `json:"value"` // the text
}

// nvdMetrics holds the CVSS metric arrays NVD may include.
type nvdMetrics struct { // we prefer v3.1, then v3.0, then v2
	V31 []nvdMetric `json:"cvssMetricV31"` // CVSS v3.1
	V30 []nvdMetric `json:"cvssMetricV30"` // CVSS v3.0
	V2  []nvdMetric `json:"cvssMetricV2"`  // CVSS v2
}

// nvdMetric wraps one CVSS metric entry.
type nvdMetric struct { // only cvssData matters here
	CVSSData nvdCVSSData `json:"cvssData"` // the scores/vector
}

// nvdCVSSData is the CVSS score payload.
type nvdCVSSData struct { // shared shape across CVSS versions
	BaseScore    float64 `json:"baseScore"`    // 0..10
	BaseSeverity string  `json:"baseSeverity"` // CRITICAL/HIGH/... (v3+)
	VectorString string  `json:"vectorString"` // CVSS vector
}

// nvdWeakness is a CWE mapping entry.
type nvdWeakness struct { // description carries the CWE ids
	Description []nvdLang `json:"description"` // e.g. value "CWE-79"
}

// nvdReference is a reference link.
type nvdReference struct { // url is what we surface
	URL  string   `json:"url"`  // the link
	Tags []string `json:"tags"` // e.g. "Patch", "Exploit"
}

// toCVE converts one NVD record into our normalized CVE.
func (x nvdCVE) toCVE() CVE { // mapping layer; keeps the NVD schema private
	c := CVE{ // start with the always-present fields
		ID:          x.ID,                    // id
		Description: english(x.Descriptions), // English description
		Published:   x.Published,             // date
	}
	if m, ok := x.Metrics.best(); ok { // pick the best available metric
		c.Score = m.CVSSData.BaseScore       // score
		c.Vector = m.CVSSData.VectorString   // vector
		c.Severity = m.CVSSData.BaseSeverity // label (may be empty for v2)
		if c.Severity == "" {                // derive a label when the source omits one
			c.Severity = SeverityFromScore(c.Score)
		}
	} else {
		c.Severity = "UNKNOWN" // no metrics published yet
	}
	c.CWEs = x.cwes()                // extract CWE ids
	for _, r := range x.References { // collect reference URLs
		if r.URL != "" {
			c.References = append(c.References, r.URL)
		}
	}
	return c // normalized record
}

// best returns the highest-preference CVSS metric available.
func (m nvdMetrics) best() (nvdMetric, bool) { // preference: v3.1 > v3.0 > v2
	switch {
	case len(m.V31) > 0:
		return m.V31[0], true
	case len(m.V30) > 0:
		return m.V30[0], true
	case len(m.V2) > 0:
		return m.V2[0], true
	default:
		return nvdMetric{}, false // no metrics
	}
}

// cwes extracts and de-duplicates CWE ids from the weaknesses list.
func (x nvdCVE) cwes() []string { // NVD may list several weaknesses
	seen := map[string]bool{}        // de-dupe
	var out []string                 // result
	for _, w := range x.Weaknesses { // walk each weakness
		for _, d := range w.Description { // and its localized values
			v := strings.TrimSpace(d.Value)               // normalize
			if strings.HasPrefix(v, "CWE-") && !seen[v] { // keep only CWE ids
				seen[v] = true       // remember it
				out = append(out, v) // collect it
			}
		}
	}
	sort.Strings(out) // stable order
	return out        // CWE ids
}

// english returns the English text from a localized list.
func english(items []nvdLang) string { // NVD marks English with lang "en"
	for _, it := range items { // prefer English...
		if it.Lang == "en" {
			return it.Value
		}
	}
	if len(items) > 0 { // ...but fall back to the first entry
		return items[0].Value
	}
	return "" // nothing available
}

// snippet trims a response body for use in an error message.
func snippet(b []byte) string { // keeps errors short
	s := strings.TrimSpace(string(b)) // normalize
	if len(s) > 300 {                 // bound the length
		s = s[:300] + "..."
	}
	return s
}
