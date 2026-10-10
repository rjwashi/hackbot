// This file adds the "capability" layer on top of the WSTG checklists: each
// checklist test is a capability, and this file maps categories and tests to
// free/open-source tools that can exercise them.
//
// Two ideas:
//
//   - Tools: a catalog of free/open-source security tools (no paid products).
//   - Checks: a curated, runnable mapping from a checklist test id to one tool
//     and a fixed argument template. Tests without a check are "manual".
//
// The runner in run.go executes checks only against allowlisted targets and only
// when scanning is explicitly enabled; everything else is shown as a plan.
package wstg // same package as wstg.go

import ( // imports for this file
	"sort"    // deterministic tool/category ordering
	"strings" // command rendering
)

// WSTGBaseURL is the canonical OWASP WSTG reference linked from plans.
const WSTGBaseURL = "https://owasp.org/www-project-web-security-testing-guide/latest/" // free reference

// Tool describes a free/open-source tool or resource.
type Tool struct { // one entry in the catalog
	Key     string `json:"key"`               // short id used by checks, e.g. "nuclei"
	Name    string `json:"name"`              // display name, e.g. "OWASP ZAP"
	Bin     string `json:"bin"`               // executable name, e.g. "zap-baseline.py"
	Kind    string `json:"kind"`              // scanner|fuzzer|fingerprint|proxy|cli|exploit
	URL     string `json:"url"`               // project home / install (free)
	License string `json:"license"`           // license (all free/open-source)
	Install string `json:"install,omitempty"` // one-line install hint
	Notes   string `json:"notes,omitempty"`   // what it is good for
}

// toolCatalog is the set of free/open-source tools hackbot knows how to drive.
// Every entry is free to use; no commercial products are included.
var toolCatalog = map[string]Tool{ // keyed by Tool.Key
	"nmap": {
		Key: "nmap", Name: "nmap", Bin: "nmap", Kind: "scanner",
		URL: "https://nmap.org/", License: "NPSL/GPL-2.0",
		Install: "apt install nmap / brew install nmap",
		Notes:   "Port facts and service/version inventory.",
	},
	"curl": {
		Key: "curl", Name: "curl", Bin: "curl", Kind: "cli",
		URL: "https://curl.se/", License: "curl (MIT-like)",
		Install: "preinstalled on most systems",
		Notes:   "Pull headers, methods, and specific paths for inspection.",
	},
	"whatweb": {
		Key: "whatweb", Name: "WhatWeb", Bin: "whatweb", Kind: "fingerprint",
		URL: "https://github.com/urbanadventurer/WhatWeb", License: "GPL-2.0",
		Install: "apt install whatweb / gem install whatweb",
		Notes:   "Fingerprint servers, frameworks, and CMS versions.",
	},
	"wafw00f": {
		Key: "wafw00f", Name: "wafw00f", Bin: "wafw00f", Kind: "fingerprint",
		URL: "https://github.com/EnableSecurity/wafw00f", License: "BSD-3-Clause",
		Install: "pip install wafw00f",
		Notes:   "Detect and name web application firewalls.",
	},
	"nuclei": {
		Key: "nuclei", Name: "nuclei", Bin: "nuclei", Kind: "scanner",
		URL: "https://github.com/projectdiscovery/nuclei", License: "MIT",
		Install: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		Notes:   "Template-driven checks for misconfig, exposures, and CVEs.",
	},
	"nikto": {
		Key: "nikto", Name: "Nikto", Bin: "nikto", Kind: "scanner",
		URL: "https://github.com/sullo/nikto", License: "GPL-2.0",
		Install: "apt install nikto",
		Notes:   "Classic web server misconfiguration scan.",
	},
	"gobuster": {
		Key: "gobuster", Name: "gobuster", Bin: "gobuster", Kind: "fuzzer",
		URL: "https://github.com/OJ/gobuster", License: "Apache-2.0",
		Install: "go install github.com/OJ/gobuster/v3@latest",
		Notes:   "Directory/file and vhost brute forcing.",
	},
	"ffuf": {
		Key: "ffuf", Name: "ffuf", Bin: "ffuf", Kind: "fuzzer",
		URL: "https://github.com/ffuf/ffuf", License: "MIT",
		Install: "go install github.com/ffuf/ffuf/v2@latest",
		Notes:   "Fast web fuzzer (paths, params, vhosts).",
	},
	"sqlmap": {
		Key: "sqlmap", Name: "sqlmap", Bin: "sqlmap", Kind: "exploit",
		URL: "https://github.com/sqlmapproject/sqlmap", License: "GPL-2.0",
		Install: "pip install sqlmap / apt install sqlmap",
		Notes:   "Detect and confirm SQL injection (only with authorization).",
	},
	"dalfox": {
		Key: "dalfox", Name: "Dalfox", Bin: "dalfox", Kind: "scanner",
		URL: "https://github.com/hahwul/dalfox", License: "MIT",
		Install: "go install github.com/hahwul/dalfox/v2@latest",
		Notes:   "XSS scanning, including DOM-based XSS.",
	},
	"commix": {
		Key: "commix", Name: "commix", Bin: "commix", Kind: "exploit",
		URL: "https://github.com/commixproject/commix", License: "GPL-3.0",
		Install: "git clone https://github.com/commixproject/commix",
		Notes:   "Command injection detection and exploitation.",
	},
	"sstimap": {
		Key: "sstimap", Name: "SSTImap", Bin: "sstimap", Kind: "exploit",
		URL: "https://github.com/vladko312/SSTImap", License: "GPL-2.0",
		Install: "pip install sstimap",
		Notes:   "Server- and client-side template injection testing.",
	},
	"testssl": {
		Key: "testssl", Name: "testssl.sh", Bin: "testssl.sh", Kind: "scanner",
		URL: "https://github.com/drwetter/testssl.sh", License: "GPL-2.0",
		Install: "git clone --depth 1 https://github.com/drwetter/testssl.sh",
		Notes:   "Deep TLS/SSL configuration and cipher testing.",
	},
	"sslscan": {
		Key: "sslscan", Name: "sslscan", Bin: "sslscan", Kind: "scanner",
		URL: "https://github.com/rbsec/sslscan", License: "GPL-3.0",
		Install: "apt install sslscan",
		Notes:   "Enumerate supported protocols, ciphers, and certs.",
	},
	"zap": {
		Key: "zap", Name: "OWASP ZAP", Bin: "zap-baseline.py", Kind: "proxy",
		URL: "https://www.zaproxy.org/", License: "Apache-2.0",
		Install: "docker pull zaproxy/zap-stable  # or install ZAP",
		Notes:   "Free proxy + baseline scan; great for manual and automated review.",
	},
	"schemathesis": {
		Key: "schemathesis", Name: "Schemathesis", Bin: "schemathesis", Kind: "fuzzer",
		URL: "https://github.com/schemathesis/schemathesis", License: "MIT",
		Install: "pip install schemathesis",
		Notes:   "Property-based testing for OpenAPI/GraphQL APIs.",
	},
	"jwt_tool": {
		Key: "jwt_tool", Name: "jwt_tool", Bin: "jwt_tool", Kind: "cli",
		URL: "https://github.com/ticarpi/jwt_tool", License: "GPL-3.0",
		Install: "git clone https://github.com/ticarpi/jwt_tool",
		Notes:   "Analyze and attack JSON Web Tokens.",
	},
	"httpx": {
		Key: "httpx", Name: "httpx", Bin: "httpx", Kind: "fingerprint",
		URL: "https://github.com/projectdiscovery/httpx", License: "MIT",
		Install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
		Notes:   "Fast HTTP probing: status, title, tech, headers.",
	},
	"wpscan": {
		Key: "wpscan", Name: "WPScan", Bin: "wpscan", Kind: "scanner",
		URL: "https://github.com/wpscanteam/wpscan", License: "GPL-3.0",
		Install: "gem install wpscan",
		Notes:   "WordPress-specific vulnerability and configuration scan (free tier).",
	},
	"feroxbuster": {
		Key: "feroxbuster", Name: "feroxbuster", Bin: "feroxbuster", Kind: "fuzzer",
		URL: "https://github.com/epi052/feroxbuster", License: "MIT",
		Install: "cargo install feroxbuster  # or download a release",
		Notes:   "Recursive content discovery (Rust, fast).",
	},
	"gau": {
		Key: "gau", Name: "gau (GetAllUrls)", Bin: "gau", Kind: "cli",
		URL: "https://github.com/lc/gau", License: "MIT",
		Install: "go install github.com/lc/gau/v2/cmd/gau@latest",
		Notes:   "Fetch known URLs from public archives (OSINT).",
	},
}

// categoryTools maps a checklist slug to the free tools most useful for it.
// Every category lists at least one tool so every agent has capabilities.
var categoryTools = map[string][]string{ // slug -> tool keys (catalog order)
	"information-gathering": {"nmap", "whatweb", "wafw00f", "curl", "httpx", "gau"},
	"config-management":     {"nuclei", "nikto", "curl", "gobuster", "testssl", "feroxbuster"},
	"identity-management":   {"curl", "ffuf", "nuclei"},
	"authentication":        {"testssl", "nuclei", "jwt_tool", "zap", "wpscan"},
	"authorization":         {"nuclei", "ffuf", "zap", "curl"},
	"session-management":    {"curl", "jwt_tool", "nuclei", "zap"},
	"injection":             {"sqlmap", "dalfox", "commix", "sstimap", "nuclei"},
	"error-handling":        {"curl", "nuclei", "nikto"},
	"weak-cryptography":     {"testssl", "sslscan", "nmap"},
	"business-logic":        {"zap", "curl"},
	"client-side":           {"dalfox", "sstimap", "nuclei", "curl", "httpx"},
	"api-testing":           {"schemathesis", "nuclei", "curl", "httpx"},
}

// manualHints gives short, per-category guidance for tests that have no
// automated check yet, so every checklist row still has a "how".
var manualHints = map[string]string{ // slug -> guidance
	"information-gathering": "Use the tools above and manual browsing; record what the app exposes.",
	"config-management":     "Inspect the platform, headers, and exposed files by hand (use curl/ZAP).",
	"identity-management":   "Walk the registration, provisioning, and account-enumeration flows manually.",
	"authentication":        "Test each login path by hand with a browser and ZAP; confirm before reporting.",
	"authorization":         "Manually replay requests as different users/roles; verify access control (ZAP helps).",
	"session-management":    "Inspect cookies, tokens, and logout behavior in a browser + ZAP.",
	"injection":             "Probe inputs manually (ZAP/browser) and confirm; automatable cases use the tools above.",
	"error-handling":        "Trigger errors with malformed input and inspect the responses by hand.",
	"weak-cryptography":     "Review TLS config and any crypto usage; confirm weak primitives manually.",
	"business-logic":        "Business logic is usually manual: map the workflow and abuse each step deliberately.",
	"client-side":           "Use browser devtools and ZAP; confirm DOM flows by hand.",
	"api-testing":           "Review the API spec and test with the tools above; confirm by hand.",
}

// checks lists the curated, runnable capabilities. Each maps one checklist test
// to a free tool and a fixed argument template. {url}, {host}, and {target} are
// substituted by the runner (this keeps user input out of any shell).
var checks = []Check{ // one row per automatable capability
	// --- Information Gathering ---
	{Slug: "information-gathering", TestID: "WSTG-INFO-02", ToolKey: "whatweb", Args: []string{"-a", "3", "{url}"}, Guarded: true},           // fingerprint the web server
	{Slug: "information-gathering", TestID: "WSTG-INFO-03", ToolKey: "curl", Args: []string{"-sS", "-i", "{url}/robots.txt"}, Guarded: true}, // read robots.txt and headers
	{Slug: "information-gathering", TestID: "WSTG-INFO-04", ToolKey: "nmap", Args: []string{"-sV", "-Pn", "{host}"}, Guarded: true},          // inventory exposed services
	{Slug: "information-gathering", TestID: "WSTG-INFO-05", ToolKey: "curl", Args: []string{"-sS", "{url}"}, Guarded: true},                  // pull page content for review

	// --- Configuration and Deployment Management ---
	{Slug: "config-management", TestID: "WSTG-CONF-01", ToolKey: "nmap", Args: []string{"-sV", "-Pn", "{host}"}, Guarded: true},                             // network infrastructure facts
	{Slug: "config-management", TestID: "WSTG-CONF-02", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "config", "-silent"}, Guarded: true},      // platform config templates
	{Slug: "config-management", TestID: "WSTG-CONF-04", ToolKey: "gobuster", Args: []string{"dir", "-u", "{url}", "-q", "-w", "common.txt"}, Guarded: true}, // hunt old/backup files
	{Slug: "config-management", TestID: "WSTG-CONF-06", ToolKey: "curl", Args: []string{"-sS", "-i", "-X", "OPTIONS", "{url}"}, Guarded: true},              // list allowed HTTP methods
	{Slug: "config-management", TestID: "WSTG-CONF-07", ToolKey: "curl", Args: []string{"-sS", "-I", "{url}"}, Guarded: true},                               // check HSTS header
	{Slug: "config-management", TestID: "WSTG-CONF-12", ToolKey: "curl", Args: []string{"-sS", "-I", "{url}"}, Guarded: true},                               // check CSP header

	// --- Authentication ---
	{Slug: "authentication", TestID: "WSTG-ATHN-01", ToolKey: "testssl", Args: []string{"--quiet", "--warnings", "off", "{url}"}, Guarded: true},           // encrypted credential transport
	{Slug: "authentication", TestID: "WSTG-ATHN-02", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "default-login", "-silent"}, Guarded: true}, // poke default credentials

	// --- Authorization ---
	{Slug: "authorization", TestID: "WSTG-ATHZ-01", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "lfi,traversal", "-silent"}, Guarded: true}, // path traversal templates

	// --- Session Management ---
	{Slug: "session-management", TestID: "WSTG-SESS-02", ToolKey: "curl", Args: []string{"-sS", "-I", "{url}"}, Guarded: true}, // inspect Set-Cookie attributes

	// --- Injection ---
	{Slug: "injection", TestID: "WSTG-INJT-01", ToolKey: "dalfox", Args: []string{"url", "{url}"}, Guarded: true},                                          // reflected/DOM XSS scan
	{Slug: "injection", TestID: "WSTG-INJT-05", ToolKey: "sqlmap", Args: []string{"-u", "{url}", "--batch", "--level", "2", "--risk", "1"}, Guarded: true}, // SQL injection detection
	{Slug: "injection", TestID: "WSTG-INJT-12", ToolKey: "commix", Args: []string{"--url", "{url}", "--batch"}, Guarded: true},                             // command injection detection
	{Slug: "injection", TestID: "WSTG-INJT-18", ToolKey: "sstimap", Args: []string{"-u", "{url}"}, Guarded: true},                                          // template injection detection

	// --- Error Handling ---
	{Slug: "error-handling", TestID: "WSTG-ERRH-01", ToolKey: "curl", Args: []string{"-sS", "-i", "{url}/hackbot-nonexistent-path"}, Guarded: true}, // trigger an error page
	{Slug: "error-handling", TestID: "WSTG-ERRH-02", ToolKey: "curl", Args: []string{"-sS", "-i", "{url}/hackbot-nonexistent-path"}, Guarded: true}, // look for stack traces

	// --- Weak Cryptography ---
	{Slug: "weak-cryptography", TestID: "WSTG-CRYP-01", ToolKey: "testssl", Args: []string{"--quiet", "--warnings", "off", "{url}"}, Guarded: true}, // grade TLS configuration
	{Slug: "weak-cryptography", TestID: "WSTG-CRYP-04", ToolKey: "sslscan", Args: []string{"{host}"}, Guarded: true},                                // enumerate weak ciphers

	// --- Client-side ---
	{Slug: "client-side", TestID: "WSTG-CLNT-01", ToolKey: "dalfox", Args: []string{"url", "{url}"}, Guarded: true},                                           // DOM XSS scan
	{Slug: "client-side", TestID: "WSTG-CLNT-07", ToolKey: "curl", Args: []string{"-sS", "-I", "-H", "Origin: https://evil.example", "{url}"}, Guarded: true}, // probe CORS headers
	{Slug: "client-side", TestID: "WSTG-CLNT-09", ToolKey: "curl", Args: []string{"-sS", "-I", "{url}"}, Guarded: true},                                       // check framing headers

	// --- API Testing ---
	{Slug: "api-testing", TestID: "WSTG-APIT-01", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "api", "-silent"}, Guarded: true}, // API recon templates

	// --- Additional coverage (deepening automation) ---
	// Each new row below points at a test id that exists in the checklist and a
	// free tool that meaningfully exercises it; non-automatable tests stay manual.
	{Slug: "information-gathering", TestID: "WSTG-INFO-01", ToolKey: "gau", Args: []string{"{host}"}, Guarded: true},                                                                   // archived URLs (OSINT)
	{Slug: "information-gathering", TestID: "WSTG-INFO-08", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "tech", "-silent"}, Guarded: true},                               // framework fingerprint
	{Slug: "information-gathering", TestID: "WSTG-INFO-09", ToolKey: "httpx", Args: []string{"-u", "{url}", "-silent", "-status-code", "-title", "-tech-detect"}, Guarded: true},       // app fingerprint
	{Slug: "config-management", TestID: "WSTG-CONF-03", ToolKey: "gobuster", Args: []string{"dir", "-u", "{url}", "-w", "common.txt", "-x", "bak,old,zip,txt,~", "-q"}, Guarded: true}, // sensitive extensions
	{Slug: "config-management", TestID: "WSTG-CONF-05", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "exposure", "-silent"}, Guarded: true},                               // admin interfaces
	{Slug: "config-management", TestID: "WSTG-CONF-10", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "takeover", "-silent"}, Guarded: true},                               // subdomain takeover
	{Slug: "config-management", TestID: "WSTG-CONF-14", ToolKey: "curl", Args: []string{"-sS", "-I", "{url}"}, Guarded: true},                                                          // security headers
	{Slug: "authorization", TestID: "WSTG-ATHZ-02", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "auth-bypass", "-silent"}, Guarded: true},                                // bypass auth schema
	{Slug: "session-management", TestID: "WSTG-SESS-01", ToolKey: "curl", Args: []string{"-sS", "-I", "{url}"}, Guarded: true},                                                         // session schema headers
	{Slug: "weak-cryptography", TestID: "WSTG-CRYP-03", ToolKey: "testssl", Args: []string{"--quiet", "--warnings", "off", "{url}"}, Guarded: true},                                    // unencrypted channels
	{Slug: "client-side", TestID: "WSTG-CLNT-03", ToolKey: "dalfox", Args: []string{"url", "{url}"}, Guarded: true},                                                                    // HTML injection
	{Slug: "api-testing", TestID: "WSTG-APIT-99", ToolKey: "nuclei", Args: []string{"-u", "{url}", "-tags", "graphql", "-silent"}, Guarded: true},                                      // GraphQL
}

// Check is a runnable capability: one checklist test, one free tool, one of a
// fixed set of arguments (no shell interpolation).
type Check struct { // one runnable row
	Slug    string   `json:"slug"`           // owning category
	TestID  string   `json:"test_id"`        // checklist test it exercises
	ToolKey string   `json:"tool"`           // catalog key
	Args    []string `json:"args"`           // argument template ({url},{host},{target})
	Guarded bool     `json:"guarded"`        // true when it sends traffic to the target
	Note    string   `json:"note,omitempty"` // optional caveat
}

// Tools returns the whole tool catalog sorted by key.
func Tools() []Tool { // used by `web tools`
	keys := make([]string, 0, len(toolCatalog)) // collect the keys
	for k := range toolCatalog {                // walk the map
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order
	out := make([]Tool, 0, len(keys))
	for _, k := range keys { // materialize the tools
		out = append(out, toolCatalog[k])
	}
	return out
}

// ToolByKey looks up a catalog tool by its key.
func ToolByKey(key string) (Tool, bool) { // used by checks and the runner
	t, ok := toolCatalog[key]
	return t, ok
}

// ToolsFor returns the free tools suggested for a category slug, in order.
func ToolsFor(slug string) []Tool { // used by `web tools <category>`
	keys := categoryTools[slug] // the curated key list
	out := make([]Tool, 0, len(keys))
	for _, k := range keys { // resolve each key
		if t, ok := toolCatalog[k]; ok {
			out = append(out, t)
		}
	}
	return out
}

// ChecksFor returns the runnable checks for a category slug.
func ChecksFor(slug string) []Check { // used by `web plan` and `web run`
	var out []Check // accumulate matches
	for _, c := range checks {
		if c.Slug == slug {
			out = append(out, c)
		}
	}
	return out
}

// CheckByTest returns the checks that target a specific test id.
func CheckByTest(id string) []Check { // used by `web run -test`
	var out []Check
	for _, c := range checks { // linear scan (small)
		if strings.EqualFold(c.TestID, strings.TrimSpace(id)) {
			out = append(out, c)
		}
	}
	return out
}

// RenderArgs substitutes target placeholders in an argument template. When a
// value is empty the placeholder is left in place, which is how plans show the
// template before a target is chosen.
func RenderArgs(args []string, url, host, target string) []string { // shared by plan and runner
	out := make([]string, len(args)) // one output slice
	for i, a := range args {         // copy + substitute each arg
		if url != "" {
			a = strings.ReplaceAll(a, "{url}", url)
		}
		if host != "" {
			a = strings.ReplaceAll(a, "{host}", host)
		}
		if target != "" {
			a = strings.ReplaceAll(a, "{target}", target)
		}
		out[i] = a
	}
	return out
}

// CommandLine renders a full command for a tool + args template.
func CommandLine(t Tool, args []string, scheme, target string) string { // used by plans and dry-runs
	url, host := "", "" // placeholders stay literal until a target exists
	if target != "" {   // when a target is known...
		url = scheme + "://" + target // ...build its URL
		host = target                 // ...and host
	}
	parts := append([]string{t.Bin}, RenderArgs(args, url, host, target)...) // command = bin + args
	return strings.Join(parts, " ")                                          // readable one-liner
}

// PlanStep is one line of a category plan: a checklist test and how to exercise it.
type PlanStep struct { // used by `web plan`
	TestID    string `json:"test_id"`           // WSTG-XXXX-NN
	Name      string `json:"name"`              // test name from the checklist
	Automated bool   `json:"automated"`         // true when a check exists
	Tool      string `json:"tool,omitempty"`    // recommended tool (automated)
	Command   string `json:"command,omitempty"` // rendered command (automated)
	Manual    string `json:"manual,omitempty"`  // guidance (manual)
}

// Plan joins a checklist with the capability catalog: every test is listed, with
// either a runnable command (automated) or manual guidance.
func Plan(c Checklist, scheme, target string) []PlanStep { // the "capabilities" view
	byTest := map[string][]Check{} // index checks by test id
	for _, ck := range ChecksFor(c.Slug) {
		byTest[ck.TestID] = append(byTest[ck.TestID], ck)
	}
	steps := make([]PlanStep, 0, len(c.Tests)) // one step per test
	for _, t := range c.Tests {                // preserve checklist order
		if ups := byTest[t.ID]; len(ups) > 0 { // a runnable capability exists...
			for _, ck := range ups { // ...possibly more than one tool
				tool, _ := ToolByKey(ck.ToolKey) // resolve the tool
				steps = append(steps, PlanStep{  // add an automated step
					TestID:    t.ID,
					Name:      t.Name,
					Automated: true,
					Tool:      tool.Name,
					Command:   CommandLine(tool, ck.Args, scheme, target),
				})
			}
			continue // done with this test
		}
		steps = append(steps, PlanStep{ // otherwise, manual guidance
			TestID: t.ID,
			Name:   t.Name,
			Manual: manualHint(c.Slug),
		})
	}
	return steps
}

// manualHint returns the per-category guidance, with a safe default.
func manualHint(slug string) string { // used by Plan
	if h, ok := manualHints[slug]; ok {
		return h
	}
	return "Review this test manually (see the OWASP WSTG)." // fallback
}
