// This file defines the recon/OSINT catalog: the free tools and runnable tasks
// behind the `recon` command (agents recon-*).
//
// Scope note: most recon tasks take a *domain* ("example.com"), which is why the
// engine grew the domain allowlist in internal/scan/scope.go. Port/service tasks
// also accept a literal IP. Every task is marked Guarded because all of them send
// traffic to (or resolve) the target; the runner still enforces the allowlist.
package ops // same package as ops.go

// ReconCatalog returns the recon/OSINT capability catalog.
func ReconCatalog() *Catalog { // used by `hackbot recon`
	// Tools: only free/open-source project-discovery utilities.
	tools := map[string]Tool{
		"subfinder": {
			Key: "subfinder", Name: "Subfinder", Bin: "subfinder", Kind: "recon",
			URL: "https://github.com/projectdiscovery/subfinder", License: "MIT",
			Install: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
			Notes:   "Passive subdomain enumeration from public sources.",
		},
		"amass": {
			Key: "amass", Name: "OWASP Amass", Bin: "amass", Kind: "recon",
			URL: "https://github.com/owasp-amass/amass", License: "Apache-2.0",
			Install: "go install github.com/owasp-amass/amass/v4/...@latest",
			Notes:   "Deeper (slower) attack-surface mapping and enumeration.",
		},
		"dnsx": {
			Key: "dnsx", Name: "dnsx", Bin: "dnsx", Kind: "resolver",
			URL: "https://github.com/projectdiscovery/dnsx", License: "MIT",
			Install: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
			Notes:   "Bulk DNS resolution and record queries.",
		},
		"dig": {
			Key: "dig", Name: "dig (BIND)", Bin: "dig", Kind: "resolver",
			URL: "https://www.isc.org/bind/", License: "MPL-2.0",
			Install: "apt install dnsutils / brew install bind",
			Notes:   "Classic DNS query tool for individual records.",
		},
		"httpx": {
			Key: "httpx", Name: "httpx", Bin: "httpx", Kind: "probe",
			URL: "https://github.com/projectdiscovery/httpx", License: "MIT",
			Install: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
			Notes:   "Fast HTTP probing: status, title, tech, redirects.",
		},
		"naabu": {
			Key: "naabu", Name: "naabu", Bin: "naabu", Kind: "scanner",
			URL: "https://github.com/projectdiscovery/naabu", License: "MIT",
			Install: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
			Notes:   "Fast SYN/CONNECT port scanner.",
		},
		"nmap": {
			Key: "nmap", Name: "nmap", Bin: "nmap", Kind: "scanner",
			URL: "https://nmap.org/", License: "NPSL/GPL-2.0",
			Install: "apt install nmap / brew install nmap",
			Notes:   "Service/version inventory for discovered hosts.",
		},
		"whois": {
			Key: "whois", Name: "whois", Bin: "whois", Kind: "cli",
			URL: "https://github.com/rfc1036/whois", License: "GPL-2.0",
			Install: "apt install whois / brew install whois",
			Notes:   "Registration/ownership data (OSINT).",
		},
		"gau": {
			Key: "gau", Name: "gau (GetAllUrls)", Bin: "gau", Kind: "recon",
			URL: "https://github.com/lc/gau", License: "MIT",
			Install: "go install github.com/lc/gau/v2/cmd/gau@latest",
			Notes:   "Fetch known URLs from public archives (OSINT).",
		},
		"katana": {
			Key: "katana", Name: "katana", Bin: "katana", Kind: "crawler",
			URL: "https://github.com/projectdiscovery/katana", License: "MIT",
			Install: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
			Notes:   "Crawl the app surface: every route is a potential logic branch.",
		},
		"waybackurls": {
			Key: "waybackurls", Name: "waybackurls", Bin: "waybackurls", Kind: "recon",
			URL: "https://github.com/tomnomnom/waybackurls", License: "MIT",
			Install: "go install github.com/tomnomnom/waybackurls@latest",
			Notes:   "Resurrect archived endpoints; historical routes often outlive their guards.",
		},
	}

	// Groups let `recon tools <group>` list alternates for a capability.
	groups := map[string][]string{
		"subdomains": {"subfinder", "amass"}, // fast vs deep enumeration
		"dns":        {"dnsx", "dig"},        // bulk vs single-record
		"ports":      {"naabu", "nmap"},      // fast port scan vs service version
		"http":       {"httpx"},              // probing
		"whois":      {"whois"},              // ownership
		"urls":       {"gau", "waybackurls"}, // archived URLs (two archive sources)
		"crawl":      {"katana"},             // app crawling
	}

	// Tasks are the runnable capabilities shown by `recon list` / `recon plan`.
	tasks := []Task{
		{
			Key: "subdomains", Name: "Subdomain enumeration", Group: "subdomains",
			ToolKey: "subfinder", Args: []string{"-d", "{host}", "-silent"}, Guarded: true,
			Note: "Passive, source-driven enumeration of the domain's subdomains.",
		},
		{
			Key: "dns", Name: "DNS resolution", Group: "dns",
			ToolKey: "dnsx", Args: []string{"-d", "{host}", "-a", "-resp", "-silent"}, Guarded: true,
			Note: "Resolve A records (and confirm which names are live).",
		},
		{
			Key: "ports", Name: "Port scan (common)", Group: "ports",
			ToolKey: "naabu", Args: []string{"-host", "{host}", "-top-ports", "100", "-silent"}, Guarded: true,
			Note: "Quick scan of the 100 most common TCP ports.",
		},
		{
			Key: "services", Name: "Service/version scan", Group: "ports",
			ToolKey: "nmap", Args: []string{"-sV", "-Pn", "{host}"}, Guarded: true,
			Note: "Version detection for open services (slower, more detail).",
		},
		{
			Key: "http", Name: "HTTP probe", Group: "http",
			ToolKey: "httpx", Args: []string{"-u", "{url}", "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"}, Guarded: true,
			Note: "Status, title, and detected technologies for one URL.",
		},
		{
			Key: "whois", Name: "WHOIS lookup", Group: "whois",
			ToolKey: "whois", Args: []string{"{host}"}, Guarded: true,
			Note: "Registration and ownership data.",
		},
		{
			Key: "urls", Name: "Archived URLs (OSINT)", Group: "urls",
			ToolKey: "gau", Args: []string{"{host}"}, Guarded: true,
			Note: "Historical URLs from public archives; useful for finding endpoints.",
		},
		{
			Key: "crawl", Name: "Site crawl", Group: "crawl",
			ToolKey: "katana", Args: []string{"-u", "{url}", "-f", "qurl", "-silent"}, Guarded: true,
			Note: "Crawl the app to map every endpoint and execution path for later probing.",
		},
		{
			Key: "endpoints", Name: "Archived endpoints (Wayback)", Group: "urls",
			ToolKey: "waybackurls", Args: []string{"{host}"}, Guarded: true,
			Note: "History of paths from the Wayback Machine; dead/forgotten routes often outlive their guards.",
		},
	}

	return NewCatalog( // assemble
		"recon",
		KindHost, // host/domain targets; gated by allowed_targets/allowed_domains
		"OSINT reconnaissance: subdomains, DNS, ports, services, HTTP, WHOIS, archived URLs, crawls",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
		tools, groups, tasks,
	).WithChains( // multi-step pipelines
		Chain{ // domain footprint: enumerate subdomains, then probe them for live HTTP
			Key:  "footprint",
			Name: "Domain footprint (subdomains -> live HTTP)",
			Note: "subfinder enumerates subdomains; piped straight into httpx to find which are live web services. One allowlisted seed domain, one command.",
			Steps: []ChainStep{
				{TaskKey: "subdomains"}, // subfinder -d {host} -silent
				{
					TaskKey:      "http",                                                                             // httpx, but reading the list from stdin
					FeedPrevious: true,                                                                               // pipe subfinder's stdout in
					Args:         []string{"-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"}, // no -u: httpx reads stdin
				},
			},
		},
	)
}
