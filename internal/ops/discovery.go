// This file defines the content-discovery catalog behind the `discover` command
// (agents discover-*).
//
// These tasks brute-force paths, files, extensions, virtual hosts, and parameters
// against a web target. They are noisy by nature, so they are Guarded and rely on
// the same enable + allowlist gates. Wordlist selection flows through
// Options.Wordlist (config `wordlist` or the -wordlist flag) and defaults to the
// free SecLists common list so a dry-run is still meaningful.
package ops // same package as ops.go

// DiscoveryCatalog returns the content-discovery capability catalog.
func DiscoveryCatalog() *Catalog { // used by `hackbot discover`
	// Tools: free/open-source content-discovery fuzzers.
	tools := map[string]Tool{
		"ffuf": {
			Key: "ffuf", Name: "ffuf", Bin: "ffuf", Kind: "fuzzer",
			URL: "https://github.com/ffuf/ffuf", License: "MIT",
			Install: "go install github.com/ffuf/ffuf/v2@latest",
			Notes:   "Fast, flexible web fuzzer (paths, vhosts, parameters).",
		},
		"gobuster": {
			Key: "gobuster", Name: "gobuster", Bin: "gobuster", Kind: "fuzzer",
			URL: "https://github.com/OJ/gobuster", License: "Apache-2.0",
			Install: "go install github.com/OJ/gobuster/v3@latest",
			Notes:   "Directory/file and vhost brute forcing.",
		},
		"feroxbuster": {
			Key: "feroxbuster", Name: "feroxbuster", Bin: "feroxbuster", Kind: "fuzzer",
			URL: "https://github.com/epi052/feroxbuster", License: "MIT",
			Install: "cargo install feroxbuster  # or download a release",
			Notes:   "Recursive content discovery (Rust, fast).",
		},
	}

	// Groups let `discover tools <group>` list alternates per capability.
	groups := map[string][]string{
		"dirs":       {"ffuf", "gobuster", "feroxbuster"},
		"files":      {"gobuster", "feroxbuster"},
		"extensions": {"gobuster"},
		"vhosts":     {"ffuf", "gobuster"},
		"params":     {"ffuf"},
	}

	// Tasks are the runnable capabilities. The `-s`/`-q` flags keep output tidy;
	// match codes are limited to "exists but not necessarily public" so results
	// are actionable rather than a wall of 404s.
	tasks := []Task{
		{
			Key: "dirs", Name: "Directory discovery", Group: "dirs",
			ToolKey: "ffuf", Args: []string{"-u", "{url}/FUZZ", "-w", "{wordlist}", "-mc", "200,204,301,302,307,401,403", "-t", "40", "-s"}, Guarded: true,
			Note: "Enumerate directories under the target.",
		},
		{
			Key: "files", Name: "File discovery", Group: "files",
			ToolKey: "gobuster", Args: []string{"dir", "-u", "{url}", "-w", "{wordlist}", "-q", "-t", "40"}, Guarded: true,
			Note: "Enumerate files/directories (gobuster's classic mode).",
		},
		{
			Key: "extensions", Name: "Extension brute force", Group: "extensions",
			ToolKey: "gobuster", Args: []string{"dir", "-u", "{url}", "-w", "{wordlist}", "-x", "php,asp,aspx,jsp,html,js,txt,bak,old,zip", "-q"}, Guarded: true,
			Note: "Look for the same names with common backup/script extensions.",
		},
		{
			Key: "vhosts", Name: "Virtual host discovery", Group: "vhosts",
			ToolKey: "ffuf", Args: []string{"-u", "{url}", "-H", "Host: FUZZ.{host}", "-w", "{wordlist}", "-s"}, Guarded: true,
			Note: "Fuzz the Host header to find vhosts served on the same IP.",
		},
		{
			Key: "params", Name: "Parameter discovery", Group: "params",
			ToolKey: "ffuf", Args: []string{"-u", "{url}?FUZZ=test", "-w", "{wordlist}", "-s"}, Guarded: true,
			Note: "Look for hidden/unlinked query parameters.",
		},
	}

	return NewCatalog( // assemble
		"discover",
		"Content discovery: directories, files, extensions, virtual hosts, parameters",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
		tools, groups, tasks,
	)
}
