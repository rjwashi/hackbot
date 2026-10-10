// This file defines the secrets-scanning catalog behind the `secrets` command
// (agents secrets-*).
//
// WHY this family exists: leaked credentials in a checkout or a repository's
// history are one of the highest-impact, easiest-to-find classes of finding, and
// the tools to detect them are entirely free and local. This family reads LOCAL
// files, so it is a KindPath catalog: the gate is enabled scanning plus the
// `allowed_paths` allowlist rather than any network allowlist, which would make
// no sense for a directory target.
//
// Safety note: every task is Guarded, meaning it must pass the enable gate before
// it runs. Nothing here leaves the machine, but "reads files" still deserves the
// same explicit opt-in as "sends packets" so hackbot never silently touches a
// directory the operator did not point it at.
package ops // same package as ops.go

// SecretsCatalog returns the secret-detection capability catalog.
func SecretsCatalog() *Catalog { // used by `hackbot secrets`
	// Tools: free/open-source secret scanners that install as a single binary.
	tools := map[string]Tool{
		"gitleaks": {
			Key: "gitleaks", Name: "Gitleaks", Bin: "gitleaks", Kind: "secret-scanner",
			URL: "https://github.com/gitleaks/gitleaks", License: "MIT",
			Install: "go install github.com/gitleaks/gitleaks/v8@latest",
			Notes:   "Fast regex + entropy secret scan of a directory or git history.",
		},
		"trufflehog": {
			Key: "trufflehog", Name: "TruffleHog", Bin: "trufflehog", Kind: "secret-scanner",
			URL: "https://github.com/trufflesecurity/trufflehog", License: "AGPL-3.0",
			Install: "go install github.com/trufflesecurity/trufflehog/v3@latest",
			Notes:   "Scans files with optional live verification of found credentials.",
		},
		"detect-secrets": {
			Key: "detect-secrets", Name: "detect-secrets", Bin: "detect-secrets", Kind: "secret-scanner",
			URL: "https://github.com/Yelp/detect-secrets", License: "Apache-2.0",
			Install: "pipx install detect-secrets",
			Notes:   "Yelp's entropy and pattern baseline scanner for unknown secret formats.",
		},
	}

	// Groups let `secrets tools <group>` list the alternates for one capability.
	groups := map[string][]string{
		"scan":    {"gitleaks"},       // broad, fast scan (working tree or history)
		"verify":  {"trufflehog"},     // actively validate whether a secret is live
		"entropy": {"detect-secrets"}, // catch formats no signature knows about
	}

	// Tasks are the runnable capabilities. All take a local {path} and read only.
	tasks := []Task{
		{
			Key: "scan", Name: "Working-tree secret scan", Group: "scan",
			ToolKey: "gitleaks", Args: []string{"dir", "--redact", "-v", "{path}"}, Guarded: true,
			Note: "Scan the directory as it is now; does not look at git history.",
		},
		{
			Key: "history", Name: "Git history secret scan", Group: "scan",
			ToolKey: "gitleaks", Args: []string{"git", "--redact", "{path}"}, Guarded: true,
			Note: "Scan every commit for secrets that were committed and later removed.",
		},
		{
			Key: "verify", Name: "Verified secret scan", Group: "verify",
			ToolKey: "trufflehog", Args: []string{"filesystem", "{path}", "--only-verified", "--no-update"}, Guarded: true,
			Note: "Report only credentials trufflehog could confirm are still live.",
		},
		{
			Key: "entropy", Name: "Entropy + pattern baseline", Group: "entropy",
			ToolKey: "detect-secrets", Args: []string{"scan", "{path}"}, Guarded: true,
			Note: "High-recall baseline that flags suspicious entropy, not just known patterns.",
		},
	}

	return NewCatalog( // assemble
		"secrets",
		KindPath, // local directory targets; gated by allowed_paths
		"Secret detection in a checkout or its git history using free local scanners",
		"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
		tools, groups, tasks,
	)
}
