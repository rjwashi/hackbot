// This file defines the dependency / SBOM catalog behind the `deps` command
// (agents deps-*).
//
// WHY this family exists: most real-world breaches exploit a known-vulnerable
// dependency, and generating a software bill of materials plus a vulnerability
// report from a local checkout is fully covered by free tools. Like secrets, this
// is a KindPath catalog because the target is a directory, so it is gated by
// enabled scanning plus the `allowed_paths` allowlist and never by a network one.
//
// Safety note: every task is Guarded so it must pass the enable gate. Two of the
// tools (trivy, grype, osv-scanner) download vulnerability databases, so "local"
// here means "reads local files" rather than "makes no network requests at all".
package ops // same package as ops.go

// DepsCatalog returns the dependency / SBOM capability catalog.
func DepsCatalog() *Catalog { // used by `hackbot deps`
	// Tools: free/open-source SCA (software composition analysis) and SBOM tools.
	tools := map[string]Tool{
		"trivy": {
			Key: "trivy", Name: "Trivy", Bin: "trivy", Kind: "sca",
			URL: "https://github.com/aquasecurity/trivy", License: "Apache-2.0",
			Install: "go install github.com/aquasecurity/trivy/cmd/trivy@latest",
			Notes:   "All-in-one scanner for dependencies, OS packages, and IaC.",
		},
		"grype": {
			Key: "grype", Name: "Grype", Bin: "grype", Kind: "sca",
			URL: "https://github.com/anchore/grype", License: "Apache-2.0",
			Install: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
			Notes:   "Vulnerability matcher for container images and directories.",
		},
		"osv-scanner": {
			Key: "osv-scanner", Name: "OSV-Scanner", Bin: "osv-scanner", Kind: "sca",
			URL: "https://github.com/google/osv-scanner", License: "Apache-2.0",
			Install: "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
			Notes:   "Queries the Google OSV database across many lockfile formats.",
		},
		"syft": {
			Key: "syft", Name: "Syft", Bin: "syft", Kind: "sbom",
			URL: "https://github.com/anchore/syft", License: "Apache-2.0",
			Install: "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
			Notes:   "Generates SBOMs in CycloneDX, SPDX, and other formats.",
		},
	}

	// Groups let `deps tools <group>` list the alternates for one capability.
	groups := map[string][]string{
		"vulns": {"trivy", "grype", "osv-scanner"}, // different databases, overlapping coverage
		"sbom":  {"syft"},                          // bill-of-materials generation
	}

	// Tasks are the runnable capabilities. All take a local {path}.
	tasks := []Task{
		{
			Key: "vulns", Name: "Filesystem vulnerability scan", Group: "vulns",
			ToolKey: "trivy", Args: []string{"fs", "--scanners", "vuln", "--quiet", "{path}"}, Guarded: true,
			Note: "Scan dependencies and OS packages under the path for known CVEs.",
		},
		{
			Key: "sbom", Name: "SBOM (CycloneDX)", Group: "sbom",
			ToolKey: "syft", Args: []string{"{path}", "-o", "cyclonedx-json"}, Guarded: true,
			Note: "Produce a CycloneDX software bill of materials for the directory.",
		},
		{
			Key: "grype", Name: "Grype vulnerability scan", Group: "vulns",
			ToolKey: "grype", Args: []string{"dir:{path}"}, Guarded: true,
			Note: "Match the directory's packages and lockfiles against Grype's database.",
		},
		{
			Key: "osv", Name: "OSV dependency scan", Group: "vulns",
			ToolKey: "osv-scanner", Args: []string{"--recursive", "{path}"}, Guarded: true,
			Note: "Query the OSV database for vulnerabilities in detected manifests.",
		},
	}

	return NewCatalog( // assemble
		"deps",
		KindPath, // local directory targets; gated by allowed_paths
		"Dependency risk and SBOM generation for a local project using free scanners",
		"https://owasp.org/www-project-vulnerable-dependency-check/",
		tools, groups, tasks,
	)
}
