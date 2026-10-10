// This file extends the scope model for the recon/OSINT and content-discovery
// agents.
//
// WHY this exists: InScope (scan.go) deliberately refuses hostnames because a
// name cannot be checked against a static IP allowlist. But reconnaissance tools
// like subfinder/amass operate on a *domain* ("example.com"), not an IP, so they
// need their own explicit allowlist. Rather than weaken InScope (which would
// silently change nmap's safety guarantees), we add a parallel, opt-in domain
// allowlist and a combined TargetInScope gate that the new agents use.
//
// Alternatives considered:
//   - Reuse allowed_targets for domains: rejected, because an operator who
//     allowed a CIDR did not consent to hitting every domain that resolves
//     inside it.
//   - Match domains with a bare strings.HasSuffix: rejected, because
//     "notexample.com" would then match "example.com" (a classic scope bug).
//     We require a label boundary ("."+allowed).
package scan // same safety home as InScope

import ( // imports for this file
	"net"           // SplitHostPort for stripping ports from URL-like inputs
	"os"            // os.Getwd for the "empty roots means the cwd" default
	"path/filepath" // filepath.Abs/Clean/Rel for robust path containment
	"strings"       // trimming, lowercasing, and suffix checks
)

// NormalizeDomain reduces a URL, host, or domain to a bare lowercase domain.
//
// It accepts inputs like "https://Sub.Example.com/path?x=1", "example.com:8443",
// "*.example.com.", and " example.com " and returns "sub.example.com" etc. This
// tolerance matters because CLI users paste URLs while the allowlist stores bare
// domains; normalizing both sides lets the comparison be exact and safe.
func NormalizeDomain(raw string) string { // exported so callers/tests share one rule
	s := strings.ToLower(strings.TrimSpace(raw)) // lowercase + trim
	if s == "" {                                 // empty stays empty
		return ""
	}
	if i := strings.Index(s, "//"); i >= 0 { // strip a scheme such as "https://"
		s = s[i+2:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 { // strip any path, query, or fragment
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil { // strip an explicit port when present
		s = host
	}
	s = strings.TrimPrefix(s, "*.") // allow wildcard entries like "*.example.com"
	s = strings.Trim(s, ".")        // drop leading/trailing dots ("example.com.")
	return s                        // normalized domain (may be empty)
}

// DomainInScope reports whether domain is covered by at least one allowed domain.
//
// Matching rules (all security-relevant):
//   - Exact match: "example.com" matches "example.com".
//   - Subdomain match: "a.example.com" matches an allowed "example.com" because it
//     ends with ".example.com" (the leading dot enforces a label boundary, so
//     "notexample.com" does NOT match "example.com").
//   - Literal IPs are refused here (they belong to InScope), so a stray IP can
//     never sneak in through the domain path.
//   - An empty/blank allowed list denies everything (safe default).
func DomainInScope(domain string, allowed []string) bool { // pure function; easy to test
	d := NormalizeDomain(domain) // normalize the candidate
	if d == "" {                 // empty candidate is never in scope
		return false
	}
	if net.ParseIP(d) != nil { // IPs are handled by InScope, not here
		return false
	}
	for _, a := range allowed { // compare against every allowed entry
		an := NormalizeDomain(a) // normalize the entry the same way
		if an == "" {            // skip blanks (e.g. trailing commas)
			continue
		}
		if d == an { // exact domain match
			return true
		}
		if strings.HasSuffix(d, "."+an) { // subdomain with a strict label boundary
			return true
		}
	}
	return false // nothing matched
}

// TargetInScope reports whether target is authorized by either allowlist.
//
// It is the single gate the recon and discovery agents consult. IP/CIDR targets
// are checked against allowedTargets via InScope; everything else is treated as a
// domain and checked against allowedDomains via DomainInScope. Trying IPs first
// keeps nmap's proven semantics intact and means a value like "10.0.0.1" can
// never be matched loosely as a domain.
func TargetInScope(target string, allowedTargets, allowedDomains []string) bool { // combined gate
	if InScope(target, allowedTargets) { // IP/CIDR path (also refuses hostnames)
		return true
	}
	return DomainInScope(target, allowedDomains) // domain path
}

// PathInScope reports whether path is contained within at least one allowed root.
//
// WHY a third allowlist: the secrets and dependency/SBOM agents read LOCAL files
// (a checkout, a container image's extracted rootfs, a build directory). A
// network allowlist cannot express "this directory is fair game", so we add an
// explicit path allowlist rather than silently letting a filesystem tool run
// wherever it is pointed. It is deliberately conservative: containment is on
// path *segments*, so /srv/app-evil does NOT match an allowed /srv/app.
//
// WHY default to the current working directory when roots is empty: the obvious
// and safe case is "scan the project I am standing in". Making the operator
// configure that would be friction with no safety gain (running from a directory
// is itself an explicit choice). An EMPTY entry still denies everything, matching
// the IP/domain rule that a blank allowlist means "nothing is authorized".
//
// Alternatives considered: os.Root / openat2 (Linux-only; we need cross-platform
// and we gate *before* exec, not at every file open); following symlinks and
// checking the target (TOCTOU-prone and would let a symlink escape the root).
// We compare cleaned absolute paths, and a target outside every root is refused.
func PathInScope(path string, roots []string) bool { // pure-ish; reads cwd only when roots is empty
	p := strings.TrimSpace(path) // normalize whitespace
	if p == "" {                 // empty path is never in scope
		return false
	}
	abs, err := filepath.Abs(p) // make the candidate absolute (relative to cwd)
	if err != nil {             // e.g. a path that cannot be resolved
		return false // refuse rather than guess
	}
	abs = filepath.Clean(abs) // collapse ".."/"." so the comparison is canonical

	effective := roots       // roots actually consulted
	if len(effective) == 0 { // no configured roots...
		wd, err := os.Getwd() // ...default to the current working directory
		if err != nil {       // if even that fails...
			return false // ...deny (safe default)
		}
		effective = []string{wd} // the cwd is the sole root
	}

	for _, r := range effective { // compare against every allowed root
		r = strings.TrimSpace(r) // normalize the entry
		if r == "" {             // skip blanks (e.g. trailing commas)
			continue
		}
		ra, err := filepath.Abs(r) // make the root absolute
		if err != nil {            // unresolvable root...
			continue // ...skip it
		}
		ra = filepath.Clean(ra) // canonicalize
		if abs == ra {          // the root itself is in scope
			return true
		}
		rel, err := filepath.Rel(ra, abs) // path of candidate relative to the root
		if err != nil {                   // different volume (Windows) or otherwise incomparable
			continue // skip
		}
		// In scope only when the relative path does not escape with "..". This is
		// the segment-boundary check: ".." alone or any "..<sep>..." prefix escapes.
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue // outside this root
		}
		return true // contained within this root
	}
	return false // no root contained the path
}
