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
	"net"     // SplitHostPort for stripping ports from URL-like inputs
	"strings" // trimming, lowercasing, and suffix checks
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
