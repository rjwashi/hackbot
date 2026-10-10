package scan // same package as scope.go

import "testing" // the testing framework

// TestNormalizeDomain verifies the tolerance rules for messy operator input.
func TestNormalizeDomain(t *testing.T) { // URL/host/domain -> bare domain
	cases := map[string]string{ // input -> expected
		"example.com":                      "example.com",     // already bare
		"  Example.COM  ":                  "example.com",     // trimmed + lowercased
		"https://sub.example.com/path?x=1": "sub.example.com", // scheme + path stripped
		"example.com:8443":                 "example.com",     // port stripped
		"*.example.com":                    "example.com",     // wildcard entry normalized
		"example.com.":                     "example.com",     // trailing dot stripped
		"":                                 "",                // empty stays empty
	}
	for in, want := range cases { // each case...
		if got := NormalizeDomain(in); got != want { // ...must normalize correctly
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDomainInScope verifies the exact/subdomain matching and the label boundary.
func TestDomainInScope(t *testing.T) { // allowlist semantics
	allowed := []string{"example.com", "sub.test.org"} // two allowed domains

	inScope := []string{ // these must all match
		"example.com",               // exact
		"www.example.com",           // subdomain
		"a.b.example.com",           // deep subdomain
		"https://WWW.Example.com/x", // URL form, mixed case
		"sub.test.org",              // exact second entry
		"x.sub.test.org",            // subdomain of second entry
	}
	for _, d := range inScope { // every candidate...
		if !DomainInScope(d, allowed) { // ...must be in scope
			t.Errorf("DomainInScope(%q) = false, want true", d)
		}
	}

	outScope := []string{ // these must all be refused
		"notexample.com",   // partial-label trap (must NOT match example.com)
		"example.com.evil", // suffix on the wrong side
		"example.org",      // different TLD
		"10.0.0.1",         // literal IP belongs to InScope
		"",                 // empty
	}
	for _, d := range outScope { // every candidate...
		if DomainInScope(d, allowed) { // ...must be refused
			t.Errorf("DomainInScope(%q) = true, want false", d)
		}
	}

	if DomainInScope("example.com", nil) { // empty allowlist denies all (safe default)
		t.Error("DomainInScope with empty allowlist should be false")
	}
}

// TestTargetInScope verifies the combined IP-or-domain gate.
func TestTargetInScope(t *testing.T) { // used by the recon/discovery agents
	targets := []string{"10.0.0.0/24"} // IP allowlist
	domains := []string{"example.com"} // domain allowlist

	if !TargetInScope("10.0.0.5", targets, domains) { // IP inside the CIDR
		t.Error("IP 10.0.0.5 should be in scope")
	}
	if TargetInScope("192.168.1.1", targets, domains) { // IP outside the CIDR
		t.Error("IP 192.168.1.1 should be out of scope")
	}
	if !TargetInScope("app.example.com", targets, domains) { // domain via domain list
		t.Error("app.example.com should be in scope")
	}
	if TargetInScope("evil.test", targets, domains) { // unknown domain
		t.Error("evil.test should be out of scope")
	}
	if TargetInScope("", targets, domains) { // empty target
		t.Error("empty target should be out of scope")
	}
	if TargetInScope("10.0.0.5", nil, nil) { // no allowlists at all
		t.Error("empty allowlists should deny everything")
	}
}
