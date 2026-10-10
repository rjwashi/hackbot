// Package scan runs nmap against explicitly allowlisted targets.
//
// Safety model: scanning is DISABLED by default and, when enabled, a target is
// only scanned if it falls within the configured allowlist. This prevents
// hackbot from being pointed at arbitrary networks by mistake or misuse.
package scan // importable as "scan"

import ( // this file's imports
	"context" // lets callers cancel a long-running scan
	"errors"  // errors.New for the sentinel ErrDisabled
	"fmt"     // Errorf for wrapping/contextual errors
	"net"     // net.ParseIP/ParseCIDR and IPNet for the allowlist logic
	"os/exec" // exec.CommandContext to actually invoke nmap
	"strings" // TrimSpace/Join for arg and error formatting

	"github.com/rjwashi/hackbot/internal/nmap" // reuse the XML parser/model in package nmap
)

// ErrDisabled is returned when scanning has not been explicitly enabled.
var ErrDisabled = errors.New("scanning is disabled (set enable_scan=true or HACKBOT_ENABLE_SCAN=1, and provide allowed_targets or allowed_domains)") // sentinel for errors.Is

// CommandRunner abstracts process execution so scans can be tested without nmap.
type CommandRunner interface { // small seam that lets tests inject a fake runner
	Run(ctx context.Context, name string, args ...string) ([]byte, error) // returns combined output and error
}

// ExecRunner runs real processes.
type ExecRunner struct{} // stateless; satisfies CommandRunner

// Run executes name with args and returns combined output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) { // real implementation
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // CombinedOutput merges stdout+stderr for diagnostics
}

// Options configures a Scanner.
type Options struct { // all inputs the scanner needs, injected for testability
	NmapPath       string   // path to the nmap binary; defaults to "nmap"
	ExtraArgs      []string // extra nmap flags inserted before the target
	AllowedTargets []string // IPs/CIDRs that may be scanned (the allowlist)
	Enable         bool     // master switch; must be true to scan at all
	Scripts        []string // NSE scripts to run (empty = none); see ReconScripts for a safe set
	ScriptArgs     string   // value for nmap's --script-args (e.g. "http.useragent=hackbot")
}

// ReconScripts is a conservative default set of NSE scripts for reconnaissance.
//
// They come from nmap's safe/version-style categories and are meant to gather
// banners, page titles, HTTP headers, and TLS/SSH key details without disrupting
// the target. Scanning still requires Enable=true and an in-scope target; this
// list only decides which scripts run once a scan is permitted.
var ReconScripts = []string{ // exposed so configs/CLIs can reuse the same profile
	"banner",       // service banners from open ports
	"http-title",   // page <title> for web services
	"http-headers", // HTTP response headers (server/software hints)
	"ssh-hostkey",  // SSH host key fingerprints (no login attempted)
	"ssl-cert",     // TLS certificate details (subject/issuer/validity)
}

// Scanner runs guarded nmap scans.
type Scanner struct { // holds options plus the runner seam
	opts   Options       // copied config
	runner CommandRunner // injected process runner (real or fake)
}

// New returns a Scanner. If runner is nil, a real ExecRunner is used.
func New(opts Options, runner CommandRunner) *Scanner { // constructor
	if opts.NmapPath == "" { // allow callers to omit the path...
		opts.NmapPath = "nmap" // ...and get the default binary name
	}
	if runner == nil { // allow callers to omit the runner...
		runner = ExecRunner{} // ...and get the real one
	}
	return &Scanner{opts: opts, runner: runner} // return the assembled scanner
}

// Scan runs nmap against target and parses its XML output.
//
// It fails unless scanning is enabled and target is in scope.
func (s *Scanner) Scan(ctx context.Context, target string) (*nmap.Scan, error) { // guarded entry point
	if !s.opts.Enable { // hard gate #1: the master switch...
		return nil, ErrDisabled // ...refuse before doing anything
	}
	if !InScope(target, s.opts.AllowedTargets) { // hard gate #2: the target must be in the allowlist
		return nil, fmt.Errorf("target %q is not in the configured allowlist; refusing to scan", target) // refuse
	}

	args := []string{"-sV", "-oX", "-"} // baseline nmap args: version detection + XML to stdout
	if len(s.opts.Scripts) > 0 {        // only add --script when the caller opted into NSE scripts...
		args = append(args, "--script", strings.Join(s.opts.Scripts, ",")) // ...passing a comma-joined list
	}
	if s.opts.ScriptArgs != "" { // only add --script-args when explicitly provided...
		args = append(args, "--script-args", s.opts.ScriptArgs) // ...so values like "http.useragent=hackbot" reach scripts
	}
	args = append(args, s.opts.ExtraArgs...) // insert any caller-provided extra flags next
	args = append(args, target)              // target MUST be last so nmap treats it as the destination

	out, err := s.runner.Run(ctx, s.opts.NmapPath, args...) // run nmap and capture combined output
	if err != nil {                                         // if nmap failed...
		return nil, fmt.Errorf("run nmap (%s %s): %w: %s", // ...wrap with the command line and stderr tail
			s.opts.NmapPath, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nmap.Parse(strings.NewReader(string(out))) // parse the XML nmap wrote to stdout
}

// InScope reports whether target is covered by at least one allowlist entry.
//
// A target must be a literal IP or CIDR (hostnames are refused because they
// cannot be verified against a static allowlist). An IP matches if it equals an
// allowed IP or falls inside an allowed CIDR. A CIDR target matches only if it
// is entirely contained within a single allowed CIDR (so you can't widen scope).
func InScope(target string, allowed []string) bool { // pure function; easy to unit test
	target = strings.TrimSpace(target) // normalize whitespace so " 10.0.0.1 " still matches
	if target == "" {                  // empty target is never in scope
		return false
	}

	if tIP, tNet, err := net.ParseCIDR(target); err == nil { // first try to interpret target as a CIDR
		_ = tIP                     // the network address alone is enough; we only use tNet below
		for _, a := range allowed { // compare against every allowed entry
			a = strings.TrimSpace(a) // normalize the entry
			if a == "" {             // ignore blanks (e.g. trailing commas)
				continue
			}
			if _, aNet, err := net.ParseCIDR(a); err == nil { // only CIDR entries can contain a CIDR target
				if subnetContains(aNet, tNet) { // allowed only if the target subnet fits inside the allowed subnet
					return true // in scope
				}
			}
		}
		return false // a CIDR target that isn't contained anywhere is refused
	}

	ip := net.ParseIP(target) // otherwise try to parse the target as a single IP
	if ip == nil {            // if it's not an IP or CIDR (e.g. a hostname), we cannot verify it
		return false // refuse to guess
	}
	for _, a := range allowed { // compare the IP against every allowed entry
		a = strings.TrimSpace(a) // normalize
		if a == "" {             // skip blanks
			continue
		}
		if aIP := net.ParseIP(a); aIP != nil { // if the entry is a literal IP...
			if aIP.Equal(ip) { // ...an exact match includes it
				return true
			}
			continue // a literal IP entry can't contain other IPs
		}
		if _, aNet, err := net.ParseCIDR(a); err == nil { // if the entry is a CIDR...
			if aNet.Contains(ip) { // ...the IP is in scope when inside it
				return true
			}
		}
	}
	return false // nothing matched
}

// subnetContains reports whether sub is equal to or contained within parent.
func subnetContains(parent, sub *net.IPNet) bool { // used to prevent scope widening
	if parent == nil || sub == nil { // defensive nil check
		return false
	}
	pOnes, pBits := parent.Mask.Size()   // number of network bits + total bits for parent
	sOnes, sBits := sub.Mask.Size()      // same for sub
	if pBits != sBits || pOnes > sOnes { // must be same address family, and parent must be no narrower than sub
		return false // otherwise sub could be wider than parent -> refuse
	}
	return parent.Contains(sub.IP) // finally, verify the subnet's base address falls inside the parent
}
