// Package scan runs nmap against explicitly allowlisted targets.
//
// Safety model: scanning is DISABLED by default and, when enabled, a target is
// only scanned if it falls within the configured allowlist. This prevents
// hackbot from being pointed at arbitrary networks by mistake or misuse.
package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/rjwashi/hackbot/internal/nmap"
)

// ErrDisabled is returned when scanning has not been explicitly enabled.
var ErrDisabled = errors.New("scanning is disabled (set enable_scan=true or HACKBOT_ENABLE_SCAN=1, and provide allowed_targets)")

// CommandRunner abstracts process execution so scans can be tested without nmap.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real processes.
type ExecRunner struct{}

// Run executes name with args and returns combined output.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Options configures a Scanner.
type Options struct {
	NmapPath       string   // path to the nmap binary; default "nmap"
	ExtraArgs      []string // extra nmap flags, inserted before the target
	AllowedTargets []string // IPs or CIDRs that may be scanned
	Enable         bool     // must be true to scan at all
}

// Scanner runs guarded nmap scans.
type Scanner struct {
	opts   Options
	runner CommandRunner
}

// New returns a Scanner. If runner is nil, a real ExecRunner is used.
func New(opts Options, runner CommandRunner) *Scanner {
	if opts.NmapPath == "" {
		opts.NmapPath = "nmap"
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Scanner{opts: opts, runner: runner}
}

// Scan runs nmap against target and parses its XML output.
//
// It fails unless scanning is enabled and target is in scope.
func (s *Scanner) Scan(ctx context.Context, target string) (*nmap.Scan, error) {
	if !s.opts.Enable {
		return nil, ErrDisabled
	}
	if !InScope(target, s.opts.AllowedTargets) {
		return nil, fmt.Errorf("target %q is not in the configured allowlist; refusing to scan", target)
	}

	args := []string{"-sV", "-oX", "-"}
	args = append(args, s.opts.ExtraArgs...)
	args = append(args, target)

	out, err := s.runner.Run(ctx, s.opts.NmapPath, args...)
	if err != nil {
		return nil, fmt.Errorf("run nmap (%s %s): %w: %s",
			s.opts.NmapPath, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nmap.Parse(strings.NewReader(string(out)))
}

// InScope reports whether target is covered by at least one allowlist entry.
//
// A target must be a literal IP or CIDR (hostnames are refused because they
// cannot be verified against a static allowlist). An IP matches if it equals an
// allowed IP or falls inside an allowed CIDR. A CIDR target matches only if it
// is entirely contained within a single allowed CIDR (so you can't widen scope).
func InScope(target string, allowed []string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	if tIP, tNet, err := net.ParseCIDR(target); err == nil {
		_ = tIP
		for _, a := range allowed {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if _, aNet, err := net.ParseCIDR(a); err == nil {
				if subnetContains(aNet, tNet) {
					return true
				}
			}
		}
		return false
	}

	ip := net.ParseIP(target)
	if ip == nil {
		return false // not an IP/CIDR: refuse to guess
	}
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if aIP := net.ParseIP(a); aIP != nil {
			if aIP.Equal(ip) {
				return true
			}
			continue
		}
		if _, aNet, err := net.ParseCIDR(a); err == nil {
			if aNet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// subnetContains reports whether sub is equal to or contained within parent.
func subnetContains(parent, sub *net.IPNet) bool {
	if parent == nil || sub == nil {
		return false
	}
	pOnes, pBits := parent.Mask.Size()
	sOnes, sBits := sub.Mask.Size()
	if pBits != sBits || pOnes > sOnes {
		return false
	}
	return parent.Contains(sub.IP)
}
