package nmap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity ranks how concerning a finding is.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// MarshalJSON renders severity as its string form (e.g. "HIGH").
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding is a single risk observation about one host/port.
type Finding struct {
	Host     string   `json:"host"`
	Port     int      `json:"port,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Service  string   `json:"service,omitempty"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
}

func (f Finding) String() string {
	target := f.Host
	if f.Port > 0 {
		target = fmt.Sprintf("%s:%d/%s", f.Host, f.Port, f.Protocol)
	}
	return fmt.Sprintf("[%s] %s — %s\n    %s", f.Severity, target, f.Title, f.Detail)
}

type rule struct {
	port     int
	severity Severity
	title    string
	detail   string
}

// defaultRules maps well-known ports to exposure guidance. This is deliberately
// conservative: it flags commonly-sensitive services rather than claiming a
// vulnerability exists.
var defaultRules = []rule{
	{21, SevMedium, "FTP exposed", "FTP transmits credentials in cleartext; prefer SFTP/FTPS and restrict access."},
	{23, SevHigh, "Telnet exposed", "Telnet is cleartext and unauthenticated at the transport layer; disable it."},
	{111, SevMedium, "rpcbind exposed", "rpcbind can enumerate NFS/RPC services; restrict to trusted networks."},
	{135, SevMedium, "MS RPC exposed", "Windows RPC endpoint mapper should not be internet-reachable."},
	{139, SevHigh, "NetBIOS exposed", "Legacy SMB/NetBIOS; disable or firewall."},
	{445, SevHigh, "SMB exposed", "SMB is a frequent ransomware entry point; never expose to untrusted networks."},
	{512, SevHigh, "rexec exposed", "Legacy r-services are cleartext and host-trust based; disable."},
	{513, SevHigh, "rlogin exposed", "Legacy r-services are cleartext and host-trust based; disable."},
	{514, SevHigh, "rsh exposed", "Legacy r-services are cleartext and host-trust based; disable."},
	{1433, SevHigh, "MSSQL exposed", "Database should not be directly reachable; put it behind a private network."},
	{1521, SevHigh, "Oracle DB exposed", "Database should not be directly reachable; restrict access."},
	{2049, SevHigh, "NFS exposed", "NFS exports can leak or allow writes; restrict and use strong auth."},
	{2375, SevCritical, "Docker API (plaintext) exposed", "Unauthenticated Docker API = host takeover. Bind to localhost or use TLS with auth."},
	{2376, SevHigh, "Docker API (TLS) exposed", "Docker API should not be broadly reachable even over TLS."},
	{3306, SevHigh, "MySQL exposed", "Database should not be directly reachable; restrict to app hosts."},
	{3389, SevHigh, "RDP exposed", "RDP is a common brute-force/ransomware target; require VPN and MFA."},
	{5432, SevHigh, "PostgreSQL exposed", "Database should not be directly reachable; restrict to app hosts."},
	{5900, SevHigh, "VNC exposed", "VNC is often weakly authenticated; restrict and tunnel."},
	{5984, SevHigh, "CouchDB exposed", "Confirm authentication is enabled; CouchDB has had auth-bypass CVEs."},
	{6379, SevCritical, "Redis exposed", "Redis frequently ships with no authentication. Bind to localhost or require auth."},
	{9200, SevHigh, "Elasticsearch exposed", "Elasticsearch can expose all indexed data; require auth and restrict access."},
	{11211, SevHigh, "Memcached exposed", "Memcached has no auth and is abused for amplification; bind to localhost."},
	{27017, SevCritical, "MongoDB exposed", "MongoDB is often unauthenticated; bind to localhost or require auth."},
}

// Analyze produces findings for every open port across all up hosts, ranked by
// severity (highest first), then host and port.
func Analyze(scan *Scan) []Finding {
	if scan == nil {
		return nil
	}
	var findings []Finding

	for _, h := range scan.Hosts {
		if h.Status != "up" {
			continue
		}
		label := h.Label()
		for _, p := range h.Ports {
			if p.State != "open" {
				continue
			}
			svcName := p.Service.Name
			if svcName == "" {
				svcName = "unknown"
			}

			if r, ok := matchRule(p.Number); ok {
				findings = append(findings, Finding{
					Host:     label,
					Port:     p.Number,
					Protocol: p.Protocol,
					Service:  svcName,
					Severity: r.severity,
					Title:    r.title,
					Detail:   withBanner(r.detail, p.Service),
				})
				continue
			}

			// No specific rule: record informational open-port sightings too,
			// but only if the service has a recognizable name.
			if svcName != "unknown" {
				findings = append(findings, Finding{
					Host:     label,
					Port:     p.Number,
					Protocol: p.Protocol,
					Service:  svcName,
					Severity: SevInfo,
					Title:    "Open " + strings.ToUpper(svcName) + " port",
					Detail:   withBanner("Service is reachable; confirm it is intended to be exposed.", p.Service),
				})
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		if findings[i].Host != findings[j].Host {
			return findings[i].Host < findings[j].Host
		}
		return findings[i].Port < findings[j].Port
	})
	return findings
}

func matchRule(port int) (rule, bool) {
	for _, r := range defaultRules {
		if r.port == port {
			return r, true
		}
	}
	return rule{}, false
}

func withBanner(detail string, s Service) string {
	var parts []string
	products := strings.TrimSpace(strings.Join([]string{s.Product, s.Version}, " "))
	switch {
	case products != "" && s.Extra != "":
		parts = append(parts, fmt.Sprintf("%s (%s)", products, s.Extra))
	case products != "":
		parts = append(parts, products)
	}
	if len(s.CPEs) > 0 {
		parts = append(parts, "cpe: "+s.CPEs[0])
	}
	if len(parts) == 0 {
		return detail
	}
	return detail + " Detected: " + strings.Join(parts, "; ") + "."
}

// Counts returns the number of findings at or above each severity from Low up.
func Counts(findings []Finding) map[Severity]int {
	m := map[Severity]int{}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}
