// This file turns a parsed nmap.Scan into ranked, human-readable risks.
// It is deliberately rule-based and conservative: it reports exposure of
// known-sensitive services, not confirmed vulnerabilities.
package nmap // same package as nmap.go so it can use the Scan/Host/Port types directly

import ( // imports for this file
	"encoding/json" // needed only by Severity.MarshalJSON to emit a JSON string
	"fmt"           // Sprintf for building finding strings
	"sort"          // stable sort to rank findings deterministically
	"strings"       // trim/join helpers when building banner text
)

// Severity ranks how concerning a finding is.
type Severity int // underlying int makes severities comparable with < and >

const ( // iota assigns increasing numbers; order encodes "worse" for easy comparisons
	SevInfo     Severity = iota // 0: informational (e.g. an open port with no known risk)
	SevLow                      // 1: low
	SevMedium                   // 2: medium
	SevHigh                     // 3: high
	SevCritical                 // 4: critical (unauthenticated takeover risk)
)

// String returns the uppercase label used in reports and JSON.
func (s Severity) String() string { // implements fmt.Stringer so %s prints the name
	switch s { // map each numeric severity to its label
	case SevCritical: // 4
		return "CRITICAL"
	case SevHigh: // 3
		return "HIGH"
	case SevMedium: // 2
		return "MEDIUM"
	case SevLow: // 1
		return "LOW"
	default: // 0 and any unexpected value
		return "INFO" // safest default: treat unknown as informational
	}
}

// MarshalJSON renders severity as its string form (e.g. "HIGH").
func (s Severity) MarshalJSON() ([]byte, error) { // custom encoder so JSON shows "HIGH" not 3
	return json.Marshal(s.String()) // delegate escaping to encoding/json
}

// Finding is a single risk observation about one host/port.
type Finding struct { // one row in the risk report
	Host     string   `json:"host"`               // host label (name + address)
	Port     int      `json:"port,omitempty"`     // port number; omitted for host-level findings
	Protocol string   `json:"protocol,omitempty"` // tcp/udp
	Service  string   `json:"service,omitempty"`  // detected service name
	Severity Severity `json:"severity"`           // ranked importance
	Title    string   `json:"title"`              // short summary
	Detail   string   `json:"detail"`             // why it matters + remediation, plus detected banner
}

// String renders a finding for humans (label, target, title, detail).
func (f Finding) String() string { // used by the CLI summary
	target := f.Host // start with the host label
	if f.Port > 0 {  // if this finding is about a specific port...
		target = fmt.Sprintf("%s:%d/%s", f.Host, f.Port, f.Protocol) // ...append ":port/proto"
	}
	return fmt.Sprintf("[%s] %s — %s\n    %s", f.Severity, target, f.Title, f.Detail) // multi-line block
}

// rule describes the built-in guidance for one well-known port.
type rule struct { // a single lookup entry
	port     int      // the port number this rule applies to
	severity Severity // how severe exposure of this port is
	title    string   // short headline for the finding
	detail   string   // explanation + remediation guidance
}

// defaultRules maps well-known ports to exposure guidance. This is deliberately
// conservative: it flags commonly-sensitive services rather than claiming a
// vulnerability exists.
var defaultRules = []rule{ // ordered list; lookup scans it linearly (small N)
	{21, SevMedium, "FTP exposed", "FTP transmits credentials in cleartext; prefer SFTP/FTPS and restrict access."},                              // cleartext credentials
	{23, SevHigh, "Telnet exposed", "Telnet is cleartext and unauthenticated at the transport layer; disable it."},                               // obsolete cleartext protocol
	{111, SevMedium, "rpcbind exposed", "rpcbind can enumerate NFS/RPC services; restrict to trusted networks."},                                 // enables enumeration
	{135, SevMedium, "MS RPC exposed", "Windows RPC endpoint mapper should not be internet-reachable."},                                          // Windows attack surface
	{139, SevHigh, "NetBIOS exposed", "Legacy SMB/NetBIOS; disable or firewall."},                                                                // legacy SMB
	{445, SevHigh, "SMB exposed", "SMB is a frequent ransomware entry point; never expose to untrusted networks."},                               // ransomware vector
	{512, SevHigh, "rexec exposed", "Legacy r-services are cleartext and host-trust based; disable."},                                            // legacy r-services
	{513, SevHigh, "rlogin exposed", "Legacy r-services are cleartext and host-trust based; disable."},                                           // legacy r-services
	{514, SevHigh, "rsh exposed", "Legacy r-services are cleartext and host-trust based; disable."},                                              // legacy r-services
	{1433, SevHigh, "MSSQL exposed", "Database should not be directly reachable; put it behind a private network."},                              // database exposure
	{1521, SevHigh, "Oracle DB exposed", "Database should not be directly reachable; restrict access."},                                          // database exposure
	{2049, SevHigh, "NFS exposed", "NFS exports can leak or allow writes; restrict and use strong auth."},                                        // file-share exposure
	{2375, SevCritical, "Docker API (plaintext) exposed", "Unauthenticated Docker API = host takeover. Bind to localhost or use TLS with auth."}, // host takeover
	{2376, SevHigh, "Docker API (TLS) exposed", "Docker API should not be broadly reachable even over TLS."},                                     // container control plane
	{3306, SevHigh, "MySQL exposed", "Database should not be directly reachable; restrict to app hosts."},                                        // database exposure
	{3389, SevHigh, "RDP exposed", "RDP is a common brute-force/ransomware target; require VPN and MFA."},                                        // brute-force vector
	{5432, SevHigh, "PostgreSQL exposed", "Database should not be directly reachable; restrict to app hosts."},                                   // database exposure
	{5900, SevHigh, "VNC exposed", "VNC is often weakly authenticated; restrict and tunnel."},                                                    // weak auth
	{5984, SevHigh, "CouchDB exposed", "Confirm authentication is enabled; CouchDB has had auth-bypass CVEs."},                                   // auth-bypass history
	{6379, SevCritical, "Redis exposed", "Redis frequently ships with no authentication. Bind to localhost or require auth."},                    // often no auth
	{9200, SevHigh, "Elasticsearch exposed", "Elasticsearch can expose all indexed data; require auth and restrict access."},                     // data exposure
	{11211, SevHigh, "Memcached exposed", "Memcached has no auth and is abused for amplification; bind to localhost."},                           // amplification abuse
	{27017, SevCritical, "MongoDB exposed", "MongoDB is often unauthenticated; bind to localhost or require auth."},                              // often no auth
}

// Analyze produces findings for every open port across all up hosts, ranked by
// severity (highest first), then host and port.
func Analyze(scan *Scan) []Finding { // main entry point for the risk report
	if scan == nil { // defensive: callers (and tests) may pass nil
		return nil // nothing to analyze
	}
	var findings []Finding // accumulator for the report

	for _, h := range scan.Hosts { // examine every host...
		if h.Status != "up" { // ...but only hosts that were reachable
			continue // skip down hosts entirely
		}
		label := h.Label()          // precompute the display label once per host
		for _, p := range h.Ports { // look at every port
			if p.State != "open" { // only open ports are meaningful exposure
				continue // skip closed/filtered ports
			}
			svcName := p.Service.Name // start from nmap's service name
			if svcName == "" {        // normalize an empty name so output stays consistent
				svcName = "unknown" // sentinel used below to suppress meaningless INFO rows
			}

			if r, ok := matchRule(p.Number); ok { // if this port has specific guidance...
				findings = append(findings, Finding{ // ...emit a rule-based finding
					Host:     label,                           // which host
					Port:     p.Number,                        // which port
					Protocol: p.Protocol,                      // tcp/udp
					Service:  svcName,                         // service name
					Severity: r.severity,                      // rule's severity
					Title:    r.title,                         // rule's headline
					Detail:   withBanner(r.detail, p.Service), // append detected product/version/CPE
				})
				continue // move to the next port; no generic finding needed
			}

			// No specific rule: record informational open-port sightings too,
			// but only if the service has a recognizable name.
			if svcName != "unknown" { // avoid noisy "open unknown port" rows
				findings = append(findings, Finding{ // emit an INFO finding
					Host:     label,                                                                                // host label
					Port:     p.Number,                                                                             // port number
					Protocol: p.Protocol,                                                                           // tcp/udp
					Service:  svcName,                                                                              // known service name
					Severity: SevInfo,                                                                              // informational only
					Title:    "Open " + strings.ToUpper(svcName) + " port",                                         // e.g. "Open SSH port"
					Detail:   withBanner("Service is reachable; confirm it is intended to be exposed.", p.Service), // guidance + banner
				})
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool { // rank the report deterministically
		if findings[i].Severity != findings[j].Severity { // first by severity...
			return findings[i].Severity > findings[j].Severity // ...highest first
		}
		if findings[i].Host != findings[j].Host { // then by host name...
			return findings[i].Host < findings[j].Host // ...alphabetically
		}
		return findings[i].Port < findings[j].Port // finally by port ascending
	})
	return findings // the ranked report
}

// matchRule returns the built-in rule for a port, if any.
func matchRule(port int) (rule, bool) { // second return value distinguishes "no rule" from a zero rule
	for _, r := range defaultRules { // linear scan is fine for ~23 entries
		if r.port == port { // exact port match
			return r, true // found it
		}
	}
	return rule{}, false // no rule for this port
}

// withBanner appends detected product/version/CPE to a finding's detail text.
func withBanner(detail string, s Service) string { // makes findings concrete and verifiable
	var parts []string                                                               // pieces of banner info to append
	products := strings.TrimSpace(strings.Join([]string{s.Product, s.Version}, " ")) // join "product version", trim spaces
	switch {                                                                         // choose how to render, avoiding empty fragments
	case products != "" && s.Extra != "": // product+version AND extra info
		parts = append(parts, fmt.Sprintf("%s (%s)", products, s.Extra)) // e.g. "OpenSSH 8.9p1 (Ubuntu Linux)"
	case products != "": // only product+version
		parts = append(parts, products) // e.g. "nginx 1.24.0"
	}
	if len(s.CPEs) > 0 { // if nmap identified a CPE...
		parts = append(parts, "cpe: "+s.CPEs[0]) // ...show the first one (most specific)
	}
	if len(parts) == 0 { // nothing useful detected
		return detail // return the original guidance unchanged
	}
	return detail + " Detected: " + strings.Join(parts, "; ") + "." // append a readable "Detected:" clause
}

// Counts returns how many findings exist at each severity.
func Counts(findings []Finding) map[Severity]int { // used to render the "CRITICAL:2 HIGH:1" summary
	m := map[Severity]int{}      // start empty; absent keys read as 0
	for _, f := range findings { // tally each finding
		m[f.Severity]++ // increment its severity bucket
	}
	return m // caller looks up the severities it cares about
}
