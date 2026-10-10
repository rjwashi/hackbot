// Package nmap parses nmap XML output into structured data and analyzes it for
// risky exposure.
//
// Only XML produced by nmap's -oX option is supported, because it is the stable
// machine-readable format. Normal/grepable output is intentionally not parsed.
package nmap // declares the package name so other packages can import it as "nmap"

import ( // groups this file's imports; Go groups stdlib and third-party separately when possible
	"encoding/xml" // stdlib XML decoder used to turn nmap's XML into Go structs
	"fmt"          // formatting/error-wrapping helpers (Sprintf, Errorf)
	"io"           // provides io.Reader so Parse can read from any source (file, string, network)
	"os"           // os.Open so ParseFile can read a file from disk
	"sort"         // sort.Slice to keep port lists deterministic (tests and diffs rely on order)
)

// Scan is a parsed nmap run.
type Scan struct { // Scan is the top-level result of one nmap invocation
	Scanner string // the value of nmap's scanner="..." attribute, usually "nmap"
	Args    string // the exact command line nmap recorded, useful for provenance/auditing
	Version string // nmap version string, so reports can record which scanner produced the data
	Hosts   []Host // every host nmap reported (up or down)
}

// Host is a single scanned host.
type Host struct { // Host is one machine within a Scan
	Status    string    // "up" or "down" (from <status state="...">)
	Addresses []Address // all addresses nmap found (IPv4, IPv6, and possibly MAC)
	Hostnames []string  // PTR/reverse-DNS names, already flattened to plain strings
	Ports     []Port    // all observed ports, including closed/filtered ones
}

// Address is an IP address with its type ("ipv4", "ipv6", "mac").
type Address struct { // Address mirrors one <address> element
	Addr string // the literal address text, e.g. "192.168.1.10"
	Type string // addrtype attribute, e.g. "ipv4"; used to prefer IPv4 in output
}

// Port is a single port/service observation.
type Port struct { // Port mirrors one <port> element plus its state/service children
	Protocol string  // "tcp" or "udp"; needed because the same number can exist on both
	Number   int     // the port number (portid attribute)
	State    string  // "open", "closed", or "filtered"; only "open" is analyzed
	Service  Service // the fingerprint nmap matched, if any
}

// Service describes the service fingerprint on a port.
type Service struct { // Service mirrors the nested <service> element
	Name    string   // canonical service name, e.g. "http", "ssh", "redis"
	Product string   // detected product, e.g. "nginx", "OpenSSH"
	Version string   // detected product version, e.g. "1.24.0"
	Extra   string   // extra banner info, e.g. "Ubuntu Linux"
	Tunnel  string   // wrapping protocol, e.g. "ssl" for https; empty when none
	CPEs    []string // Common Platform Enumeration IDs; useful for future CVE correlation
}

// PrimaryAddress returns the first usable address, preferring IPv4.
func (h Host) PrimaryAddress() string { // method on Host so callers can get one canonical address
	for _, a := range h.Addresses { // iterate addresses in the order nmap emitted them
		if a.Type == "ipv4" { // prefer IPv4 because it is the most familiar/parseable for reports
			return a.Addr // found an IPv4 address: return immediately
		}
	}
	if len(h.Addresses) > 0 { // no IPv4 found, but some address exists...
		return h.Addresses[0].Addr // ...fall back to the first address of any type (e.g. IPv6)
	}
	return "" // no addresses at all: caller must handle an empty string
}

// Name returns the first hostname, or "" if none.
func (h Host) Name() string { // convenience accessor that hides the slice empty-check
	if len(h.Hostnames) > 0 { // only index when the slice is non-empty to avoid a panic
		return h.Hostnames[0] // return the first (nmap puts the best name first)
	}
	return "" // no hostname recorded
}

// Label returns a human-friendly identifier for the host.
func (h Host) Label() string { // Label combines name + address for readable reports
	if n := h.Name(); n != "" { // if we have a hostname, prefer showing it
		if a := h.PrimaryAddress(); a != "" { // and append the address if we have one
			return fmt.Sprintf("%s (%s)", n, a) // e.g. "gateway.local (192.168.1.10)"
		}
		return n // hostname only
	}
	if a := h.PrimaryAddress(); a != "" { // no hostname, but an address exists
		return a // e.g. "192.168.1.50"
	}
	return "(unknown host)" // nothing to identify the host with
}

// OpenPorts returns only ports whose state is "open".
func (h Host) OpenPorts() []Port { // filtering helper so analysis/output only sees reachable ports
	var out []Port              // nil slice; appends allocate as needed
	for _, p := range h.Ports { // scan every port
		if p.State == "open" { // keep only genuinely open ports (ignore closed/filtered)
			out = append(out, p) // collect it
		}
	}
	return out // return the filtered slice (nil if none)
}

// ---- XML decoding ----

// xmlRun is the private mirror of the <nmaprun> XML root, used only for decoding.
type xmlRun struct { // kept unexported so the public API isn't tied to XML details
	XMLName xml.Name  `xml:"nmaprun"`      // asserts the root element is <nmaprun>; guards against wrong input
	Scanner string    `xml:"scanner,attr"` // read the scanner attribute into Scanner
	Args    string    `xml:"args,attr"`    // read the args attribute (full command line)
	Version string    `xml:"version,attr"` // read the version attribute
	Hosts   []xmlHost `xml:"host"`         // decode each <host> child into xmlHost
}

// xmlHost mirrors one <host> element.
type xmlHost struct { // intermediate struct; converted to the public Host after decoding
	Status    xmlStatus    `xml:"status"`             // the <status> child (up/down)
	Addresses []xmlAddress `xml:"address"`            // all <address> children
	Hostnames []xmlName    `xml:"hostnames>hostname"` // flatten <hostnames><hostname> to a slice
	Ports     []xmlPort    `xml:"ports>port"`         // flatten <ports><port> to a slice
}

// xmlStatus mirrors a <status> element (used for both hosts and ports).
type xmlStatus struct { // shared shape because both host and port expose a state attribute
	State string `xml:"state,attr"` // "up"/"down" for hosts, "open"/"closed"/"filtered" for ports
}

// xmlAddress mirrors one <address> element.
type xmlAddress struct { // decodes address + addrtype attributes
	Addr string `xml:"addr,attr"`     // the address literal
	Type string `xml:"addrtype,attr"` // "ipv4", "ipv6", or "mac"
}

// xmlName mirrors one <hostname> element.
type xmlName struct { // only the name attribute matters for our purposes
	Name string `xml:"name,attr"` // the hostname string
}

// xmlPort mirrors one <port> element.
type xmlPort struct { // decodes port identity, state, and nested service
	Protocol string     `xml:"protocol,attr"` // "tcp" or "udp"
	PortID   int        `xml:"portid,attr"`   // numeric port
	State    xmlStatus  `xml:"state"`         // nested <state>
	Service  xmlService `xml:"service"`       // nested <service>
}

// xmlService mirrors the nested <service> element.
type xmlService struct { // decodes the fingerprint attributes plus any <cpe> children
	Name    string   `xml:"name,attr"`      // service name
	Product string   `xml:"product,attr"`   // product name
	Version string   `xml:"version,attr"`   // product version
	Extra   string   `xml:"extrainfo,attr"` // extra banner text
	Tunnel  string   `xml:"tunnel,attr"`    // e.g. "ssl"
	CPEs    []string `xml:"cpe"`            // collect repeated <cpe> elements
}

// Parse decodes nmap XML from r.
func Parse(r io.Reader) (*Scan, error) { // accepts any reader so tests can pass strings.Reader
	var xr xmlRun                           // destination for decoded XML
	dec := xml.NewDecoder(r)                // streaming decoder avoids loading the whole file into memory
	if err := dec.Decode(&xr); err != nil { // decode; on failure wrap with context for the caller
		return nil, fmt.Errorf("parse nmap xml: %w", err) // %w preserves the original error for errors.Is/As
	}
	if xr.XMLName.Local != "nmaprun" { // XMLName is set even if root is wrong, so validate explicitly
		return nil, fmt.Errorf("parse nmap xml: root element is <%s>, want <nmaprun>", xr.XMLName.Local) // clear message
	}

	scan := &Scan{Scanner: xr.Scanner, Args: xr.Args, Version: xr.Version} // start building the public result
	for _, xh := range xr.Hosts {                                          // convert each XML host into the public Host type
		h := Host{Status: xh.Status.State} // copy the up/down status
		for _, a := range xh.Addresses {   // copy every address
			h.Addresses = append(h.Addresses, Address{Addr: a.Addr, Type: a.Type}) // map xmlAddress -> Address
		}
		for _, n := range xh.Hostnames { // copy hostnames, skipping empties
			if n.Name != "" { // guard against empty <hostname name="">
				h.Hostnames = append(h.Hostnames, n.Name) // keep only real names
			}
		}
		for _, xp := range xh.Ports { // convert each XML port into the public Port type
			h.Ports = append(h.Ports, Port{ // build a Port
				Protocol: xp.Protocol,    // protocol string
				Number:   xp.PortID,      // numeric port
				State:    xp.State.State, // open/closed/filtered
				Service: Service{ // map the nested service fingerprint
					Name:    xp.Service.Name,    // service name
					Product: xp.Service.Product, // product
					Version: xp.Service.Version, // version
					Extra:   xp.Service.Extra,   // extra banner
					Tunnel:  xp.Service.Tunnel,  // ssl or empty
					CPEs:    xp.Service.CPEs,    // CPE list
				},
			})
		}
		sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Number < h.Ports[j].Number }) // deterministic order
		scan.Hosts = append(scan.Hosts, h)                                                        // add the finished host to the scan
	}

	return scan, nil // success
}

// ParseFile parses an nmap XML file from disk.
func ParseFile(path string) (*Scan, error) { // thin convenience wrapper around Parse
	f, err := os.Open(path) // open the file for reading
	if err != nil {         // if the file is missing/unreadable...
		return nil, fmt.Errorf("open nmap xml %s: %w", path, err) // ...return a contextual error
	}
	defer f.Close() // ensure the file descriptor is released even if Parse panics
	return Parse(f) // delegate the actual decoding to Parse
}

// UpHosts returns hosts whose status is "up".
func (s *Scan) UpHosts() []Host { // used by analysis and output to skip down hosts
	var out []Host              // accumulator
	for _, h := range s.Hosts { // examine every host
		if h.Status == "up" { // keep only reachable hosts
			out = append(out, h) // collect it
		}
	}
	return out // nil when none are up
}
