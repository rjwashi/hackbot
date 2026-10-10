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
	Scripts   []Script  // host-level NSE script results (from <hostscript>)
}

// Address is an IP address with its type ("ipv4", "ipv6", "mac").
type Address struct { // Address mirrors one <address> element
	Addr string // the literal address text, e.g. "192.168.1.10"
	Type string // addrtype attribute, e.g. "ipv4"; used to prefer IPv4 in output
}

// Port is a single port/service observation.
type Port struct { // Port mirrors one <port> element plus its state/service children
	Protocol string   // "tcp" or "udp"; needed because the same number can exist on both
	Number   int      // the port number (portid attribute)
	State    string   // "open", "closed", or "filtered"; only "open" is analyzed
	Service  Service  // the fingerprint nmap matched, if any
	Scripts  []Script // NSE script results attached to this port
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

// Script is one Nmap Scripting Engine (NSE) result, e.g. "http-title".
type Script struct { // Script mirrors one <script> element in nmap XML
	ID     string        // the script id, e.g. "banner" or "http-title"
	Output string        // the human-readable output text nmap recorded
	Elems  []ScriptElem  // flat key/value fields from direct <elem> children
	Tables []ScriptTable // structured blocks from direct <table> children
}

// ScriptTable is a structured block inside NSE output.
type ScriptTable struct { // ScriptTable mirrors one nested <table> element
	Key    string        // the table's key attribute, if nmap provided one
	Elems  []ScriptElem  // key/value rows directly inside this table
	Tables []ScriptTable // tables nested inside this table
}

// ScriptElem is a single key/value field inside NSE output.
type ScriptElem struct { // ScriptElem mirrors one <elem> element
	Key   string // the field name, e.g. "title"
	Value string // the field value rendered as text
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

// ScriptByID returns the host-level script with the given id, if present.
func (h Host) ScriptByID(id string) (Script, bool) { // looks up host-level <hostscript> output
	for _, s := range h.Scripts { // scan the host's scripts...
		if s.ID == id { // ...for a matching id
			return s, true // found it
		}
	}
	return Script{}, false // not present on this host
}

// ScriptByID returns the port-level script with the given id, if present.
func (p Port) ScriptByID(id string) (Script, bool) { // looks up a port's <script> output
	for _, s := range p.Scripts { // scan this port's scripts...
		if s.ID == id { // ...for a matching id
			return s, true // found it
		}
	}
	return Script{}, false // not present on this port
}

// Elem returns a value by key, searching flat elems and nested tables depth-first.
func (s Script) Elem(key string) (string, bool) { // convenience accessor for structured NSE output
	if v, ok := lookupElem(s.Elems, key); ok { // first check the script's top-level fields
		return v, true // found at the top level
	}
	for _, t := range s.Tables { // otherwise search each top-level table...
		if v, ok := t.elem(key); ok { // ...recursively
			return v, true // found inside a table
		}
	}
	return "", false // key not found anywhere in this script
}

// elem searches a table (and its nested tables) for a key.
func (t ScriptTable) elem(key string) (string, bool) { // recursive helper used by Script.Elem
	if v, ok := lookupElem(t.Elems, key); ok { // check this table's own rows first
		return v, true // found here
	}
	for _, nested := range t.Tables { // then recurse into any nested tables
		if v, ok := nested.elem(key); ok { // depth-first search
			return v, true // found deeper
		}
	}
	return "", false // not found in this subtree
}

// lookupElem finds a key in a flat list of ScriptElem.
func lookupElem(elems []ScriptElem, key string) (string, bool) { // shared by Elem and elem
	for _, e := range elems { // linear scan (NSE outputs are small)
		if e.Key == key { // exact key match
			return e.Value, true // return the first match
		}
	}
	return "", false // no such key
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
	Status      xmlStatus    `xml:"status"`             // the <status> child (up/down)
	Addresses   []xmlAddress `xml:"address"`            // all <address> children
	Hostnames   []xmlName    `xml:"hostnames>hostname"` // flatten <hostnames><hostname> to a slice
	Ports       []xmlPort    `xml:"ports>port"`         // flatten <ports><port> to a slice
	HostScripts []xmlScript  `xml:"hostscript>script"`  // host-level NSE scripts under <hostscript>
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
type xmlPort struct { // decodes port identity, state, nested service, and NSE scripts
	Protocol string      `xml:"protocol,attr"` // "tcp" or "udp"
	PortID   int         `xml:"portid,attr"`   // numeric port
	State    xmlStatus   `xml:"state"`         // nested <state>
	Service  xmlService  `xml:"service"`       // nested <service>
	Scripts  []xmlScript `xml:"script"`        // NSE <script> children on this port
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

// xmlScript mirrors one <script> element (NSE output).
type xmlScript struct { // decodes id/output attributes plus the nested structure
	ID     string     `xml:"id,attr"`     // the script id, e.g. "http-title"
	Output string     `xml:"output,attr"` // human-readable output text
	Elems  []xmlElem  `xml:"elem"`        // direct <elem> children
	Tables []xmlTable `xml:"table"`       // direct <table> children
}

// xmlTable mirrors a nested <table> element inside script output.
type xmlTable struct { // recursive shape allows arbitrarily nested tables
	Key    string     `xml:"key,attr"` // the table's label, if present
	Elems  []xmlElem  `xml:"elem"`     // <elem> rows
	Tables []xmlTable `xml:"table"`    // nested <table> blocks
}

// xmlElem mirrors an <elem> element (a single key/value field).
type xmlElem struct { // NSE renders the value as character data
	Key   string `xml:"key,attr"`  // field name
	Value string `xml:",chardata"` // field value text
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
		h.Scripts = convertScripts(xh.HostScripts) // copy host-level NSE results (may be nil)
		for _, xp := range xh.Ports {              // convert each XML port into the public Port type
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
				Scripts: convertScripts(xp.Scripts), // NSE results attached to this port
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

// convertScripts maps decoded XML scripts into the public Script type.
func convertScripts(xs []xmlScript) []Script { // shared by host- and port-level scripts
	if len(xs) == 0 { // avoid allocating for the common "no scripts" case
		return nil // nil keeps JSON output clean and comparisons simple
	}
	out := make([]Script, 0, len(xs)) // preallocate for the known count
	for _, x := range xs {            // convert each decoded script
		out = append(out, Script{
			ID:     x.ID,                    // copy the script id
			Output: x.Output,                // copy the output text
			Elems:  convertElems(x.Elems),   // convert flat fields
			Tables: convertTables(x.Tables), // convert nested tables
		})
	}
	return out // converted slice
}

// convertElems maps decoded <elem> children into ScriptElem values.
func convertElems(xs []xmlElem) []ScriptElem { // used by both scripts and tables
	if len(xs) == 0 { // nothing to convert
		return nil
	}
	out := make([]ScriptElem, 0, len(xs)) // preallocate
	for _, x := range xs {                // copy each key/value pair
		out = append(out, ScriptElem{Key: x.Key, Value: x.Value})
	}
	return out // converted fields
}

// convertTables maps decoded <table> children into ScriptTable values.
func convertTables(xs []xmlTable) []ScriptTable { // recursive over the nesting
	if len(xs) == 0 { // nothing to convert
		return nil
	}
	out := make([]ScriptTable, 0, len(xs)) // preallocate
	for _, x := range xs {                 // convert each table
		out = append(out, ScriptTable{
			Key:    x.Key,                   // copy the table label
			Elems:  convertElems(x.Elems),   // convert its rows
			Tables: convertTables(x.Tables), // recurse into nested tables
		})
	}
	return out // converted tables
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
