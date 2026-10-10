// Package nmap parses nmap XML output into structured data and analyzes it for
// risky exposure.
//
// Only XML produced by nmap's -oX option is supported, because it is the stable
// machine-readable format. Normal/grepable output is intentionally not parsed.
package nmap

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
)

// Scan is a parsed nmap run.
type Scan struct {
	Scanner string
	Args    string
	Version string
	Hosts   []Host
}

// Host is a single scanned host.
type Host struct {
	Status    string // "up", "down", ...
	Addresses []Address
	Hostnames []string
	Ports     []Port
}

// Address is an IP address with its type ("ipv4", "ipv6", "mac").
type Address struct {
	Addr string
	Type string
}

// Port is a single port/service observation.
type Port struct {
	Protocol string // "tcp", "udp"
	Number   int
	State    string // "open", "closed", "filtered"
	Service  Service
}

// Service describes the service fingerprint on a port.
type Service struct {
	Name    string
	Product string
	Version string
	Extra   string
	Tunnel  string // e.g. "ssl"
	CPEs    []string
}

// PrimaryAddress returns the first usable address, preferring IPv4.
func (h Host) PrimaryAddress() string {
	for _, a := range h.Addresses {
		if a.Type == "ipv4" {
			return a.Addr
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}

// Name returns the first hostname, or "" if none.
func (h Host) Name() string {
	if len(h.Hostnames) > 0 {
		return h.Hostnames[0]
	}
	return ""
}

// Label returns a human-friendly identifier for the host.
func (h Host) Label() string {
	if n := h.Name(); n != "" {
		if a := h.PrimaryAddress(); a != "" {
			return fmt.Sprintf("%s (%s)", n, a)
		}
		return n
	}
	if a := h.PrimaryAddress(); a != "" {
		return a
	}
	return "(unknown host)"
}

// OpenPorts returns only ports whose state is "open".
func (h Host) OpenPorts() []Port {
	var out []Port
	for _, p := range h.Ports {
		if p.State == "open" {
			out = append(out, p)
		}
	}
	return out
}

// ---- XML decoding ----

type xmlRun struct {
	XMLName xml.Name  `xml:"nmaprun"`
	Scanner string    `xml:"scanner,attr"`
	Args    string    `xml:"args,attr"`
	Version string    `xml:"version,attr"`
	Hosts   []xmlHost `xml:"host"`
}

type xmlHost struct {
	Status    xmlStatus    `xml:"status"`
	Addresses []xmlAddress `xml:"address"`
	Hostnames []xmlName    `xml:"hostnames>hostname"`
	Ports     []xmlPort    `xml:"ports>port"`
}

type xmlStatus struct {
	State string `xml:"state,attr"`
}

type xmlAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type xmlName struct {
	Name string `xml:"name,attr"`
}

type xmlPort struct {
	Protocol string     `xml:"protocol,attr"`
	PortID   int        `xml:"portid,attr"`
	State    xmlStatus  `xml:"state"`
	Service  xmlService `xml:"service"`
}

type xmlService struct {
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
	Extra   string   `xml:"extrainfo,attr"`
	Tunnel  string   `xml:"tunnel,attr"`
	CPEs    []string `xml:"cpe"`
}

// Parse decodes nmap XML from r.
func Parse(r io.Reader) (*Scan, error) {
	var xr xmlRun
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&xr); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	if xr.XMLName.Local != "nmaprun" {
		return nil, fmt.Errorf("parse nmap xml: root element is <%s>, want <nmaprun>", xr.XMLName.Local)
	}

	scan := &Scan{Scanner: xr.Scanner, Args: xr.Args, Version: xr.Version}
	for _, xh := range xr.Hosts {
		h := Host{Status: xh.Status.State}
		for _, a := range xh.Addresses {
			h.Addresses = append(h.Addresses, Address{Addr: a.Addr, Type: a.Type})
		}
		for _, n := range xh.Hostnames {
			if n.Name != "" {
				h.Hostnames = append(h.Hostnames, n.Name)
			}
		}
		for _, xp := range xh.Ports {
			h.Ports = append(h.Ports, Port{
				Protocol: xp.Protocol,
				Number:   xp.PortID,
				State:    xp.State.State,
				Service: Service{
					Name:    xp.Service.Name,
					Product: xp.Service.Product,
					Version: xp.Service.Version,
					Extra:   xp.Service.Extra,
					Tunnel:  xp.Service.Tunnel,
					CPEs:    xp.Service.CPEs,
				},
			})
		}
		sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Number < h.Ports[j].Number })
		scan.Hosts = append(scan.Hosts, h)
	}

	return scan, nil
}

// ParseFile parses an nmap XML file from disk.
func ParseFile(path string) (*Scan, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open nmap xml %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// UpHosts returns hosts whose status is "up".
func (s *Scan) UpHosts() []Host {
	var out []Host
	for _, h := range s.Hosts {
		if h.Status == "up" {
			out = append(out, h)
		}
	}
	return out
}
