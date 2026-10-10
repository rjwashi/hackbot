// This file surfaces NSE (Nmap Scripting Engine) results as reconnaissance.
// Parsing lives in nmap.go; this file only rearranges the parsed data into a
// flat, display-friendly list so the CLI and agent can show script output.
package nmap // same package as nmap.go so it can use Scan/Host/Port/Script directly

import ( // imports for this file
	"fmt"     // Sprintf for the ReconItem.String rendering
	"sort"    // stable sort so recon output order is deterministic
	"strings" // ReplaceAll to indent multi-line script output
)

// ReconItem is one piece of reconnaissance gathered by an NSE script.
type ReconItem struct { // flattened view of a Script, tagged for JSON output
	Host     string `json:"host"`               // host label the script ran against
	Port     int    `json:"port,omitempty"`     // port number, 0 for host-level scripts
	Protocol string `json:"protocol,omitempty"` // tcp/udp for port-level scripts
	Service  string `json:"service,omitempty"`  // service name for port-level scripts
	Script   string `json:"script"`             // the NSE script id, e.g. "http-title"
	Output   string `json:"output"`             // the script's human-readable output
}

// Recon flattens all NSE script results across a scan into a deterministic list.
//
// Only hosts that are up are considered, and port-level scripts are reported for
// open ports. Host-level ("hostscript") results have Port == 0.
func Recon(scan *Scan) []ReconItem { // used by the CLI and the agent pipeline
	if scan == nil { // defensive: nothing to do without a scan
		return nil // nil keeps JSON output clean
	}
	var items []ReconItem              // accumulator
	for _, h := range scan.UpHosts() { // only reachable hosts
		label := h.Label()            // precompute the display label once per host
		for _, s := range h.Scripts { // host-level scripts first
			items = append(items, ReconItem{Host: label, Script: s.ID, Output: s.Output}) // Port stays 0
		}
		for _, p := range h.OpenPorts() { // then port-level scripts on open ports
			for _, s := range p.Scripts { // one item per script
				items = append(items, ReconItem{
					Host:     label,          // host label
					Port:     p.Number,       // port number
					Protocol: p.Protocol,     // tcp/udp
					Service:  p.Service.Name, // service name
					Script:   s.ID,           // script id
					Output:   s.Output,       // script output
				})
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool { // deterministic ordering for tests/diffs
		if items[i].Host != items[j].Host { // group by host...
			return items[i].Host < items[j].Host
		}
		if items[i].Port != items[j].Port { // ...then by port...
			return items[i].Port < items[j].Port
		}
		return items[i].Script < items[j].Script // ...then by script id
	})
	return items // the flat recon list
}

// String renders one recon item as a short multi-line block.
func (r ReconItem) String() string { // used by the CLI's human output
	where := r.Host // start with the host label
	if r.Port > 0 { // port-level scripts add the port...
		where = fmt.Sprintf("%s:%d/%s", r.Host, r.Port, r.Protocol)
		if r.Service != "" { // ...and the service name when known
			where = fmt.Sprintf("%s (%s)", where, r.Service)
		}
	}
	out := strings.TrimSpace(r.Output) // trim stray whitespace from nmap
	if out == "" {                     // some scripts emit an empty output attribute
		return fmt.Sprintf("[%s] %s", r.Script, where) // render just the header
	}
	out = strings.ReplaceAll(out, "\n", "\n    ")               // indent continuation lines under the header
	return fmt.Sprintf("[%s] %s\n    %s", r.Script, where, out) // header + indented output
}
