package nmap // same package as nmap.go

import ( // test imports
	"path/filepath" // build the testdata path portably
	"strings"       // strings.NewReader for in-memory XML inputs
	"testing"       // the testing framework
)

// loadSample parses the shared fixture, failing the test on error.
func loadSample(t *testing.T) *Scan { // shared fixture loader
	t.Helper()                                                      // mark as helper
	scan, err := ParseFile(filepath.Join("testdata", "sample.xml")) // parse the fixture
	if err != nil {                                                 // a broken fixture should fail loudly...
		t.Fatalf("ParseFile: %v", err) // ...here, not in every test
	}
	return scan // return the parsed scan
}

// TestParseSample verifies the fixture decodes with the expected shape.
func TestParseSample(t *testing.T) { // main parse test
	scan := loadSample(t)       // parse fixture
	if scan.Version != "7.94" { // nmap version attribute...
		t.Errorf("Version = %q, want 7.94", scan.Version) // ...should be captured
	}
	if len(scan.Hosts) != 3 { // fixture has 3 hosts
		t.Fatalf("len(Hosts) = %d, want 3", len(scan.Hosts))
	}

	up := scan.UpHosts() // filter to up hosts
	if len(up) != 2 {    // fixture has 2 up, 1 down
		t.Fatalf("len(UpHosts) = %d, want 2", len(up))
	}

	gw := up[0]                                       // first up host is the gateway
	if gw.Label() != "gateway.local (192.168.1.10)" { // label combines name + address
		t.Errorf("Label = %q", gw.Label())
	}
	if got := len(gw.OpenPorts()); got != 3 { // gateway has 3 open ports
		t.Errorf("gateway open ports = %d, want 3", got)
	}
	for _, p := range gw.Ports { // find the https port...
		if p.Number == 443 && p.Service.Product != "nginx" { // ...and check its product
			t.Errorf("port 443 product = %q, want nginx", p.Service.Product)
		}
	}
	if gw.Ports[0].Number != 22 { // ports should be sorted ascending
		t.Errorf("ports not sorted; first = %d", gw.Ports[0].Number)
	}
}

// TestParseRejectsNonNmapXML verifies the root-element guard.
func TestParseRejectsNonNmapXML(t *testing.T) { // validation
	if _, err := Parse(strings.NewReader("<notnmap/>")); err == nil { // wrong root...
		t.Fatal("expected error for non-nmap root element") // ...must error
	}
}

// TestParseRejectsGarbage verifies non-XML input errors.
func TestParseRejectsGarbage(t *testing.T) { // validation
	if _, err := Parse(strings.NewReader("this is not xml")); err == nil { // invalid XML...
		t.Fatal("expected error for non-XML input") // ...must error
	}
}

// TestParseFileMissing verifies a missing file errors.
func TestParseFileMissing(t *testing.T) { // error path
	if _, err := ParseFile(filepath.Join("testdata", "nope.xml")); err == nil { // nonexistent file...
		t.Fatal("expected error for missing file") // ...must error
	}
}

// TestPrimaryAddressPrefersIPv4 verifies IPv4 selection over IPv6.
func TestPrimaryAddressPrefersIPv4(t *testing.T) { // accessor behavior
	h := Host{Addresses: []Address{ // host with both address families
		{Addr: "fe80::1", Type: "ipv6"},  // IPv6 first...
		{Addr: "10.0.0.1", Type: "ipv4"}, // ...IPv4 second
	}}
	if h.PrimaryAddress() != "10.0.0.1" { // IPv4 must win despite order
		t.Errorf("PrimaryAddress = %q, want 10.0.0.1", h.PrimaryAddress())
	}
}

// TestParsePortScripts verifies per-port NSE output decodes into the model.
func TestParsePortScripts(t *testing.T) { // script parsing (fixture)
	scan := loadSample(t)        // parse fixture
	gw := scan.UpHosts()[0]      // gateway is the first up host
	var p443 Port                // find port 443
	for _, p := range gw.Ports { // scan the gateway's ports
		if p.Number == 443 { // match the https port
			p443 = p
		}
	}
	title, ok := p443.ScriptByID("http-title") // look up a known script
	if !ok {                                   // it must exist in the fixture
		t.Fatal("http-title script missing on port 443")
	}
	if title.Output != "Example Domain" { // the output attribute is captured
		t.Errorf("http-title output = %q", title.Output)
	}
	if v, ok := title.Elem("title"); !ok || v != "Example Domain" { // the <elem> child is captured
		t.Errorf("title elem = %q ok=%v", v, ok)
	}
	hh, ok := p443.ScriptByID("http-headers") // a table-based script
	if !ok {
		t.Fatal("http-headers script missing on port 443")
	}
	if v, ok := hh.Elem("server"); !ok || v != "nginx/1.24.0" { // lookup inside a nested <table>
		t.Errorf("server elem = %q ok=%v", v, ok)
	}
}

// TestParseHostScripts verifies <hostscript> output decodes at host level.
func TestParseHostScripts(t *testing.T) { // host-level scripts via inline XML
	const x = `<nmaprun scanner="nmap" version="7.94"><host><status state="up"/>` + // minimal root + host
		`<address addr="10.0.0.1" addrtype="ipv4"/>` + // one address
		`<hostscript><script id="smb-os-discovery" output="Windows 10"><elem key="os">Windows 10</elem></script></hostscript>` + // host script
		`</host></nmaprun>` // close root
	scan, err := Parse(strings.NewReader(x)) // parse it
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	s, ok := scan.Hosts[0].ScriptByID("smb-os-discovery") // host-level lookup
	if !ok {
		t.Fatal("host script missing")
	}
	if s.Output != "Windows 10" { // output captured
		t.Errorf("output = %q", s.Output)
	}
}

// TestScriptElemNested verifies Elem searches nested tables.
func TestScriptElemNested(t *testing.T) { // recursive lookup
	s := Script{Tables: []ScriptTable{{ // one table...
		Tables: []ScriptTable{{ // ...containing a nested table...
			Elems: []ScriptElem{{Key: "deep", Value: "found"}}, // ...with the field
		}},
	}}}
	if v, ok := s.Elem("deep"); !ok || v != "found" { // must find it depth-first
		t.Errorf("Elem(deep) = %q ok=%v, want found/true", v, ok)
	}
}
