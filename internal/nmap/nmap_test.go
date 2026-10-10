package nmap

import (
	"path/filepath"
	"strings"
	"testing"
)

func loadSample(t *testing.T) *Scan {
	t.Helper()
	scan, err := ParseFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return scan
}

func TestParseSample(t *testing.T) {
	scan := loadSample(t)
	if scan.Version != "7.94" {
		t.Errorf("Version = %q, want 7.94", scan.Version)
	}
	if len(scan.Hosts) != 3 {
		t.Fatalf("len(Hosts) = %d, want 3", len(scan.Hosts))
	}

	up := scan.UpHosts()
	if len(up) != 2 {
		t.Fatalf("len(UpHosts) = %d, want 2", len(up))
	}

	gw := up[0]
	if gw.Label() != "gateway.local (192.168.1.10)" {
		t.Errorf("Label = %q", gw.Label())
	}
	if got := len(gw.OpenPorts()); got != 3 {
		t.Errorf("gateway open ports = %d, want 3", got)
	}
	for _, p := range gw.Ports {
		if p.Number == 443 && p.Service.Product != "nginx" {
			t.Errorf("port 443 product = %q, want nginx", p.Service.Product)
		}
	}
	if gw.Ports[0].Number != 22 {
		t.Errorf("ports not sorted; first = %d", gw.Ports[0].Number)
	}
}

func TestParseRejectsNonNmapXML(t *testing.T) {
	if _, err := Parse(strings.NewReader("<notnmap/>")); err == nil {
		t.Fatal("expected error for non-nmap root element")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse(strings.NewReader("this is not xml")); err == nil {
		t.Fatal("expected error for non-XML input")
	}
}

func TestParseFileMissing(t *testing.T) {
	if _, err := ParseFile(filepath.Join("testdata", "nope.xml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestPrimaryAddressPrefersIPv4(t *testing.T) {
	h := Host{Addresses: []Address{
		{Addr: "fe80::1", Type: "ipv6"},
		{Addr: "10.0.0.1", Type: "ipv4"},
	}}
	if h.PrimaryAddress() != "10.0.0.1" {
		t.Errorf("PrimaryAddress = %q, want 10.0.0.1", h.PrimaryAddress())
	}
}
