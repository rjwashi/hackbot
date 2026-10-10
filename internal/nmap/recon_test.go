package nmap // same package as recon.go

import ( // test imports
	"strings" // string assertions
	"testing" // the testing framework
)

// TestReconListsOpenPortScripts verifies recon flattens and orders script output.
func TestReconListsOpenPortScripts(t *testing.T) { // recon happy path
	items := Recon(loadSample(t)) // flatten the fixture's scripts
	if len(items) == 0 {
		t.Fatal("expected recon items")
	}
	if items[0].Host != "192.168.1.50" { // deterministic lexicographic sort puts "192..." before "gateway..."
		t.Errorf("first host = %q", items[0].Host)
	}
	found := map[string]bool{} // track which scripts we saw
	for _, it := range items { // walk the flattened list
		found[it.Script] = true        // record the script id
		if it.Script == "http-title" { // spot-check a port-level item
			if it.Port != 443 || it.Protocol != "tcp" || it.Service != "https" { // fields must be filled
				t.Errorf("http-title item = %+v", it)
			}
		}
	}
	for _, want := range []string{"http-title", "http-headers", "ssh-hostkey", "redis-info"} { // expected scripts
		if !found[want] { // each fixture script must appear
			t.Errorf("missing recon script %q", want)
		}
	}
}

// TestReconNil verifies nil input yields nil output.
func TestReconNil(t *testing.T) { // defensive
	if got := Recon(nil); got != nil {
		t.Errorf("Recon(nil) = %v, want nil", got)
	}
}

// TestReconItemString verifies the human rendering, including newline indenting.
func TestReconItemString(t *testing.T) { // rendering
	it := ReconItem{Host: "h", Port: 443, Protocol: "tcp", Service: "https", Script: "http-title", Output: "Example\nDomain"}
	got := it.String()
	if !strings.Contains(got, "[http-title] h:443/tcp (https)") { // header line
		t.Errorf("String() missing header: %q", got)
	}
	if !strings.Contains(got, "Example\n    Domain") { // continuation line must be indented
		t.Errorf("String() did not indent output: %q", got)
	}
}
