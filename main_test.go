package main // tests the unexported CLI helpers directly

import ( // test imports
	"flag"          // construct a FlagSet to exercise reorderArgs
	"path/filepath" // platform-independent expected vulscan paths
	"testing"       // the testing framework

	"github.com/rjwashi/hackbot/internal/nmap" // Severity type for parseSeverity tests
)

// TestReorderArgsFlagsAnywhere verifies flags after positionals are parsed.
func TestReorderArgsFlagsAnywhere(t *testing.T) { // regression test for the flag-order bug
	fs := flag.NewFlagSet("t", flag.ContinueOnError) // fresh flag set
	json := fs.Bool("json", false, "")               // boolean flag
	issues := fs.Bool("issues", false, "")           // boolean flag
	repo := fs.String("repo", "", "")                // string flag (takes a value)

	got := reorderArgs(fs, []string{"pipeline", "scan.xml", "-issues", "-repo", "a/b", "-json"}) // flags interleaved + trailing
	if err := fs.Parse(got); err != nil {                                                        // parse the reordered args
		t.Fatalf("Parse: %v", err)
	}

	if fs.Arg(0) != "pipeline" || fs.Arg(1) != "scan.xml" { // positionals keep their order
		t.Errorf("positionals = %v, want [pipeline scan.xml]", fs.Args())
	}
	if !*json || !*issues || *repo != "a/b" { // every flag was parsed correctly
		t.Errorf("flags not parsed: json=%v issues=%v repo=%q", *json, *issues, *repo)
	}
}

// TestReorderArgsDoubleDash verifies the "--" end-of-flags marker.
func TestReorderArgsDoubleDash(t *testing.T) { // edge case
	fs := flag.NewFlagSet("t", flag.ContinueOnError)                         // fresh flag set
	_ = fs.Bool("json", false, "")                                           // declare a flag
	got := reorderArgs(fs, []string{"py", "helper.py", "--", "-not-a-flag"}) // "-not-a-flag" must stay positional
	if err := fs.Parse(got); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"py", "helper.py", "-not-a-flag"} // expected positionals
	if len(fs.Args()) != 3 || fs.Arg(2) != want[2] {   // third positional preserved verbatim
		t.Errorf("args = %v, want %v", fs.Args(), want)
	}
}

// TestParseSeverity verifies severity string parsing.
func TestParseSeverity(t *testing.T) { // table-based
	valid := map[string]nmap.Severity{ // accepted spellings
		"info":     nmap.SevInfo,     // info
		"LOW":      nmap.SevLow,      // case-insensitive
		"medium":   nmap.SevMedium,   // medium
		"med":      nmap.SevMedium,   // shorthand
		"high":     nmap.SevHigh,     // high
		"critical": nmap.SevCritical, // critical
		"crit":     nmap.SevCritical, // shorthand
	}
	for in, want := range valid { // each accepted input...
		got, err := parseSeverity(in) // ...parse it
		if err != nil {
			t.Errorf("parseSeverity(%q) error: %v", in, err)
		}
		if got != want { // must map correctly
			t.Errorf("parseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := parseSeverity("nope"); err == nil { // invalid input must error
		t.Error("expected error for invalid severity")
	}
}

// TestFirstNonEmpty verifies the flag-overrides-config helper.
func TestFirstNonEmpty(t *testing.T) { // small utility
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" { // first non-blank wins
		t.Errorf("firstNonEmpty = %q, want x", got)
	}
	if got := firstNonEmpty("", " "); got != "" { // all blank -> empty
		t.Errorf("firstNonEmpty = %q, want empty", got)
	}
}

// TestResolveScripts verifies flag > config > default precedence.
func TestResolveScripts(t *testing.T) { // script resolution
	if got := resolveScripts("banner,http-title", []string{"ignored"}); len(got) != 2 || got[1] != "http-title" { // flag wins
		t.Errorf("flag precedence: %v", got)
	}
	if got := resolveScripts("", []string{}); got == nil || len(got) != 0 { // empty config overrides the default
		t.Errorf("empty config should disable scripts, got %v", got)
	}
	got := resolveScripts("", nil) // nothing configured -> built-in profile
	if len(got) == 0 || got[0] != "banner" {
		t.Errorf("default profile = %v", got)
	}
	if got := resolveScripts("none", nil); got == nil || len(got) != 0 { // flag none disables
		t.Errorf("flag none = %v, want non-nil empty", got)
	}
	if got := parseScriptList("a, b ,, c"); len(got) != 3 || got[2] != "c" { // comma parsing drops blanks
		t.Errorf("parseScriptList = %v", got)
	}
}

// TestVulscanHelpers verifies the vulscan script/arg helpers.
func TestVulscanHelpers(t *testing.T) { // vulscan wiring helpers
	if got := vulscanScriptPath(""); got != "vulscan/vulscan.nse" { // default docs install
		t.Errorf("vulscanScriptPath(\"\") = %q", got)
	}
	if got := vulscanScriptPath("/opt/vulscan"); got != filepath.Join("/opt/vulscan", "vulscan.nse") { // explicit dir
		t.Errorf("vulscanScriptPath = %q", got)
	}
	if got := appendUnique([]string{"banner"}, "vulscan/vulscan.nse"); len(got) != 2 { // appended
		t.Errorf("appendUnique = %v", got)
	}
	if got := appendUnique([]string{"vulscan/vulscan.nse"}, "vulscan/vulscan.nse"); len(got) != 1 { // no duplicate
		t.Errorf("appendUnique dup = %v", got)
	}
	if got := withVulscanDB("", true, "cve.csv"); got != "vulscandb=cve.csv" { // only the vulscan arg
		t.Errorf("withVulscanDB = %q", got)
	}
	if got := withVulscanDB("x=1", true, "cve.csv"); got != "x=1,vulscandb=cve.csv" { // appended
		t.Errorf("withVulscanDB append = %q", got)
	}
	if got := withVulscanDB("x=1", false, "cve.csv"); got != "x=1" { // disabled: unchanged
		t.Errorf("withVulscanDB disabled = %q", got)
	}
}

// TestAgentsRegistry verifies the agent listing is populated and complete.
func TestAgentsRegistry(t *testing.T) { // `hackbot agents`
	if len(agents) == 0 {
		t.Fatal("no agents registered")
	}
	for _, a := range agents { // every row needs all three columns
		if a.Name == "" || a.Command == "" || a.Description == "" {
			t.Errorf("incomplete agent: %+v", a)
		}
	}
}
