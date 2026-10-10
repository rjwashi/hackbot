package main // tests the unexported CLI helpers directly

import ( // test imports
	"flag"          // construct a FlagSet to exercise reorderArgs
	"fmt"           // build the expected agents headline dynamically
	"os"            // read docs/README for the generated-agent sync test
	"path/filepath" // platform-independent expected vulscan paths
	"strings"       // string checks for agent rendering
	"testing"       // the testing framework

	"github.com/rjwashi/hackbot/internal/nmap" // Severity type for parseSeverity tests
	"github.com/rjwashi/hackbot/internal/wstg" // load the embedded WSTG checklists
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

// TestAgentsRegistry verifies the agent registry is populated and complete.
func TestAgentsRegistry(t *testing.T) { // `hackbot agents`
	if len(agents) == 0 {
		t.Fatal("no agents registered")
	}
	seen := map[string]bool{}  // detect duplicate names (skills need unique ids)
	for _, a := range agents { // every row needs all fields
		if a.Name == "" || a.Command == "" || a.Description == "" {
			t.Errorf("incomplete agent: %+v", a)
		}
		if len(a.Triggers) == 0 { // triggers seed the future skill description
			t.Errorf("agent %q has no triggers", a.Name)
		}
		if seen[a.Name] { // names double as skill ids, so they must be unique
			t.Errorf("duplicate agent name %q", a.Name)
		}
		seen[a.Name] = true // remember
	}
}

// TestAgentsRenderers verifies the text/markdown/json/skill outputs.
func TestAgentsRenderers(t *testing.T) { // `hackbot agents -format ...`
	text := agentsText()                                                    // text listing
	if !strings.HasPrefix(text, fmt.Sprintf("%d agents:\n", len(agents))) { // headline includes the count
		t.Errorf("agentsText headline = %q", strings.SplitN(text, "\n", 2)[0])
	}
	for _, a := range agents { // every agent appears in the text listing
		if !strings.Contains(text, a.Name) {
			t.Errorf("agentsText missing %q", a.Name)
		}
	}
	md := agentsMarkdown()                                           // markdown table
	if !strings.Contains(md, "| Agent | Command | What it does |") { // header present
		t.Error("agentsMarkdown missing header")
	}
	if strings.Count(md, "\n") != len(agents)+2 { // header + separator + one row per agent
		t.Errorf("agentsMarkdown rows = %d, want %d", strings.Count(md, "\n"), len(agents)+2)
	}
	js, err := agentsJSON() // JSON registry
	if err != nil {
		t.Fatalf("agentsJSON: %v", err)
	}
	if !strings.Contains(js, `"name": "nmap-analyze"`) { // serializes fields
		t.Errorf("agentsJSON = %s", js)
	}
	skill := agentSkill(agents[0])                                                                                // skill scaffold
	for _, want := range []string{"---\nname: " + agents[0].Name, "## Command", "hackbot " + agents[0].Command} { // frontmatter + command
		if !strings.Contains(skill, want) {
			t.Errorf("agentSkill missing %q", want)
		}
	}
	if err := printAgents("skill", "does-not-exist"); err == nil { // unknown agent errors
		t.Error("expected error for unknown skill agent")
	}
	if err := printAgents("nonsense", ""); err == nil { // unknown format errors
		t.Error("expected error for unknown format")
	}
}

// TestAgentsDocsInSync fails if the generated agent listings drift from the docs.
//
// The registry in main.go is the single source of truth; the Markdown table in
// docs/agents.md and the snapshot in README.md are generated from it. When you
// add an agent, update both files between the markers so this test stays green.
func TestAgentsDocsInSync(t *testing.T) { // guards against stale docs
	md := extractBetween(t, filepath.Join("docs", "agents.md"), agentTableBegin, agentTableEnd) // docs table
	if want := strings.TrimRight(agentsMarkdown(), "\n"); md != want {                          // must match the generator
		t.Errorf("docs/agents.md table is stale\n--- want ---\n%s\n--- got ---\n%s", want, md)
	}
	readme := extractBetween(t, filepath.Join("README.md"), agentsSnapBegin, agentsSnapEnd) // README snapshot
	if want := strings.TrimRight(agentsText(), "\n"); stripCodeFence(readme) != want {      // fenced text must match
		t.Errorf("README.md snapshot is stale\n--- want ---\n%s\n--- got ---\n%s", want, readme)
	}
}

// TestLayoutDocsInSync fails if the generated repo layout drifts from the README.
//
// Run `hackbot layout` from the repo root and paste the output between the
// markers so this test stays green.
func TestLayoutDocsInSync(t *testing.T) { // guards the README layout tree
	readme := extractBetween(t, "README.md", layoutBegin, layoutEnd) // README layout block
	want, err := layoutText(".")                                     // generate from the working tree
	if err != nil {
		t.Fatalf("layoutText: %v", err)
	}
	if got := stripCodeFence(readme); got != strings.TrimRight(want, "\n") { // must match
		t.Errorf("README.md layout is stale\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

// TestChecklistsEmbedded verifies the embedded WSTG checklists load correctly.
func TestChecklistsEmbedded(t *testing.T) { // guards the //go:embed directive
	checklists, err := wstg.Load(checklistsFS, checklistsDir) // load the embedded files
	if err != nil {
		t.Fatalf("load embedded checklists: %v", err)
	}
	if len(checklists) != 12 { // the WSTG set has 12 categories
		t.Fatalf("categories = %d, want 12", len(checklists))
	}
	total := 0                     // count every test item
	for _, c := range checklists { // across all categories
		total += len(c.Tests)                                 // accumulate
		if c.Code == "" || c.Category == "" || c.Slug == "" { // each checklist must be complete
			t.Errorf("incomplete checklist: %+v", c)
		}
		if len(c.Tests) == 0 { // and must have at least one test
			t.Errorf("checklist %s has no tests", c.File)
		}
	}
	if total < 100 { // the WSTG set totals well over 100 items
		t.Errorf("total tests = %d, want >= 100", total)
	}
}

// TestWebAgentsCoverChecklists verifies every WSTG checklist has a matching
// agent. Add a new file under src/agent_files/ and you must add an agent too.
func TestWebAgentsCoverChecklists(t *testing.T) { // registry <-> checklists invariant
	checklists, err := wstg.Load(checklistsFS, checklistsDir) // load the embedded files
	if err != nil {
		t.Fatalf("load embedded checklists: %v", err)
	}
	for _, c := range checklists { // each checklist needs an agent...
		name := "web-" + c.Slug  // ...named web-<slug>
		a, ok := findAgent(name) // look it up
		if !ok {                 // missing agent...
			t.Errorf("no agent for checklist %s (expected %q)", c.File, name) // ...fail
			continue
		}
		if want := "web show " + c.Slug; !strings.Contains(a.Command, want) { // command must point at the checklist
			t.Errorf("agent %s command = %q, want it to contain %q", name, a.Command, want)
		}
	}
}

// extractBetween returns the text between two markers in a file, normalized to
// LF and trimmed of surrounding newlines.
func extractBetween(t *testing.T, path, begin, end string) string { // test helper
	t.Helper() // cleaner failures
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n") // normalize line endings
	i := strings.Index(s, begin)                        // locate the start marker
	if i < 0 {
		t.Fatalf("%s: missing begin marker %q", path, begin)
	}
	rest := s[i+len(begin):]      // text after the start marker
	j := strings.Index(rest, end) // locate the end marker
	if j < 0 {
		t.Fatalf("%s: missing end marker %q", path, end)
	}
	return strings.Trim(rest[:j], "\n") // between the markers
}

// stripCodeFence removes a surrounding ``` fence (and optional language) from s.
func stripCodeFence(s string) string { // test helper for the README snapshot
	lines := strings.Split(s, "\n") // split into lines
	if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[0]), "```") {
		lines = lines[1:] // drop the opening fence
	}
	if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), "```") {
		lines = lines[:len(lines)-1] // drop the closing fence
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n") // reassemble
}
