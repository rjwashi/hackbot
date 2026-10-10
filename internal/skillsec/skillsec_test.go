package skillsec // same package as the code under test

import ( // test imports
	"context"        // Run takes a context
	"errors"         // errors.Is against the sentinel errors
	"os"             // read the real rubric files from the repo
	"path/filepath"  // build a temporary skill directory
	"strings"        // assertions on rendered commands
	"testing"        // the testing framework
	"testing/fstest" // in-memory fixtures for the parser

	"github.com/rjwashi/hackbot/internal/ops" // ops.ErrDisabled, the shared sentinel
)

// realRubrics loads the on-disk rubrics (the same files the binary embeds) so
// these tests validate against the real checks rather than a private fixture.
func realRubrics(t *testing.T) []Rubric { // helper for the tests below
	t.Helper()                                              // cleaner failures
	rs, err := Load(os.DirFS("../../src/agent_files"), ".") // read the repo's rubrics
	if err != nil {                                         // a failure here means nothing else can run
		t.Fatalf("load rubrics: %v", err)
	}
	if len(rs) < 3 { // all three rubrics must be present
		t.Fatalf("rubrics = %d, want at least 3 (malicious, over-privileged, insecure-metadata)", len(rs))
	}
	return rs
}

// TestLoadRealRubrics parses the three shipped rubrics and checks their shape:
// the right slugs, the right number of checks, and a provenance line each.
func TestLoadRealRubrics(t *testing.T) { // end-to-end parse of the real files
	rs := realRubrics(t)          // the shipped rubrics
	bySlug := map[string]Rubric{} // index for lookup
	for _, r := range rs {        // walk them
		bySlug[r.Slug] = r // index by slug
	}
	for slug, wantChecks := range map[string]int{ // slug -> expected check count
		"malicious-skills":       6,  // checks 1.1 through 1.6
		"over-privileged-skills": 8,  // checks 3.1 through 3.8
		"insecure-metadata":      12, // checks 4.1 through 4.12
	} {
		r, ok := bySlug[slug] // look it up
		if !ok {              // a missing rubric means the parser skipped it...
			t.Fatalf("rubric %q not found (got %d rubrics)", slug, len(rs))
		}
		if len(r.Checks) != wantChecks { // wrong row count means rows were dropped...
			t.Errorf("%s: checks = %d, want %d", slug, len(r.Checks), wantChecks)
		}
		if r.Motivation == "" { // the rubric's provenance must survive parsing...
			t.Errorf("%s: motivation is empty, want the Motivated by line", slug)
		}
		if r.Category == "" || r.Code == "" { // identity is derived from the file name...
			t.Errorf("%s: category/code empty (category=%q code=%q)", slug, r.Category, r.Code)
		}
	}
}

// TestParseSkipsWSTG verifies a WSTG checklist in the same directory is not
// mistaken for a rubric, which is what lets both families share one embed dir.
func TestParseSkipsWSTG(t *testing.T) { // mixed-directory tolerance
	fsys := fstest.MapFS{ // a rubric next to a WSTG checklist
		"Injection.md": {Data: []byte("# Testing Checklist\n\n| Test ID | Test Name |\n|---------|-----------|\n| **WSTG-INJT** | **Injection** |\n| WSTG-INJT-01 | SQL Injection |\n")},
		"Skill.md":     {Data: []byte("| # | Check | Evidence to look for |\n|---|-------|---------------------|\n| 1.1 | Something | Evidence |\n")},
	}
	rs, err := Load(fsys, ".") // load the mixed directory
	if err != nil {            // must not fail...
		t.Fatalf("Load on a mixed directory: %v", err)
	}
	if len(rs) != 1 { // only the rubric survives...
		t.Fatalf("rubrics = %d, want 1 (WSTG file skipped)", len(rs))
	}
	if rs[0].Slug != "skill" { // and it is the right one
		t.Errorf("kept slug %q, want skill", rs[0].Slug)
	}
}

// TestParseRejectsNonRubric checks the sentinel a file with no check rows
// returns, so callers can tell "not a rubric" apart from "broken rubric".
func TestParseNonRubricFile(t *testing.T) { // sentinel behaviour
	_, ok, err := Parse("Notes.md", "# Just prose\n\nNo table here at all.\n") // no rows
	if ok {                                                                    // must not report success...
		t.Error("ok = true, want false for a file with no check rows")
	}
	if !errors.Is(err, ErrNotRubric) { // and must return the sentinel
		t.Errorf("err = %v, want ErrNotRubric", err)
	}
}

// TestFind covers every handle an operator would reasonably type at the prompt:
// slug, code, category and bare file name, in any case.
func TestFind(t *testing.T) { // tolerant lookup
	rs := realRubrics(t)        // the shipped rubrics
	for _, q := range []string{ // every natural handle
		"malicious-skills", "MALICIOUS-SKILLS", "Malicious Skills", "MaliciousSkills",
		"maliciousskills.md", "MALICIOUS-SKILLS.MD",
	} {
		if _, ok := Find(rs, q); !ok { // all of these must resolve...
			t.Errorf("Find(%q) = false, want true", q)
		}
	}
	if _, ok := Find(rs, "no-such-rubric"); ok { // an unknown query must not
		t.Error("Find(no-such-rubric) = true, want false")
	}
}

// TestRulesCoverEveryCheck is the drift guard between the rubrics and the probe
// catalog: every numbered row in every shipped rubric must have at least one
// registered probe, so a rubric can never ship with a silently unevaluated check.
func TestRulesCoverEveryCheck(t *testing.T) { // rubric <-> rules coverage
	rs := realRubrics(t)   // the shipped rubrics
	for _, r := range rs { // for every rubric...
		for _, c := range r.Checks { // ...and every check in it...
			rule, ok := RuleFor(r.Slug, c.ID) // look the probes up
			if !ok {                          // a row with no probes...
				t.Errorf("%s %s has no registered rule (add one to rules.go)", r.Slug, c.ID)
				continue // report and keep checking the rest
			}
			if len(rule.Probes) == 0 { // a rule with an empty probe list...
				t.Errorf("%s %s: rule has zero probes", r.Slug, c.ID) // is just as unevaluated
			}
		}
	}
}

// TestNoOrphanRules checks the other direction of the coverage invariant: a rule
// must point at a rubric check that actually exists, so typos cannot leave dead
// probes behind that look wired up but never run.
func TestNoOrphanRules(t *testing.T) { // rules -> rubric coverage
	rs := realRubrics(t)                // the shipped rubrics
	ids := map[string]map[string]bool{} // slug -> set of check ids
	for _, r := range rs {              // index every real check id
		set := map[string]bool{}     // for this rubric
		for _, c := range r.Checks { // walk its checks
			set[c.ID] = true // record the id
		}
		ids[r.Slug] = set // index it
	}
	for _, rule := range AllRules() { // every registered rule...
		set, ok := ids[rule.Slug] // must name a real rubric...
		if !ok {
			t.Errorf("rule %s/%s references unknown rubric %q", rule.Slug, rule.CheckID, rule.Slug)
			continue
		}
		if !set[rule.CheckID] { // ...and a check id that exists in it
			t.Errorf("rule %s/%s references a check that does not exist", rule.Slug, rule.CheckID)
		}
	}
}

// TestSearchProbesWellFormed validates the invariant every search probe depends
// on: a non-empty pattern, a declared expectation, and a regex Go can compile.
// A malformed pattern would otherwise only surface at run time on a user's skill.
func TestSearchProbesWellFormed(t *testing.T) { // probe shape
	for _, rule := range AllRules() { // every rule...
		for i, p := range rule.Probes { // ...and every probe in it...
			switch p.Kind { // check by kind
			case ProbeSearch: // must carry a usable pattern
				if p.Pattern == "" { // an empty pattern matches nothing...
					t.Errorf("%s %s probe %d: empty pattern", rule.Slug, rule.CheckID, i)
				}
				if p.Expect == "" { // and must say how to judge it
					t.Errorf("%s %s probe %d: no expectation", rule.Slug, rule.CheckID, i)
				}
			case ProbeExec: // must carry a tool and arguments
				if p.ToolKey == "" { // no tool means no command...
					t.Errorf("%s %s probe %d: empty tool key", rule.Slug, rule.CheckID, i)
				}
				if _, ok := ToolCatalog()[p.ToolKey]; !ok { // ...and an unknown tool...
					t.Errorf("%s %s probe %d: unknown tool %q", rule.Slug, rule.CheckID, i, p.ToolKey)
				}
				joined := strings.Join(p.Args, " ")      // for the placeholder check
				if !strings.Contains(joined, "{path}") { // ...without {path} it cannot point at the skill
					t.Errorf("%s %s probe %d: args have no {path} placeholder", rule.Slug, rule.CheckID, i)
				}
			case ProbeManual: // must tell the human what to do
				if p.Manual == "" { // an empty instruction is not an instruction...
					t.Errorf("%s %s probe %d: empty manual guidance", rule.Slug, rule.CheckID, i)
				}
			default: // an unregistered kind would never run
				t.Errorf("%s %s probe %d: unknown kind %q", rule.Slug, rule.CheckID, i, p.Kind)
			}
		}
	}
}

// TestBuiltinSearchFindsMatch proves the in-process fallback actually scans a
// file: it is what makes the capability return results on a machine with no
// search tool installed at all.
func TestBuiltinSearchFindsMatch(t *testing.T) { // fallback scanner
	dir := t.TempDir() // a scratch skill directory
	// A skill that reaches for the SSH key directory: check 3.8 must find it.
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("Read ~/.ssh/id_rsa for convenience.\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := builtinSearch(context.Background(), "id_rsa", dir) // scan it
	if err != nil {                                                // must not error...
		t.Fatalf("builtinSearch: %v", err)
	}
	if !strings.Contains(got, "SKILL.md:1:") { // must return ripgrep-style evidence...
		t.Errorf("output = %q, want a SKILL.md:1: match", got)
	}
	// A pattern that must not match must leave the output empty.
	got, err = builtinSearch(context.Background(), "definitely-not-present-xyz", dir) // scan again
	if err != nil {                                                                   // still no error...
		t.Fatalf("builtinSearch: %v", err)
	}
	if got != "" { // no match means empty output...
		t.Errorf("output = %q, want empty", got)
	}
}

// TestBuiltinSearchSkipsGit checks the scanner does not read VCS internals,
// matching the `!.git/**` exclusion the ripgrep probe passes explicitly.
func TestBuiltinSearchSkipsGit(t *testing.T) { // no VCS internals
	dir := t.TempDir()                                                     // a scratch skill directory
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil { // a .git directory
		t.Fatalf("mkdir: %v", err)
	}
	// The only match lives inside .git, so a correct scan must return nothing.
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("canary-marker-here\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := builtinSearch(context.Background(), "canary-marker-here", dir) // scan it
	if err != nil {                                                            // must not error...
		t.Fatalf("builtinSearch: %v", err)
	}
	if got != "" { // .git must be excluded...
		t.Errorf("output = %q, want empty (.git must be skipped)", got)
	}
}

// TestRunRefusesWithoutEnable verifies the master switch gates a real run, which
// is the safety property every other active capability shares.
func TestRunRefusesWithoutEnable(t *testing.T) { // master switch
	r := realRubrics(t)[0]                                       // any rubric will do
	_, err := Run(context.Background(), r, t.TempDir(), Options{ // disabled...
		Enable: false, DryRun: false,
	})
	if !errors.Is(err, ops.ErrDisabled) { // must return the shared sentinel...
		t.Errorf("err = %v, want ErrDisabled", err)
	}
}

// TestRunRefusesOutOfScopePath verifies the path allowlist is enforced by Run
// itself, so a new caller cannot bypass it by forgetting a pre-check.
func TestRunRefusesOutOfScopePath(t *testing.T) { // path allowlist
	r := realRubrics(t)[0]                                   // any rubric will do
	outside := t.TempDir()                                   // a directory outside the allowlist
	_, err := Run(context.Background(), r, outside, Options{ // enabled, but out of scope
		Enable: true, DryRun: false,
		AllowedPaths: []string{filepath.Join(t.TempDir(), "allowed")}, // a different root
	})
	if err == nil { // must refuse...
		t.Fatal("Run outside allowed_paths = nil error, want a scope error")
	}
	if !strings.Contains(err.Error(), "allowed_paths") { // and say which allowlist denied it
		t.Errorf("err = %v, want an 'allowed_paths' message", err)
	}
}

// TestRunRequiresTarget verifies the usage error an operator gets when they
// forget the directory argument, rather than an obscure failure later on.
func TestRunRequiresTarget(t *testing.T) { // usage guard
	r := realRubrics(t)[0]                                  // any rubric will do
	_, err := Run(context.Background(), r, "  ", Options{}) // no path
	if !errors.Is(err, ErrNoTarget) {                       // must be the usage sentinel...
		t.Errorf("err = %v, want ErrNoTarget", err)
	}
}

// TestRunDryRunTouchesNothing checks a dry run executes no probe: the commands
// come back rendered, but no process is started and no file is read.
func TestRunDryRunTouchesNothing(t *testing.T) { // dry-run safety
	r := realRubrics(t)[0]                                         // any rubric will do
	res, err := Run(context.Background(), r, t.TempDir(), Options{ // dry run, no enable
		DryRun: true, Enable: false,
		Runner: fakeRunner{t: t, failIfCalled: true}, // any execution fails the test
	})
	if err != nil { // a dry run must not be refused...
		t.Fatalf("Run dry-run: %v", err)
	}
	if len(res) != len(r.Checks) { // one row per check, even in a dry run...
		t.Fatalf("results = %d, want %d", len(res), len(r.Checks))
	}
	for _, got := range res { // every row must be present...
		if got.Verdict == VerdictPass || got.Verdict == VerdictFail { // but never a real verdict...
			t.Errorf("%s: dry run returned %s, want no executed verdict", got.CheckID, got.Verdict)
		}
	}
}

// fakeRunner is a scan.CommandRunner that records calls and, optionally, fails
// any test that expected no execution.
type fakeRunner struct { // injected process seam
	t            *testing.T // the test to fail on unexpected calls
	failIfCalled bool       // when true, any call is a failure
	output       string     // canned output to return
	exitErr      error      // canned error to return (nil means success)
}

// Run records the call and returns the canned result. Value receiver so struct
// literals satisfy scan.CommandRunner without needing a pointer.
func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) { // seam method
	if f.failIfCalled { // the test forbade execution...
		f.t.Errorf("fakeRunner: unexpected call to %s %v", name, args) // fail loudly
	}
	if f.exitErr != nil { // a canned failure...
		return []byte(f.output), f.exitErr // ...returned as-is
	}
	return []byte(f.output), nil // otherwise canned output
}

// TestRunAggregatesVerdicts exercises the verdict precedence directly: a FAIL
// must dominate the row even when a sibling probe passed.
func TestRunAggregatesVerdicts(t *testing.T) { // verdict aggregation
	if got := aggregate([]ProbeResult{ // a failure next to a pass...
		{Verdict: VerdictPass}, {Verdict: VerdictFail},
	}); got != VerdictFail { // must read FAIL...
		t.Errorf("aggregate(PASS,FAIL) = %s, want FAIL", got)
	}
	if got := aggregate([]ProbeResult{ // an unavailable probe next to a pass...
		{Verdict: VerdictSkip}, {Verdict: VerdictPass},
	}); got != VerdictPass { // must read PASS, so a missing optional tool never hides a clean result
		t.Errorf("aggregate(SKIP,PASS) = %s, want PASS", got)
	}
	if got := aggregate([]ProbeResult{ // nothing ran at all...
		{Verdict: VerdictSkip}, {Verdict: VerdictSkip},
	}); got != VerdictSkip { // must read SKIP, never PASS
		t.Errorf("aggregate(SKIP,SKIP) = %s, want SKIP", got)
	}
	if got := aggregate(nil); got != VerdictSkip { // an empty probe set is not a pass
		t.Errorf("aggregate(nil) = %s, want SKIP", got)
	}
}

// TestJudgeSearch checks the two pattern-shaped expectations, which is where a
// subtly inverted regex would otherwise turn a violation into a pass.
func TestJudgeSearch(t *testing.T) { // expectation semantics
	if got := judgeSearch(ExpectNone, true); got != VerdictFail { // a match is a violation...
		t.Errorf("judgeSearch(none, found) = %s, want FAIL", got)
	}
	if got := judgeSearch(ExpectNone, false); got != VerdictPass { // no match is clean...
		t.Errorf("judgeSearch(none, absent) = %s, want PASS", got)
	}
	if got := judgeSearch(ExpectSome, true); got != VerdictPass { // required evidence present...
		t.Errorf("judgeSearch(some, found) = %s, want PASS", got)
	}
	if got := judgeSearch(ExpectSome, false); got != VerdictFail { // required evidence missing...
		t.Errorf("judgeSearch(some, absent) = %s, want FAIL", got)
	}
}

// TestPlanCoversEveryCheck guarantees `skill plan` prints one line per rubric
// row, so an operator can see the whole evaluation strategy at a glance.
func TestPlanCoversEveryCheck(t *testing.T) { // plan coverage
	for _, r := range realRubrics(t) { // every rubric...
		steps := Plan(r, "", Options{})  // ...planned with a placeholder target
		if len(steps) != len(r.Checks) { // one step per check...
			t.Errorf("%s: plan steps = %d, want %d", r.Slug, len(steps), len(r.Checks))
		}
		for _, s := range steps { // every step must say something concrete
			if s.Automated && s.Command == "" { // an automated step needs a command...
				t.Errorf("%s %s: automated but no command", r.Slug, s.CheckID)
			}
			if !s.Automated && s.Manual == "" { // a manual step needs guidance...
				t.Errorf("%s %s: manual but no guidance", r.Slug, s.CheckID)
			}
		}
	}
}

// TestPlanShowsPathPlaceholder verifies a plan with no target still renders the
// {path} placeholder, so the output reads as a template rather than a broken command.
func TestPlanShowsPathPlaceholder(t *testing.T) { // placeholder rendering
	r := realRubrics(t)[0]          // any rubric will do
	steps := Plan(r, "", Options{}) // no target
	found := false                  // whether any automated step rendered
	for _, s := range steps {       // walk the plan
		if s.Automated && strings.Contains(s.Command, "{path}") { // a template...
			found = true // ...seen
			break        // one is enough
		}
	}
	if !found { // none rendered a placeholder...
		t.Error("no automated plan step kept the {path} placeholder")
	}
}

// TestSearchCommandPrefersTools verifies the documented tool ladder: ripgrep
// when present, grep otherwise, and the built-in scanner as a last resort.
func TestSearchCommandLadder(t *testing.T) { // tool selection
	both := func(string) bool { return true }       // everything is installed
	none := func(string) bool { return false }      // nothing is installed
	_, cmd := searchCommandLine("pat", "dir", both) // with ripgrep present
	if !strings.HasPrefix(cmd, "rg ") {             // ripgrep must win...
		t.Errorf("cmd = %q, want an rg command", cmd)
	}
	tool, cmd := searchCommandLine("pat", "dir", none) // with nothing installed
	if tool != builtinSearchTool {                     // the built-in must take over...
		t.Errorf("tool = %q, want %q", tool, builtinSearchTool)
	}
	if !strings.Contains(cmd, "pat") || !strings.Contains(cmd, "dir") { // and still show the work
		t.Errorf("cmd = %q, want the pattern and target", cmd)
	}
}
