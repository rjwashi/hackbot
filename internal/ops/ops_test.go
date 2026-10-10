package ops // same package as the code under test

import ( // test imports
	"context" // pass a context to Run
	"errors"  // errors.Is for the disabled sentinel
	"strings" // assertions on rendered commands
	"testing" // the testing framework
)

// fakeRunner records calls and returns canned output (implements scan.CommandRunner).
type fakeRunner struct {
	calls [][]string
	out   []byte
	err   error
}

// Run records the command and returns the canned result.
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

// TestCatalogsValid verifies both shipped catalogs are internally consistent.
func TestCatalogsValid(t *testing.T) { // guards recon.go + discovery.go
	for _, c := range []*Catalog{ReconCatalog(), DiscoveryCatalog()} { // both catalogs...
		if c.Name == "" || c.Summary == "" { // ...need identity
			t.Errorf("catalog missing name/summary: %+v", c)
		}
		seen := map[string]bool{}        // task-key uniqueness
		for _, task := range c.Tasks() { // every task...
			if task.Key == "" || task.Name == "" { // ...needs identity
				t.Errorf("%s: incomplete task: %+v", c.Name, task)
			}
			if seen[task.Key] { // duplicate task key
				t.Errorf("%s: duplicate task key %q", c.Name, task.Key)
			}
			seen[task.Key] = true
			if _, ok := c.ToolByKey(task.ToolKey); !ok { // ...must resolve its tool
				t.Errorf("%s: task %s references unknown tool %q", c.Name, task.Key, task.ToolKey)
			}
			if len(task.Args) == 0 { // ...must have arguments
				t.Errorf("%s: task %s has no args", c.Name, task.Key)
			}
			if !task.Guarded { // every shipped task sends traffic
				t.Errorf("%s: task %s not marked guarded", c.Name, task.Key)
			}
			if task.Group == "" { // grouping is required for `tools <group>`
				t.Errorf("%s: task %s has no group", c.Name, task.Key)
			}
		}
		for _, g := range c.GroupNames() { // every group...
			if len(c.ToolsFor(g)) == 0 { // ...must resolve at least one tool
				t.Errorf("%s: group %q has no tools", c.Name, g)
			}
		}
		for _, tool := range c.Tools() { // every tool...
			if tool.Key == "" || tool.Bin == "" || tool.URL == "" || tool.License == "" { // ...needs the basics
				t.Errorf("%s: incomplete tool: %+v", c.Name, tool)
			}
		}
	}
}

// TestSubsAndRender verifies placeholder substitution semantics.
func TestSubsAndRender(t *testing.T) { // plan vs run rendering
	// With no target, placeholders are left literal (plan mode).
	subs := Subs("https", "", "")
	got := Render([]string{"-u", "{url}", "-w", "{wordlist}"}, subs)
	if got[1] != "{url}" || got[3] != "{wordlist}" {
		t.Errorf("empty-target render = %v", got)
	}
	// With a target and wordlist, everything is filled in.
	subs = Subs("https", "example.com", "/wl.txt")
	got = Render([]string{"-u", "{url}", "-H", "Host: FUZZ.{host}", "-w", "{wordlist}"}, subs)
	if got[1] != "https://example.com" || got[3] != "Host: FUZZ.example.com" || got[5] != "/wl.txt" {
		t.Errorf("rendered = %v", got)
	}
}

// TestPlan verifies the plan covers every task and renders commands.
func TestPlan(t *testing.T) { // `<cmd> plan`
	c := ReconCatalog()                         // recon
	steps := c.Plan("https", "example.com", "") // with a target
	if len(steps) != len(c.Tasks()) {           // one step per task
		t.Fatalf("steps = %d, want %d", len(steps), len(c.Tasks()))
	}
	for _, s := range steps { // each step is fully rendered
		if s.Tool == "" || s.Command == "" {
			t.Errorf("incomplete step: %+v", s)
		}
		if strings.Contains(s.Command, "{") { // no placeholders left with a target
			t.Errorf("unrendered placeholder in %q", s.Command)
		}
	}
}

// TestRunnerDryRun verifies dry-run renders a command and runs nothing.
func TestRunnerDryRun(t *testing.T) { // safe preview
	fake := &fakeRunner{}                                                          // must not be called
	r := New(ReconCatalog(), Options{DryRun: true, Runner: fake, Scheme: "https"}) // dry-run
	task, _ := r.cat.TaskByKey("http")
	res, err := r.Run(context.Background(), task, "example.com")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.DryRun || res.OK || res.Command == "" || len(fake.calls) != 0 {
		t.Errorf("dry-run result = %+v calls=%v", res, fake.calls)
	}
	if !strings.Contains(res.Command, "httpx") { // right tool
		t.Errorf("command = %q", res.Command)
	}
}

// TestRunnerDisabled verifies a real run refuses without enable.
func TestRunnerDisabled(t *testing.T) { // master switch
	fake := &fakeRunner{}
	r := New(ReconCatalog(), Options{Enable: false, DryRun: false, Runner: fake})
	task, _ := r.cat.TaskByKey("subdomains")
	if _, err := r.Run(context.Background(), task, "example.com"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
	if len(fake.calls) != 0 {
		t.Errorf("runner was called: %v", fake.calls)
	}
}

// TestRunnerScope verifies both the IP and domain allowlists gate real runs.
func TestRunnerScope(t *testing.T) { // allowlists
	fake := &fakeRunner{}
	r := New(ReconCatalog(), Options{
		Enable:         true,
		DryRun:         false,
		AllowedTargets: []string{"10.0.0.0/24"},
		AllowedDomains: []string{"example.com"},
		Runner:         fake,
	})
	task, _ := r.cat.TaskByKey("subdomains")

	if _, err := r.Run(context.Background(), task, "evil.test"); err == nil { // unknown domain
		t.Error("expected out-of-scope error for evil.test")
	}
	if len(fake.calls) != 0 { // nothing ran
		t.Errorf("runner was called: %v", fake.calls)
	}
	if _, err := r.Run(context.Background(), task, "www.example.com"); err != nil { // allowed subdomain
		t.Fatalf("in-scope domain refused: %v", err)
	}
	if len(fake.calls) != 1 { // it ran once
		t.Errorf("calls = %v", fake.calls)
	}
}

// TestRunnerExecutes verifies an in-scope run reaches the tool with the target arg.
func TestRunnerExecutes(t *testing.T) { // happy path
	fake := &fakeRunner{out: []byte("found\n")}
	r := New(DiscoveryCatalog(), Options{
		Enable:         true,
		DryRun:         false,
		AllowedDomains: []string{"example.com"},
		Wordlist:       "/wl.txt",
		Runner:         fake,
	})
	task, _ := r.cat.TaskByKey("dirs")
	res, err := r.Run(context.Background(), task, "example.com")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OK || res.Output != "found" {
		t.Errorf("result = %+v", res)
	}
	if len(fake.calls) != 1 || fake.calls[0][0] != "ffuf" {
		t.Fatalf("calls = %v", fake.calls)
	}
	joined := strings.Join(fake.calls[0], " ")
	if !strings.Contains(joined, "https://example.com/FUZZ") || !strings.Contains(joined, "/wl.txt") {
		t.Errorf("args = %v", fake.calls[0])
	}
}

// TestRunnerToolError verifies a tool failure is returned as evidence.
func TestRunnerToolError(t *testing.T) { // missing tool
	fake := &fakeRunner{out: []byte("not found"), err: errors.New("exit status 127")}
	r := New(ReconCatalog(), Options{Enable: true, DryRun: false, AllowedDomains: []string{"example.com"}, Runner: fake})
	task, _ := r.cat.TaskByKey("whois")
	res, err := r.Run(context.Background(), task, "example.com")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK || res.Error == "" || res.Output != "not found" {
		t.Errorf("result = %+v", res)
	}
}
