package ops // same package as the code under test

import ( // test imports
	"context" // pass a context to Run
	"errors"  // errors.Is for the disabled sentinel
	"strings" // assertions on rendered commands
	"testing" // the testing framework

	"github.com/rjwashi/hackbot/internal/scan" // PathInScope in the prefix-trap test
)

// fakeRunner records calls and returns canned output (implements scan.CommandRunner).
// It also implements scan.StdinRunner so chain tests can exercise the piped path.
type fakeRunner struct {
	calls  [][]string
	stdins [][]byte
	out    []byte
	err    error
}

// Run records the command and returns the canned result.
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

// RunStdin records the command plus the piped stdin and returns the canned result.
func (f *fakeRunner) RunStdin(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	f.stdins = append(f.stdins, stdin)
	return f.out, f.err
}

// TestCatalogsValid verifies every shipped catalog is internally consistent.
func TestCatalogsValid(t *testing.T) { // guards recon.go + discovery.go + secrets.go + deps.go
	for _, c := range []*Catalog{ReconCatalog(), DiscoveryCatalog(), SecretsCatalog(), DepsCatalog()} { // all catalogs...
		if c.Name == "" || c.Summary == "" { // ...need identity
			t.Errorf("catalog missing name/summary: %+v", c)
		}
		if c.Kind != KindHost && c.Kind != KindPath { // ...and a valid target kind
			t.Errorf("%s: invalid kind %q", c.Name, c.Kind)
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
	subs := Subs(KindHost, "https", "", "")
	got := Render([]string{"-u", "{url}", "-w", "{wordlist}"}, subs)
	if got[1] != "{url}" || got[3] != "{wordlist}" {
		t.Errorf("empty-target render = %v", got)
	}
	// With a target and wordlist, everything is filled in.
	subs = Subs(KindHost, "https", "example.com", "/wl.txt")
	got = Render([]string{"-u", "{url}", "-H", "Host: FUZZ.{host}", "-w", "{wordlist}"}, subs)
	if got[1] != "https://example.com" || got[3] != "Host: FUZZ.example.com" || got[5] != "/wl.txt" {
		t.Errorf("rendered = %v", got)
	}
	// A path target fills {path} and deliberately does NOT set {host}/{url}.
	subs = Subs(KindPath, "https", "/srv/app", "")
	got = Render([]string{"dir", "{path}"}, subs)
	if got[1] != "/srv/app" {
		t.Errorf("path render = %v", got)
	}
	if _, ok := subs["host"]; ok {
		t.Errorf("path kind must not set {host}: %v", subs)
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

// TestChainsValid verifies every declared chain resolves its tasks and wires the
// piped steps sanely (never a first step that reads nonexistent previous output).
func TestChainsValid(t *testing.T) { // guards chain definitions
	for _, c := range []*Catalog{ReconCatalog(), DiscoveryCatalog(), SecretsCatalog(), DepsCatalog()} {
		for _, ch := range c.Chains() { // every chain...
			if ch.Key == "" || ch.Name == "" || len(ch.Steps) == 0 { // ...needs identity + steps
				t.Errorf("%s: incomplete chain: %+v", c.Name, ch)
			}
			for i, st := range ch.Steps { // every step...
				if _, ok := c.TaskByKey(st.TaskKey); !ok { // ...must resolve its task
					t.Errorf("%s: chain %q references unknown task %q", c.Name, ch.Key, st.TaskKey)
				}
				if st.FeedPrevious && i == 0 { // ...and only later steps may read stdin
					t.Errorf("%s: chain %q step 1 cannot read previous output", c.Name, ch.Key)
				}
			}
		}
	}
}

// TestRunnerPathScope verifies a KindPath catalog is gated by allowed_paths.
func TestRunnerPathScope(t *testing.T) { // local filesystem gate
	fake := &fakeRunner{}
	r := New(SecretsCatalog(), Options{
		Enable:       true,
		DryRun:       false,
		AllowedPaths: []string{"/srv/app"},
		Runner:       fake,
	})
	task, _ := r.cat.TaskByKey("scan")

	if _, err := r.Run(context.Background(), task, "/etc"); err == nil { // outside the root
		t.Error("expected out-of-scope error for /etc")
	}
	if len(fake.calls) != 0 { // nothing ran
		t.Errorf("runner was called: %v", fake.calls)
	}
	if _, err := r.Run(context.Background(), task, "/srv/app/internal"); err != nil { // inside the root
		t.Fatalf("in-scope path refused: %v", err)
	}
	if len(fake.calls) != 1 { // it ran once
		t.Errorf("calls = %v", fake.calls)
	}
}

// TestRunnerPathScopePrefixTrap verifies /srv/app-evil is NOT treated as inside
// /srv/app (the path equivalent of the "notexample.com" domain trap).
func TestRunnerPathScopePrefixTrap(t *testing.T) { // segment-boundary check
	if scan.PathInScope("/srv/app-evil", []string{"/srv/app"}) {
		t.Error("/srv/app-evil must not be inside /srv/app")
	}
	if !scan.PathInScope("/srv/app/sub", []string{"/srv/app"}) {
		t.Error("/srv/app/sub should be inside /srv/app")
	}
}

// TestRunnerChainDryRun verifies a chain previews every step and runs nothing.
func TestRunnerChainDryRun(t *testing.T) { // footprint preview
	fake := &fakeRunner{}
	r := New(ReconCatalog(), Options{DryRun: true, Runner: fake, Scheme: "https"})
	ch, ok := r.cat.ChainByKey("footprint") // the shipped chain
	if !ok {
		t.Fatal("footprint chain missing")
	}
	res, err := r.RunChain(context.Background(), ch, "example.com")
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if len(res) != 2 { // two steps
		t.Fatalf("steps = %d, want 2", len(res))
	}
	if !res[0].DryRun || !res[1].DryRun { // both previewed
		t.Errorf("dry-run flags = %+v", res)
	}
	if !res[1].Stdin { // the second step is marked as reading stdin
		t.Errorf("second step should be marked stdin: %+v", res[1])
	}
	if strings.Contains(res[1].Command, "{") { // and fully rendered
		t.Errorf("unrendered placeholder in %q", res[1].Command)
	}
	if len(fake.calls) != 0 { // nothing executed
		t.Errorf("runner was called: %v", fake.calls)
	}
}

// TestRunnerChainExec verifies the previous step's stdout is piped to the next.
func TestRunnerChainExec(t *testing.T) { // footprint execution
	fake := &fakeRunner{out: []byte("a.example.com\n")}
	r := New(ReconCatalog(), Options{
		Enable:         true,
		DryRun:         false,
		AllowedDomains: []string{"example.com"},
		Scheme:         "https",
		Runner:         fake,
	})
	ch, _ := r.cat.ChainByKey("footprint")
	res, err := r.RunChain(context.Background(), ch, "example.com")
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}
	if len(res) != 2 || !res[0].OK || !res[1].OK { // both succeeded
		t.Fatalf("results = %+v", res)
	}
	if len(fake.stdins) != 1 || string(fake.stdins[0]) != "a.example.com\n" { // piped verbatim
		t.Fatalf("stdins = %q", fake.stdins)
	}
}

// TestRunnerChainScope verifies the chain's single up-front gate refuses an
// out-of-scope target before any step runs.
func TestRunnerChainScope(t *testing.T) { // chain scope gate
	fake := &fakeRunner{}
	r := New(ReconCatalog(), Options{
		Enable:         true,
		DryRun:         false,
		AllowedDomains: []string{"example.com"},
		Runner:         fake,
	})
	ch, _ := r.cat.ChainByKey("footprint")
	if _, err := r.RunChain(context.Background(), ch, "evil.test"); err == nil {
		t.Error("expected out-of-scope error for evil.test")
	}
	if len(fake.calls) != 0 {
		t.Errorf("runner was called: %v", fake.calls)
	}
}
