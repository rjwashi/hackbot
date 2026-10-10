// Package ops is the guarded-operations engine shared by hackbot's recon/OSINT
// and content-discovery agents.
//
// WHY a shared engine: the WSTG work already proved the shape we want — a catalog
// of free tools, a list of runnable tasks with fixed argument templates, and a
// runner that refuses unless scanning is enabled and the target is allowlisted.
// Recon and discovery need exactly that shape, so instead of copy-pasting it
// twice we factor it here. wstg keeps its own (checklist-shaped) capability layer
// because it also parses Markdown; ops is the task-shaped general case.
//
// Safety: nothing here executes on its own. The Runner in runner.go is the only
// executor, and it enforces both gates (enable + scope) before any process runs.
// Argument templates are fixed strings, so user input never reaches a shell.
package ops // importable as "ops"

import ( // imports for this file
	"fmt"     // Errorf for scope-refusal messages
	"sort"    // deterministic tool/task ordering
	"strings" // command rendering

	"github.com/rjwashi/hackbot/internal/scan" // reuse InScope/TargetInScope + CommandRunner
)

// DefaultWordlist is the fallback wordlist for content discovery when neither the
// config nor the -wordlist flag supplies one. It is the widely used, free
// SecLists "common.txt"; using a well-known default keeps the dry-run output
// meaningful even before an operator picks a list.
const DefaultWordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt" // free (SecLists)

// Target kinds tell the engine which allowlist (and which placeholder math) a
// catalog uses. Most catalogs are host-based (IPs/CIDRs/domains); the secrets and
// dependency/SBOM catalogs are path-based (local directories). Keeping the kind
// on the catalog — rather than inferring it from the arguments — means the scope
// gate is decided by the catalog's intent, not by a guess about user input.
const (
	KindHost = "host" // target is an IP/CIDR/domain; gated by allowed_targets/domains
	KindPath = "path" // target is a local directory; gated by allowed_paths
)

// Tool describes a free/open-source tool hackbot can drive.
//
// It mirrors wstg.Tool's shape on purpose: the two catalogs read the same way in
// `tools` output, and a future refactor could unify them. We keep a separate type
// for now so these packages evolve independently.
type Tool struct { // one catalog entry
	Key     string `json:"key"`               // short id used by tasks, e.g. "subfinder"
	Name    string `json:"name"`              // display name, e.g. "Subfinder"
	Bin     string `json:"bin"`               // executable name
	Kind    string `json:"kind"`              // recon|resolver|probe|scanner|fuzzer|cli
	URL     string `json:"url"`               // project home (free)
	License string `json:"license"`           // license (all free/open-source)
	Install string `json:"install,omitempty"` // one-line install hint
	Notes   string `json:"notes,omitempty"`   // what it is good for
}

// Task is a runnable capability: one tool plus a fixed argument template.
//
// Placeholders are substituted by the runner at run time: {target}, {host},
// {url}, {domain}, {path}, and {wordlist}. {path} is for path-based catalogs
// (secrets/deps) and is the local directory target. Keeping arguments as a
// template (rather than a free-form string) is what lets us render an honest
// dry-run and guarantees the target is passed as a single argv element, never
// shell-interpolated.
type Task struct { // one runnable capability
	Key     string   `json:"key"`            // task id, e.g. "subdomains"
	Name    string   `json:"name"`           // human name, e.g. "Subdomain enumeration"
	Group   string   `json:"group"`          // grouping key for `tools <group>`
	ToolKey string   `json:"tool"`           // catalog key
	Args    []string `json:"args"`           // argument template
	Guarded bool     `json:"guarded"`        // true when the task must pass the enable gate (sends traffic or reads scoped local data)
	Note    string   `json:"note,omitempty"` // short caveat / purpose
}

// Catalog is a named set of tools, tool groups, and tasks (recon, discovery,
// secrets, deps, ...).
type Catalog struct { // one engine instance
	Name    string              // e.g. "recon"
	Kind    string              // KindHost or KindPath: which allowlist gates runs
	Summary string              // one-line description for `list`
	BaseURL string              // reference link (e.g. the project docs)
	tools   map[string]Tool     // key -> tool
	groups  map[string][]string // group -> tool keys (for `tools <group>`)
	tasks   []Task              // runnable capabilities, in display order
	chains  []Chain             // multi-step pipelines (e.g. recon footprint)
}

// Chain is a named, ordered pipeline that runs several tasks and can feed one
// step's output into the next (e.g. subfinder -> httpx). Chains exist so a whole
// workflow is a first-class, previewable thing rather than a shell one-liner the
// safety model cannot see: the runner still gates the chain, and a dry-run shows
// every step before anything executes.
type Chain struct { // one pipeline
	Key   string      `json:"key"`            // id, e.g. "footprint"
	Name  string      `json:"name"`           // human name
	Note  string      `json:"note,omitempty"` // what the chain accomplishes
	Steps []ChainStep `json:"steps"`          // ordered steps
}

// ChainStep is one task in a chain.
type ChainStep struct { // one link
	TaskKey      string   `json:"task"`                    // task to run
	Args         []string `json:"args,omitempty"`          // optional args override (e.g. drop -u to read stdin)
	FeedPrevious bool     `json:"feed_previous,omitempty"` // pipe the previous step's stdout into this one
}

// NewCatalog assembles a Catalog from its parts. kind is KindHost or KindPath;
// an empty kind defaults to KindHost so older call sites keep host semantics.
//
// It is exported so recon.go/discovery.go/secrets.go/deps.go (same package) can
// build catalogs declaratively, and so tests can construct small catalogs.
func NewCatalog(name, kind, summary, baseURL string, tools map[string]Tool, groups map[string][]string, tasks []Task) *Catalog {
	if kind == "" { // default to the host gate...
		kind = KindHost // ...so a missing kind can never silently mean "path"
	}
	return &Catalog{Name: name, Kind: kind, Summary: summary, BaseURL: baseURL, tools: tools, groups: groups, tasks: tasks}
}

// WithChains attaches pipelines to a catalog and returns the catalog (builder).
func (c *Catalog) WithChains(chains ...Chain) *Catalog { // fluent, keeps NewCatalog stable
	c.chains = chains
	return c
}

// Chains returns the catalog's pipelines (a copy, so callers can't mutate).
func (c *Catalog) Chains() []Chain { // used by `<cmd> chains` and the runner
	out := make([]Chain, len(c.chains))
	copy(out, c.chains)
	return out
}

// ChainByKey looks up a chain by key (case-insensitive).
func (c *Catalog) ChainByKey(key string) (Chain, bool) { // used by `<cmd> <chain>`
	k := strings.ToLower(strings.TrimSpace(key))
	for _, ch := range c.chains {
		if strings.EqualFold(ch.Key, k) {
			return ch, true
		}
	}
	return Chain{}, false
}

// Tools returns the whole catalog sorted by key (deterministic for display).
func (c *Catalog) Tools() []Tool { // used by `<cmd> tools`
	keys := make([]string, 0, len(c.tools)) // collect keys
	for k := range c.tools {                // walk the map
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable order
	out := make([]Tool, 0, len(keys))
	for _, k := range keys { // materialize
		out = append(out, c.tools[k])
	}
	return out
}

// ToolByKey looks up a tool by key.
func (c *Catalog) ToolByKey(key string) (Tool, bool) { // used by the runner + plan
	t, ok := c.tools[key]
	return t, ok
}

// ToolsFor returns the tools in a named group, in declared order.
func (c *Catalog) ToolsFor(group string) []Tool { // used by `<cmd> tools <group>`
	keys := c.groups[group] // curated keys
	out := make([]Tool, 0, len(keys))
	for _, k := range keys { // resolve each
		if t, ok := c.tools[k]; ok {
			out = append(out, t)
		}
	}
	return out
}

// GroupNames returns the group keys sorted.
func (c *Catalog) GroupNames() []string { // used by help/usage
	keys := make([]string, 0, len(c.groups))
	for k := range c.groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Tasks returns the tasks in declared order (a copy, so callers can't mutate).
func (c *Catalog) Tasks() []Task { // used by `<cmd> list` and the runner
	out := make([]Task, len(c.tasks))
	copy(out, c.tasks)
	return out
}

// TaskByKey looks up a task by its key (case-insensitive).
func (c *Catalog) TaskByKey(key string) (Task, bool) { // used by `<cmd> <task>`
	k := strings.ToLower(strings.TrimSpace(key))
	for _, t := range c.tasks {
		if strings.EqualFold(t.Key, k) {
			return t, true
		}
	}
	return Task{}, false
}

// Subs computes the placeholder substitutions for a run.
//
// WHEN target is empty we return no substitutions, so `plan` output shows the
// template ({url}, {host}) instead of an empty string — that is what makes a plan
// read as a plan rather than a broken command. When target is set we derive the
// host/domain by stripping any scheme/port/path (via scan.NormalizeDomain, the
// same normalizer the scope check uses, so display and safety agree).
//
// kind matters: a KindPath target is a directory, not a host, so we set {path}
// and deliberately do NOT compute {host}/{domain}/{url} from it (passing a
// filesystem path through NormalizeDomain would produce nonsense). A KindHost
// target gets the host/domain/url set as before.
func Subs(kind, scheme, target, wordlist string) map[string]string { // shared by plan + runner
	subs := map[string]string{}          // placeholder -> value
	if strings.TrimSpace(target) != "" { // only substitute when we have a target
		subs["target"] = strings.TrimSpace(target) // always: the raw target
		if kind == KindPath {                      // path-based catalog...
			subs["path"] = strings.TrimSpace(target) // ...the directory is {path}
		} else { // host-based catalog
			host := scan.NormalizeDomain(target) // strip scheme/port/path
			if host == "" {                      // a bare IPv6 or odd input...
				host = strings.TrimSpace(target) // ...fall back to the raw target
			}
			subs["host"] = host                                      // host form
			subs["domain"] = host                                    // domain alias
			subs["url"] = scheme + "://" + strings.TrimSpace(target) // URL form
		}
	}
	if strings.TrimSpace(wordlist) != "" { // a wordlist only matters when set
		subs["wordlist"] = strings.TrimSpace(wordlist)
	}
	return subs
}

// Render substitutes placeholders in an argument template.
//
// Any placeholder without a value is left literal, which is how a plan shows
// "{url}" before a target is chosen.
func Render(args []string, subs map[string]string) []string { // shared by plan + runner
	out := make([]string, len(args)) // one output per input
	for i, a := range args {         // copy + substitute each arg
		for k, v := range subs { // apply every known substitution
			a = strings.ReplaceAll(a, "{"+k+"}", v)
		}
		out[i] = a
	}
	return out
}

// CommandLine renders a full command line for a tool and a template.
func CommandLine(t Tool, args []string, subs map[string]string) string { // used by plan + dry-run
	parts := append([]string{t.Bin}, Render(args, subs)...) // bin + rendered args
	return strings.Join(parts, " ")                         // readable one-liner
}

// PlanStep is one line of a plan: a task and the command it would run.
type PlanStep struct { // used by `<cmd> plan`
	TaskKey string `json:"task"`              // task id
	Name    string `json:"name"`              // task name
	Tool    string `json:"tool,omitempty"`    // tool display name
	Command string `json:"command,omitempty"` // rendered command (placeholders if no target)
	Guarded bool   `json:"guarded"`           // sends traffic to the target
}

// Plan renders every task as a step, resolving tools and commands.
//
// With an empty target the commands keep their placeholders; with a target they
// are fully rendered. This single function powers both `<cmd> plan` and the
// dry-run banner.
func (c *Catalog) Plan(scheme, target, wordlist string) []PlanStep { // used by `<cmd> plan`
	subs := Subs(c.Kind, scheme, target, wordlist) // compute substitutions once
	steps := make([]PlanStep, 0, len(c.tasks))
	for _, t := range c.tasks { // one step per task
		tool, ok := c.ToolByKey(t.ToolKey) // resolve the tool
		cmd := ""                          // command text
		name := ""                         // tool display name
		if ok {                            // only when the tool resolves
			name = tool.Name
			cmd = CommandLine(tool, t.Args, subs)
		}
		steps = append(steps, PlanStep{ // record the step
			TaskKey: t.Key,
			Name:    t.Name,
			Tool:    name,
			Command: cmd,
			Guarded: t.Guarded,
		})
	}
	return steps
}

// CheckScope applies the allowlist gate appropriate to a catalog kind.
//
// It is exported so the CLI can pre-check for a precise message while the Runner
// re-checks authoritatively; both call this one function so the two can never
// disagree. KindPath consults allowedPaths via scan.PathInScope; anything else
// consults the IP and domain allowlists via scan.TargetInScope.
func CheckScope(kind, target string, allowedTargets, allowedDomains, allowedPaths []string) error { // shared gate
	if kind == KindPath { // local filesystem target
		if !scan.PathInScope(target, allowedPaths) { // gated by allowed_paths
			return fmt.Errorf("path %q is not inside allowed_paths; refusing to run", target)
		}
		return nil
	}
	if !scan.TargetInScope(target, allowedTargets, allowedDomains) { // IP or domain allowlist
		return fmt.Errorf("target %q is not in the configured allowlist; refusing to run", target)
	}
	return nil
}
