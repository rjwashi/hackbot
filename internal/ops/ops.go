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
	"sort"    // deterministic tool/task ordering
	"strings" // command rendering

	"github.com/rjwashi/hackbot/internal/scan" // reuse InScope/TargetInScope + CommandRunner
)

// DefaultWordlist is the fallback wordlist for content discovery when neither the
// config nor the -wordlist flag supplies one. It is the widely used, free
// SecLists "common.txt"; using a well-known default keeps the dry-run output
// meaningful even before an operator picks a list.
const DefaultWordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt" // free (SecLists)

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
// {url}, {domain}, and {wordlist}. Keeping arguments as a template (rather than a
// free-form string) is what lets us render an honest dry-run and guarantees the
// target is passed as a single argv element, never shell-interpolated.
type Task struct { // one runnable capability
	Key     string   `json:"key"`            // task id, e.g. "subdomains"
	Name    string   `json:"name"`           // human name, e.g. "Subdomain enumeration"
	Group   string   `json:"group"`          // grouping key for `tools <group>`
	ToolKey string   `json:"tool"`           // catalog key
	Args    []string `json:"args"`           // argument template
	Guarded bool     `json:"guarded"`        // true when it sends traffic to the target
	Note    string   `json:"note,omitempty"` // short caveat / purpose
}

// Catalog is a named set of tools, tool groups, and tasks (recon or discovery).
type Catalog struct { // one engine instance
	Name    string              // e.g. "recon"
	Summary string              // one-line description for `list`
	BaseURL string              // reference link (e.g. the project docs)
	tools   map[string]Tool     // key -> tool
	groups  map[string][]string // group -> tool keys (for `tools <group>`)
	tasks   []Task              // runnable capabilities, in display order
}

// NewCatalog assembles a Catalog from its parts.
//
// It is exported so recon.go/discovery.go (same package) can build catalogs
// declaratively, and so tests can construct small catalogs without files.
func NewCatalog(name, summary, baseURL string, tools map[string]Tool, groups map[string][]string, tasks []Task) *Catalog {
	return &Catalog{Name: name, Summary: summary, BaseURL: baseURL, tools: tools, groups: groups, tasks: tasks}
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
func Subs(scheme, target, wordlist string) map[string]string { // shared by plan + runner
	subs := map[string]string{}          // placeholder -> value
	if strings.TrimSpace(target) != "" { // only substitute when we have a target
		host := scan.NormalizeDomain(target) // strip scheme/port/path
		if host == "" {                      // a bare IPv6 or odd input...
			host = strings.TrimSpace(target) // ...fall back to the raw target
		}
		subs["target"] = strings.TrimSpace(target)
		subs["host"] = host
		subs["domain"] = host
		subs["url"] = scheme + "://" + strings.TrimSpace(target)
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
	subs := Subs(scheme, target, wordlist) // compute substitutions once
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
