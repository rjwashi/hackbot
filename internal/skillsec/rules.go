package skillsec // same package as the code under test

import ( // imports for this file
	"strings" // Expand's literal substitution and joinCmd's rendering

	"github.com/rjwashi/hackbot/internal/ops" // reuse ops.Tool so the two catalogs read alike
)

// This file is the heart of the skill-evaluation capability: it maps every
// numbered rubric check onto something that can actually be run and observed,
// rather than onto prose. Three probe kinds exist because the rubrics mix three
// kinds of question:
//
//   - search probes look for a regex inside the skill's files. This is the
//     workhorse: it answers both "does the skill declare X" and "does the skill
//     do Y" checks, and it runs through ripgrep or grep with a pure-Go fallback
//     so a bare machine still produces results instead of a row of SKIPs.
//   - exec probes run a real external command (git provenance lookup, git
//     signature verification, semgrep's intent-oriented scan, gitleaks' secret
//     detection). These are the checks where a purpose-built tool answers the
//     question better than a regex, and they are what makes the capability
//     "execute commands to get results" rather than "display a checklist".
//   - manual probes are the checks that genuinely cannot be decided from static
//     evidence (canary-testing a skill in a sandbox). They are reported as
//     MANUAL with instructions instead of being silently skipped, so a report
//     never looks greener than it is.
//
// Every tool here is free and open-source, which is a hard requirement for this
// project: ripgrep (MIT), grep (GPL-3.0), git (GPL-2.0), semgrep (LGPL-2.1) and
// gitleaks (MIT). Nothing in this file phones home or needs a licence key.
//
// All search probes run case-insensitively (the -i flag on the command line and
// a (?i) prefix on the built-in scanner) because the rubric rows talk about
// concepts, not about a particular capitalisation a skill author happened to use.

// ProbeKind tells the runner how to obtain evidence for one probe.
type ProbeKind string // the three ways a probe can gather evidence

const (
	// ProbeSearch greps the skill's files for Probe.Pattern.
	ProbeSearch ProbeKind = "search"
	// ProbeExec runs Probe.ToolKey with Probe.Args as a real process.
	ProbeExec ProbeKind = "exec"
	// ProbeManual cannot be automated and needs human judgment.
	ProbeManual ProbeKind = "manual"
)

// Expectation decides what a probe's raw output means for the verdict.
//
// The distinction matters because the probes answer different questions: some
// look for a violation that must be absent, some look for evidence that must be
// present, some care only about whether the command itself succeeded, and some
// hand evidence to a human who weighs it.
type Expectation string // how to interpret probe output

const (
	// ExpectNone fails when a match was found: the violation exists.
	ExpectNone Expectation = "none"
	// ExpectSome fails when no match was found: required evidence is missing.
	ExpectSome Expectation = "some"
	// ExpectExit0 fails when the command exits non-zero (git verify-commit with
	// no signature, or gitleaks finding a leaked key).
	ExpectExit0 Expectation = "exit0"
	// ExpectReview always reports REVIEW: the evidence is real but the rubric
	// leaves the final judgment to a person.
	ExpectReview Expectation = "review"
)

// Probe is one executable step for one rubric check.
type Probe struct { // what to run and how to read the result
	Kind    ProbeKind   `json:"kind"`              // search | exec | manual
	ToolKey string      `json:"tool,omitempty"`    // exec: which tool in the catalog
	Args    []string    `json:"args,omitempty"`    // exec: arguments, with {path}
	Pattern string      `json:"pattern,omitempty"` // search: the regex to look for
	Expect  Expectation `json:"expect,omitempty"`  // how to judge output
	GoOnly  bool        `json:"go_only,omitempty"` // search: always use the built-in scanner
	Manual  string      `json:"manual,omitempty"`  // manual: what a human must do
	Note    string      `json:"note,omitempty"`    // why this probe answers the check
}

// Rule attaches probes to one numbered check of one rubric.
//
// A check may need more than one probe: "no access to credential stores" is
// answered both by searching for the paths a skill must never touch and by
// running gitleaks over the whole directory, because the second sees inside
// files the first can only name. All probes of a check contribute to a single
// verdict, so a report still has exactly one row per rubric row.
type Rule struct { // one rubric check's probes
	Slug    string  `json:"slug"`   // which rubric, e.g. "over-privileged-skills"
	CheckID string  `json:"check"`  // which check, e.g. "3.8"
	Probes  []Probe `json:"probes"` // the probes, in execution order
}

// ToolCatalog returns the free/open-source tools the probes drive. It returns a
// fresh map each call so callers cannot mutate the shared catalog.
func ToolCatalog() map[string]ops.Tool { // used by `skill rules`
	return map[string]ops.Tool{ // every tool here is free and open-source
		"rg": { // ripgrep: the preferred pattern search (fast, safe defaults)
			Key: "rg", Name: "ripgrep", Bin: "rg", Kind: "search",
			URL: "https://github.com/BurntSushi/ripgrep", License: "MIT",
			Install: "winget install BurntSushi.ripgrep.MSVC || brew install ripgrep",
			Notes:   "finds the patterns each check looks for, and skips .git by default",
		},
		"grep": { // GNU grep: the fallback search when ripgrep is absent
			Key: "grep", Name: "GNU grep", Bin: "grep", Kind: "search",
			URL: "https://www.gnu.org/software/grep/", License: "GPL-3.0",
			Install: "preinstalled on Linux; macOS ships BSD grep; Windows via Git for Windows",
			Notes:   "portable fallback for ripgrep when rg is not installed",
		},
		"git": { // git: answers provenance and signature questions the rubric asks
			Key: "git", Name: "Git", Bin: "git", Kind: "vcs",
			URL: "https://git-scm.com/", License: "GPL-2.0",
			Install: "winget install Git.Git || brew install git",
			Notes:   "source origin (check 1.1) and signed-commit verification (check 1.3)",
		},
		"semgrep": { // semgrep OSS: intent-oriented static analysis of skill code
			Key: "semgrep", Name: "Semgrep OSS", Bin: "semgrep", Kind: "scanner",
			URL: "https://github.com/semgrep/semgrep", License: "LGPL-2.1",
			Install: "brew install semgrep || pip install semgrep",
			Notes:   "community security rules over a skill's code, backing check 1.2",
		},
		"gitleaks": { // gitleaks: detects embedded credentials in over-privileged skills
			Key: "gitleaks", Name: "Gitleaks", Bin: "gitleaks", Kind: "scanner",
			URL: "https://github.com/gitleaks/gitleaks", License: "MIT",
			Install: "winget install Gitleaks.Gitleaks || brew install gitleaks",
			Notes:   "finds keys a skill should never carry, backing check 3.8",
		},
	}
}

// searchOrder is the ripgrep-first, grep-second strategy used by every
// ProbeSearch probe. Both accept the pattern syntax the checks rely on (POSIX
// character classes, bounded repetition) and both follow the same exit-code
// convention — 0 match found, 1 no match, 2 error — so swapping one for the
// other can never change a verdict.
//
// {pattern} and {path} are substituted at run time; keeping the template here
// means a check never hardcodes its own tool invocation.
var searchOrder = []struct {
	ToolKey string   // which tool to try
	Args    []string // argument template with {pattern} and {path}
}{
	{"rg", []string{"-i", "--hidden", "-g", "!.git/**", "-n", "-e", "{pattern}", "{path}"}},
	{"grep", []string{"-rInEi", "-e", "{pattern}", "{path}"}},
}

// builtinSearchTool is the pseudo-tool key used when neither ripgrep nor grep
// is installed, or when a probe's pattern uses syntax only Go understands: the
// runner then scans the files in-process with the same regex, so results never
// depend on what happens to be on PATH.
const builtinSearchTool = "builtin-search" // Go-native fallback key

// builtinCommand renders the in-process scanner's command line. With an empty
// target the {path} placeholder is kept, so a plan reads as a template to fill.
func builtinCommand(pattern, target string) string { // the built-in scanner's line
	if strings.TrimSpace(target) == "" { // no target supplied...
		return builtinSearchTool + " -i -n -e " + pattern + " {path}" // ...leave the placeholder
	}
	return builtinSearchTool + " -i -n -e " + pattern + " " + strings.TrimSpace(target) // the real scan
}

// searchCommandLine picks the first available search tool and renders its
// command line. avail reports whether a binary is on PATH; when none is it
// returns builtinSearchTool so a plan still reads as something concrete.
func searchCommandLine(pattern, target string, avail func(string) bool) (string, string) {
	for _, s := range searchOrder { // prefer ripgrep, then grep...
		if avail != nil && avail(s.ToolKey) { // ...when the binary is present
			subs := map[string]string{"pattern": pattern} // pattern always has a value
			if strings.TrimSpace(target) != "" {          // but path only when given...
				subs["path"] = strings.TrimSpace(target) // ...so a plan keeps {path}
			}
			args := make([]string, len(s.Args)) // copy the template
			for i, a := range s.Args {          // substitute each arg
				args[i] = Expand(a, subs)
			}
			return s.ToolKey, joinCmd(s.ToolKey, args) // the executable command
		}
	}
	// No external search tool: describe the in-process scan that replaces it.
	return builtinSearchTool, builtinCommand(pattern, target)
}

// Expand substitutes {placeholders} in one template string. Placeholders with
// no supplied value are left intact so output still shows a value is missing.
func Expand(t string, subs map[string]string) string { // literal substitution
	for k, v := range subs { // for each supplied placeholder...
		t = strings.ReplaceAll(t, "{"+k+"}", v) // ...swap in the real value
	}
	return t // substituted
}

// joinCmd renders a command and its arguments as a copyable single line.
func joinCmd(bin string, args []string) string { // helper for plan output
	parts := make([]string, 0, len(args)+1) // bin plus every argument
	parts = append(parts, bin)              // start with the binary
	parts = append(parts, args...)          // then the arguments
	return strings.Join(parts, " ")         // one line you can paste into a shell
}

// rules is the complete probe catalog: one entry per numbered check of every
// rubric that ships with hackbot. A new rubric needs a matching entry here for
// its checks to be automated; TestRulesCoverEveryCheck enforces that pairing so
// a rubric row can never be silently left without a probe.
//
// Each pattern is written once and carries a comment naming the rubric row it
// answers and why it is shaped the way it is, because an unexplained regex in a
// security tool is a regex nobody will trust.
var rules = []Rule{ // ===== malicious-skills (MaliciousSkills.md) =====
	{ // 1.1: obtained from a verified, trusted source, not a typosquat
		Slug: "malicious-skills", CheckID: "1.1",
		Probes: []Probe{{
			Kind: ProbeExec, ToolKey: "git",
			Args:   []string{"-C", "{path}", "remote", "get-url", "origin"},
			Expect: ExpectExit0, // no origin, or not a repo, means provenance cannot be shown
			Note:   "asks git where the skill was cloned from; no origin means no verifiable provenance",
		}},
	},
	{ // 1.2: behavioral security analysis, not just pattern matching
		Slug: "malicious-skills", CheckID: "1.2",
		Probes: []Probe{{
			Kind: ProbeExec, ToolKey: "semgrep",
			Args:   []string{"--config", "p/security-audit", "--json", "--quiet", "{path}"},
			Expect: ExpectReview, // a scanner report informs a human; it never decides alone
			Note:   "runs Semgrep's community security rules over the skill and hands the report to a reviewer",
		}},
	},
	{ // 1.3: cryptographic signature verification
		Slug: "malicious-skills", CheckID: "1.3",
		Probes: []Probe{{
			Kind: ProbeExec, ToolKey: "git",
			Args:   []string{"-C", "{path}", "verify-commit", "HEAD"},
			Expect: ExpectExit0, // an unsigned or unverifiable HEAD fails outright
			Note:   "verify-commit exits non-zero when the commit is unsigned or the key is unknown",
		}},
	},
	{ // 1.4: review scripts AND natural-language instructions for malicious patterns
		Slug: "malicious-skills", CheckID: "1.4",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// Delivery chains are unambiguous enough to fail outright: a URL piped
			// into a shell, base64 piped into a shell, a bash reverse shell, or
			// PowerShell's encoded-command escape hatch. Plainer encoding calls are
			// left to check 1.2's semantic scan rather than failing on their own.
			Pattern: "(curl|wget)[^|]{0,120}(https?|ftp)://[^|]{0,120}[|][[:space:]]*(ba|z)?sh([^a-zA-Z]|$)|base64[[:space:]]+(-d|--decode)[^|]{0,60}[|][[:space:]]*(ba|z)?sh|/dev/tcp/|bash[[:space:]]+-i|invoke-expression|iex[[:space:]]*[(]|powershell.{0,60}-e(nc|ncodedcommand)([^a-zA-Z]|$)|frombase64string|certutil.{0,40}urlcache|bitsadmin.{0,40}/transfer",
			Note:    "matches the classic delivery chains: URL|sh, base64|sh, /dev/tcp, and PowerShell -EncodedCommand",
		}},
	},
	{ // 1.5: canary testing before first real use — inherently a human exercise
		Slug: "malicious-skills", CheckID: "1.5",
		Probes: []Probe{{
			Kind:   ProbeManual,
			Manual: "Run the skill in a disposable sandbox (container or VM) with no secrets, egress observed, and a canary file present; treat any attempt to read the canary or reach out as a finding.",
			Note:   "no static evidence can prove a skill behaves itself at runtime",
		}},
	},
	{ // 1.6: must not write to the agent's identity files
		Slug: "malicious-skills", CheckID: "1.6",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// Writes are matched, not mere mentions: a redirection, a shell write
			// utility, or a filesystem call aimed at SOUL.md / MEMORY.md / AGENTS.md.
			// A skill that only discusses identity files in prose does not fail here.
			Pattern: "(>>?|tee[[:space:]]|write-?file|append-?file|createfile|set-content|add-content|out-file).{0,48}(soul|memory|agents)[.]md([^a-zA-Z]|$)",
			Note:    "catches shell redirections and filesystem writes aimed at SOUL.md, MEMORY.md or AGENTS.md",
		}},
	},

	// ===== over-privileged-skills (OverPrivilegedSkills.md) =====
	{ // 3.1: the skill must declare a permission manifest at all
		Slug: "over-privileged-skills", CheckID: "3.1",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectSome,
			// Presence of any permissions-style key IS the manifest, so this probe
			// looks for the key rather than for a particular spelling of its value:
			// skills declare permissions as YAML, JSON, frontmatter or plain text,
			// and all of those put a recognisable key at the start of a line.
			Pattern: "^[[:space:]]*\"?[a-z_-]*(permission|capabilit|manifest|scope|allowed|network|tool)[a-z_-]*\"?[[:space:]]*[:=]",
			Note:    "presence of any permissions-style key is the manifest itself; absence means the skill declares nothing",
		}},
	},
	{ // 3.2: declared permissions must be minimized, not open-ended
		Slug: "over-privileged-skills", CheckID: "3.2",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// An open-ended VALUE on a permission-style key is the finding: a bare
			// "*", a quoted "**", or a word like "all"/"any"/"full". The trailing
			// [^a-zA-Z] guard keeps "permissions: allocation" from counting as
			// "all" while still catching "all," or "all" at end of line.
			Pattern: "^[[:space:]]*\"?[a-z_-]*(permission|capabilit|allowed|access|scope|tool)[a-z_-]*\"?[[:space:]]*[:=][[:space:]]*(\\[[[:space:]]*)?\"?((\\*)|((all|any|full|unrestricted|read.?write|everything)([^a-zA-Z]|$)))",
			Note:    "flags wildcard or all/any/full values sitting on a permission-style key",
		}},
	},
	{ // 3.3: no unrestricted shell execution
		Slug: "over-privileged-skills", CheckID: "3.3",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// Two shapes matter: a config key whose value turns shell on without
			// qualification (shell: true, allow_shell: 1), and prose that grants
			// unrestricted shell access. A key naming a shell path (shell: /bin/sh)
			// deliberately does not match, because naming an interpreter is not the
			// same as handing over an unrestricted one.
			Pattern: "^[[:space:]]*\"?[a-z_.-]*shell[a-z_.-]*\"?[[:space:]]*[:=][[:space:]]*\"?((true|yes|on|1|full|unrestricted)([^a-zA-Z]|$)|\\*)\"?|((allow|grant|enable)[a-z _-]{0,30}(unrestricted|full|arbitrary|any)[a-z _-]{0,20}shell)",
			Note:    "a binary shell flag or an explicitly unrestricted shell is exactly what the rubric forbids",
		}},
	},
	{ // 3.4: no filesystem-wide globs such as **/*
		Slug: "over-privileged-skills", CheckID: "3.4",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// Quotes are required around the glob so ordinary Markdown bold (**)
			// and headings cannot trip the check: only a glob actually written into
			// a permission scope is quoted like "**/*" or '**'.
			Pattern: "[\"'][*][*]/[*][\"']|[\"'][*][*][\"']",
			Note:    "quoted ** or **/* globs appear only in permission scopes, never in ordinary prose",
		}},
	},
	{ // 3.5: credentials must be per-skill, not shared agent-level keys
		Slug: "over-privileged-skills", CheckID: "3.5",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// Heuristic by design: the rubric asks whether a skill leans on the
			// agent's own credentials, and the clearest static signal is a reference
			// to a well-known agent-level key name. A mention in documentation still
			// reports, because a reviewer should decide whether it is a reference or
			// an example — that is what the evidence column asks a human to weigh.
			Pattern: "(anthropic|openai|claude|openclaw|clawhub|agent)_(api[_-]?key|token|secret)",
			Note:    "references to well-known agent-level keys suggest shared credentials rather than a per-skill scope",
		}},
	},
	{ // 3.6: identity-file access must be flagged for elevated review
		Slug: "over-privileged-skills", CheckID: "3.6",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectReview,
			// Deliberately broader than check 1.6: any mention of an identity file
			// is evidence, because the rubric asks for the access to be FLAGGED for
			// elevated review rather than proven malicious.
			Pattern: "(soul|memory|agents)[.]md([^a-zA-Z]|$)",
			Note:    "any mention of an identity file is evidence a reviewer must weigh against the skill's stated purpose",
		}},
	},
	{ // 3.7: network access as a domain allowlist, never a binary switch
		Slug: "over-privileged-skills", CheckID: "3.7",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// A binary network flag replaces the domain allowlist the rubric wants.
			// A skill with no network declaration at all passes, because the safe
			// default is deny — the check is about turning the switch on, not about
			// having a switch.
			Pattern: "^[[:space:]]*\"?[a-z_-]*(network|egress|outbound|internet)[a-z_-]*\"?[[:space:]]*[:=][[:space:]]*\"?((true|yes|on|1)([^a-zA-Z]|$)|\\*)\"?",
			Note:    "a binary network flag replaces the domain allowlist the rubric requires; no declaration means default-deny",
		}},
	},
	{ // 3.8: no access to credential stores beyond stated function
		Slug: "over-privileged-skills", CheckID: "3.8",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// The credential stores a skill has no business reading unless its
			// stated function names them: SSH and AWS keys, Docker config, GPG
			// material, wallet files, dotenv files, and browser login databases.
			// Both separators are matched so Windows paths score the same as POSIX.
			Pattern: "([\\\\/][.]ssh[\\\\/]|[\\\\/][.]aws[\\\\/]|[\\\\/][.]docker[\\\\/]|[\\\\/][.]gnupg[\\\\/]|id_rsa|id_ed25519|[.]pem([^a-zA-Z]|$)|[.]wallet[\\\\/]|[.]env([^a-zA-Z]|$)|credentials[.](json|ini|ya?ml)|login data)",
			Note:    "lists the credential stores a skill has no business reading unless its function names them",
		}, {
			Kind: ProbeExec, ToolKey: "gitleaks",
			Args:   []string{"dir", "{path}", "--redact", "--no-banner", "--exit-code", "1"},
			Expect: ExpectExit0, // gitleaks exits 1 when it finds a leaked key
			Note:   "scans the whole skill for embedded secrets, which the path-based probe cannot see inside",
		}},
	},

	// ===== insecure-metadata (InsecureMetadata.md) =====
	{ // 4.1: the description must reflect actual functionality — a human comparison
		Slug: "insecure-metadata", CheckID: "4.1",
		Probes: []Probe{{
			Kind:   ProbeManual,
			Manual: "Read the skill's declared description and manifest, then trace what the code actually does; any capability that is not disclosed (network calls, file reads, credential access) is the finding.",
			Note:   "only a person can judge whether the description honestly matches observed behavior",
		}},
	},
	{ // 4.2: metadata scanned for ASCII smuggling, zero-width Unicode and base64 payloads
		Slug: "insecure-metadata", CheckID: "4.2",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone, GoOnly: true,
			// The Go engine is the only one of the three that understands \x{...}
			// escapes, so this probe is marked GoOnly: it scans for control
			// characters (minus the ordinary whitespace ones), zero-width Unicode
			// format characters, and long base64 blobs that could hide a payload
			// in plain sight. Unicode claims here are ASCII/control-oriented on
			// purpose, matching the smuggling techniques the rubric cites.
			Pattern: "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F-\\x9F\\x{200B}-\\x{200F}\\x{2060}-\\x{206F}\\x{FEFF}]|[A-Za-z0-9+/]{120,}={0,2}",
			Note:    "control characters, zero-width spaces and 120+ char base64 blobs are the smuggling signals the rubric names",
		}},
	},
	{ // 4.3: default metadata configurations must be secure, not permissive
		Slug: "insecure-metadata", CheckID: "4.3",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// A default-open value on a defaults-style key is the finding: nothing
			// about a *default* should ever read allow/any/full. A skill that sets
			// no defaults also passes, because the secure default is denied.
			Pattern: "default[_-]?(permission|access|policy|scope|filter|network)[a-z_-]*[[:space:]]*[:=][[:space:]]*\"?((\\*|all|any|open|allow|full|unrestricted|read-?write)([^a-zA-Z]|$)|((true|yes|1)([^a-zA-Z]|$)))",
			Note:    "a default-open grant on any config key means a fresh install is permissive by accident",
		}},
	},
	{ // 4.4: metadata validated against a security schema
		Slug: "insecure-metadata", CheckID: "4.4",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectSome,
			// A skill that is validated against a schema carries or references one:
			// jsonschema, pydantic, or a schema key in its own configuration. The
			// absence of any such reference is the finding, because it means no
			// validation is visible from the skill itself.
			Pattern: "(jsonschema|json[-_]schema|pydantic|schema[a-z_-]*[[:space:]]*[:=]|validate[a-z_-]*[[:space:]]*[:=])",
			Note:    "presence of a schema or validation reference suggests the metadata is actually checked somewhere",
		}},
	},
	{ // 4.5: declared risk_tier consistent with actual permission scope
		Slug: "insecure-metadata", CheckID: "4.5",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectSome,
			// The tier must at least be declared before anyone can cross-reference
			// it against the permission probes (3.3, 3.7 and 3.8 report on the
			// other half of the equation).
			Pattern: "risk[_-]?(tier|level)[a-z_-]*[[:space:]]*[:=][[:space:]]*[A-Za-z0-9]",
			Note:    "an undeclared risk tier cannot be cross-referenced; the reviewer pairs it with the permission findings",
		}},
	},
	{ // 4.6: brand or trademark impersonation
		Slug: "insecure-metadata", CheckID: "4.6",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectReview,
			// The ClawHub campaigns the rubric cites impersonated Google, Solana
			// and Polymarket, so a scan for well-known brand names is the flag the
			// evidence column asks for; the reviewer then decides affiliation.
			// \b is supported by ripgrep, GNU grep -E and Go alike.
			Pattern: "\\b(google|openai|anthropic|meta|glean|windsurf|claude|chatgpt|deepseek|solana|polymarket|coinbase|binance|ethereum|bitcoin|stripe|paypal)\\b",
			Note:    "a skill name or description hitting a known brand is impersonation evidence a reviewer must weigh",
		}},
	},
	{ // 4.7: YAML parsed only with safe loaders
		Slug: "insecure-metadata", CheckID: "4.7",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectNone,
			// The unsafe markers the rubric names: bare yaml.load(), any
			// !!!python/.. tag, and pickle.load/loads(). A documentation mention
			// of yaml.load can trip this probe, which is acceptable: the rubric
			// wants these calls gone, not explained.
			Pattern: "(yaml[.]load[[:space:]]*\\(|yaml[.]unsafe_load|!!python/(object|apply|module|new)|pickle[.]loads?[[:space:]]*\\()",
			Note:    "bare yaml.load and !!python/* tags are arbitrary-code-execution vectors on metadata parse",
		}},
	},
	{ // 4.8: config parsed in an isolated subprocess or container — runtime property
		Slug: "insecure-metadata", CheckID: "4.8",
		Probes: []Probe{{
			Kind:   ProbeManual,
			Manual: "Confirm the skill loader parses the skill's YAML/JSON in a sandboxed subprocess or container (no host secret mounts, no network, no persistent store); a deserialization that runs in the agent's own context is the finding.",
			Note:   "isolation happens in the loader at runtime, which no static scan of the skill's files can confirm",
		}},
	},
	{ // 4.9: an allowlist of permitted metadata keys is enforced
		Slug: "insecure-metadata", CheckID: "4.9",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectSome,
			// A skill that participates in key allowlisting declares it; the
			// absence of any allowlist reference is the finding, because it means
			// unexpected fields would be accepted without comment.
			Pattern: "(allowed[_-]?(keys|fields|tags)|allowlist|permitted[_ -]?(keys|fields)|reject[_-]?unknown)",
			Note:    "an allowlist declaration is visible from the skill when it exists; none at all is the finding",
		}},
	},
	{ // 4.10: dependency manifests treated as untrusted code
		Slug: "insecure-metadata", CheckID: "4.10",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectReview,
			// The manifests themselves are evidence: their presence tells the
			// reviewer exactly which files must be installed in a sandbox, which
			// is what the rubric's evidence column demands.
			Pattern: "(requirements[.]txt|package[.]json|pyproject[.]toml|Pipfile[.]lock|setup[.]py|setup[.]cfg|go[.]mod|package-lock[.]json)",
			Note:    "lists the dependency manifests a reviewer must confirm are installed without agent privileges",
		}},
	},
	{ // 4.11: schema validation before any deserialization
		Slug: "insecure-metadata", CheckID: "4.11",
		Probes: []Probe{{
			Kind: ProbeSearch, Expect: ExpectReview,
			// Validation libraries referenced inside the skill are evidence that
			// validation happens at all; the reviewer confirms it precedes parsing
			// in the loader pipeline rather than after it.
			Pattern: "(pydantic|BaseModel|jsonschema|json[-_]schema|parse_obj|validate[_-]?arguments|typeddict)",
			Note:    "referenced validation libraries are evidence a reviewer pairs with the loader's actual order of operations",
		}},
	},
	{ // 4.12: deserialization with minimum privileges — runtime property
		Slug: "insecure-metadata", CheckID: "4.12",
		Probes: []Probe{{
			Kind:   ProbeManual,
			Manual: "Confirm the loader drops privileges (runs as an unprivileged account, no agent credentials in scope) before it parses any skill-provided data; parsing in the elevated agent context is the finding.",
			Note:   "privilege drop is a loader-side runtime property, so the guidance is manual by necessity",
		}},
	},
}

// RulesFor returns the probes registered for a rubric's slug, in rubric order.
func RulesFor(slug string) []Rule { // used by `skill plan` and `skill run`
	var out []Rule            // matched rules
	for _, r := range rules { // scan the catalog
		if r.Slug == slug { // keep only this rubric's checks
			out = append(out, r)
		}
	}
	return out // the rubric's probes
}

// RuleFor returns the single rule for one rubric check, if one exists.
func RuleFor(slug, checkID string) (Rule, bool) { // precise lookup
	for _, r := range rules { // scan the catalog
		if r.Slug == slug && r.CheckID == checkID { // exact match
			return r, true
		}
	}
	return Rule{}, false // nothing registered
}

// AllRules returns every registered rule, for the drift tests and `skill rules`.
func AllRules() []Rule { // full catalog
	return rules // shared slice, read-only by convention
}
