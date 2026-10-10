// Package skillsec evaluates AI agent skills against the skill-security rubrics
// that ship as Markdown tables under src/agent_files/.
//
// A rubric lists numbered checks ("3.1", "3.8"), each paired with the evidence
// that would answer it, and closes with a "Motivated by" line explaining the
// campaign the rubric came from. This is deliberately shaped like package wstg —
// parse a Markdown checklist into structured data, then map it to tooling — so
// the two rubric families read the same way in the CLI.
//
// Two differences from wstg are forced by the rubric format itself:
//
//   - Rubric rows are bare section numbers ("3.1"), not prefixed ids
//     ("WSTG-INJT-05"), so files are recognised by their leading
//     "# | Check | Evidence to look for" table rather than an id prefix.
//   - Rubric identity (code, category, slug) is derived from the file name, so a
//     new rubric needs only a Markdown file and no code changes at all.
package skillsec // importable as "skillsec"

import ( // imports for this file
	"errors"  // errors.Is against ErrNotRubric when scanning a mixed directory
	"fmt"     // Errorf for contextual parse failures
	"io/fs"   // read the embedded rubric files from any fs.FS
	"path"    // join and trim file paths
	"regexp"  // recognize the "3.1" check-id shape
	"sort"    // deterministic ordering of loaded rubrics
	"strings" // table and line parsing
)

// ErrNotRubric marks a Markdown file that is not a skill-security rubric at all.
//
// src/agent_files/ is shared with the WSTG web-security checklists, whose rows
// carry "WSTG-..." ids and so never look like rubric rows. Returning this
// sentinel from Parse lets Load skip those files instead of failing, which is
// what lets both families live in one embedded directory.
var ErrNotRubric = errors.New("no skill-rubric check rows found") // sentinel for errors.Is

// checkID matches the rubric's section-numbered ids such as "3.1" or "12.4".
// Anchored to the whole cell so table separators ("---") and headers ("#") can
// never be mistaken for a check.
var checkID = regexp.MustCompile(`^\d+\.\d+$`)

// motivationPrefix opens the rubric's closing provenance line.
const motivationPrefix = "**Motivated by**" // the rubric's "why this exists" line

// Check is one numbered rubric row: the question plus the evidence that answers it.
type Check struct { // one row of a rubric table
	ID       string `json:"id"`       // section number, e.g. "3.1"
	Test     string `json:"test"`     // the question being asked
	Evidence string `json:"evidence"` // what would prove it (or disprove it)
}

// Rubric is a single skill-security rubric and its checks.
type Rubric struct { // one rubric file
	File       string  `json:"file"`                 // source file name, e.g. "OverPrivilegedSkills.md"
	Code       string  `json:"code"`                 // derived code, e.g. "OVER-PRIVILEGED-SKILLS"
	Category   string  `json:"category"`             // human name, e.g. "Over-Privileged Skills"
	Slug       string  `json:"slug"`                 // CLI handle, e.g. "over-privileged-skills"
	Motivation string  `json:"motivation,omitempty"` // campaign the rubric came from
	Checks     []Check `json:"checks"`               // the checks, in file order
}

// Load reads every *.md rubric under dir in fsys and parses it, returning the
// rubrics sorted by slug. Files that are not rubrics are skipped, so this can
// safely read the shared src/agent_files/ directory that also holds WSTG
// checklists.
func Load(fsys fs.FS, dir string) ([]Rubric, error) { // main entry point
	entries, err := fs.ReadDir(fsys, dir) // list the rubric directory
	if err != nil {                       // a missing directory is a real error
		return nil, err
	}
	var out []Rubric            // accumulated rubrics
	for _, e := range entries { // one rubric per Markdown file
		if e.IsDir() { // skip sub-directories
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".md") { // only Markdown files
			continue
		}
		name := path.Join(dir, e.Name())     // full path within the FS
		data, err := fs.ReadFile(fsys, name) // read the file
		if err != nil {                      // propagate read errors
			return nil, err
		}
		r, ok, err := Parse(e.Name(), string(data)) // parse the rubric table
		if errors.Is(err, ErrNotRubric) {           // not a rubric (e.g. a WSTG file)...
			continue // ...so skip it rather than failing the whole directory
		}
		if err != nil { // other parse errors are real and propagate
			return nil, err
		}
		if !ok { // defensive: Parse only returns ok=false alongside ErrNotRubric
			continue
		}
		out = append(out, r) // collect
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug }) // stable order
	return out, nil                                                           // parsed rubrics
}

// Parse extracts the checks and provenance from one rubric table.
//
// The boolean reports whether any check row was found, which callers use to
// tell "some other Markdown file" apart from "a broken rubric".
func Parse(file, content string) (Rubric, bool, error) { // one file -> one Rubric
	base := strings.TrimSuffix(file, path.Ext(file)) // strip the ".md" extension
	slug := Slugify(base)                            // CLI handle from the file name
	r := Rubric{                                     // seed identity derived from the file name
		File:     file,
		Code:     Code(slug),     // e.g. "OVER-PRIVILEGED-SKILLS"
		Category: humanize(slug), // e.g. "Over-Privileged Skills"
		Slug:     slug,
	}
	for _, raw := range strings.Split(content, "\n") { // consider every line
		line := strings.TrimSpace(raw) // tolerate surrounding whitespace
		if line == "" {                // skip blanks quickly
			continue
		}
		if strings.HasPrefix(line, motivationPrefix) { // the provenance line...
			r.Motivation = parseMotivation(line) // ...captured for `skill show`
			continue
		}
		if !strings.HasPrefix(line, "|") { // only Markdown table rows matter
			continue
		}
		cells := splitRow(line) // split into trimmed cells
		if len(cells) < 3 {     // a rubric row needs id + check + evidence
			continue
		}
		id := strings.TrimSpace(cells[0]) // the section-number cell
		if !checkID.MatchString(id) {     // header, separator, and WSTG rows all fail here
			continue
		}
		r.Checks = append(r.Checks, Check{ // a real rubric check row
			ID:       id,                          // e.g. "3.1"
			Test:     strings.TrimSpace(cells[1]), // the question
			Evidence: strings.TrimSpace(cells[2]), // the evidence to look for
		})
	}
	if len(r.Checks) == 0 { // a file with no check rows is not a rubric
		return Rubric{}, false, fmt.Errorf("skillsec: %s: %w", file, ErrNotRubric) // wrap so callers can detect it
	}
	return r, true, nil // parsed rubric
}

// parseMotivation trims the "**Motivated by**:" marker off the provenance line,
// tolerating extra bold markers or missing colons in the hand-written files.
func parseMotivation(line string) string { // used by Parse
	body := strings.TrimPrefix(line, motivationPrefix) // drop the marker
	body = strings.TrimLeft(body, " *:")               // drop the colon/bold that follows
	return strings.TrimSpace(body)                     // the prose itself
}

// Slugify turns a file base name into a kebab-case CLI handle:
// "MaliciousSkills" -> "malicious-skills", "OverPrivilegedSkills" ->
// "over-privileged-skills". It matches wstg.Slugify on purpose so both rubric
// families pick the same spelling for the same file name.
func Slugify(name string) string { // used for agent names and lookups
	var b strings.Builder    // accumulate the slug
	for i, r := range name { // walk each rune
		switch { // decide what to emit
		case r >= 'A' && r <= 'Z': // an uppercase letter starts a new word...
			if i > 0 { // ...but not at the very start
				b.WriteByte('-')
			}
			b.WriteRune(r + ('a' - 'A')) // lowercase it
		case r == ' ' || r == '_': // spaces/underscores become separators
			b.WriteByte('-')
		default: // everything else is kept as-is
			b.WriteRune(r)
		}
	}
	return strings.ToLower(b.String()) // normalized, lowercase slug
}

// Code renders a slug in the SCREAMING-KEBAB form used as the rubric's short
// code, so "over-privileged-skills" becomes "OVER-PRIVILEGED-SKILLS".
func Code(slug string) string { // derived rubric code
	return strings.ToUpper(slug) // the slug, shouted
}

// humanize turns a slug back into a readable category name while keeping
// compound words intact: "over-privileged-skills" -> "Over-Privileged Skills".
func humanize(slug string) string { // derived rubric category
	parts := strings.Split(slug, "-") // one word per hyphen-separated segment
	for i, p := range parts {         // title-case each segment
		if p == "" { // a leading/trailing hyphen leaves an empty segment
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:] // capitalize the first letter
	}
	return strings.Join(parts, "-") // rejoin so compounds stay hyphenated
}

// splitRow splits a Markdown table row into trimmed cells.
func splitRow(line string) []string { // "| a | b |" -> ["a", "b"]
	line = strings.Trim(line, "|")    // drop the leading/trailing pipes
	parts := strings.Split(line, "|") // split on the cell separators
	for i := range parts {            // trim each cell
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts // the cells
}

// Find looks up a rubric by slug, code, category name, or file name
// (case-insensitive, ".md" optional). It returns the rubric and whether it was found.
func Find(rubrics []Rubric, query string) (Rubric, bool) { // tolerant lookup
	q := strings.ToLower(strings.TrimSpace(query)) // normalize the query
	q = strings.TrimSuffix(q, ".md")               // allow "MaliciousSkills.md"
	q = strings.ReplaceAll(q, " ", "-")            // "Malicious Skills" == "malicious-skills"
	for _, r := range rubrics {                    // scan every rubric
		switch q { // accept any of the natural handles
		case strings.ToLower(r.Slug), strings.ToLower(r.Code),
			strings.ToLower(r.Category), strings.ToLower(strings.TrimSuffix(r.File, ".md")):
			return r, true
		}
	}
	return Rubric{}, false // not found
}

// Summary renders one rubric as a human-readable list, provenance included.
func (r Rubric) Summary() string { // used by `skill show`
	var b strings.Builder                                                         // accumulate text
	fmt.Fprintf(&b, "%s (%s) — %d check(s)\n", r.Category, r.Code, len(r.Checks)) // headline
	for _, c := range r.Checks {                                                  // one line per check
		fmt.Fprintf(&b, "  %-6s %s\n", c.ID, c.Test)
	}
	if r.Motivation != "" { // the rubric's provenance, when present
		fmt.Fprintf(&b, "\nMotivated by: %s\n", r.Motivation)
	}
	return b.String() // finished summary
}

// List renders all rubrics as a short catalog.
func List(rubrics []Rubric) string { // used by `skill list`
	total := 0                  // count all checks
	for _, r := range rubrics { // sum across rubrics
		total += len(r.Checks)
	}
	var b strings.Builder                                                           // accumulate text
	fmt.Fprintf(&b, "%d skill-security rubrics, %d checks:\n", len(rubrics), total) // headline
	for _, r := range rubrics {                                                     // one line per rubric
		fmt.Fprintf(&b, "  %-26s %-24s %-28s %d checks\n", r.Slug, r.Code, r.Category, len(r.Checks))
	}
	return b.String() // finished catalog
}
