// Package wstg parses the OWASP Web Security Testing Guide (WSTG) checklists
// that ship as Markdown tables under src/agent_files/ and exposes them as
// structured data for hackbot's web-security-testing agents.
//
// Each checklist file is a Markdown table with a category row (the code in
// bold, e.g. **WSTG-INJT**) followed by one row per test
// (e.g. WSTG-INJT-05 | SQL Injection). Parsing keeps the ID, name, status, and
// notes so a checklist can round-trip later.
package wstg // importable as "wstg"

import ( // imports for this file
	"fmt"     // Summary/List formatting
	"io/fs"   // read the embedded checklist files from any fs.FS
	"path"    // join and trim file paths
	"sort"    // deterministic ordering of loaded checklists
	"strings" // table and line parsing
)

// Test is one WSTG test item within a category.
type Test struct { // one row of a checklist table
	ID     string `json:"id"`               // e.g. "WSTG-INJT-05"
	Name   string `json:"name"`             // e.g. "SQL Injection"
	Status string `json:"status,omitempty"` // Pass/Fail/N-A, when filled in
	Notes  string `json:"notes,omitempty"`  // free-form notes, when filled in
}

// Checklist is a single WSTG category and its tests.
type Checklist struct { // one checklist file
	File     string `json:"file"`     // source file name, e.g. "Injection.md"
	Code     string `json:"code"`     // category code, e.g. "WSTG-INJT"
	Category string `json:"category"` // human name, e.g. "Injection"
	Slug     string `json:"slug"`     // CLI handle, e.g. "injection"
	Tests    []Test `json:"tests"`    // the test items, in file order
}

// Load reads every *.md checklist under dir in fsys and parses it, returning the
// checklists sorted by slug.
func Load(fsys fs.FS, dir string) ([]Checklist, error) { // main entry point
	entries, err := fs.ReadDir(fsys, dir) // list the checklist directory
	if err != nil {                       // missing directory is a real error
		return nil, err
	}
	var out []Checklist         // accumulated checklists
	for _, e := range entries { // one checklist per Markdown file
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
		c, err := Parse(e.Name(), string(data)) // parse the table
		if err != nil {                         // propagate parse errors
			return nil, err
		}
		out = append(out, c) // collect
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug }) // stable order
	return out, nil                                                           // parsed checklists
}

// Parse extracts the category and tests from one checklist table.
func Parse(file, content string) (Checklist, error) { // one file -> one Checklist
	base := strings.TrimSuffix(file, path.Ext(file))   // strip the ".md" extension
	c := Checklist{File: file, Slug: slugify(base)}    // seed file + slug (code/category come from the table)
	for _, raw := range strings.Split(content, "\n") { // consider every line
		line := strings.TrimSpace(raw)     // tolerate surrounding whitespace
		if !strings.HasPrefix(line, "|") { // only Markdown table rows matter
			continue
		}
		cells := splitRow(line) // split into trimmed cells
		if len(cells) < 2 {     // need at least ID + name
			continue
		}
		id := strings.Trim(cells[0], "* ")                // strip bold markers from the id cell
		name := strings.Trim(cells[1], "* ")              // strip bold markers from the name cell
		if id == "" || strings.EqualFold(id, "Test ID") { // skip blank/header rows
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(id), "WSTG-") { // only WSTG rows
			continue
		}
		if isCategoryRow(id) { // the bold category row, e.g. "WSTG-INJT"
			c.Code = strings.ToUpper(id) // remember the code
			c.Category = name            // and the human name
			continue                     // it is not a test
		}
		t := Test{ID: strings.ToUpper(id), Name: name} // a real test row
		if len(cells) > 2 {                            // status column, when present
			t.Status = cells[2]
		}
		if len(cells) > 3 { // notes column, when present
			t.Notes = cells[3]
		}
		c.Tests = append(c.Tests, t) // collect the test
	}
	if c.Code == "" { // a checklist without a category row is malformed
		return Checklist{}, fmt.Errorf("wstg: %s: no category row (WSTG-XXXX) found", file)
	}
	if c.Category == "" { // fall back to the code when the name is missing
		c.Category = c.Code
	}
	return c, nil // parsed checklist
}

// isCategoryRow reports whether id is a bare category code ("WSTG-INJT") rather
// than a numbered test ("WSTG-INJT-05").
func isCategoryRow(id string) bool { // distinguishes the two row shapes
	return len(strings.Split(id, "-")) == 2 // "WSTG" + CODE, with no "-NN" suffix
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

// slugify turns a file base name into a kebab-case CLI handle:
// "ApiTesting" -> "api-testing", "ClientSide" -> "client-side", "Injection" -> "injection".
func slugify(name string) string { // used for agent names and lookups
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

// Find looks up a checklist by slug, code, category name, or file name
// (case-insensitive, ".md" optional). It returns the checklist and whether it
// was found.
func Find(checklists []Checklist, query string) (Checklist, bool) { // tolerant lookup
	q := strings.ToLower(strings.TrimSpace(query)) // normalize the query
	q = strings.TrimSuffix(q, ".md")               // allow "Injection.md"
	for _, c := range checklists {                 // scan every checklist
		switch q { // accept any of the natural handles
		case strings.ToLower(c.Slug), strings.ToLower(c.Code),
			strings.ToLower(c.Category), strings.ToLower(strings.TrimSuffix(c.File, ".md")):
			return c, true
		}
	}
	return Checklist{}, false // not found
}

// Summary renders one checklist as a human-readable list.
func (c Checklist) Summary() string { // used by `web show`
	var b strings.Builder                                                       // accumulate text
	fmt.Fprintf(&b, "%s (%s) — %d test(s)\n", c.Category, c.Code, len(c.Tests)) // headline
	for _, t := range c.Tests {                                                 // one line per test
		fmt.Fprintf(&b, "  %-14s %s\n", t.ID, t.Name)
	}
	return b.String() // finished summary
}

// List renders all checklists as a short catalog.
func List(checklists []Checklist) string { // used by `web list`
	total := 0                     // count all tests
	for _, c := range checklists { // sum across categories
		total += len(c.Tests)
	}
	var b strings.Builder                                                      // accumulate text
	fmt.Fprintf(&b, "%d WSTG categories, %d tests:\n", len(checklists), total) // headline
	for _, c := range checklists {                                             // one line per category
		fmt.Fprintf(&b, "  %-26s %-11s %-44s %d tests\n", c.Slug, c.Code, c.Category, len(c.Tests))
	}
	return b.String() // finished catalog
}
