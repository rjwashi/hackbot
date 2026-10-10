package wstg // same package as wstg.go

import ( // test imports
	"strings"        // assertions on rendered text
	"testing"        // the testing framework
	"testing/fstest" // in-memory fs.FS for Load tests
)

// sample is a minimal checklist in the same shape as src/agent_files/*.md.
const sample = `# Testing Checklist

| Test ID           | Test Name                      | Status | Notes          |
|-------------------|--------------------------------|--------|----------------|
| **WSTG-INJT**     | **Injection**                  |        |                |
| WSTG-INJT-01      | Reflected Cross Site Scripting |        |                |
| WSTG-INJT-05      | SQL Injection                  | Fail   | tried ' OR 1=1 |
`

// authSample is a second checklist so Load ordering can be checked.
const authSample = `# Testing Checklist

| Test ID           | Test Name           | Status | Notes |
|-------------------|---------------------|--------|-------|
| **WSTG-ATHN**     | **Authentication**  |        |       |
| WSTG-ATHN-02      | Default Credentials |        |       |
`

// TestParse verifies a checklist table is parsed into code, category, and tests.
func TestParse(t *testing.T) { // table parsing
	c, err := Parse("Injection.md", sample) // parse the sample
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Code != "WSTG-INJT" || c.Category != "Injection" { // category row parsed
		t.Errorf("category = %q/%q", c.Code, c.Category)
	}
	if c.Slug != "injection" || c.File != "Injection.md" { // slug/file derived from the name
		t.Errorf("slug/file = %q/%q", c.Slug, c.File)
	}
	if len(c.Tests) != 2 { // two test rows
		t.Fatalf("tests = %d, want 2", len(c.Tests))
	}
	if c.Tests[0].ID != "WSTG-INJT-01" || c.Tests[0].Name != "Reflected Cross Site Scripting" { // first row
		t.Errorf("test[0] = %+v", c.Tests[0])
	}
	if c.Tests[1].Status != "Fail" || c.Tests[1].Notes != "tried ' OR 1=1" { // status/notes preserved
		t.Errorf("test[1] = %+v", c.Tests[1])
	}
}

// TestParseNoCategory verifies a malformed checklist errors.
func TestParseNoCategory(t *testing.T) { // error path
	if _, err := Parse("Bad.md", "# Nothing\n\nno table here\n"); err == nil {
		t.Error("expected an error for a checklist without a category row")
	}
}

// TestLoad verifies every Markdown checklist in a directory is parsed and sorted.
func TestLoad(t *testing.T) { // directory loading
	fsys := fstest.MapFS{ // in-memory checklist directory
		"checklists/Injection.md":      {Data: []byte(sample)},
		"checklists/Authentication.md": {Data: []byte(authSample)},
	}
	got, err := Load(fsys, "checklists") // load
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 { // two checklists
		t.Fatalf("checklists = %d, want 2", len(got))
	}
	if got[0].Slug != "authentication" || got[1].Slug != "injection" { // sorted by slug
		t.Errorf("order = %q, %q", got[0].Slug, got[1].Slug)
	}
}

// TestFind verifies lookup by slug, code, category, and file name.
func TestFind(t *testing.T) { // tolerant lookup
	c, _ := Parse("Injection.md", sample) // build a checklist
	list := []Checklist{c}                // one-item list
	for _, q := range []string{"injection", "WSTG-INJT", "wstg-injt", "Injection", "Injection.md", "INJECTION"} {
		if _, ok := Find(list, q); !ok { // every handle must resolve
			t.Errorf("Find(%q) not found", q)
		}
	}
	if _, ok := Find(list, "nope"); ok { // unknown query
		t.Error("Find(nope) unexpectedly found something")
	}
}

// TestSummaryAndList verifies the human renderers.
func TestSummaryAndList(t *testing.T) { // renderers
	c, _ := Parse("Injection.md", sample) // build a checklist
	sum := c.Summary()                    // one checklist
	if !strings.Contains(sum, "Injection (WSTG-INJT)") || !strings.Contains(sum, "WSTG-INJT-05") {
		t.Errorf("Summary = %q", sum)
	}
	list := List([]Checklist{c}) // catalog
	if !strings.Contains(list, "1 WSTG categories, 2 tests") || !strings.Contains(list, "injection") {
		t.Errorf("List = %q", list)
	}
}

// TestSlugify verifies kebab-case conversion of file names.
func TestSlugify(t *testing.T) { // name normalization
	cases := map[string]string{
		"ApiTesting":           "api-testing",
		"ClientSide":           "client-side",
		"ConfigManagement":     "config-management",
		"InformationGathering": "information-gathering",
		"Injection":            "injection",
		"WeakCryptography":     "weak-cryptography",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
