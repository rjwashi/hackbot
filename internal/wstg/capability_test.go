package wstg // same package as the code under test

import ( // test imports
	"os"      // open the real checklist directory
	"strings" // assertions on rendered commands
	"testing" // the testing framework
)

// realChecklists loads the on-disk WSTG checklists (the same files the binary
// embeds) so capability tests validate against real test ids.
func realChecklists(t *testing.T) []Checklist { // helper for the tests below
	t.Helper()                                              // cleaner failures
	cs, err := Load(os.DirFS("../../src/agent_files"), ".") // read the repo's checklists
	if err != nil {                                         // a failure here means the tests can't run
		t.Fatalf("load checklists: %v", err)
	}
	if len(cs) == 0 { // sanity: there should be some
		t.Fatal("no checklists found")
	}
	return cs
}

// TestChecksValid verifies every curated check references real ids and tools.
func TestChecksValid(t *testing.T) { // guards the capability table
	checklists := realChecklists(t)        // real checklists
	bySlug := map[string]map[string]bool{} // slug -> set of test ids
	for _, c := range checklists {         // index test ids per category
		ids := map[string]bool{}
		for _, test := range c.Tests { // collect ids
			ids[test.ID] = true
		}
		bySlug[c.Slug] = ids
	}
	for _, ck := range checks { // every check...
		if _, ok := ToolByKey(ck.ToolKey); !ok { // ...must name a real tool
			t.Errorf("check %s references unknown tool %q", ck.TestID, ck.ToolKey)
		}
		if ids, ok := bySlug[ck.Slug]; !ok { // ...must belong to a real category
			t.Errorf("check %s references unknown category %q", ck.TestID, ck.Slug)
		} else if !ids[ck.TestID] { // ...and its test id must exist in that checklist
			t.Errorf("check %s is not a test in category %q", ck.TestID, ck.Slug)
		}
		if len(ck.Args) == 0 { // ...and must have arguments
			t.Errorf("check %s has no args", ck.TestID)
		}
		if !ck.Guarded { // all current checks touch the target
			t.Errorf("check %s is not marked guarded", ck.TestID)
		}
	}
}

// TestCategoryToolsComplete verifies every category has a free toolset.
func TestCategoryToolsComplete(t *testing.T) { // every agent must have capabilities
	for _, c := range realChecklists(t) { // for each category...
		if len(ToolsFor(c.Slug)) == 0 { // ...there must be at least one tool
			t.Errorf("category %s has no tools", c.Slug)
		}
		for _, tool := range ToolsFor(c.Slug) { // every listed tool must resolve
			if tool.Key == "" || tool.Bin == "" { // and be complete
				t.Errorf("category %s has an incomplete tool: %+v", c.Slug, tool)
			}
		}
	}
}

// TestToolCatalogComplete verifies every catalog tool is fully described.
func TestToolCatalogComplete(t *testing.T) { // catalog hygiene
	for _, tool := range Tools() { // every tool...
		if tool.Key == "" || tool.Name == "" || tool.Bin == "" { // ...needs identity
			t.Errorf("incomplete tool: %+v", tool)
		}
		if tool.URL == "" || tool.License == "" { // ...and a free reference + license
			t.Errorf("tool %s missing url/license", tool.Key)
		}
	}
	if len(Tools()) == 0 { // sanity
		t.Fatal("empty tool catalog")
	}
}

// TestPlanCoversEveryTest verifies every checklist row appears in the plan.
func TestPlanCoversEveryTest(t *testing.T) { // the "capabilities" invariant
	for _, c := range realChecklists(t) { // for each checklist...
		steps := Plan(c, "https", "") // build the plan (no target -> templates)
		seen := map[string]bool{}     // track which ids appeared
		for _, s := range steps {     // walk the steps
			seen[s.TestID] = true // remember
			if s.Automated {      // automated steps...
				if s.Tool == "" || s.Command == "" { // ...need a tool and a command
					t.Errorf("plan %s: automated step missing tool/command: %+v", c.Slug, s)
				}
				if !strings.Contains(s.Command, "{url}") && !strings.Contains(s.Command, "{host}") { // and a placeholder
					t.Errorf("plan %s: command has no placeholder: %q", c.Slug, s.Command)
				}
			} else if s.Manual == "" { // manual steps need guidance
				t.Errorf("plan %s: manual step missing guidance: %+v", c.Slug, s)
			}
		}
		for _, test := range c.Tests { // every checklist test must be covered
			if !seen[test.ID] {
				t.Errorf("plan %s missing test %s", c.Slug, test.ID)
			}
		}
	}
}

// TestRenderArgs verifies placeholder substitution behavior.
func TestRenderArgs(t *testing.T) { // plan vs run rendering
	args := []string{"-u", "{url}", "{host}", "{target}"}
	if got := RenderArgs(args, "https://h", "h", "h"); got[1] != "https://h" || got[2] != "h" || got[3] != "h" { // all replaced
		t.Errorf("RenderArgs replaced = %v", got)
	}
	if got := RenderArgs(args, "", "", ""); got[1] != "{url}" || got[2] != "{host}" || got[3] != "{target}" { // placeholders kept
		t.Errorf("RenderArgs placeholders = %v", got)
	}
}

// TestCommandLine verifies command rendering with and without a target.
func TestCommandLine(t *testing.T) { // used by plans and dry-runs
	tool, _ := ToolByKey("dalfox")                                  // pick a tool
	got := CommandLine(tool, []string{"url", "{url}"}, "https", "") // template
	if got != "dalfox url {url}" {                                  // placeholders preserved
		t.Errorf("template command = %q", got)
	}
	got = CommandLine(tool, []string{"url", "{url}"}, "https", "10.0.0.1") // concrete
	if got != "dalfox url https://10.0.0.1" {                              // target rendered
		t.Errorf("rendered command = %q", got)
	}
}

// TestCheckByTest verifies lookups by test id.
func TestCheckByTest(t *testing.T) { // used by `web run -test`
	if got := CheckByTest("WSTG-INJT-05"); len(got) != 1 || got[0].ToolKey != "sqlmap" { // exact id
		t.Errorf("CheckByTest = %+v", got)
	}
	if got := CheckByTest("wstg-injt-05"); len(got) != 1 { // case-insensitive
		t.Errorf("CheckByTest case = %+v", got)
	}
	if got := CheckByTest("nope"); got != nil { // unknown id
		t.Errorf("CheckByTest unknown = %+v", got)
	}
}
