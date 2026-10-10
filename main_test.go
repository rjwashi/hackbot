package main

import (
	"flag"
	"testing"

	"github.com/rjwashi/hackbot/internal/nmap"
)

func TestReorderArgsFlagsAnywhere(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	json := fs.Bool("json", false, "")
	issues := fs.Bool("issues", false, "")
	repo := fs.String("repo", "", "")

	// Flags interleaved with and after positional args.
	got := reorderArgs(fs, []string{"pipeline", "scan.xml", "-issues", "-repo", "a/b", "-json"})
	if err := fs.Parse(got); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if fs.Arg(0) != "pipeline" || fs.Arg(1) != "scan.xml" {
		t.Errorf("positionals = %v, want [pipeline scan.xml]", fs.Args())
	}
	if !*json || !*issues || *repo != "a/b" {
		t.Errorf("flags not parsed: json=%v issues=%v repo=%q", *json, *issues, *repo)
	}
}

func TestReorderArgsDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	_ = fs.Bool("json", false, "")
	got := reorderArgs(fs, []string{"py", "helper.py", "--", "-not-a-flag"})
	if err := fs.Parse(got); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"py", "helper.py", "-not-a-flag"}
	if len(fs.Args()) != 3 || fs.Arg(2) != want[2] {
		t.Errorf("args = %v, want %v", fs.Args(), want)
	}
}

func TestParseSeverity(t *testing.T) {
	valid := map[string]nmap.Severity{
		"info":     nmap.SevInfo,
		"LOW":      nmap.SevLow,
		"medium":   nmap.SevMedium,
		"med":      nmap.SevMedium,
		"high":     nmap.SevHigh,
		"critical": nmap.SevCritical,
		"crit":     nmap.SevCritical,
	}
	for in, want := range valid {
		got, err := parseSeverity(in)
		if err != nil {
			t.Errorf("parseSeverity(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("parseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := parseSeverity("nope"); err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty = %q, want x", got)
	}
	if got := firstNonEmpty("", " "); got != "" {
		t.Errorf("firstNonEmpty = %q, want empty", got)
	}
}
