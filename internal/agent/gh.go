// This file implements the real IssueCreator backed by the GitHub CLI.
package agent // same package as the pipeline

import ( // imports for this file
	"context" // pass through cancellation to the gh process
	"fmt"     // Errorf for contextual errors
	"os/exec" // exec.CommandContext to run gh
	"strings" // TrimSpace/Join for args and output
)

// GHIssueCreator creates issues via the GitHub CLI (`gh`).
type GHIssueCreator struct { // production implementation of IssueCreator
	GHPath string // path to the gh binary; defaults to "gh" (found on PATH)
}

// CreateIssue runs `gh issue create` and returns the created issue URL.
func (g GHIssueCreator) CreateIssue(ctx context.Context, repo, title, body string, labels []string) (string, error) { // shells out
	path := g.GHPath // choose the gh binary...
	if path == "" {  // ...defaulting when unset
		path = "gh"
	}

	args := []string{"issue", "create", "--repo", repo, "--title", title, "--body", body} // base gh command
	if len(labels) > 0 {                                                                  // only add labels when we have some (empty --label would error)
		args = append(args, "--label", strings.Join(labels, ",")) // gh accepts a comma-separated label list
	}

	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput() // run gh, capture output for errors
	if err != nil {                                                      // gh exited non-zero...
		return "", fmt.Errorf("gh issue create: %w: %s", err, strings.TrimSpace(string(out))) // ...include stderr
	}
	return strings.TrimSpace(string(out)), nil // gh prints the new issue URL on success
}
