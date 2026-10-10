package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// GHIssueCreator creates issues via the GitHub CLI (`gh`).
type GHIssueCreator struct {
	GHPath string // default "gh"
}

// CreateIssue runs `gh issue create` and returns the created issue URL.
func (g GHIssueCreator) CreateIssue(ctx context.Context, repo, title, body string, labels []string) (string, error) {
	path := g.GHPath
	if path == "" {
		path = "gh"
	}

	args := []string{"issue", "create", "--repo", repo, "--title", title, "--body", body}
	if len(labels) > 0 {
		args = append(args, "--label", strings.Join(labels, ","))
	}

	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gh issue create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
