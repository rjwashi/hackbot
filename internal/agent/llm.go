package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrLLMNotConfigured is returned when no LLM endpoint/model is configured.
var ErrLLMNotConfigured = errors.New("LLM not configured (set HACKBOT_LLM_BASE_URL and HACKBOT_LLM_MODEL)")

// LLMClient is a minimal OpenAI-compatible chat client. Any provider exposing
// /chat/completions (including OpenCode Zen) works.
type LLMClient struct {
	BaseURL string // e.g. https://opencode.ai/zen/v1
	APIKey  string
	Model   string // e.g. step-5-preview-free
	HTTP    *http.Client
}

// Configured reports whether the client has enough settings to make a call.
func (c LLMClient) Configured() bool {
	return strings.TrimSpace(c.BaseURL) != "" && strings.TrimSpace(c.Model) != ""
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete sends a single user prompt and returns the assistant's reply.
func (c LLMClient) Complete(ctx context.Context, prompt string) (string, error) {
	if !c.Configured() {
		return "", ErrLLMNotConfigured
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	body, err := json.Marshal(chatRequest{
		Model:    c.Model,
		Messages: []chatMessage{{Role: "user", Content: prompt}},
	})
	if err != nil {
		return "", err
	}

	url := strings.TrimRight(c.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()

	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("llm decode (status %d): %w", resp.StatusCode, err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("llm error (status %d): %s", resp.StatusCode, parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm status %d", resp.StatusCode)
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("llm returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}
