// This file implements a tiny OpenAI-compatible chat client used by the
// optional LLM stage. It talks HTTP directly to avoid pulling in an SDK.
package agent // same package as the pipeline

import ( // imports for this file
	"bytes"         // bytes.NewReader to send the JSON request body
	"context"       // propagate cancellation/timeout to the HTTP call
	"encoding/json" // marshal the request and decode the response
	"errors"        // errors.New for the "not configured" sentinel
	"fmt"           // Errorf for contextual errors
	"net/http"      // the HTTP client and request types
	"strings"       // TrimRight/TrimSpace for URL and content cleanup
)

// ErrLLMNotConfigured is returned when no LLM endpoint/model is configured.
var ErrLLMNotConfigured = errors.New("LLM not configured (set HACKBOT_LLM_BASE_URL and HACKBOT_LLM_MODEL)") // sentinel

// LLMClient is a minimal OpenAI-compatible chat client. Any provider exposing
// /chat/completions (including OpenCode Zen) works.
type LLMClient struct { // value type; safe to copy
	BaseURL string       // e.g. https://opencode.ai/zen/v1 (no trailing /chat/completions)
	APIKey  string       // bearer token; may be empty for local endpoints
	Model   string       // model ID, e.g. "step-5-preview-free"
	HTTP    *http.Client // optional custom client (timeouts, tests); defaults to http.DefaultClient
}

// Configured reports whether the client has enough settings to make a call.
func (c LLMClient) Configured() bool { // used to decide whether to attempt the LLM stage
	return strings.TrimSpace(c.BaseURL) != "" && strings.TrimSpace(c.Model) != "" // need at least a URL and a model
}

// chatRequest is the OpenAI-compatible request body.
type chatRequest struct { // only the fields we need
	Model    string        `json:"model"`    // which model to call
	Messages []chatMessage `json:"messages"` // conversation; we send a single user message
}

// chatMessage is one message in the conversation.
type chatMessage struct { // role + content, matching the OpenAI schema
	Role    string `json:"role"`    // "user" or "assistant"
	Content string `json:"content"` // the text
}

// chatResponse is the subset of the response we care about.
type chatResponse struct { // tolerant of extra fields (json ignores unknowns)
	Choices []struct {
		Message chatMessage `json:"message"` // assistant's reply
	} `json:"choices"` // array; we use the first element
	Error *struct { // some providers return an error object alongside a non-200 status
		Message string `json:"message"` // human-readable error text
	} `json:"error"` // nil when absent
}

// Complete sends a single user prompt and returns the assistant's reply.
func (c LLMClient) Complete(ctx context.Context, prompt string) (string, error) { // one-shot completion
	if !c.Configured() { // fail fast if the caller forgot to configure it...
		return "", ErrLLMNotConfigured // ...caller can special-case this sentinel
	}
	httpClient := c.HTTP   // pick the client to use...
	if httpClient == nil { // ...defaulting when none was provided
		httpClient = http.DefaultClient // shared client; fine for a CLI
	}

	body, err := json.Marshal(chatRequest{ // build the request payload
		Model:    c.Model,                                        // model ID
		Messages: []chatMessage{{Role: "user", Content: prompt}}, // single user turn
	})
	if err != nil { // marshalling a struct of strings should never fail...
		return "", err // ...but propagate if it somehow does
	}

	url := strings.TrimRight(c.BaseURL, "/") + "/chat/completions"                           // join base + endpoint without a double slash
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) // attach context for cancellation
	if err != nil {                                                                          // malformed URL, etc.
		return "", err
	}
	req.Header.Set("Content-Type", "application/json") // tell the server it's JSON
	if c.APIKey != "" {                                // only set auth when a key exists...
		req.Header.Set("Authorization", "Bearer "+c.APIKey) // ...Bearer scheme
	}

	resp, err := httpClient.Do(req) // perform the request
	if err != nil {                 // network/DNS/timeout failures
		return "", fmt.Errorf("llm request: %w", err) // wrap so callers see the stage
	}
	defer resp.Body.Close() // always release the body

	var parsed chatResponse                                            // decode into our subset struct
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil { // decoding errors include the status for context
		return "", fmt.Errorf("llm decode (status %d): %w", resp.StatusCode, err)
	}
	if parsed.Error != nil { // provider-reported error...
		return "", fmt.Errorf("llm error (status %d): %s", resp.StatusCode, parsed.Error.Message) // ...surface the message
	}
	if resp.StatusCode != http.StatusOK { // any other non-200...
		return "", fmt.Errorf("llm status %d", resp.StatusCode) // ...report the code
	}
	if len(parsed.Choices) == 0 { // 200 but no content
		return "", errors.New("llm returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil // return the first reply, trimmed
}
