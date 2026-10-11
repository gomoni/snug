// Package llm talks to an OpenAI-compatible chat endpoint (llama-server) and
// can start one as a child process that dies with snug-setup.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gomoni/snug/setup/internal/intent"
)

// MaxTokens bounds a reply. Eight short actions fit well inside it.
const MaxTokens = 256

// Client is a chat-completions client.
type Client struct {
	// URL is the server base: http://host:port, optionally ending in /v1 or in
	// the full /v1/chat/completions path.
	URL  string
	HTTP *http.Client
}

// Endpoint returns the chat-completions URL for c.URL, or an error when c.URL
// is not an http(s) URL.
func (c *Client) Endpoint() (string, error) {
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("--llm-url %q is not an http(s) URL such as http://127.0.0.1:8080", c.URL)
	}
	switch {
	case strings.HasSuffix(u.Path, "/chat/completions"):
	case strings.HasSuffix(u.Path, "/v1"):
		u.Path += "/chat/completions"
	default:
		u.Path += "/v1/chat/completions"
	}
	return u.String(), nil
}

// IsLoopback reports whether the client talks to this machine. The prompt
// carries the host's key comments, GitHub logins, git author and a digest of
// the file being read, so anything else is worth saying out loud.
func (c *Client) IsLoopback() bool {
	u, err := url.Parse(c.URL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type chatRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	Temperature    float64         `json:"temperature"`
	MaxTokens      int             `json:"max_tokens"`
	Stream         bool            `json:"stream"`
	ResponseFormat json.RawMessage `json:"response_format"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func responseFormat() json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"type":        "json_schema",
		"json_schema": map[string]any{"schema": json.RawMessage(intent.Schema)},
	})
	return b
}

// Complete sends one system and one user message and returns the assistant's
// text. Decoding is constrained to schema.json by the server; the caller still
// validates with intent.Parse, because a server may ignore the constraint.
// An error is returned for an unreachable server, a non-200 status (with the
// server's own message) or a reply without a choice.
func (c *Client) Complete(ctx context.Context, system, user string, temperature float64) (string, error) {
	ep, err := c.Endpoint()
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(chatRequest{
		Model: "snug-setup",
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature:    temperature,
		MaxTokens:      MaxTokens,
		ResponseFormat: responseFormat(),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach the model server at %s (start llama-server, or pass --model FILE.gguf): %w", c.URL, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("model server answered %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Choices []struct {
			Message chatMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("model server at %s sent a reply that is not a chat completion", c.URL)
	}
	return out.Choices[0].Message.Content, nil
}
