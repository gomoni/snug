// Package llm is how snug-setup asks a model for actions. A Backend is chosen
// once at construction (cmd/snug-setup) and nothing after that asks which one
// it is: Remote talks to an OpenAI-compatible server, Server starts a
// llama-server of its own and is a Remote, and package inproc runs the model
// inside the process.
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
)

// Remote is a Backend that speaks chat completions to a server it did not
// start.
type Remote struct {
	// URL is the server base: http://host:port, optionally ending in /v1 or in
	// the full /v1/chat/completions path.
	URL  string
	HTTP *http.Client
}

// Caps reports an unconstrained backend: the request carries the schema as
// response_format, but a server of unknown make may ignore it, and the
// absence of a grammar is not something snug-setup can observe.
func (c *Remote) Caps() Caps {
	return Caps{Where: c.URL + " (remote)", Local: c.IsLoopback()}
}

// Close does nothing: the server is not ours.
func (c *Remote) Close() error { return nil }

// Endpoint returns the chat-completions URL for c.URL, or an error when c.URL
// is not an http(s) URL.
func (c *Remote) Endpoint() (string, error) {
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
func (c *Remote) IsLoopback() bool {
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

func responseFormat(schema json.RawMessage) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"type":        "json_schema",
		"json_schema": map[string]any{"schema": schema},
	})
	return b
}

// Complete sends one system and one user message and returns the assistant's
// text. The schema goes as response_format; a server that honours it
// constrains decoding, and the caller validates with intent.Parse either way.
// An error is returned for an unreachable server, a non-200 status (with the
// server's own message) or a reply without a choice.
func (c *Remote) Complete(ctx context.Context, r Request) (string, error) {
	ep, err := c.Endpoint()
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(chatRequest{
		Model: "snug-setup",
		Messages: []chatMessage{
			{Role: "system", Content: r.System},
			{Role: "user", Content: r.User},
		},
		Temperature:    r.Temperature,
		MaxTokens:      r.MaxTokens,
		ResponseFormat: responseFormat(r.Schema),
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
		return "", fmt.Errorf("cannot reach the model server at %s (start the server, or pass --model FILE.gguf to run the model in-process): %w", c.URL, err)
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
