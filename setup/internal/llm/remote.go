// Package llm is how snug-setup asks a model for actions: Remote talks to an
// OpenAI-compatible server it did not start (llama-server, ollama, a hosted
// API). snug-setup runs no model and starts no server of its own.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// ModelName is the "model" of the request. llama-server ignores it; ollama
	// and hosted servers need the name of an installed model. Empty sends
	// DefaultModelName.
	ModelName string
}

// DefaultModelName is sent when Remote.ModelName is empty.
const DefaultModelName = "snug-setup"

// Caps says where the server is and whether that is this machine.
func (c *Remote) Caps() Caps {
	return Caps{Where: c.Display() + " (remote)", Local: c.IsLoopback()}
}

// Display is c.URL without its userinfo, for every line snug-setup prints.
// The whole userinfo goes, not only the password url.Redacted blanks: a token
// typed as the user name (http://TOKEN@host) is sent as Basic auth just the
// same. A URL that does not parse is shown as "(unparsable URL)": quoting it
// back could print what it was meant to hide.
func (c *Remote) Display() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return "(unparsable URL)"
	}
	u.User = nil
	return u.String()
}

// Close does nothing: the server is not ours.
func (c *Remote) Close() error { return nil }

// Endpoint returns the chat-completions URL for c.URL, or an error when c.URL
// is not an http(s) URL.
func (c *Remote) Endpoint() (string, error) {
	u, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("--openai-url %q is not an http(s) URL such as http://127.0.0.1:8080", c.Display())
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
		Model: c.modelName(),
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
		// *url.Error quotes the request URL with its user name in clear;
		// Display already says where.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("cannot reach the model server at %s (start the server, or run without --openai-url to read requests by the rules): %w", c.Display(), err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		msg := serverMessage(raw)
		err := fmt.Errorf("model server answered %s: %s", resp.Status, msg)
		if strings.Contains(strings.ToLower(msg), "not found") {
			err = fmt.Errorf("%w\nthe server does not have the model %q: name one it has with --model NAME (ollama: `ollama list`)", err, c.modelName())
		}
		return "", err
	}
	var out struct {
		Choices []struct {
			Message chatMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("model server at %s sent a reply that is not a chat completion", c.Display())
	}
	return out.Choices[0].Message.Content, nil
}

func (c *Remote) modelName() string {
	if c.ModelName != "" {
		return c.ModelName
	}
	return DefaultModelName
}

// serverMessage is the text of an error body: the string of {"error":"..."},
// the message of {"error":{"message":"..."}}, or the body itself.
func serverMessage(raw []byte) string {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Error) > 0 {
		var s string
		if json.Unmarshal(e.Error, &s) == nil {
			return s
		}
		var o struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &o) == nil && o.Message != "" {
			return o.Message
		}
	}
	return strings.TrimSpace(string(raw))
}
