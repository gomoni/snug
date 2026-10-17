package llm

import (
	"context"
	"encoding/json"

	"github.com/gomoni/snug/setup/internal/intent"
)

// MaxTokens bounds a reply. Eight short actions fit well inside it.
const MaxTokens = 256

// Request is one turn.
type Request struct {
	System, User string
	Temperature  float64
	MaxTokens    int
	// Schema is the JSON schema the reply must satisfy. It goes to the server
	// as response_format, which a server may ignore, so intent.Parse decides
	// on every reply anyway.
	Schema json.RawMessage
}

// Caps is what a Backend says about itself, for the one sentence main prints.
type Caps struct {
	// Where names the backend for the "starting" line.
	Where string
	// Local: the prompt never leaves this machine. It carries ssh key
	// comments, GitHub logins, the git author and the digest of any file the
	// user asks to read, so a prompt that leaves is worth saying out loud.
	Local bool
}

// Backend answers Requests. Complete returns the model's text or an error;
// it is called from one goroutine at a time. Close is safe to call twice.
type Backend interface {
	Complete(ctx context.Context, r Request) (string, error)
	Caps() Caps
	Close() error
}

// Model adapts a Backend to the Completer that Interpreter calls. It is the
// one place that knows intent.Schema and MaxTokens.
type Model struct{ B Backend }

// Complete sends system and user to the backend under intent.Schema.
func (m Model) Complete(ctx context.Context, system, user string, temperature float64) (string, error) {
	return m.B.Complete(ctx, Request{System: system, User: user, Temperature: temperature,
		MaxTokens: MaxTokens, Schema: intent.Schema})
}
