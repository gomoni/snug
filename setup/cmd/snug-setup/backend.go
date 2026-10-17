package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/rules"
	"github.com/gomoni/snug/setup/internal/session"
)

// backendFlags is what the command line says about the model. Without URL
// there is none; with it, Model is the name of a model on that server, and
// may be empty.
type backendFlags struct {
	URL   string // an OpenAI-compatible server that is already running
	Model string
}

// check refuses a model name without a server to ask: snug-setup runs no
// model of its own.
func (f backendFlags) check() error {
	if f.Model != "" && f.URL == "" {
		return errors.New("--model names a model on the --openai-url server; snug-setup runs no model of its own, so give the server too, or neither")
	}
	return nil
}

// newInterpreter builds the one interpreter the session will use: the rules,
// unless the command line names a server. This is the only place that knows
// which.
func newInterpreter(_ context.Context, f backendFlags) (session.Interpreter, io.Closer, error) {
	if f.URL == "" {
		return rules.Interpreter{}, io.NopCloser(nil), nil
	}
	r := &llm.Remote{URL: f.URL, ModelName: f.Model}
	if _, err := r.Endpoint(); err != nil {
		return nil, nil, err
	}
	describe(r.Caps(), os.Stderr)
	return llm.Interpreter{M: llm.Model{B: r}}, r, nil
}

// describe prints, from Caps, what the user is told about the server. The
// schema goes as response_format, which a server may ignore, so that is said
// for every server.
func describe(c llm.Caps, w io.Writer) {
	if !c.Local {
		fmt.Fprintf(w, "warning: the model is at %s, which is not on this machine. Every request sends it your ssh key comments, GitHub logins, git author and the digest of any file you ask it to read.\n", c.Where)
	}
	fmt.Fprintf(w, "model at %s: output is not known to be constrained to the action schema; a reply that is not an action list is refused, never guessed.\n", c.Where)
}
