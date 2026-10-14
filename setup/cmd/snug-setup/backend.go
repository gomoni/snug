package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/rules"
	"github.com/gomoni/snug/setup/internal/session"
)

// backendFlags is what the command line says about the model. With neither
// Model nor URL there is none. Without URL, Model is a GGUF run by a
// llama-server child of ours; with URL, it is the name of a model on that
// server, and may be empty.
type backendFlags struct {
	Model     string
	URL       string // a server that is already running, with its own model
	ServerBin string
}

// check refuses a command line that names the llama-server binary without a
// GGUF for it to run.
func (f backendFlags) check() error {
	if f.ServerBin != "" && f.URL != "" {
		return errors.New("--llama-server names the binary snug-setup starts for a GGUF, and is meaningless with --openai-url")
	}
	if f.ServerBin != "" && f.Model == "" {
		return errors.New("--llama-server names the binary snug-setup starts for --model FILE.gguf; give the GGUF too, or neither")
	}
	return nil
}

// newInterpreter builds the one interpreter the session will use: the rules,
// unless the command line names a model. This is the only place that knows
// which; the closer stops what it started.
func newInterpreter(ctx context.Context, f backendFlags, home string) (session.Interpreter, io.Closer, error) {
	if f.Model == "" && f.URL == "" {
		return rules.Interpreter{}, io.NopCloser(nil), nil
	}
	b, err := newBackend(ctx, f, home)
	if err != nil {
		return nil, nil, err
	}
	describe(b.Caps(), os.Stderr)
	return llm.Interpreter{M: llm.Model{B: b}}, b, nil
}

// newBackend builds the one Backend the session will use. This is the only
// place that knows which kind it is; everything after it goes through
// llm.Backend, and the sentence about what it cannot promise is printed from
// Caps rather than decided by a branch in the caller.
func newBackend(ctx context.Context, f backendFlags, home string) (llm.Backend, error) {
	if f.URL == "" {
		bin, err := llm.FindServer(f.ServerBin, home)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "starting %s on %s (this can take a while)\n", bin.Path, f.Model)
		return llm.StartServer(ctx, bin, f.Model, 5*time.Minute)
	}
	r := &llm.Remote{URL: f.URL, ModelName: f.Model}
	if _, err := r.Endpoint(); err != nil {
		return nil, err
	}
	return r, nil
}

// describe prints, from Caps, what the user is told about the backend.
func describe(c llm.Caps, w interface{ Write([]byte) (int, error) }) {
	if !c.Local {
		fmt.Fprintf(w, "warning: the model is at %s, which is not on this machine. Every request sends it your ssh key comments, GitHub logins, git author and the digest of any file you ask it to read.\n", c.Where)
	}
	if !c.Constrained {
		fmt.Fprintf(w, "model at %s: output is not known to be constrained to the action schema; a reply that is not an action list is refused, never guessed.\n", c.Where)
	}
}
