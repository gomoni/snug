package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gomoni/snug/setup/internal/llm"
)

// backendFlags is what the command line says about the model. Without URL,
// Model is a GGUF run by a llama-server child of ours; with URL, it is the
// name of a model on that server, and may be empty.
type backendFlags struct {
	Model     string
	URL       string // a server that is already running, with its own model
	ServerBin string
}

// check refuses a command line that names no way to reach a model.
func (f backendFlags) check() error {
	if f.Model == "" && f.URL == "" {
		return errors.New("give --model FILE.gguf, or --openai-url URL of a server that is already running: there is no built-in model, and guessing a server would send your host's key comments and logins somewhere you did not choose")
	}
	if f.ServerBin != "" && f.URL != "" {
		return errors.New("--llama-server names the binary snug-setup starts for a GGUF, and is meaningless with --openai-url")
	}
	return nil
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
		fmt.Fprintf(os.Stderr, "starting %s on %s (this can take a while)\n", bin, f.Model)
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
