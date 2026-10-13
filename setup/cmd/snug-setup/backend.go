package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gomoni/snug/setup/internal/llm"
)

// backendFlags is what the command line says about the model. Exactly one of
// Model, ServerModel and URL is set.
type backendFlags struct {
	Model       string // GGUF run inside this process
	ServerModel string // GGUF run by a llama-server child
	URL         string // a server that is already running
	ServerBin   string
	Threads     int
}

// check refuses anything but exactly one of the three ways to reach a model.
func (f backendFlags) check() error {
	n := 0
	for _, s := range []string{f.Model, f.ServerModel, f.URL} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return errors.New("give exactly one of --model, --llama-server-model and --llm-url: there is no built-in model, and guessing a server would send your host's key comments and logins somewhere you did not choose")
	}
	if f.ServerBin != "" && f.ServerModel == "" {
		return errors.New("--llama-server names the binary --llama-server-model starts, and is meaningless without it")
	}
	return nil
}

// newBackend builds the one Backend the session will use. This is the only
// place that knows which kind it is; everything after it goes through
// llm.Backend, and the sentence about what it cannot promise is printed from
// Caps rather than decided by a branch in the caller.
func newBackend(ctx context.Context, f backendFlags, home string) (llm.Backend, error) {
	switch {
	case f.Model != "":
		fmt.Fprintf(os.Stderr, "loading %s in-process (a few seconds)\n", f.Model)
		return openInproc(f.Model, f.Threads)
	case f.ServerModel != "":
		bin, err := llm.FindServer(f.ServerBin, home)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "starting %s on %s (this can take a while)\n", bin, f.ServerModel)
		return llm.StartServer(ctx, bin, f.ServerModel, 5*time.Minute)
	default:
		r := &llm.Remote{URL: f.URL}
		if _, err := r.Endpoint(); err != nil {
			return nil, err
		}
		return r, nil
	}
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
