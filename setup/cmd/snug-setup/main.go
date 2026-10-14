// Command snug-setup builds a snug profile from a conversation. It reads the
// project and the host, proposes what they make plain, and reads what you say
// with fixed rules into a list of actions; everything exact, and every
// question about identities, is Go's. A model can read requests instead
// (--model, --openai-url). It is a convenience: snug never needs it, and a
// profile it writes is read by snug like any other file.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/plain"
	"github.com/gomoni/snug/setup/internal/session"
)

const usage = `usage: snug-setup [--model FILE.gguf | --openai-url URL [--model NAME]] [--llama-server PATH] [--offline] [--profile-dir DIR] [DIR]

  Without --model or --openai-url, requests are read by fixed rules: no model, no server, nothing
  leaves this machine but what --offline turns off.

  --model FILE.gguf    read requests with a model: run llama-server on it, on a private unix socket
  --openai-url URL     use a server that is already running and speaks the OpenAI chat-completions API
                       (llama-server, ollama); --model NAME then names the model on it (ollama needs an
                       installed model's name; llama-server ignores it). To use our GGUF in ollama, import
                       it with a Modelfile that carries the Qwen chat template.
  --llama-server PATH  llama-server binary for --model (default: PATH, then ~/.cache/snug-setup/llama.cpp/*/*/;
                       scripts/fetch-llama-server.sh puts the tested release there)
  --offline            never ask GitHub whether an ssh key belongs to an account
  --plain              accepted and ignored: snug-setup always asks nothing. The question printed just
                       before is answered with a line of yes, no or its numbers; any with /accept, /decline
                       and /pick (/help lists them).
  --profile-dir DIR    where profiles are saved (default: $XDG_CONFIG_HOME/snug/profiles.d)
  DIR                  the project directory the profile is for (default: the current directory)
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "snug-setup: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("snug-setup", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var bf backendFlags
	fs.StringVar(&bf.Model, "model", "", "")
	fs.StringVar(&bf.URL, "openai-url", "", "")
	fs.StringVar(&bf.ServerBin, "llama-server", "", "")
	offline := fs.Bool("offline", false, "")
	fs.Bool("plain", false, "")
	profileDir := fs.String("profile-dir", "", "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if err := bf.check(); err != nil {
		fs.Usage()
		return err
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return fmt.Errorf("at most one directory")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot find your home directory: %w", err)
	}
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	dir := "."
	if fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	target, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if t, err := filepath.EvalSymlinks(target); err == nil {
		target = t
	}
	if err := draft.CheckTarget(target); err != nil {
		return err
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", target)
	}
	if *profileDir == "" {
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" {
			cfg = filepath.Join(home, ".config")
		}
		*profileDir = filepath.Join(cfg, "snug", "profiles.d")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	interp, closer, err := newInterpreter(ctx, bf, home)
	if err != nil {
		return err
	}
	defer closer.Close()

	// The loop blocks reading stdin, so a signal has to end the process from
	// here; the backend is closed first because os.Exit skips deferred calls.
	var finished atomic.Bool
	go func() {
		<-ctx.Done()
		if finished.Load() {
			return
		}
		closer.Close()
		os.Exit(130)
	}()

	host := draft.Host{
		Home:       home,
		Target:     target,
		RuntimeDir: os.Getenv("XDG_RUNTIME_DIR"),
		ConfigHome: os.Getenv("XDG_CONFIG_HOME"),
	}
	// One front end serves the terminal too: it asks nothing, so only a line
	// that is nothing but an answer is taken for one, and it is the only one
	// that follows the session's rules.
	plain.Run(ctx, plain.Config{
		Session: session.Config{
			Interpreter: interp,
			Run:         hostfacts.ExecRunner,
			Host:        host,
			Offline:     *offline,
			ProfileDir:  *profileDir,
			ProfileDirs: ingest.ProfileDirs(os.Getenv("XDG_CONFIG_HOME"), home),
		},
		In:   os.Stdin,
		Out:  os.Stdout,
		Echo: !isTerminal(os.Stdin),
	})
	finished.Store(true)
	return nil
}
