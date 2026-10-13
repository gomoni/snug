// Command snug-setup builds a snug profile from a conversation. A small local
// model turns what you say into a list of actions; everything exact, and every
// question about identities, is Go's. It is a convenience: snug never needs it,
// and a profile it writes is read by snug like any other file.
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
	"time"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/plain"
	"github.com/gomoni/snug/setup/internal/repl"
	"github.com/gomoni/snug/setup/internal/session"
)

const usage = `usage: snug-setup (--model FILE.gguf | --llm-url URL) [--llama-server PATH] [--offline] [--plain] [--profile-dir DIR] [DIR]

  --model FILE.gguf   run llama-server on this model, on 127.0.0.1, for the session
  --llm-url URL       use a server that is already running (OpenAI-compatible)
  --llama-server PATH llama-server binary (default: PATH, then ~/.cache/snug-setup/llama.cpp/*/*/)
  --offline           never ask GitHub whether an ssh key belongs to an account
  --plain             ask nothing: open questions are answered with /accept, /decline and
                      /pick lines (/help lists them). The default when stdin or stdout is
                      not a terminal.
  --profile-dir DIR   where profiles are saved (default: $XDG_CONFIG_HOME/snug/profiles.d)
  DIR                 the project directory the profile is for (default: the current directory)
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
	model := fs.String("model", "", "")
	llmURL := fs.String("llm-url", "", "")
	llama := fs.String("llama-server", "", "")
	offline := fs.Bool("offline", false, "")
	plainMode := fs.Bool("plain", false, "")
	profileDir := fs.String("profile-dir", "", "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if (*model == "") == (*llmURL == "") {
		fs.Usage()
		return fmt.Errorf("give exactly one of --model and --llm-url: there is no built-in model, and guessing a server would send your host's key comments and logins somewhere you did not choose")
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

	client := &llm.Client{URL: *llmURL}
	var srv *llm.Server
	if *model != "" {
		bin, err := llm.FindServer(*llama, home)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "starting %s on %s (this can take a while)\n", bin, *model)
		srv, err = llm.StartServer(ctx, bin, *model, 5*time.Minute)
		if err != nil {
			return err
		}
		client.URL = srv.URL
	} else if !client.IsLoopback() {
		fmt.Fprintf(os.Stderr, "warning: %s is not on this machine. Every request sends it your ssh key comments, GitHub logins, git author and the digest of any file you ask it to read.\n", *llmURL)
	}
	if _, err := client.Endpoint(); err != nil {
		return err
	}

	// The loop blocks reading stdin, so a signal has to end the process from
	// here; the server is killed first because os.Exit skips deferred calls.
	var finished atomic.Bool
	go func() {
		<-ctx.Done()
		if finished.Load() {
			return
		}
		if srv != nil {
			srv.Close()
		}
		os.Exit(130)
	}()

	host := draft.Host{
		Home:       home,
		Target:     target,
		RuntimeDir: os.Getenv("XDG_RUNTIME_DIR"),
	}
	// The prompting repl stays the terminal path until the TUI can save; it
	// must never see piped input, which its prompts would eat.
	if *plainMode || !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		plain.Run(ctx, plain.Config{
			Session: session.Config{
				Model:      client,
				Run:        hostfacts.ExecRunner,
				Host:       host,
				Offline:    *offline,
				ProfileDir: *profileDir,
			},
			In:   os.Stdin,
			Out:  os.Stdout,
			Echo: !isTerminal(os.Stdin),
		})
	} else {
		repl.New(ctx, repl.Config{
			Model:      client,
			In:         os.Stdin,
			Out:        os.Stdout,
			Run:        hostfacts.ExecRunner,
			Host:       host,
			Offline:    *offline,
			ProfileDir: *profileDir,
		}).Run(ctx)
	}
	finished.Store(true)
	if srv != nil {
		srv.Close()
	}
	return nil
}
