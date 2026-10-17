// Command snug-setup builds a snug profile from a conversation. It reads the
// project and the host, proposes what they make plain, and reads what you say
// with fixed rules into a list of actions; everything exact, and every
// question about identities, is Go's. A model can read requests instead
// (--model, --openai-url). It is a convenience: snug never needs it, and a
// profile it writes is read by snug like any other file.
//
// Exit status: 0 when the session ended with nothing to lose (a profile was
// saved and nothing changed after it, or no change was ever accepted and no
// question is open); 1 for a usage or startup error; 3 when the draft was not
// saved; 4 when only questions are still open; 130 when a signal ended it.
// 3 wins over 4. A refused /save leaves the draft unsaved, so a session that
// ends after one exits 3 or 4 and never 0.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
  --plain              accepted for compatibility and changes nothing: snug-setup reads lines from stdin and
                       prints its questions as text. The question printed just before is answered with a
                       line of yes, no or its numbers; or with /accept, /decline and /pick (/help lists them).
  --profile-dir DIR    where profiles are saved (default: $XDG_CONFIG_HOME/snug/profiles.d)
  DIR                  the project directory the profile is for (default: the current directory)

exit status:
  0    nothing to lose: the profile was saved, or nothing was accepted and no question is open
  1    usage or startup error
  3    the session ended with a draft that was not saved (a refused /save counts)
  4    the session ended with questions still open and no unsaved draft
  130  interrupted
`

const (
	exitUnsaved = 3
	exitOpen    = 4
)

// exitStatus is the status a finished session earns. Unsaved wins over open
// questions: a script that sees 4 knows no draft was lost.
func exitStatus(unsaved bool, open int) int {
	switch {
	case unsaved:
		return exitUnsaved
	case open > 0:
		return exitOpen
	}
	return 0
}

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug-setup: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run() (int, error) {
	fs := flag.NewFlagSet("snug-setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var bf backendFlags
	fs.StringVar(&bf.Model, "model", "", "")
	fs.StringVar(&bf.URL, "openai-url", "", "")
	fs.StringVar(&bf.ServerBin, "llama-server", "", "")
	offline := fs.Bool("offline", false, "")
	fs.Bool("plain", false, "")
	profileDir := fs.String("profile-dir", "", "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usage)
			return 0, nil
		}
		fmt.Fprint(os.Stderr, usage)
		return 1, err
	}
	if err := bf.check(); err != nil {
		fmt.Fprint(os.Stderr, usage)
		return 1, err
	}
	if fs.NArg() > 1 {
		fmt.Fprint(os.Stderr, usage)
		return 1, fmt.Errorf("at most one directory")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return 1, fmt.Errorf("cannot find your home directory: %w", err)
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
		return 1, err
	}
	if t, err := filepath.EvalSymlinks(target); err == nil {
		target = t
	}
	if err := draft.CheckTarget(target); err != nil {
		return 1, err
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		return 1, fmt.Errorf("%s is not a directory", target)
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
		return 1, err
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
	// One front end serves the terminal and a pipe alike: questions are
	// printed as text, and only a line that is nothing but an answer is taken
	// for one, under the session's rules.
	sess := plain.Run(ctx, plain.Config{
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
	return exitStatus(sess.Unsaved(), len(sess.Pending())), nil
}
