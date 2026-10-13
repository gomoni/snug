//go:build !snug_setup_noinproc

// Package inproc runs a GGUF model inside the snug-setup process with
// github.com/goccy/go-llama: llama.cpp compiled to wasm and translated to Go,
// so there is no cgo, no shared library and no second process. The C++ parser
// of the model file runs on a wasm linear memory, which is a Go slice with
// bounds checks: a model file that trips a ggml assertion surfaces as a Go
// error from the call, not as an abort of snug-setup. The model file is still
// untrusted input and the engine is still a very large generated dependency;
// the server backend of package llm is the alternative for anyone who prefers
// the llama.cpp they already run.
package inproc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	gollama "github.com/goccy/go-llama"

	"github.com/gomoni/snug/setup/internal/llm"
)

// Options configures Open. Schema and Grammar travel together: Grammar is the
// GBNF form of Schema, and Complete refuses a Request carrying any other
// schema rather than decode it under a grammar for a different contract.
type Options struct {
	Schema  []byte
	Grammar string
	// Threads defaults to NumCPU-2 (at least 1), so the machine stays usable.
	Threads int
	// NCtx and NBatch default to 4096 and 2048. A prompt over NBatch tokens is
	// refused with its size, since the engine decodes a prompt as one batch.
	NCtx, NBatch int
	// MaxMemory bounds the wasm linear memory; zero means 6 GiB. The 1.5B
	// q4_k_m model uses about 2.6 GB of it, and a model file that asks for
	// more fails to load instead of taking the machine's memory.
	MaxMemory uint64
	// Log receives the engine's stderr; Open's errors quote its tail.
	Log *llm.Tail
}

// Engine is a loaded model and one context with a KV cache that survives
// between Complete calls.
type Engine struct {
	opts  Options
	where string
	log   *llm.Tail

	mu     sync.Mutex
	l      *gollama.Llama
	m      *gollama.Model
	c      *gollama.Context
	closed bool
	last   Stats
}

// Stats describes the last Complete.
type Stats struct {
	PromptTokens, CachedTokens, DecodedTokens int
	Prefill, Decode                           time.Duration
}

// checkBuild refuses a build whose kernels are scalar. goarch and settings
// are runtime.GOARCH and the debug.BuildInfo settings. Without GOAMD64 of v2
// or more the engine's SIMD kernels are not used and the first prompt takes
// minutes (a 982-token prompt on a 0.5B model did not finish in 900 s), which
// looks like a hang; a refusal names the fix instead.
func checkBuild(goarch string, settings map[string]string) error {
	if goarch != "amd64" {
		return nil
	}
	switch settings["GOAMD64"] {
	case "v2", "v3", "v4":
		return nil
	}
	return fmt.Errorf("this snug-setup was built with GOAMD64=%q, and the in-process engine is unusably slow without v2 or better (minutes per prompt); rebuild with GOAMD64=v3 (make setup), or run the model with --llama-server-model FILE.gguf or --llm-url URL", settings["GOAMD64"])
}

func buildSettings() map[string]string {
	out := map[string]string{}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			out[s.Key] = s.Value
		}
	}
	return out
}

// Open loads the GGUF at path. It returns an error when the build is
// unsuitable (see checkBuild), when o.Schema or o.Grammar is empty, and when
// the file cannot be read as a model; the last quotes the engine's own log.
// A truncated or corrupt file is an error here, never a crash.
func Open(path string, o Options) (*Engine, error) {
	if err := checkBuild(runtime.GOARCH, buildSettings()); err != nil {
		return nil, err
	}
	if len(o.Schema) == 0 || o.Grammar == "" {
		return nil, errors.New("in-process engine: Options.Schema and Options.Grammar are both required")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("model file %s: %w", path, err)
	}
	if o.Threads <= 0 {
		o.Threads = max(1, runtime.NumCPU()-2)
	}
	if o.NCtx <= 0 {
		o.NCtx = 4096
	}
	if o.NBatch <= 0 {
		o.NBatch = 2048
	}
	if o.MaxMemory == 0 {
		o.MaxMemory = 6 << 30
	}
	log := o.Log
	if log == nil {
		log = &llm.Tail{}
	}
	fail := func(what string, err error) error {
		return fmt.Errorf("in-process engine: %s %s: %w\nengine log: %s\n(the file may be truncated or not a GGUF model; --llama-server-model or --llm-url use a server instead)", what, path, err, log.String())
	}
	l, err := gollama.New(gollama.WithStderr(log), gollama.WithMaxMemory(o.MaxMemory))
	if err != nil {
		return nil, fail("cannot start the engine for", err)
	}
	m, err := l.LoadModel(path)
	if err != nil {
		l.Close()
		return nil, fail("cannot load", err)
	}
	c, err := m.NewContext(gollama.ContextParams{NCtx: uint32(o.NCtx), NBatch: uint32(o.NBatch), NThreads: uint32(o.Threads)})
	if err != nil {
		m.Close()
		l.Close()
		return nil, fail("cannot make a context for", err)
	}
	return &Engine{opts: o, where: "in-process (" + path + ")", log: log, l: l, m: m, c: c}, nil
}

// Caps reports a local backend that enforces the schema.
func (e *Engine) Caps() llm.Caps {
	return llm.Caps{Constrained: true, Local: true, Where: e.where}
}

// LastStats returns the numbers of the most recent Complete.
func (e *Engine) LastStats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.last
}

// Complete renders the model's own chat template over system and user, decodes
// under the grammar, and keeps the KV cache so that the next call re-decodes
// only the part of its prompt that differs from this one. It returns an error
// for a Request.Schema other than Options.Schema, a prompt over the batch
// size, a closed engine, and any failure of the engine; ctx cancelled
// interrupts the generation and CLOSES the engine, because go-llama's only
// interrupt is closing the context, so the engine is unusable afterwards.
func (e *Engine) Complete(ctx context.Context, r llm.Request) (string, error) {
	if string(r.Schema) != string(e.opts.Schema) {
		return "", errors.New("in-process engine: the request's schema is not the one its grammar was derived from; refusing to decode under a different contract")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return "", errors.New("in-process engine: closed")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	prompt, err := e.m.ApplyChatTemplate([]gollama.Message{
		{Role: "system", Content: r.System}, {Role: "user", Content: r.User},
	}, "", true)
	if err != nil {
		return "", fmt.Errorf("in-process engine: the model has no usable chat template: %w", err)
	}
	toks, err := e.m.Tokenize(prompt, false, true)
	if err != nil {
		return "", fmt.Errorf("in-process engine: cannot tokenize the prompt: %w", err)
	}
	if limit := min(e.opts.NBatch, e.opts.NCtx-r.MaxTokens); len(toks) > limit {
		return "", fmt.Errorf("in-process engine: the prompt is %d tokens and this engine takes %d (context %d, batch %d, reply %d)", len(toks), limit, e.opts.NCtx, e.opts.NBatch, r.MaxTokens)
	}
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			e.c.Close()
		case <-stopWatch:
		}
	}()
	start := time.Now()
	var first time.Duration
	res, err := e.c.Stream(prompt, gollama.Params{
		Grammar:     e.opts.Grammar,
		Temperature: float32(r.Temperature),
		NPredict:    r.MaxTokens,
		CachePrompt: true,
	}, func(string) {
		if first == 0 {
			first = time.Since(start)
		}
	})
	close(stopWatch)
	<-watchDone
	if ctx.Err() != nil {
		e.closed = true
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("in-process engine: generation failed: %w\nengine log: %s", err, e.log.String())
	}
	e.last = Stats{PromptTokens: res.NPrompt, CachedTokens: res.NCached, DecodedTokens: res.NDecoded,
		Prefill: first, Decode: time.Since(start) - first}
	return res.Text, nil
}

// Close frees the context, the model and the engine, in that order, and is
// safe to call twice. It may be called while a Complete is running: closing
// the context first is what interrupts that generation, so the signal path
// does not wait for the reply it is abandoning.
func (e *Engine) Close() error {
	cerr := e.c.Close()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.l == nil {
		return nil
	}
	e.closed = true
	err := errors.Join(cerr, e.m.Close(), e.l.Close())
	e.l = nil
	return err
}
