package main

import (
	"context"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/rules"
)

func TestBackendFlags(t *testing.T) {
	for name, f := range map[string]backendFlags{
		"binary with a url":  {URL: "http://x", ServerBin: "/bin/llama-server"},
		"binary and no gguf": {ServerBin: "/bin/llama-server"},
	} {
		if err := f.check(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, f := range map[string]backendFlags{
		"rules":          {},
		"server":         {Model: "a.gguf", ServerBin: "/x"},
		"url":            {URL: "http://127.0.0.1:1"},
		"url with model": {URL: "http://127.0.0.1:1", Model: "snug-setup:latest"},
	} {
		if err := f.check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDescribeSaysWhatIsNotPromised(t *testing.T) {
	var b strings.Builder
	describe(llm.Caps{Constrained: true, Local: true, Where: "llama-server on a socket"}, &b)
	if b.Len() != 0 {
		t.Errorf("a local constrained backend needs no warning: %q", b.String())
	}
	describe(llm.Caps{Where: "http://203.0.113.5:8080 (remote)"}, &b)
	for _, want := range []string{"not on this machine", "not known to be constrained", "never guessed"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in %q", want, b.String())
		}
	}
}

// TestNoFlagsIsTheRules: the default needs no model, starts nothing and
// reaches no server.
func TestNoFlagsIsTheRules(t *testing.T) {
	i, c, err := newInterpreter(context.Background(), backendFlags{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := i.(rules.Interpreter); !ok {
		t.Errorf("default interpreter is %T", i)
	}
	if err := c.Close(); err != nil {
		t.Error(err)
	}
}
