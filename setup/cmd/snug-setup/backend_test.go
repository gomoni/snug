package main

import (
	"context"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/rules"
)

func TestBackendFlags(t *testing.T) {
	if err := (backendFlags{Model: "qwen2.5:1.5b"}).check(); err == nil || !strings.Contains(err.Error(), "--openai-url") {
		t.Errorf("a model name with no server accepted: %v", err)
	}
	for name, f := range map[string]backendFlags{
		"rules":          {},
		"url":            {URL: "http://127.0.0.1:1"},
		"url with model": {URL: "http://127.0.0.1:1", Model: "qwen2.5:1.5b"},
	} {
		if err := f.check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDescribeSaysWhatIsNotPromised(t *testing.T) {
	var b strings.Builder
	describe(llm.Caps{Local: true, Where: "http://127.0.0.1:8080 (remote)"}, &b)
	if strings.Contains(b.String(), "not on this machine") || !strings.Contains(b.String(), "not known to be constrained") {
		t.Errorf("local server: %q", b.String())
	}
	b.Reset()
	describe(llm.Caps{Where: "http://203.0.113.5:8080 (remote)"}, &b)
	for _, want := range []string{"not on this machine", "not known to be constrained", "never guessed"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in %q", want, b.String())
		}
	}
}

// TestNoFlagsIsTheRules: the default needs no model and reaches no server.
func TestNoFlagsIsTheRules(t *testing.T) {
	i, c, err := newInterpreter(context.Background(), backendFlags{})
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
