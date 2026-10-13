package main

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/llm"
)

func TestBackendFlagsNeedExactlyOne(t *testing.T) {
	for name, f := range map[string]backendFlags{
		"none":         {},
		"two":          {Model: "a.gguf", URL: "http://127.0.0.1:1"},
		"three":        {Model: "a", ServerModel: "b", URL: "c"},
		"binary alone": {URL: "http://x", ServerBin: "/bin/llama-server"},
	} {
		if err := f.check(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, f := range map[string]backendFlags{
		"inproc": {Model: "a.gguf"},
		"server": {ServerModel: "a.gguf", ServerBin: "/x"},
		"url":    {URL: "http://127.0.0.1:1"},
	} {
		if err := f.check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDescribeSaysWhatIsNotPromised(t *testing.T) {
	var b strings.Builder
	describe(llm.Caps{Constrained: true, Local: true, Where: "in-process"}, &b)
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
