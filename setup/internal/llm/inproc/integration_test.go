//go:build integration && !snug_setup_noinproc

package inproc

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/setup/internal/gbnf"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/llm"
)

func testModel(t *testing.T) string {
	t.Helper()
	m := os.Getenv("SNUG_SETUP_TEST_MODEL")
	if m == "" {
		t.Skip("SNUG_SETUP_TEST_MODEL names no GGUF")
	}
	return m
}

// TestInprocRoundTrip loads a real GGUF and checks the three properties the
// backend exists for: the reply is accepted by the Go gate, the second turn
// re-decodes only the suffix that changed, and a request under another schema
// is refused.
func TestInprocRoundTrip(t *testing.T) {
	e, err := Open(testModel(t), Options{Schema: intent.Schema, Grammar: gbnfSchema()})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	m := llm.Model{B: e}
	prefix := strings.Repeat("host ssh key: id_ed25519 (michal@laptop); github login: vyskocilm; ", 12)
	ask := func(req string) (string, Stats) {
		t.Helper()
		out, err := m.Complete(context.Background(), intent.System, prefix+"\nrequest: "+req, 0)
		if err != nil {
			t.Fatal(err)
		}
		return out, e.LastStats()
	}
	out1, s1 := ask("let the build reach the network")
	if !strings.HasPrefix(out1, "{") || !strings.Contains(out1, `"actions"`) {
		t.Fatalf("reply is not under the grammar: %q", out1)
	}
	// A model that is not the fine-tune can run out of tokens inside a long
	// reply; a complete reply must pass the Go gate.
	if json.Valid([]byte(out1)) {
		if _, err := intent.Parse([]byte(out1)); err != nil {
			t.Errorf("Go gate refuses the engine's reply %q: %v", out1, err)
		}
	}
	if s1.CachedTokens != 0 {
		t.Errorf("first turn reused %d tokens of an empty cache", s1.CachedTokens)
	}
	_, s2 := ask("show me the draft")
	if s2.CachedTokens < s2.PromptTokens/2 {
		t.Errorf("second turn reused %d of %d prompt tokens; the shared prefix is most of the prompt", s2.CachedTokens, s2.PromptTokens)
	}
	t.Logf("turn 1: %d tokens, prefill %v, decode %v; turn 2: %d tokens, %d cached, prefill %v, decode %v",
		s1.PromptTokens, s1.Prefill, s1.Decode, s2.PromptTokens, s2.CachedTokens, s2.Prefill, s2.Decode)

	if _, err := e.Complete(context.Background(), llm.Request{System: "s", User: "u", MaxTokens: 8, Schema: []byte(`{"type":"object"}`)}); err == nil {
		t.Error("a request under another schema was decoded")
	}
	big := strings.Repeat("word ", 5000)
	if _, err := e.Complete(context.Background(), llm.Request{System: "s", User: big, MaxTokens: 256, Schema: intent.Schema}); err == nil || !strings.Contains(err.Error(), "tokens") {
		t.Errorf("a prompt over the batch: %v", err)
	}
}

// TestInprocCancelStopsGeneration: cancelling ctx ends a running generation
// promptly instead of waiting for the reply, and the engine closes cleanly.
func TestInprocCancelStopsGeneration(t *testing.T) {
	e, err := Open(testModel(t), Options{Schema: intent.Schema, Grammar: gbnfSchema()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = e.Complete(ctx, llm.Request{System: intent.System, User: strings.Repeat("word ", 1500), MaxTokens: 256, Schema: intent.Schema})
	if err == nil {
		t.Fatal("cancelled generation succeeded")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("cancel took %v", d)
	}
	if err := e.Close(); err != nil {
		t.Errorf("close after cancel: %v", err)
	}
}

func gbnfSchema() string { return gbnf.Schema }
