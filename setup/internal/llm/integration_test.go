//go:build integration

package llm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/setup/internal/intent"
)

func realServer(t *testing.T) (bin ServerBin, model string) {
	t.Helper()
	model = os.Getenv("SNUG_SETUP_TEST_MODEL")
	if model == "" {
		t.Skip("SNUG_SETUP_TEST_MODEL names no GGUF")
	}
	home, _ := os.UserHomeDir()
	bin, err := FindServer(os.Getenv("SNUG_SETUP_LLAMA_SERVER"), home)
	if err != nil {
		t.Skip(err)
	}
	return bin, model
}

// TestRealServerRoundTrip runs the real llama-server on a real GGUF through
// the Server backend: the reply is under the schema, the Go gate accepts a
// complete one, and Close leaves nothing behind.
func TestRealServerRoundTrip(t *testing.T) {
	bin, model := realServer(t)
	s, err := StartServer(context.Background(), bin, model, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dir := s.dir
	out, err := Model{B: s}.Complete(context.Background(), intent.System, "target: /tmp/x\nrequest: let the build reach the network", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "{") || !strings.Contains(out, `"actions"`) {
		t.Fatalf("reply is not under the schema: %q", out)
	}
	if json.Valid([]byte(out)) {
		if _, err := intent.Parse([]byte(out)); err != nil {
			t.Errorf("Go gate refuses %q: %v", out, err)
		}
	}
	s.Close()
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("socket directory %s left behind", dir)
	}
}

// TestRealServerRefusesACorruptModel: the model file is untrusted input to
// llama.cpp's parser, and a file it cannot read ends the child, not
// snug-setup; the caller gets an error carrying the server's own log.
func TestRealServerRefusesACorruptModel(t *testing.T) {
	bin, model := realServer(t)
	b, err := os.ReadFile(model)
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(t.TempDir(), "cut.gguf")
	os.WriteFile(cut, b[:1<<20], 0o644)
	_, err = StartServer(context.Background(), bin, cut, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "exited") {
		t.Errorf("a truncated model started: %v", err)
	}
}
