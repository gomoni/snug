package llm

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("SNUG_FAKE_LLAMA") == "1" {
		fs := flag.NewFlagSet("fake", flag.ExitOnError)
		fs.String("port", "", "")
		fs.String("model", "", "")
		host := fs.String("host", "", "")
		fs.String("c", "", "")
		fs.String("np", "", "")
		_ = fs.Parse(os.Args[1:])
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
		if l, err := net.Listen("unix", *host); err == nil {
			http.Serve(l, mux)
		}
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:8080":        "http://127.0.0.1:8080/v1/chat/completions",
		"http://127.0.0.1:8080/":       "http://127.0.0.1:8080/v1/chat/completions",
		"http://h/v1":                  "http://h/v1/chat/completions",
		"http://h/v1/chat/completions": "http://h/v1/chat/completions",
	} {
		got, err := (&Client{URL: in}).Endpoint()
		if err != nil || got != want {
			t.Errorf("%s -> %s, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "127.0.0.1:8080", "ftp://x", "http://"} {
		if _, err := (&Client{URL: bad}).Endpoint(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:1": true, "http://localhost:1": true, "http://[::1]:1": true,
		"http://10.0.0.5:1": false, "https://api.example.com": false,
	} {
		if got := (&Client{URL: u}).IsLoopback(); got != want {
			t.Errorf("%s: %v", u, got)
		}
	}
}

func TestComplete(t *testing.T) {
	var seen map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &seen)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"actions\":[{\"op\":\"show\"}]}"}}]}`))
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL}
	got, err := c.Complete(context.Background(), "SYS", "USER", 0)
	if err != nil || got != `{"actions":[{"op":"show"}]}` {
		t.Fatalf("%q %v", got, err)
	}
	if seen["temperature"] != float64(0) || seen["max_tokens"] != float64(256) {
		t.Errorf("sampling: %v", seen)
	}
	rf := seen["response_format"].(map[string]any)
	js := rf["json_schema"].(map[string]any)
	if rf["type"] != "json_schema" || js["schema"].(map[string]any)["required"] == nil {
		t.Errorf("response_format: %v", rf)
	}
	msgs := seen["messages"].([]any)
	if len(msgs) != 2 || msgs[0].(map[string]any)["content"] != "SYS" || msgs[1].(map[string]any)["content"] != "USER" {
		t.Errorf("messages: %v", msgs)
	}
}

func TestCompleteErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"model not loaded"}`, http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if _, err := (&Client{URL: bad.URL}).Complete(context.Background(), "s", "u", 0); err == nil || !strings.Contains(err.Error(), "model not loaded") {
		t.Errorf("%v", err)
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer empty.Close()
	if _, err := (&Client{URL: empty.URL}).Complete(context.Background(), "s", "u", 0); err == nil {
		t.Error("empty reply accepted")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	url := "http://" + l.Addr().String()
	l.Close()
	if _, err := (&Client{URL: url}).Complete(context.Background(), "s", "u", 0); err == nil || !strings.Contains(err.Error(), "--model") {
		t.Errorf("unreachable server error should say what to do: %v", err)
	}
}

// TestStartServerAndClose: the server listens on a unix socket in a 0700
// directory of its own, not on a 127.0.0.1 port. Redteam setup r1 S6: a port
// picked free and bound later could be taken first by another local user, and
// any local user could query a loopback server for the prompts it served,
// which carry key comments, logins and the git author.
func TestStartServerAndClose(t *testing.T) {
	t.Setenv("SNUG_FAKE_LLAMA", "1")
	model := filepath.Join(t.TempDir(), "m.gguf")
	os.WriteFile(model, []byte("x"), 0o644)
	exe, _ := os.Executable()
	s, err := StartServer(context.Background(), exe, model, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.URL, "127.0.0.1") || s.HTTP == nil {
		t.Errorf("server must not be reached over TCP: %s", s.URL)
	}
	fi, err := os.Stat(s.dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("socket directory %s: %v %v", s.dir, fi.Mode(), err)
	}
	if fi, err := os.Stat(filepath.Join(s.dir, "llama.sock")); err != nil || fi.Mode()&fs.ModeSocket == 0 {
		t.Errorf("no socket: %v", err)
	}
	if resp, err := s.HTTP.Get(s.URL + "/health"); err != nil || resp.StatusCode != 200 {
		t.Errorf("health over the socket: %v", err)
	} else {
		resp.Body.Close()
	}
	s.Close()
	s.Close()
	if _, err := os.Stat(s.dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("socket directory left behind: %v", err)
	}
}

func TestStartServerReportsEarlyExit(t *testing.T) {
	model := filepath.Join(t.TempDir(), "m.gguf")
	os.WriteFile(model, []byte("x"), 0o644)
	if _, err := StartServer(context.Background(), "/bin/false", model, 5*time.Second); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Errorf("%v", err)
	}
	if _, err := StartServer(context.Background(), "/bin/false", "/nonexistent.gguf", time.Second); err == nil {
		t.Error("missing model accepted")
	}
}

func TestFindServer(t *testing.T) {
	home := t.TempDir()
	if p, err := FindServer("/x/llama-server", home); err != nil || p != "/x/llama-server" {
		t.Error(p, err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := FindServer("", home); err == nil || !strings.Contains(err.Error(), "--llama-server") {
		t.Errorf("%v", err)
	}
	d := filepath.Join(home, ".cache/snug-setup/llama.cpp/b1/llama-b1")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "llama-server"), nil, 0o755)
	if p, err := FindServer("", home); err != nil || !strings.HasSuffix(p, "llama-b1/llama-server") {
		t.Error(p, err)
	}
}
