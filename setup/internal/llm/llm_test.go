package llm

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

	"github.com/gomoni/snug/setup/internal/intent"
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
		got, err := (&Remote{URL: in}).Endpoint()
		if err != nil || got != want {
			t.Errorf("%s -> %s, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "127.0.0.1:8080", "ftp://x", "http://"} {
		if _, err := (&Remote{URL: bad}).Endpoint(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:1": true, "http://localhost:1": true, "http://[::1]:1": true,
		"http://10.0.0.5:1": false, "https://api.example.com": false,
	} {
		if got := (&Remote{URL: u}).IsLoopback(); got != want {
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
	c := &Remote{URL: srv.URL}
	got, err := c.Complete(context.Background(), Request{System: "SYS", User: "USER", MaxTokens: MaxTokens, Schema: intent.Schema})
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
	if _, err := (&Remote{URL: bad.URL}).Complete(context.Background(), Request{System: "s", User: "u", Schema: intent.Schema}); err == nil || !strings.Contains(err.Error(), "model not loaded") {
		t.Errorf("%v", err)
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer empty.Close()
	if _, err := (&Remote{URL: empty.URL}).Complete(context.Background(), Request{System: "s", User: "u", Schema: intent.Schema}); err == nil {
		t.Error("empty reply accepted")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	url := "http://" + l.Addr().String()
	l.Close()
	if _, err := (&Remote{URL: url}).Complete(context.Background(), Request{System: "s", User: "u", Schema: intent.Schema}); err == nil || !strings.Contains(err.Error(), "--model") {
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
	if c := s.Caps(); !c.Constrained || !c.Local || !strings.Contains(c.Where, "llama.sock") {
		t.Errorf("a spawned llama-server is local and constrained: %+v", c)
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

type recorder struct{ got Request }

func (r *recorder) Complete(_ context.Context, q Request) (string, error) {
	r.got = q
	return "ok", nil
}
func (r *recorder) Caps() Caps   { return Caps{} }
func (r *recorder) Close() error { return nil }

// TestModelAdapterOwnsSchemaAndBudget: callers pass text and a temperature;
// the contract and the reply bound come from one place.
func TestModelAdapterOwnsSchemaAndBudget(t *testing.T) {
	r := &recorder{}
	out, err := Model{B: r}.Complete(context.Background(), "S", "U", 0.3)
	if err != nil || out != "ok" {
		t.Fatal(out, err)
	}
	if r.got.System != "S" || r.got.User != "U" || r.got.Temperature != 0.3 || r.got.MaxTokens != MaxTokens || string(r.got.Schema) != string(intent.Schema) {
		t.Errorf("%+v", r.got)
	}
}

func TestRemoteCapsAreUnconstrained(t *testing.T) {
	c := (&Remote{URL: "http://127.0.0.1:1"}).Caps()
	if c.Constrained || !c.Local {
		t.Errorf("%+v", c)
	}
	if c := (&Remote{URL: "https://api.example.com"}).Caps(); c.Local || !strings.Contains(c.Where, "api.example.com") {
		t.Errorf("%+v", c)
	}
	var _ Backend = (*Remote)(nil)
	var _ Backend = (*Server)(nil)
}

// TestRemoteOllamaShape: a server shaped like ollama's OpenAI endpoint wants
// the model named; a missing one answers with an error body, and the user is
// told which flag to change.
func TestRemoteOllamaShape(t *testing.T) {
	var seen map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &seen)
		if seen["model"] != "snug-setup:latest" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":{"message":"model \"%v\" not found, try pulling it first","type":"api_error"}}`, seen["model"])
			return
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"actions\":[{\"op\":\"show\"}]}"}}]}`))
	}))
	defer srv.Close()
	req := Request{System: "s", User: "u", MaxTokens: MaxTokens, Schema: intent.Schema}

	_, err := (&Remote{URL: srv.URL}).Complete(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), `model "snug-setup" not found, try pulling it first`) || !strings.Contains(err.Error(), "--remote-model") {
		t.Errorf("a missing model should name the flag: %v", err)
	}
	if path != "/v1/chat/completions" || seen["response_format"] == nil {
		t.Errorf("path %s, body %v", path, seen)
	}

	got, err := (&Remote{URL: srv.URL + "/v1", ModelName: "snug-setup:latest"}).Complete(context.Background(), req)
	if err != nil || !strings.Contains(got, "show") {
		t.Fatalf("%q %v", got, err)
	}
	if seen["model"] != "snug-setup:latest" || path != "/v1/chat/completions" {
		t.Errorf("model/path: %v %s", seen["model"], path)
	}
	rf := seen["response_format"].(map[string]any)
	if rf["type"] != "json_schema" {
		t.Errorf("response_format %v", rf)
	}
}

func TestServerMessageShapes(t *testing.T) {
	for in, want := range map[string]string{
		`{"error":"model \"x\" not found, try pulling it first"}`: `model "x" not found, try pulling it first`,
		`{"error":{"message":"nope","type":"t"}}`:                 "nope",
		"plain text\n":         "plain text",
		`{"error":{"code":1}}`: `{"error":{"code":1}}`,
	} {
		if got := serverMessage([]byte(in)); got != want {
			t.Errorf("%s -> %q, want %q", in, got, want)
		}
	}
}
