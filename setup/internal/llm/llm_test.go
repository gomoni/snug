package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"regexp"
	"strings"
	"syscall"
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
	s, err := StartServer(context.Background(), ServerBin{Path: exe}, model, 20*time.Second)
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
	if _, err := StartServer(context.Background(), ServerBin{Path: "/bin/false"}, model, 5*time.Second); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Errorf("%v", err)
	}
	if _, err := StartServer(context.Background(), ServerBin{Path: "/bin/false"}, "/nonexistent.gguf", time.Second); err == nil {
		t.Error("missing model accepted")
	}
}

func TestFindServer(t *testing.T) {
	home := t.TempDir()
	if p, err := FindServer("/x/llama-server", home); err != nil || p != (ServerBin{Path: "/x/llama-server"}) {
		t.Error(p, err)
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := FindServer("", home); err == nil || !strings.Contains(err.Error(), "--llama-server") {
		t.Errorf("%v", err)
	}
	d := filepath.Join(home, ".cache/snug-setup/llama.cpp", PinnedTag, "llama-"+PinnedTag)
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "llama-server"), nil, 0o755)
	if p, err := FindServer("", home); err != nil || !p.Cached || !strings.HasSuffix(p.Path, "llama-"+PinnedTag+"/llama-server") {
		t.Error(p, err)
	}
}

// TestFindServerPrefersThePinnedTagNotALaterSortingDir is redteam setup r5
// R5-1: a directory planted beside the pinned one, whose name sorts later,
// must not be the llama-server snug-setup runs outside any sandbox.
func TestFindServerPrefersThePinnedTagNotALaterSortingDir(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	home := t.TempDir()
	base := filepath.Join(home, ".cache/snug-setup/llama.cpp")
	for _, d := range []string{PinnedTag + "/llama-" + PinnedTag, "zzz/zzz", PinnedTag + "z/llama-" + PinnedTag + "z"} {
		os.MkdirAll(filepath.Join(base, d), 0o755)
		os.WriteFile(filepath.Join(base, d, "llama-server"), nil, 0o755)
	}
	p, err := FindServer("", home)
	if err != nil || !p.Cached || p.Path != filepath.Join(base, PinnedTag, "llama-"+PinnedTag, "llama-server") {
		t.Errorf("%+v %v", p, err)
	}
	os.RemoveAll(filepath.Join(base, PinnedTag))
	if p, err := FindServer("", home); err == nil {
		t.Errorf("only planted directories are left and %+v was chosen", p)
	}
}

// plantCache lays out a cache holding the pinned names with content that is
// not llama.cpp's, and a llama-server that records that it ran.
func plantCache(t *testing.T) (home, marker string) {
	t.Helper()
	home = t.TempDir()
	marker = filepath.Join(t.TempDir(), "ran")
	d := filepath.Join(home, ".cache/snug-setup/llama.cpp", PinnedTag, "llama-"+PinnedTag)
	os.MkdirAll(d, 0o755)
	m, err := parseManifest(pinnedManifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.files {
		os.WriteFile(filepath.Join(d, f.name), []byte("not llama.cpp"), 0o755)
	}
	os.WriteFile(filepath.Join(d, "llama-server"), []byte("#!/bin/sh\n: > "+marker+"\n"), 0o755)
	return home, marker
}

// TestTamperedCacheIsRefusedBeforeExec is redteam setup r5 R5-1: a cache whose
// binary or whose shared library is not the pinned release's is not run, and
// the planted llama-server never starts.
func TestTamperedCacheIsRefusedBeforeExec(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	model := filepath.Join(t.TempDir(), "m.gguf")
	os.WriteFile(model, []byte("x"), 0o644)
	home, marker := plantCache(t)
	sb, err := FindServer("", home)
	if err != nil {
		t.Fatal(err)
	}
	_, err = StartServer(context.Background(), sb, model, 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "sha256") || !strings.Contains(err.Error(), "fetch-llama-server.sh") {
		t.Errorf("tampered binary and libraries: %v", err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Error("the planted llama-server ran")
	}
}

// TestStageChecksEveryFile pins stage with a manifest small enough to build:
// success copies and links, and each of a changed library, a missing file, a
// link in place of a file and an extra ggml backend is refused.
func TestStageChecksEveryFile(t *testing.T) {
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	man := "tag t\nsha256 " + sum("bin") + " llama-server\nsha256 " + sum("lib") + " libllama.so.0\nlink libllama.so libllama.so.0\n"
	m, err := parseManifest(man)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() string {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, "llama-server"), []byte("bin"), 0o755)
		os.WriteFile(filepath.Join(d, "libllama.so.0"), []byte("lib"), 0o755)
		return d
	}
	src := mk()
	dst := t.TempDir()
	if err := m.stage(src, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "libllama.so")); string(b) != "lib" {
		t.Errorf("link not staged: %q", b)
	}
	cases := map[string]func(d string){
		"changed library": func(d string) { os.WriteFile(filepath.Join(d, "libllama.so.0"), []byte("evil"), 0o755) },
		"missing file":    func(d string) { os.Remove(filepath.Join(d, "libllama.so.0")) },
		"link for a file": func(d string) {
			os.Remove(filepath.Join(d, "llama-server"))
			os.WriteFile(filepath.Join(d, "other"), []byte("bin"), 0o755)
			os.Symlink("other", filepath.Join(d, "llama-server"))
		},
		"fifo for a file": func(d string) {
			os.Remove(filepath.Join(d, "llama-server"))
			syscall.Mkfifo(filepath.Join(d, "llama-server"), 0o755)
		},
		"extra backend": func(d string) { os.WriteFile(filepath.Join(d, "libggml-evil.so"), []byte("x"), 0o755) },
	}
	for name, mutate := range cases {
		d := mk()
		mutate(d)
		if err := m.stage(d, t.TempDir()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestPinnedTagMatchesTheFetchScript: the Go constant, the manifest and the
// script that unpacks the release name the same tag.
func TestPinnedTagMatchesTheFetchScript(t *testing.T) {
	b, err := os.ReadFile("../../../scripts/fetch-llama-server.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^tag=(\S+)$`).FindSubmatch(b)
	if m == nil || string(m[1]) != PinnedTag {
		t.Errorf("scripts/fetch-llama-server.sh pins %q, llm.PinnedTag is %q", m, PinnedTag)
	}
	man, err := parseManifest(pinnedManifest)
	if err != nil || man.tag != PinnedTag {
		t.Errorf("llama-server.manifest: %q %v", man.tag, err)
	}
	if !man.has("llama-server") {
		t.Error("the manifest does not cover llama-server")
	}
}

// TestRemoteWhereRedactsUserinfo is redteam setup r5 R5-4: a password in
// --openai-url is not printed by Caps, by the unreachable-server error or by
// the URL error.
func TestRemoteWhereRedactsUserinfo(t *testing.T) {
	c := &Remote{URL: "http://tok:S3CRET@127.0.0.1:1/"}
	if w := c.Caps().Where; strings.Contains(w, "S3CRET") || !strings.Contains(w, "127.0.0.1:1") {
		t.Errorf("Where: %q", w)
	}
	_, err := c.Complete(context.Background(), Request{})
	if err == nil || strings.Contains(err.Error(), "S3CRET") {
		t.Errorf("unreachable: %v", err)
	}
	_, err = (&Remote{URL: "ftp://tok:S3CRET@host"}).Endpoint()
	if err == nil || strings.Contains(err.Error(), "S3CRET") {
		t.Errorf("endpoint: %v", err)
	}
}

// TestServerLogInErrorIsSanitized is redteam setup r5 R5-5: llama-server's
// output echoes the untrusted model file, and none of it may reach the error
// as an escape sequence or as a line of its own.
func TestServerLogInErrorIsSanitized(t *testing.T) {
	dir := t.TempDir()
	sh := filepath.Join(dir, "llama-server")
	os.WriteFile(sh, []byte("#!/bin/sh\nprintf 'a\\033]0;pwned\\007b\\033[2J\\342\\200\\256c\\nsnug-setup: saved everything\\r\\n'\nexit 1\n"), 0o755)
	model := filepath.Join(dir, "m.gguf")
	os.WriteFile(model, []byte("x"), 0o644)
	_, err := StartServer(context.Background(), ServerBin{Path: sh}, model, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{"\x1b", "\x07", "\r", "\u202e"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error holds %q: %q", bad, err)
		}
	}
	for _, l := range strings.Split(err.Error(), "\n")[1:] {
		if !strings.HasPrefix(l, "    | ") {
			t.Errorf("log text starts a line of its own: %q", l)
		}
	}
	if !strings.Contains(err.Error(), "saved everything") {
		t.Errorf("log lost: %q", err)
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
	if err == nil || !strings.Contains(err.Error(), `model "snug-setup" not found, try pulling it first`) || !strings.Contains(err.Error(), "--model NAME") {
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
