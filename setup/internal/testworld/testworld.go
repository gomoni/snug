// Package testworld is a fake host for tests of the session engine and its
// front ends: a home with three ssh keys, an ssh-agent holding one, gh with two
// logins and a GitHub that lists one key, a global git author, a model that
// answers from a table, and a `snug --dry-run --json` that resolves the profile
// file it is handed. Nothing here touches the real host but t.TempDir.
package testworld

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/verify"
)

// BlobOf is a valid ssh-ed25519 key blob that differs per seed.
func BlobOf(seed byte) string {
	raw := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	for i := 0; i < 32; i++ {
		raw[len(raw)-1-i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// Model answers from a table keyed by the request text, with "|file" appended
// when the prompt carries a file digest. Each reply is used once.
type Model struct {
	mu      sync.Mutex
	replies map[string][]string
	Prompts []string
}

// Complete implements llm.Completer.
func (m *Model) Complete(_ context.Context, _, user string, _ float64) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Prompts = append(m.Prompts, user)
	lines := strings.Split(user, "\n")
	key := strings.TrimPrefix(lines[len(lines)-1], "request: ")
	if strings.Contains(user, "\nfile ") {
		key += "|file"
	}
	q := m.replies[key]
	if len(q) == 0 {
		return "", fmt.Errorf("fake model: no reply left for %q", key)
	}
	m.replies[key] = q[1:]
	return q[0], nil
}

// Requests returns the request line of every prompt, in order.
func (m *Model) Requests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, p := range m.Prompts {
		lines := strings.Split(p, "\n")
		out = append(out, strings.TrimPrefix(lines[len(lines)-1], "request: "))
	}
	return out
}

// World is one fake host.
type World struct {
	t       *testing.T
	Home    string
	Target  string
	ProfDir string
	Model   *Model
	Cmds    []string
	Envs    [][]string

	GHAccounts string // gh auth status output
	APIBlob    string // key blob the fake GitHub lists for the user
	APILogin   string
	SnugErr    error
	NoGH       bool
	NoSnug     bool
	// Refuse maps a profile name to the message the fake snug refuses it with
	// when asked about the human's own configuration (no XDG_CONFIG_HOME in
	// the command's environment).
	Refuse map[string]string
	// DryRunDoc, when set, is what the fake snug prints for --dry-run instead
	// of resolving the file.
	DryRunDoc string
}

// GHTwo is `gh auth status` with two logins on github.com.
const GHTwo = `github.com
  ✓ Logged in to github.com account account1 (keyring)
  - Active account: true
  ✓ Logged in to github.com account account2 (keyring)
  - Active account: false
`

// New returns a world whose home holds id_account1, id_account2 (held by the
// agent and listed by GitHub for account2) and id_other.
func New(t *testing.T) *World {
	w := &World{t: t, Home: t.TempDir(), Target: t.TempDir(), ProfDir: filepath.Join(t.TempDir(), "snug", "profiles.d"),
		GHAccounts: GHTwo, APILogin: "account2", APIBlob: BlobOf(2)}
	w.Model = &Model{replies: map[string][]string{}}
	w.Key("id_account1", "account1@laptop", 1)
	w.Key("id_account2", "account2@laptop", 2)
	w.Key("id_other", "other@example.org", 3)
	return w
}

// Key writes ~/.ssh/STEM.pub with comment.
func (w *World) Key(stem, comment string, seed byte) {
	dir := filepath.Join(w.Home, ".ssh")
	os.MkdirAll(dir, 0o700)
	line := "ssh-ed25519 " + BlobOf(seed) + " " + comment + "\n"
	if err := os.WriteFile(filepath.Join(dir, stem+".pub"), []byte(line), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// Reply queues the model's answer to request.
func (w *World) Reply(request string, actions ...string) {
	w.Model.mu.Lock()
	defer w.Model.mu.Unlock()
	w.Model.replies[request] = append(w.Model.replies[request], `{"actions":[`+strings.Join(actions, ",")+`]}`)
}

// RawReply queues a reply that is not built from actions.
func (w *World) RawReply(request, reply string) {
	w.Model.mu.Lock()
	defer w.Model.mu.Unlock()
	w.Model.replies[request] = append(w.Model.replies[request], reply)
}

// Profile writes NAME.toml with body into the world's profile directory, the
// one the session reads the human's own profiles from.
func (w *World) Profile(file, body string) {
	if err := os.MkdirAll(w.ProfDir, 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.ProfDir, file), []byte(body), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// Host is the draft.Host of this world.
func (w *World) Host() draft.Host {
	return draft.Host{Home: w.Home, Target: w.Target, RuntimeDir: "/run/user/1000"}
}

// LookPath finds gh at /usr/bin/gh and snug at /fake/snug unless switched off.
func (w *World) LookPath(n string) (string, error) {
	switch n {
	case "gh":
		if w.NoGH {
			return "", exec.ErrNotFound
		}
		return "/usr/bin/gh", nil
	case "snug":
		if w.NoSnug {
			return "", exec.ErrNotFound
		}
		return "/fake/snug", nil
	}
	return "", exec.ErrNotFound
}

// Run is the world's hostfacts.Runner.
func (w *World) Run(ctx context.Context, env []string, name string, args ...string) (hostfacts.Result, error) {
	argv := strings.Join(append([]string{name}, args...), " ")
	w.Cmds = append(w.Cmds, argv)
	w.Envs = append(w.Envs, env)
	switch {
	case name == "ssh-add":
		return hostfacts.Result{Stdout: []byte("ssh-ed25519 " + BlobOf(2) + " held\n")}, nil
	case name == "gh" && w.NoGH:
		return hostfacts.Result{}, exec.ErrNotFound
	case argv == "gh auth status":
		return hostfacts.Result{Stdout: []byte(w.GHAccounts)}, nil
	case strings.HasPrefix(argv, "gh auth token"):
		return hostfacts.Result{Stdout: []byte("ghp_SECRET\n")}, nil
	case strings.HasPrefix(argv, "gh api") && strings.HasSuffix(argv, " user"):
		return hostfacts.Result{Stdout: []byte(`{"login":"` + w.APILogin + `"}`)}, nil
	case strings.HasPrefix(argv, "gh api") && strings.HasSuffix(argv, "user/keys"):
		return hostfacts.Result{Stdout: []byte(`[{"key":"ssh-ed25519 ` + w.APIBlob + `"}]`)}, nil
	case name == "git" && args[len(args)-1] == "user.name":
		return hostfacts.Result{Stdout: []byte("Account Two\n")}, nil
	case name == "git" && args[len(args)-1] == "user.email":
		return hostfacts.Result{Stdout: []byte("two@example.com\n")}, nil
	case name == "/fake/snug" && args[0] == "--dry-run":
		return w.dryRun(env, args)
	case name == "/fake/snug":
		if w.SnugErr != nil {
			return hostfacts.Result{Stderr: []byte("snug: unknown key")}, w.SnugErr
		}
		return hostfacts.Result{}, nil
	}
	return hostfacts.Result{}, errors.New("unexpected command: " + argv)
}

// APICalls counts `gh api` invocations.
func (w *World) APICalls() int {
	n := 0
	for _, c := range w.Cmds {
		if strings.HasPrefix(c, "gh api") {
			n++
		}
	}
	return n
}

var (
	fakeInclude = regexp.MustCompile(`(?m)^  "(@[a-z-]+)",$`)
	fakeUser    = regexp.MustCompile(`(?m)^  "([a-zA-Z0-9][a-zA-Z0-9-]*)",$`)
	fakeList    = regexp.MustCompile(`(?m)^(ro|rw|tmpfs) = \[(.*)\]$`)
)

// dryRun is a fake `snug --dry-run --json [--no-defaults] -p NAME DIR`: it
// reads the profile file the check wrote and resolves only what
// verify.Compare reads. verify's TestCheckAgainstRealSnug is what holds the
// shape to snug's.
func (w *World) dryRun(env, args []string) (hostfacts.Result, error) {
	if w.DryRunDoc != "" {
		return hostfacts.Result{Stdout: []byte(w.DryRunDoc)}, nil
	}
	if len(env) == 0 {
		name := args[slices.Index(args, "-p")+1]
		if msg, bad := w.Refuse[name]; bad {
			out, _ := json.Marshal(map[string]any{
				"snug":    map[string]any{"format": 2, "outcome": "refused", "lossy": false, "exit_code": 77, "policy_resolved": false},
				"refusal": map[string]any{"message": msg},
			})
			return hostfacts.Result{Stdout: out}, errors.New("exit status 77")
		}
		out, _ := json.Marshal(map[string]any{
			"snug":     map[string]any{"format": 2, "outcome": "ok", "lossy": false, "exit_code": 0, "policy_resolved": true},
			"profiles": map[string]any{"selected": []string{"@sys", "@home", "@target-rw", name}, "implied": []string{}},
			"network":  map[string]any{"mode": "isolated", "egress": false},
		})
		return hostfacts.Result{Stdout: out}, nil
	}
	xdg := strings.TrimPrefix(env[0], "XDG_CONFIG_HOME=")
	noDefaults := slices.Contains(args, "--no-defaults")
	name := args[slices.Index(args, "-p")+1]
	// HOSTREAD-EXEMPT: the file verify.Run wrote a moment ago into a
	// directory it created with os.MkdirTemp.
	body, err := os.ReadFile(filepath.Join(xdg, "snug", "profiles.d", name+".toml"))
	if err != nil {
		return hostfacts.Result{}, err
	}
	var selected []string
	if !noDefaults {
		selected = append(selected, verify.Defaults...)
	}
	selected = append(selected, name)
	var implied []string
	for _, m := range fakeInclude.FindAllStringSubmatch(string(body), -1) {
		for _, n := range draft.Closure(m[1]) {
			if !slices.Contains(selected, n) && !slices.Contains(implied, n) {
				implied = append(implied, n)
			}
		}
	}
	for _, m := range fakeUser.FindAllStringSubmatch(string(body), -1) {
		if !slices.Contains(selected, m[1]) && !slices.Contains(implied, m[1]) {
			implied = append(implied, m[1])
		}
	}
	expand := strings.NewReplacer("{target}", w.Target, "{home}", w.Home, "~/", w.Home+"/")
	type mount struct {
		Guest  string   `json:"guest"`
		Host   string   `json:"host"`
		Kind   string   `json:"kind"`
		Access string   `json:"access"`
		From   []string `json:"from"`
	}
	var mounts []mount
	for _, m := range fakeList.FindAllStringSubmatch(string(body), -1) {
		for _, p := range strings.Split(strings.Trim(m[2], `"`), `", "`) {
			host, guest, staged := strings.Cut(p, ":")
			switch {
			case staged:
				mounts = append(mounts, mount{guest, expand.Replace(host), "bind", "ro", []string{name}})
			case m[1] == "tmpfs":
				mounts = append(mounts, mount{expand.Replace(p), "", "tmpfs", "rw", []string{name}})
			default:
				mounts = append(mounts, mount{expand.Replace(p), expand.Replace(p), "bind", m[1], []string{name}})
			}
		}
	}
	net := slices.Contains(selected, "@net") || slices.Contains(implied, "@net")
	doc := map[string]any{
		"snug":     map[string]any{"format": 2, "outcome": "ok", "lossy": false, "exit_code": 0, "policy_resolved": true},
		"profiles": map[string]any{"selected": selected, "implied": implied},
		"mounts":   mounts,
		"network":  map[string]any{"mode": map[bool]string{true: "egress", false: "isolated"}[net], "egress": net},
	}
	out, err := json.Marshal(doc)
	return hostfacts.Result{Stdout: out}, err
}

// LLMServer serves the world's Model as an OpenAI-compatible
// /v1/chat/completions endpoint, for tests that go through llm.Remote.
func (w *World) LLMServer() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Temperature float64 `json:"temperature"`
		}
		if r.URL.Path != "/v1/chat/completions" || json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Messages) != 2 {
			http.Error(rw, "bad request", http.StatusBadRequest)
			return
		}
		reply, err := w.Model.Complete(r.Context(), req.Messages[0].Content, req.Messages[1].Content, req.Temperature)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": reply}}},
		})
	}))
	w.t.Cleanup(srv.Close)
	return srv
}
