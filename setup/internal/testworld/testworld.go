// Package testworld is a fake host for tests: a home with three ssh keys, an
// ssh-agent holding one, gh with two logins and a GitHub that lists one key, a
// global git author, and a `snug --dry-run --json` that resolves the profile
// file it is handed. Nothing here touches the real host but t.TempDir.
package testworld

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/verify"
)

// keyOf is the ed25519 key of seed: real, so a commit can be signed with it.
func keyOf(seed byte) ed25519.PrivateKey {
	var sd [ed25519.SeedSize]byte
	for i := range sd {
		sd[i] = seed + byte(i)
	}
	return ed25519.NewKeyFromSeed(sd[:])
}

func putString(b *bytes.Buffer, s []byte) {
	binary.Write(b, binary.BigEndian, uint32(len(s)))
	b.Write(s)
}

func pubBlob(seed byte) []byte {
	var b bytes.Buffer
	putString(&b, []byte("ssh-ed25519"))
	putString(&b, keyOf(seed).Public().(ed25519.PublicKey))
	return b.Bytes()
}

// BlobOf is the ssh-ed25519 public key blob of seed, base64 as in a .pub file.
func BlobOf(seed byte) string { return base64.StdEncoding.EncodeToString(pubBlob(seed)) }

// SignCommit is the armoured SSHSIG that `git commit -S` with gpg.format=ssh
// makes with the key of seed over payload (namespace git, sha512).
func SignCommit(seed byte, payload []byte) string {
	h := sha512.Sum512(payload)
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, f := range [][]byte{[]byte("git"), nil, []byte("sha512"), h[:]} {
		putString(&signed, f)
	}
	var sig bytes.Buffer
	putString(&sig, []byte("ssh-ed25519"))
	putString(&sig, ed25519.Sign(keyOf(seed), signed.Bytes()))
	var b bytes.Buffer
	b.WriteString("SSHSIG")
	binary.Write(&b, binary.BigEndian, uint32(1))
	for _, f := range [][]byte{pubBlob(seed), []byte("git"), nil, []byte("sha512"), sig.Bytes()} {
		putString(&b, f)
	}
	enc := base64.StdEncoding.EncodeToString(b.Bytes())
	var lines []string
	for len(enc) > 70 {
		lines = append(lines, enc[:70])
		enc = enc[70:]
	}
	return "-----BEGIN SSH SIGNATURE-----\n" + strings.Join(append(lines, enc), "\n") + "\n-----END SSH SIGNATURE-----"
}

// World is one fake host.
type World struct {
	t       *testing.T
	Home    string
	Target  string
	ProfDir string
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
