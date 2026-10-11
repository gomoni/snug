package hostfacts

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func blobOf(seed byte) string {
	raw := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	for i := 0; i < 32; i++ {
		raw[len(raw)-1-i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func writeKey(t *testing.T, home, stem, comment string, seed byte) string {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := "ssh-ed25519 " + blobOf(seed)
	if comment != "" {
		line += " " + comment
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".pub"), []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return blobOf(seed)
}

type call struct {
	env  []string
	argv []string
}

type fake struct {
	calls []call
	reply func(argv []string, env []string) (Result, error)
}

func (f *fake) run(_ context.Context, env []string, name string, args ...string) (Result, error) {
	argv := append([]string{name}, args...)
	f.calls = append(f.calls, call{env, argv})
	return f.reply(argv, env)
}

func TestSSHKeysAndAgent(t *testing.T) {
	home := t.TempDir()
	a := writeKey(t, home, "id_a", "alice@laptop", 1)
	writeKey(t, home, "id_b", "", 50)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_a"), []byte("PRIVATE KEY MATERIAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "junk.pub"), []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fake{reply: func(argv, _ []string) (Result, error) {
		return Result{Stdout: []byte("ssh-ed25519 " + a + " held\n")}, nil
	}}
	keys, warns := SSHKeys(context.Background(), home, f.run)
	if len(keys) != 2 || keys[0].Stem != "id_a" || keys[1].Stem != "id_b" {
		t.Fatalf("keys: %+v", keys)
	}
	if !keys[0].InAgent || keys[1].InAgent {
		t.Errorf("agent flags: %+v", keys)
	}
	if keys[0].Comment != "alice@laptop" || !strings.HasPrefix(keys[0].Fingerprint, "SHA256:") {
		t.Errorf("key 0: %+v", keys[0])
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "junk.pub") {
		t.Errorf("warnings: %v", warns)
	}
}

func TestSSHAgentUnreachableWarns(t *testing.T) {
	home := t.TempDir()
	writeKey(t, home, "id_a", "x", 1)
	f := &fake{reply: func(argv, _ []string) (Result, error) { return Result{}, exec.ErrNotFound }}
	keys, warns := SSHKeys(context.Background(), home, f.run)
	if len(keys) != 1 || keys[0].InAgent || len(warns) != 1 {
		t.Fatalf("keys %+v warns %v", keys, warns)
	}
}

func TestSSHKeysNoSSHDir(t *testing.T) {
	f := &fake{reply: func(argv, _ []string) (Result, error) { t.Fatal("ran a command with no keys"); return Result{}, nil }}
	keys, warns := SSHKeys(context.Background(), t.TempDir(), f.run)
	if len(keys) != 0 || len(warns) != 0 {
		t.Fatalf("%+v %v", keys, warns)
	}
}

// TestSSHKeysSkipsAFifo: a FIFO named *.pub must neither block nor be read.
// An open without O_NONBLOCK would wait for a writer that never comes.
func TestSSHKeysSkipsAFifo(t *testing.T) {
	home := t.TempDir()
	writeKey(t, home, "id_real", "me@host", 1)
	if err := syscall.Mkfifo(filepath.Join(home, ".ssh", "id_fifo.pub"), 0o644); err != nil {
		t.Skip(err)
	}
	f := &fake{reply: func(argv, _ []string) (Result, error) { return Result{}, nil }}
	done := make(chan []SSHKey, 1)
	go func() { keys, _ := SSHKeys(context.Background(), home, f.run); done <- keys }()
	select {
	case keys := <-done:
		if len(keys) != 1 || keys[0].Stem != "id_real" {
			t.Errorf("%+v", keys)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSHKeys blocked on a FIFO")
	}
}

func TestCommentControlCharsRemoved(t *testing.T) {
	_, _, c, err := parsePub("ssh-ed25519 " + blobOf(1) + " a\x1b[31mb\u202ec")
	if err != nil || c != "a[31mbc" {
		t.Fatalf("%q %v", c, err)
	}
}

const ghStatus = `github.com
  ✓ Logged in to github.com account alice (keyring)
  - Active account: true
  - Git operations protocol: ssh
  - Token: gho_************************************
  - Token scopes: 'repo'

  ✓ Logged in to github.com account alice-corp (keyring)
  - Active account: false
  - Git operations protocol: https
ghe.corp.example
  X Failed to log in to ghe.corp.example account bob (keyring)
  - The token in keyring is invalid.
`

func TestParseGHStatus(t *testing.T) {
	got := ParseGHStatus(ghStatus)
	want := []GHAccount{{"github.com", "alice", true}, {"github.com", "alice-corp", false}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("%+v", got)
	}
	leg := ParseGHStatus("github.com\n  ✓ Logged in to github.com as carol (oauth_token)\n")
	if len(leg) != 1 || leg[0].User != "carol" || !leg[0].Active {
		t.Fatalf("legacy %+v", leg)
	}
}

func TestGitHubAccountsToleratesMissingGh(t *testing.T) {
	f := &fake{reply: func(argv, _ []string) (Result, error) { return Result{}, exec.ErrNotFound }}
	a, inst := GitHubAccounts(context.Background(), f.run)
	if a != nil || inst {
		t.Fatalf("%v %v", a, inst)
	}
	f = &fake{reply: func(argv, _ []string) (Result, error) {
		return Result{Stderr: []byte(ghStatus)}, errors.New("exit status 1")
	}}
	a, inst = GitHubAccounts(context.Background(), f.run)
	if len(a) != 2 || !inst {
		t.Fatalf("%v %v", a, inst)
	}
}

func TestGitAuthors(t *testing.T) {
	f := &fake{reply: func(argv, _ []string) (Result, error) {
		switch argv[len(argv)-1] {
		case "user.name":
			return Result{Stdout: []byte("Alice Doe\n")}, nil
		case "user.email":
			return Result{Stdout: []byte("alice@example.com\n")}, nil
		}
		return Result{}, errors.New("?")
	}}
	got := GitAuthors(context.Background(), f.run)
	if len(got) != 1 || got[0].String() != "Alice Doe <alice@example.com>" {
		t.Fatalf("%v", got)
	}
	none := &fake{reply: func(argv, _ []string) (Result, error) { return Result{}, exec.ErrNotFound }}
	if GitAuthors(context.Background(), none.run) != nil {
		t.Fatal("expected none")
	}
}

func ghFake(login, keyBlob string) *fake {
	return &fake{reply: func(argv, env []string) (Result, error) {
		switch {
		case argv[1] == "auth":
			return Result{Stdout: []byte("tok123\n")}, nil
		case argv[len(argv)-1] == "user":
			return Result{Stdout: []byte(`{"login":"` + login + `"}`)}, nil
		case argv[len(argv)-1] == "user/keys":
			return Result{Stdout: []byte(`[{"id":1,"key":"ssh-ed25519 ` + keyBlob + `"}]`)}, nil
		}
		return Result{}, errors.New("unexpected")
	}}
}

func TestCheckKeyOwnership(t *testing.T) {
	blob := blobOf(1)
	fp, _ := FingerprintOf(blob)
	key := SSHKey{Fingerprint: fp}

	f := ghFake("alice", blob)
	got, err := CheckKeyOwnership(context.Background(), f.run, "github.com", "alice", key)
	if err != nil || !got.Match {
		t.Fatalf("match: %+v %v", got, err)
	}
	for _, c := range f.calls[:1] {
		if len(c.env) != 0 {
			t.Errorf("token minting must not carry a token env: %v", c.env)
		}
	}
	for _, c := range f.calls[1:] {
		if len(c.env) != 1 || c.env[0] != "GH_TOKEN=tok123" {
			t.Errorf("api call env %v, want only GH_TOKEN", c.env)
		}
		if strings.Contains(strings.Join(c.argv, " "), "tok123") {
			t.Errorf("token leaked into argv: %v", c.argv)
		}
	}

	f = ghFake("alice", blobOf(99))
	got, err = CheckKeyOwnership(context.Background(), f.run, "github.com", "alice", key)
	if err != nil || got.Match || !strings.Contains(got.Detail, fp) {
		t.Fatalf("mismatch: %+v %v", got, err)
	}

	f = ghFake("mallory", blob)
	if _, err = CheckKeyOwnership(context.Background(), f.run, "github.com", "alice", key); err == nil {
		t.Fatal("token of another login accepted")
	}

	f = ghFake("alice", blob)
	if _, err = CheckKeyOwnership(context.Background(), f.run, "ghe.corp.example", "alice", key); err != nil {
		t.Fatal(err)
	}
	if f.calls[1].env[0] != "GH_ENTERPRISE_TOKEN=tok123" {
		t.Errorf("enterprise env: %v", f.calls[1].env)
	}
}
