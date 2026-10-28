package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// Fake values only: every token below is a fixture, and none of these tests
// touch the host's glab, ~/.netrc or keyring.
const (
	fakeGlabToken = "glpat-FAKEFAKEFAKE_0123"
	glabHost      = "gitlab.example"
)

func glabID(src policy.GlabTokenSource) *policy.Identity {
	return &policy.Identity{Glab: policy.IdentityGlab{Host: glabHost, User: "you", TokenSource: src}}
}

type glabFakes struct {
	acct         glabAccount
	mintErr      error
	netrc        string
	netrcErr     error
	mintCalls    int
	netrcReads   int
	mintedFor    string
	lastNetrcLen int
}

func (f *glabFakes) mint(host string) (glabAccount, error) {
	f.mintCalls++
	f.mintedFor = host
	return f.acct, f.mintErr
}

func (f *glabFakes) read() ([]byte, error) {
	f.netrcReads++
	return []byte(f.netrc), f.netrcErr
}

func newGlabFakes() *glabFakes {
	return &glabFakes{
		acct:  glabAccount{User: "you", Token: policy.Secret(fakeGlabToken)},
		netrc: "machine " + glabHost + " login you password " + fakeGlabToken + "\n",
	}
}

func TestGlabMinterEnvStripsTheThreeTokenVars(t *testing.T) {
	in := []string{
		"PATH=/usr/bin", "GITLAB_TOKEN=a", "GITLAB_ACCESS_TOKEN=b", "OAUTH_TOKEN=c",
		"GITLAB_TOKEN_NOT=keep", "XOAUTH_TOKEN=keep", "HOME=/home/u", "GITLAB_TOKEN",
	}
	got := glabMinterEnv(in)
	want := []string{"PATH=/usr/bin", "GITLAB_TOKEN_NOT=keep", "XOAUTH_TOKEN=keep", "HOME=/home/u"}
	if !slices.Equal(got, want) {
		t.Errorf("glabMinterEnv = %v, want %v", got, want)
	}
	if len(in) != 8 || in[1] != "GITLAB_TOKEN=a" {
		t.Error("glabMinterEnv modified its argument")
	}
}

func TestStageGlabRefusesARealRunWithNoToken(t *testing.T) {
	for name, tc := range map[string]struct {
		src  policy.GlabTokenSource
		edit func(*glabFakes)
	}{
		"glab: no glab":       {policy.GlabTokenFromGlab, func(f *glabFakes) { f.mintErr = errors.New("glab is not installed on the host") }},
		"netrc: no file":      {policy.GlabTokenFromNetrc, func(f *glabFakes) { f.netrcErr = os.ErrNotExist }},
		"netrc: other host":   {policy.GlabTokenFromNetrc, func(f *glabFakes) { f.netrc = "machine other.example login you password x\n" }},
		"netrc: only default": {policy.GlabTokenFromNetrc, func(f *glabFakes) { f.netrc = "default login you password " + fakeGlabToken + "\n" }},
	} {
		t.Run(name, func(t *testing.T) {
			pol, f := ghPolicy(t), newGlabFakes()
			tc.edit(f)
			err := stageGlabConfig(pol, glabID(tc.src), false, f.mint, f.read)
			if err == nil {
				t.Fatal("a real run with no credential for the pinned account started; the sandbox then silently has no glab")
			}
			for _, w := range []string{"no usable GitLab credential", glabHost, "does not fall back"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal does not contain %q: %v", w, err)
				}
			}
			if strings.Contains(err.Error(), fakeGlabToken) {
				t.Error("refusal printed a token")
			}
			if len(pol.Mounts) != 0 || len(pol.Env) != 0 {
				t.Errorf("a refused run staged mounts %v / env %v", pol.Mounts, pol.Env)
			}
		})
	}
}

func TestStageGlabRefusesUserMismatch(t *testing.T) {
	for _, src := range []policy.GlabTokenSource{policy.GlabTokenFromGlab, policy.GlabTokenFromNetrc} {
		pol, f := ghPolicy(t), newGlabFakes()
		f.acct.User = "someone-else"
		f.netrc = "machine " + glabHost + " login someone-else password " + fakeGlabToken + "\n"
		err := stageGlabConfig(pol, glabID(src), false, f.mint, f.read)
		if err == nil || !strings.Contains(err.Error(), `"someone-else"`) || !strings.Contains(err.Error(), "never selects") {
			t.Errorf("source %q: err = %v, want a mismatch refusal naming the stored login", src, err)
		}
		if len(pol.Mounts) != 0 {
			t.Errorf("source %q: staged %v for the wrong account", src, pol.Mounts)
		}
	}
}

func TestStageGlabRefusesOAuthHost(t *testing.T) {
	pol, f := ghPolicy(t), newGlabFakes()
	f.acct.OAuth = true
	err := stageGlabConfig(pol, glabID(policy.GlabTokenFromGlab), false, f.mint, f.read)
	if err == nil || !strings.Contains(err.Error(), "glab auth login --hostname "+glabHost) {
		t.Fatalf("err = %v, want the OAuth refusal naming `glab auth login --hostname %s`", err, glabHost)
	}
	if len(pol.Mounts) != 0 {
		t.Errorf("an OAuth session was staged: %v", pol.Mounts)
	}
}

func TestStageGlabRefusesATokenThatIsSyntax(t *testing.T) {
	for _, bad := range []string{"tok\nhosts: {}", "a b", "tok: x", "tok#c"} {
		pol, f := ghPolicy(t), newGlabFakes()
		f.acct.Token = policy.Secret(bad)
		err := stageGlabConfig(pol, glabID(policy.GlabTokenFromGlab), false, f.mint, f.read)
		if err == nil {
			t.Errorf("token %q staged", bad)
		} else if strings.Contains(err.Error(), bad) {
			t.Errorf("refusal printed the token %q", bad)
		}
	}
}

func TestStageGlabNetrcMissingEntryDoesNotFallBackToGlab(t *testing.T) {
	pol, f := ghPolicy(t), newGlabFakes()
	f.netrc = "machine other.example login you password x\n"
	if err := stageGlabConfig(pol, glabID(policy.GlabTokenFromNetrc), false, f.mint, f.read); err == nil {
		t.Fatal("a netrc source with no entry for the host started")
	}
	if f.mintCalls != 0 {
		t.Errorf("glab was asked for a token %d time(s) after the netrc entry was missing; "+
			"the profile chose where the credential lives", f.mintCalls)
	}
}

func TestStageGlabGlabSourceNeverReadsNetrc(t *testing.T) {
	pol, f := ghPolicy(t), newGlabFakes()
	f.mintErr = errors.New("no token")
	_ = stageGlabConfig(pol, glabID(policy.GlabTokenFromGlab), false, f.mint, f.read)
	f.mintErr = nil
	if err := stageGlabConfig(pol, glabID(policy.GlabTokenFromGlab), false, f.mint, f.read); err != nil {
		t.Fatal(err)
	}
	if f.netrcReads != 0 {
		t.Errorf("~/.netrc was read %d time(s) by a glab-sourced block", f.netrcReads)
	}
	if f.mintedFor != glabHost {
		t.Errorf("minted for %q, want %q", f.mintedFor, glabHost)
	}
}

func TestStageGlabGateIsTheUser(t *testing.T) {
	pol, f := ghPolicy(t), newGlabFakes()
	id := &policy.Identity{Glab: policy.IdentityGlab{Host: glabHost}}
	if err := stageGlabConfig(pol, id, false, f.mint, f.read); err != nil {
		t.Fatal(err)
	}
	if f.mintCalls != 0 || f.netrcReads != 0 || len(pol.Mounts) != 0 {
		t.Error("a host with no user minted or staged something: that is the unpinned credential")
	}
}

func TestReadHostNetrcRefusesGroupReadableAndSymlink(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".netrc")
	body := "machine " + glabHost + " login you password " + fakeGlabToken + "\n"

	if _, err := readHostNetrc(home); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent ~/.netrc: err = %v, want ErrNotExist", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readHostNetrc(home); err != nil || string(got) != body {
		t.Fatalf("control: a 0600 netrc: %q, %v", got, err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := readHostNetrc(home)
		if err == nil || !strings.Contains(err.Error(), "chmod 600 ~/.netrc") {
			t.Errorf("mode %04o: err = %v, want the chmod instruction", mode, err)
		}
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(home, "real")
	if err := os.WriteFile(real, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readHostNetrc(home); err == nil {
		t.Error("a symlinked ~/.netrc was read")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHostNetrc(home); err == nil {
		t.Error("a FIFO at ~/.netrc was read")
	}
}

func TestStageGlabDryRunWarnsAndStagesNothing(t *testing.T) {
	for _, src := range []policy.GlabTokenSource{policy.GlabTokenFromGlab, policy.GlabTokenFromNetrc} {
		pol, f := ghPolicy(t), newGlabFakes()
		f.mintErr = errors.New("glab is not installed on the host")
		f.netrcErr = errors.New("~/.netrc is readable by others; chmod 600 ~/.netrc")
		var err error
		out := captureStderr(t, func() {
			err = stageGlabConfig(pol, glabID(src), true, f.mint, f.read)
		})
		if err != nil {
			t.Fatalf("source %q: a dry run refused: %v", src, err)
		}
		for _, w := range []string{"no usable GitLab credential", "dry run: continuing", "config.yml or .netrc row"} {
			if !strings.Contains(out, w) {
				t.Errorf("source %q: stderr lacks %q:\n%s", src, w, out)
			}
		}
		if len(pol.Mounts) != 0 || len(pol.Env) != 0 {
			t.Errorf("source %q: dry run staged %v / %v", src, pol.Mounts, pol.Env)
		}
	}
}

func TestStageGlabStagesExactlyOneHost(t *testing.T) {
	for _, src := range []policy.GlabTokenSource{policy.GlabTokenFromGlab, policy.GlabTokenFromNetrc} {
		t.Run(string(src)+"/https", func(t *testing.T) {
			pol, f := ghPolicy(t), newGlabFakes()
			if err := stageGlabConfig(pol, glabID(src), false, f.mint, f.read); err != nil {
				t.Fatal(err)
			}
			cfg := pol.Mounts["/home/u/.config/glab-cli/config.yml"]
			wantCfg := "# Generated by snug. The host's glab config is not mounted.\n" +
				"hosts:\n  gitlab.example:\n    api_host: gitlab.example\n    api_protocol: https\n" +
				"    git_protocol: https\n    token: " + fakeGlabToken + "\n    user: you\n"
			if string(cfg.Content) != wantCfg {
				t.Errorf("config.yml =\n%s\nwant\n%s", string(cfg.Content), wantCfg)
			}
			netrc := pol.Mounts["/home/u/.netrc"]
			wantNetrc := "machine gitlab.example login you password " + fakeGlabToken + "\n"
			if string(netrc.Content) != wantNetrc {
				t.Errorf(".netrc = %q, want %q", string(netrc.Content), wantNetrc)
			}
			if cfg.Access != policy.AccessRW || netrc.Access != policy.AccessRO {
				t.Errorf("access config=%v netrc=%v, want rw and ro", cfg.Access, netrc.Access)
			}
			for name, m := range map[string]policy.Mount{"config.yml": cfg, ".netrc": netrc} {
				if m.Kind != policy.KindData || m.Perms == nil || *m.Perms != 0o600 {
					t.Errorf("%s: kind %v perms %v, want data 0600", name, m.Kind, m.Perms)
				}
				if !slices.Equal(m.From, []string{"(identity)"}) {
					t.Errorf("%s: From = %v", name, m.From)
				}
			}
			if len(pol.Mounts) != 2 {
				t.Errorf("staged %d mounts, want exactly 2: %v", len(pol.Mounts), pol.Mounts)
			}
			if got := pol.Env["GLAB_CONFIG_DIR"].Entries[0].Value; got != "/home/u/.config/glab-cli" {
				t.Errorf("GLAB_CONFIG_DIR = %q", got)
			}
			if got := pol.Env["GITLAB_HOST"].Entries[0].Value; got != glabHost {
				t.Errorf("GITLAB_HOST = %q", got)
			}
			for n, v := range pol.Env {
				for _, e := range v.Entries {
					if strings.Contains(e.Value, fakeGlabToken) {
						t.Errorf("the token is in the environment under %s", n)
					}
				}
			}
			if len(pol.Env) != 2 {
				t.Errorf("authored %d env names, want GLAB_CONFIG_DIR and GITLAB_HOST only", len(pol.Env))
			}
		})
	}

	t.Run("ssh git protocol only for the pinned ssh host", func(t *testing.T) {
		for _, tc := range []struct {
			sshHost string
			agent   policy.SSHMode
			want    string
		}{
			{glabHost, policy.SSHAgentProxy, "ssh"},
			{"elsewhere.example", policy.SSHAgentProxy, "https"},
			{glabHost, policy.SSHNone, "https"},
		} {
			pol, f := ghPolicy(t), newGlabFakes()
			id := glabID("")
			id.SSH = policy.IdentitySSH{Host: tc.sshHost, Agent: tc.agent}
			if err := stageGlabConfig(pol, id, false, f.mint, f.read); err != nil {
				t.Fatal(err)
			}
			body := string(pol.Mounts["/home/u/.config/glab-cli/config.yml"].Content)
			if !strings.Contains(body, "    git_protocol: "+tc.want+"\n") {
				t.Errorf("ssh host %q agent %q: want git_protocol %s:\n%s", tc.sshHost, tc.agent, tc.want, body)
			}
			if !strings.Contains(string(pol.Mounts["/home/u/.netrc"].Content), "machine "+glabHost) {
				t.Error("the netrc entry is not generated beside the ssh rule; it is one rule for both")
			}
		}
	})
}

func TestStageGlabConfigHasNoOAuthOrBinaryKeys(t *testing.T) {
	pol, f := ghPolicy(t), newGlabFakes()
	if err := stageGlabConfig(pol, glabID(""), false, f.mint, f.read); err != nil {
		t.Fatal(err)
	}
	body := string(pol.Mounts["/home/u/.config/glab-cli/config.yml"].Content)
	for _, k := range []string{"use_keyring", "oauth2", "is_oauth2", "duo", "orbit", "proxy", "alias", "editor", "browser", "!"} {
		if strings.Contains(body, k) {
			t.Errorf("config.yml names %q, which is a setting or an exec path snug does not author:\n%s", k, body)
		}
	}
	if n := strings.Count(string(pol.Mounts["/home/u/.netrc"].Content), "\n"); n != 1 {
		t.Errorf(".netrc has %d lines, want 1", n)
	}
}

func TestGlabDryRunRedactsToken(t *testing.T) {
	pol, f := ghPolicy(t), newGlabFakes()
	pol.Mounts["/home/u"] = policy.Mount{Guest: "/home/u", Kind: policy.KindTmpfs, Access: policy.AccessRW}
	if err := stageGlabConfig(pol, glabID(""), false, f.mint, f.read); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := dryRun(newEnvFakeEnv(), &b, pol, pol.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatalf("dryRun: %v", err)
	}
	if strings.Contains(b.String(), fakeGlabToken) {
		t.Errorf("the dry-run screen prints the token:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "/home/u/.netrc") || !strings.Contains(b.String(), "/home/u/.config/glab-cli/config.yml") {
		t.Errorf("the dry-run screen does not name the generated files:\n%s", b.String())
	}
	var full bytes.Buffer
	if err := dryRun(newEnvFakeEnv(), &full, pol, pol.BwrapArgs(0, 0), config{json: true}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(full.String(), fakeGlabToken) {
		t.Error("the --json dry run prints the token")
	}
	var js bytes.Buffer
	if err := renderJSON(&js, Report{Files: buildFiles(pol)}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(js.String(), fakeGlabToken) {
		t.Error("the JSON report prints the token")
	}
}

func TestNotGrantedQualifiesTheHostGlabConfigOnceSnugGeneratesItsOwn(t *testing.T) {
	home := homeWithDirs(t, ".config/glab-cli", ".ssh")
	if err := os.WriteFile(filepath.Join(home, ".netrc"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, f := ghPolicy(t), newGlabFakes()
	pol.Home = home
	pol.Target = filepath.Join(home, "proj")
	if err := stageGlabConfig(pol, glabID(""), false, f.mint, f.read); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(notGranted(pol), "\n")
	for _, want := range []string{"~/.config/glab-cli (host's; snug generates its own here)", "~/.netrc (host's; snug generates its own here)"} {
		if !strings.Contains(got, want) {
			t.Errorf("NOT GRANTED lacks %q, so a reader is told the generated files are absent:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "~/.ssh") {
		t.Errorf("control: ~/.ssh missing from NOT GRANTED:\n%s", got)
	}
}
