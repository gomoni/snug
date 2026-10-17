package draft

import (
	"errors"
	"flag"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/setup/internal/intent"
)

var update = flag.Bool("update", false, "rewrite golden files")

type fakeInfo struct{ mode fs.FileMode }

func (fakeInfo) Name() string        { return "x" }
func (fakeInfo) Size() int64         { return 0 }
func (f fakeInfo) Mode() fs.FileMode { return f.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (f fakeInfo) IsDir() bool       { return f.mode.IsDir() }
func (fakeInfo) Sys() any            { return nil }

func testHost() Host {
	links := map[string]string{"/home/alice/link-to-ssh": "/home/alice/.ssh", "/home/alice/link-to-bin": "/home/alice/.local/bin"}
	return Host{
		Home: "/home/alice", Target: "/home/alice/src/webapp", RuntimeDir: "/run/user/1000",
		EvalSymlinks: func(p string) (string, error) {
			if r, ok := links[p]; ok {
				return r, nil
			}
			return p, nil
		},
		Stat: func(p string) (fs.FileInfo, error) {
			switch {
			case strings.Contains(p, "missing"):
				return nil, fs.ErrNotExist
			case strings.HasSuffix(p, ".sock"), strings.HasSuffix(p, "/agent.4242"):
				return fakeInfo{fs.ModeSocket}, nil
			}
			return fakeInfo{0o644}, nil
		},
	}
}

func act(op string, kv ...string) intent.Action {
	a := intent.Action{Op: op}
	for i := 0; i < len(kv); i += 2 {
		switch kv[i] {
		case "name":
			a.Name = kv[i+1]
		case "path":
			a.Path = kv[i+1]
		case "access":
			a.Access = kv[i+1]
		case "host":
			a.Host = kv[i+1]
		case "verb":
			a.Verb = kv[i+1]
		case "kind":
			a.Kind = kv[i+1]
		case "account":
			a.Account = kv[i+1]
		case "value":
			a.Value, a.HasValue = kv[i+1], true
		}
	}
	return a
}

func TestSafetyRulesRefuse(t *testing.T) {
	cases := []struct {
		path string
		code string
	}{
		{"~/.ssh", "sensitive_home"},
		{"~/.ssh/id_ed25519", "sensitive_home"},
		{"{home}/.aws", "sensitive_home"},
		{"/home/alice/.gnupg", "sensitive_home"},
		{"~/.config/gh", "sensitive_home"},
		{"~/.config/gh/hosts.yml", "sensitive_home"},
		{"~/.netrc", "sensitive_home"},
		{"~/.docker", "sensitive_home"},
		{"~/.kube", "sensitive_home"},
		{"~/.claude", "sensitive_home"},
		{"~/.local/share/keyrings", "sensitive_home"},
		{"~/.config", "sensitive_home"},
		{"~/.local/share", "sensitive_home"},
		{"~/data/../.ssh", "sensitive_home"},
		{"~/link-to-ssh", "sensitive_home"},
		{"/home/alice", "whole_home"},
		{"{home}", "whole_home"},
		{"/home", "whole_home"},
		{"/", "whole_home"},
		{"/proc", CodeKernelPath},
		{"/proc/self/mem", CodeKernelPath},
		{"/dev", CodeKernelPath},
		{"/dev/shm", CodeKernelPath},
		{"/sys/fs", CodeKernelPath},
		{"/snug", CodeKernelPath},
		{"/snug/bin", CodeKernelPath},
		{"/var/run/docker.sock", "docker_sock"},
		{"/run/podman/podman.sock", "docker_sock"},
		{"/run/docker", "docker_sock"},
		{"/tmp/.X11-unix", "desktop_socket"},
		{"/tmp/.X11-unix/X0", "desktop_socket"},
		{"/run/user/1000", "desktop_socket"},
		{"/run/user/1000/wayland-0", "desktop_socket"},
		{"/run/user", "desktop_socket"},
		{"/run/dbus", "desktop_socket"},
		{"/run", "desktop_socket"},
		{"/srv/thing.sock", "desktop_socket"},
		{"/tmp/ssh-XXXX/agent.4242", "desktop_socket"},
		{"/srv/a:b", CodeBadValue},
		{"/srv/a\"b", CodeBadValue},
	}
	for _, c := range cases {
		for _, access := range []string{"ro", "rw", "tmpfs"} {
			d := New(testHost())
			o := d.Apply(act(intent.OpGrantPath, "path", c.path, "access", access))
			if o.Refused != c.code {
				t.Errorf("grant %s %s: refused=%q (%s), want %q", access, c.path, o.Refused, o.Msg, c.code)
			}
			if !d.Empty() {
				t.Errorf("grant %s %s changed the draft", access, c.path)
			}
		}
	}
}

// TestHostRunFilesNotWritable is redteam setup r1 S2: a rw grant on a file the
// host later executes or reads as configuration lets sandboxed code plant
// something that runs outside the sandbox. Reading one stays allowed.
func TestHostRunFilesNotWritable(t *testing.T) {
	for _, p := range []string{"~/.bashrc", "~/.profile", "~/.bash_profile", "~/.zshrc", "~/.zshenv",
		"~/.config/systemd/user", "~/.config/systemd/user/evil.service", "~/.config/autostart",
		"~/.local/bin", "~/.local/bin/git", "~/.gitconfig", "~/.config/git/config", "~/.config/environment.d",
		"~/.local/share/applications"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "rw")); o.Refused != "sensitive_home" {
			t.Errorf("grant rw %s: refused=%q (%s), want sensitive_home", p, o.Refused, o.Msg)
		}
		for _, access := range []string{"ro", "tmpfs"} {
			d := New(testHost())
			if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", access)); o.Refused != "" {
				t.Errorf("grant %s %s refused: %+v", access, p, o)
			}
		}
	}
	// A directory above one of them is just as writable.
	for _, p := range []string{"~/.local", "~/.config/systemd", "~/link-to-bin"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "rw")); o.Refused != "sensitive_home" {
			t.Errorf("grant rw %s: refused=%q (%s), want sensitive_home", p, o.Refused, o.Msg)
		}
	}
}

// TestSnugConfigNotWritable is redteam setup r7 R7-5's setup half: rw on
// snug's own config directory, or on any directory above it, lets the sandbox
// write the profiles the next snug run trusts. That holds for ~/.config/snug
// and for $XDG_CONFIG_HOME/snug outside the home; ro stays allowed.
func TestSnugConfigNotWritable(t *testing.T) {
	h := testHost()
	h.ConfigHome = "/mnt/cfg"
	for _, p := range []string{"~/.config/snug", "~/.config/snug/profiles.d", "~/.config", "/mnt/cfg/snug/profiles.d", "/mnt/cfg", "/mnt"} {
		d := New(h)
		if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "rw")); o.Refused != "sensitive_home" {
			t.Errorf("grant rw %s: refused=%q (%s), want sensitive_home", p, o.Refused, o.Msg)
		}
		if !d.Empty() {
			t.Errorf("grant rw %s changed the draft", p)
		}
	}
	for _, p := range []string{"~/.config/snug/profiles.d", "/mnt/cfg/snug"} {
		d := New(h)
		if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "ro")); o.Refused != "" {
			t.Errorf("grant ro %s refused: %+v", p, o)
		}
	}
	if o := New(h).Apply(act(intent.OpGrantPath, "path", "/mnt/other", "access", "rw")); o.Refused != "" {
		t.Errorf("a sibling of the config home refused: %+v", o)
	}
}

// TestCredentialFilesRefused is redteam setup r1 S2's read half: files that
// hold a token are refused at any access, like ~/.ssh.
func TestCredentialFilesRefused(t *testing.T) {
	for _, p := range []string{"~/.git-credentials", "~/.npmrc", "~/.pypirc", "~/.cargo/credentials.toml",
		"~/.cargo/credentials", "~/.config/containers/auth.json", "~/.config/containers",
		// redteam setup r7 R7-5.
		"~/.config/gcloud", "~/.password-store", "~/.password-store/work", "~/.mozilla", "~/.mozilla/firefox",
		"~/.librewolf", "~/.config/google-chrome", "~/.config/chromium/Default", "~/.config/BraveSoftware"} {
		for _, access := range []string{"ro", "rw", "tmpfs"} {
			d := New(testHost())
			if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", access)); o.Refused != "sensitive_home" {
				t.Errorf("grant %s %s: refused=%q (%s), want sensitive_home", access, p, o.Refused, o.Msg)
			}
		}
	}
}

// TestQuoteEscapesInvisibles is redteam setup r1 S5's second half: whatever
// string reaches the TOML, a control or formatting rune is written as an
// escape, so the file a human reads shows the same text the screen did.
func TestQuoteEscapesInvisibles(t *testing.T) {
	for in, want := range map[string]string{
		"ali\u202ece": `"ali\u202Ece"`,
		"a\u200bb":    `"a\u200Bb"`,
		"x\ty":        `"x\u0009y"`,
		`a"b\c`:       `"a\"b\\c"`,
		"Žluťoučký":   `"Žluťoučký"`,
	} {
		if got := q(in); got != want {
			t.Errorf("q(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestCheckTargetRefusesInvisibles is redteam setup r2 R2-2: a target directory
// named "x\nINJECTED: evil" put a forged line into the model's prompt and
// split the startup banner. snug-setup refuses such a target before either.
func TestCheckTargetRefusesInvisibles(t *testing.T) {
	for _, p := range []string{"/srv/a\nINJECTED: evil", "/srv/a\rb", "/srv/a\u202eb", "/srv/a\u2028b", "/srv/a\x00b"} {
		if err := CheckTarget(p); err == nil {
			t.Errorf("CheckTarget(%q) accepted it", p)
		}
	}
	for _, p := range []string{"/srv/webapp", "/home/alice/src/my project", "/srv/Žluťoučký kůň"} {
		if err := CheckTarget(p); err != nil {
			t.Errorf("CheckTarget(%q): %v", p, err)
		}
	}
}

func TestSafetyRulesAllowOrdinary(t *testing.T) {
	for _, p := range []string{"/mnt/data", "~/data", "~/src", "{target}/out", "/mnt/cache", "~/.cache/pip"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "rw")); o.Refused != "" {
			t.Errorf("%s refused: %+v", p, o)
		}
	}
}

func TestStageBinaryChecksHostPath(t *testing.T) {
	d := New(testHost())
	if o := d.Apply(act(intent.OpStageBinary, "host", "~/.ssh/id_ed25519", "name", "ssh-key")); o.Refused != "sensitive_home" {
		t.Errorf("%+v", o)
	}
	if o := d.Apply(act(intent.OpStageBinary, "host", "~/bin/foo", "name", "..")); o.Refused != CodeBadValue {
		t.Errorf("%+v", o)
	}
	if o := d.Apply(act(intent.OpStageBinary, "host", "~/bin/missing", "name", "foo")); o.Refused != CodeBadValue {
		t.Errorf("missing file: %+v", o)
	}
	if o := d.Apply(act(intent.OpStageBinary, "host", "~/bin/foo", "name", "foo")); o.Refused != "" || !strings.Contains(d.Render(), `"~/bin/foo:/snug/bin/foo"`) {
		t.Errorf("%+v\n%s", o, d.Render())
	}
}

// TestSetEnvRefusesCredentialNames is redteam setup r2 R2-1: names that hold a
// credential without saying TOKEN or SECRET reached the saved TOML, and snug
// put the host value in /proc/self/environ. Ordinary names that merely contain
// the letters stay allowed.
func TestSetEnvRefusesCredentialNames(t *testing.T) {
	for _, name := range []string{"DATABASE_URL", "PRIVATE_KEY", "ACCESS_KEY", "AWS_ACCESS_KEY_ID", "DEPLOY_KEY",
		"SIGNING_KEY", "DB_PASS", "MYSQL_PWD", "REDIS_URL", "MONGODB_URI", "SENTRY_DSN", "NPM_AUTH",
		"GPG_KEYS", "DB_PASSWD", "AUTH_HEADER",
		// redteam setup r3 R3-1: still passed after the R2-1 fix.
		"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "BORG_PASSPHRASE", "GPG_PASSPHRASE",
		"AZURE_STORAGE_CONNECTION_STRING", "CONN_STR", "SESSION_COOKIE", "OP_SESSION_my", "SESSION", "SESSIONID",
		"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "OPENAIKEY", "PRIVKEY", "SLACK_WEBHOOK_URL",
		"DISCORD_WEBHOOK", "JWT", "JWT_SIGNING", "BEARER", "HMAC", "SIGNING_SALT", "STRIPE_SK", "DATABASE_URL_RO",
		"KAFKA_URL", "ELASTICSEARCH_URL", "SMTP_URL", "NATS_URL", "APITOKEN_X",
		// redteam setup r7 R7-5: a personal access token by its usual name.
		"GITHUB_PAT", "GH_PAT", "PAT", "GITLAB_PAT_RO"} {
		for _, verb := range []string{"inherit", "set"} {
			d := New(testHost())
			o := d.Apply(act(intent.OpSetEnv, "name", name, "verb", verb, "value", "x"))
			if o.Refused != "secret_in_env" {
				t.Errorf("%s %s: refused=%q (%s), want secret_in_env", verb, name, o.Refused, o.Msg)
			}
		}
	}
	for _, name := range []string{"EDITOR", "PAGER", "KEYBOARD_LAYOUT", "XKB_DEFAULT_LAYOUT", "LC_ALL",
		"PASSTHROUGH", "AUTHOR_NAME", "BASE_URL", "TOKENIZERS_PARALLELISM", "MAX_TOKENS", "NO_PROXY", "GOPROXY",
		"KUBECONFIG", "PGPASSFILE", "VAULT_ADDR", "DOCKER_CONFIG", "KEYFILE", "PATTERN", "SPATIAL_DIR"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpSetEnv, "name", name, "verb", "inherit")); o.Refused != "" {
			t.Errorf("inherit %s refused: %+v", name, o)
		}
	}
}

// TestHostPointerEnvRefused: a variable naming a host program, keyring,
// agent, display or bus is refused at every verb with what to use instead;
// none of them is a name snug writes in every run (writtenBySnug).
func TestHostPointerEnvRefused(t *testing.T) {
	for name, alt := range map[string]string{"GIT_ASKPASS": "pin an identity", "SSH_ASKPASS": "pin an identity",
		"SSH_AUTH_SOCK": "pins an identity", "GNUPGHOME": "ssh signing key", "XDG_RUNTIME_DIR": "0700",
		"DBUS_SESSION_BUS_ADDRESS": "no desktop bus", "DISPLAY": "no X11", "WAYLAND_DISPLAY": "no Wayland"} {
		if slices.Contains(writtenBySnug, name) {
			t.Errorf("%s is snug's own; its refusal is reserved_env", name)
		}
		for _, verb := range []string{"inherit", "set"} {
			d := New(testHost())
			o := d.Apply(act(intent.OpSetEnv, "name", name, "verb", verb, "value", "/x"))
			if o.Refused != CodeHostPointer || !strings.Contains(o.Msg, alt) || !d.Empty() {
				t.Errorf("%s %s: %+v", verb, name, o)
			}
		}
	}
}

// TestSetEnvRefusesCredentialValues is redteam setup r3 R3-1's value half: a
// harmless name with a credential for a value reached the TOML.
func TestSetEnvRefusesCredentialValues(t *testing.T) {
	for _, v := range []string{"postgres://u:pw@db/x", "https://user@host/x", "ghp_0123456789abcdef", "github_pat_11AB",
		"glpat-xyz", "xoxb-123", "sk-abc123", "AKIAIOSFODNN7EXAMPLE", "id=AKIAIOSFODNN7EXAMPLE", "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpSetEnv, "name", "MY_SETTING", "verb", "set", "value", v)); o.Refused != "secret_in_env" {
			t.Errorf("set MY_SETTING=%q: refused=%q (%s), want secret_in_env", v, o.Refused, o.Msg)
		}
	}
	for _, v := range []string{"vim", "https://example.com/x", "{target}/sk-notes", "mailto:a@b", "less -R"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpSetEnv, "name", "MY_SETTING", "verb", "set", "value", v)); o.Refused != "" {
			t.Errorf("set MY_SETTING=%q refused: %+v", v, o)
		}
	}
}

// TestPrependUnderTargetNeedsAGrant is redteam setup r3 R3-3: setup counted
// the target as granted, and snug refused the save with "prepends PATH=...,
// which it does not grant". The draft now refuses it at once, naming the fix.
func TestPrependUnderTargetNeedsAGrant(t *testing.T) {
	d := New(testHost())
	if o := d.Apply(act(intent.OpSetEnv, "name", "PATH", "verb", "prepend", "value", "{target}/bin")); o.Refused != CodeNotGranted {
		t.Errorf("prepend without a grant: %+v", o)
	}
	if o := d.Apply(act(intent.OpGrantPath, "path", "{target}/bin", "access", "ro")); o.Refused != "" {
		t.Fatalf("%+v", o)
	}
	if o := d.Apply(act(intent.OpSetEnv, "name", "PATH", "verb", "prepend", "value", "{target}/bin")); o.Refused != "" {
		t.Errorf("prepend after the grant: %+v", o)
	}
}

// TestWrittenBySnugMatchesPolicy holds writtenBySnug, plus the SNUG prefix
// setEnv refuses on its own, equal to snug's SnugOwnedEnv and bwrapOwnedEnv.
// The copy had drifted: TERM, LANG and TZ were missing, so snug-setup saved a
// profile that snug --dry-run refused with exit 77.
func TestWrittenBySnugMatchesPolicy(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/policy/env.go")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, v := range []string{"SnugOwnedEnv", "bwrapOwnedEnv"} {
		m := regexp.MustCompile(`(?s)\nvar ` + v + ` = \[\]string\{(.*?)\}`).FindSubmatch(raw)
		if m == nil {
			t.Fatalf("no %s in internal/policy/env.go", v)
		}
		for _, q := range regexp.MustCompile(`"([A-Z0-9_]+)"`).FindAllSubmatch(m[1], -1) {
			if n := string(q[1]); !strings.HasPrefix(n, "SNUG") {
				want = append(want, n)
			}
		}
	}
	got := slices.Clone(writtenBySnug)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("writtenBySnug = %v, snug owns %v", got, want)
	}
	for _, n := range append(want, "SNUG_TARGET") {
		d := New(testHost())
		if o := d.Apply(act(intent.OpSetEnv, "name", n, "verb", "set", "value", "x")); o.Refused != CodeReservedEnv {
			t.Errorf("set %s: %+v", n, o)
		}
	}
}

func TestEnvRules(t *testing.T) {
	refused := []struct {
		a    intent.Action
		code string
	}{
		{act(intent.OpSetEnv, "name", "GITHUB_TOKEN", "verb", "set", "value", "x"), "secret_in_env"},
		{act(intent.OpSetEnv, "name", "MY_PASSWORD", "verb", "inherit"), "secret_in_env"},
		{act(intent.OpSetEnv, "name", "aws_secret_access_key", "verb", "set", "value", "x"), "secret_in_env"},
		{act(intent.OpSetEnv, "name", "OPENAI_API_KEY", "verb", "inherit"), "secret_in_env"},
		{act(intent.OpSetEnv, "name", "APIKEY", "verb", "set", "value", "x"), "secret_in_env"},
		{act(intent.OpSetEnv, "name", "DB_CREDENTIALS", "verb", "set", "value", "x"), "secret_in_env"},
		{act(intent.OpSetEnv, "name", "HOME", "verb", "set", "value", "/x"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "PATH", "verb", "set", "value", "/x"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "SHELL", "verb", "inherit"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "USER", "verb", "set", "value", "root"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "LOGNAME", "verb", "set", "value", "root"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "TMPDIR", "verb", "set", "value", "/x"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "PS1", "verb", "set", "value", "x"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "SNUG_TARGET", "verb", "set", "value", "/"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "SNUG", "verb", "inherit"), CodeReservedEnv},
		{act(intent.OpSetEnv, "name", "LD_PRELOAD", "verb", "set", "value", "/x.so"), CodeNoVerb},
		{act(intent.OpSetEnv, "name", "EDITOR", "verb", "prepend", "value", "/x"), CodeUnknownList},
		{act(intent.OpSetEnv, "name", "EDITOR", "verb", "set", "value", "a\nb"), CodeBadValue},
		{act(intent.OpSetEnv, "name", "EDITOR", "verb", "set", "value", "{tmp}/x"), CodeBadValue},
		{act(intent.OpSetEnv, "name", "PATH", "verb", "prepend", "value", "~/go/bin"), CodeNotGranted},
		{act(intent.OpSetEnv, "name", "PATH", "verb", "prepend", "value", "bin"), CodeBadValue},
	}
	for _, c := range refused {
		d := New(testHost())
		if o := d.Apply(c.a); o.Refused != c.code {
			t.Errorf("%+v: %+v, want %s", c.a, o, c.code)
		}
		if !d.Empty() {
			t.Errorf("%+v changed the draft", c.a)
		}
	}
	d := New(testHost())
	for _, a := range []intent.Action{
		act(intent.OpSetEnv, "name", "EDITOR", "verb", "set", "value", "vim"),
		act(intent.OpSetEnv, "name", "PAGER", "verb", "inherit"),
		act(intent.OpGrantPath, "path", "~/go/bin", "access", "ro"),
		act(intent.OpSetEnv, "name", "PATH", "verb", "prepend", "value", "~/go/bin"),
	} {
		if o := d.Apply(a); o.Refused != "" || !o.Changed {
			t.Errorf("%+v: %+v", a, o)
		}
	}
}

func TestRelativePathsResolveAgainstTarget(t *testing.T) {
	for _, p := range []string{"here", ".", "", "./"} {
		d := New(testHost())
		d.Apply(act(intent.OpGrantPath, "path", p, "access", "rw"))
		if len(d.RW) != 1 || d.RW[0] != "{target}" {
			t.Errorf("%q -> %v", p, d.RW)
		}
	}
	d := New(testHost())
	d.Apply(act(intent.OpGrantPath, "path", "out/cache", "access", "rw"))
	if len(d.RW) != 1 || d.RW[0] != "/home/alice/src/webapp/out/cache" {
		t.Errorf("%v", d.RW)
	}
}

func TestReadonlyTarget(t *testing.T) {
	d := New(testHost())
	d.Apply(act(intent.OpGrantPath, "path", "{target}", "access", "ro"))
	if !d.ReadOnlyTarget {
		t.Fatal("not readonly")
	}
	out := d.Render()
	for _, want := range []string{`"@home"`, `"@sys"`, `ro = ["{target}"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(d.RunLine("/p"), "snug --no-defaults -p NAME /p") {
		t.Error(d.RunLine("/p"))
	}
	d.Apply(act(intent.OpUseProfile, "name", "@target-rw"))
	if d.ReadOnlyTarget || strings.Contains(d.RunLine("/p"), "--no-defaults") {
		t.Error("@target-rw should end the read-only target")
	}
}

func TestLayering(t *testing.T) {
	d := New(testHost())
	d.Apply(act(intent.OpGrantPath, "path", "~/data", "access", "ro"))
	d.Apply(act(intent.OpGrantPath, "path", "~/data/out", "access", "rw"))
	if len(d.RO) != 1 || len(d.RW) != 1 {
		t.Fatalf("%v %v", d.RO, d.RW)
	}
	d.Apply(act(intent.OpGrantPath, "path", "~/data", "access", "rw"))
	if len(d.RO) != 0 || len(d.RW) != 2 {
		t.Fatalf("ro->rw: %v %v", d.RO, d.RW)
	}
	if o := d.Apply(act(intent.OpGrantPath, "path", "~/data", "access", "ro")); o.Changed {
		t.Errorf("ro after rw should not narrow: %+v", o)
	}
	if o := d.Apply(act(intent.OpDropPath, "path", "~/data")); !o.Changed || len(d.RW) != 1 {
		t.Errorf("%+v %v", o, d.RW)
	}
	if o := d.Apply(act(intent.OpDropPath, "path", "~/nothing")); o.Refused != CodeNoSuchEntry {
		t.Errorf("%+v", o)
	}
}

func TestProfilesInteract(t *testing.T) {
	d := New(testHost())
	d.Apply(act(intent.OpUseProfile, "name", "@podman-socket"))
	d.Apply(act(intent.OpUseProfile, "name", "@podman-build"))
	if len(d.Include) != 1 || d.Include[0] != "@podman-build" {
		t.Errorf("%v", d.Include)
	}
	if o := d.Apply(act(intent.OpUseProfile, "name", "@podman-socket")); o.Changed {
		t.Errorf("%+v", o)
	}
	d.Apply(act(intent.OpDropProfile, "name", "@podman-socket"))
	d.Apply(act(intent.OpUseProfile, "name", "@net"))
	d.Apply(act(intent.OpUseProfile, "name", "@net"))
	if len(d.Include) != 1 {
		t.Errorf("%v", d.Include)
	}
	d.Apply(act(intent.OpDropProfile, "name", "@net"))
	if !d.Empty() {
		t.Errorf("%+v", d)
	}
}

func TestParentROInHomeRefused(t *testing.T) {
	h := testHost()
	h.Target = "/home/alice/webapp"
	d := New(h)
	if o := d.Apply(act(intent.OpUseProfile, "name", "@parent-ro")); o.Refused != "whole_home" {
		t.Errorf("%+v", o)
	}
}

func TestNameProfile(t *testing.T) {
	d := New(testHost())
	if o := d.Apply(act(intent.OpNameProfile, "name", "my_work")); o.Refused == "" {
		t.Error("underscore accepted")
	}
	if o := d.Apply(act(intent.OpNameProfile, "name", "work")); !o.Changed || d.Name != "work" {
		t.Error("name not set")
	}
	if !d.Apply(act(intent.OpShow)).NotMine {
		t.Error("show is not the draft's")
	}
}

func TestCloneIsDeep(t *testing.T) {
	d := New(testHost())
	d.Apply(act(intent.OpUseProfile, "name", "@net"))
	d.SetGit("A", "a@x")
	c := d.Clone()
	c.Apply(act(intent.OpUseProfile, "name", "@git"))
	c.Git.Name = "B"
	c.Include[0] = "@claude"
	if len(d.Include) != 1 || d.Include[0] != "@net" || d.Git.Name != "A" {
		t.Errorf("clone shares state: %+v", d)
	}
}

func TestSummary(t *testing.T) {
	d := New(testHost())
	d.Name = "webapp"
	d.Apply(act(intent.OpUseProfile, "name", "@net"))
	d.Apply(act(intent.OpUseProfile, "name", "@git"))
	d.Apply(act(intent.OpGrantPath, "path", "/mnt/data", "access", "rw"))
	d.SetSSH("/home/alice/.ssh/id_work.pub")
	d.SetGH("github.com", "alice-corp")
	_, user := intent.FormatPrompt(intent.Context{Target: d.Host.Target, Draft: d.Summary()}, "x")
	want := "draft: name=webapp include=@net,@git rw=/mnt/data ro=- tmpfs=- env=- identity=ssh:id_work,github:alice-corp"
	if !strings.Contains(user, want) {
		t.Errorf("%s", user)
	}
}

func TestIdentityRender(t *testing.T) {
	d := New(testHost())
	d.Name = "ent"
	d.SetSSH("/home/alice/.ssh/id_ent.pub")
	d.SetGH("ghe.corp.example", "alice")
	out := d.Render()
	if strings.Count(out, `host = "ghe.corp.example"`) != 2 {
		t.Errorf("a non-default host must be written to both blocks:\n%s", out)
	}
	d2 := New(testHost())
	d2.Name = "p"
	d2.SetGH("github.com", "alice")
	d2.SetSSH("/home/alice/.ssh/id_a.pub")
	if strings.Contains(d2.Render(), "host =") {
		t.Errorf("default host written:\n%s", d2.Render())
	}
	if !strings.Contains(d2.Render(), `key = "{home}/.ssh/id_a.pub"`) || !strings.Contains(d2.Render(), `agent = "proxy"`) {
		t.Error(d2.Render())
	}
}

var normRE = regexp.MustCompile(`\s+`)

func normalise(s string) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		l = strings.TrimPrefix(l, "#")
		lines = append(lines, l)
	}
	return normRE.ReplaceAllString(strings.Join(lines, " "), " ")
}

func TestAbuseSentencesAreStillInBaseToml(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/profile/profiles/base.toml")
	if err != nil {
		t.Fatal(err)
	}
	base := normalise(string(raw))
	for name, sentence := range Abuse {
		if !strings.Contains(base, sentence) {
			t.Errorf("the abuse sentence for %s is not in base.toml any more:\n%s", name, sentence)
		}
	}
	for _, n := range append([]string{"@sys", "@home"}, intent.Builtins...) {
		if Abuse[n] == "" {
			t.Errorf("no abuse sentence for %s", n)
		}
	}
}

func TestDescriptionsAreStillInBaseToml(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/profile/profiles/base.toml")
	if err != nil {
		t.Fatal(err)
	}
	base := string(raw)
	for name, text := range Describe {
		if !strings.Contains(base, `description = "`+text+`"`) {
			t.Errorf("the description of %s is not in base.toml any more:\n%s", name, text)
		}
	}
	for _, n := range append([]string{"@sys", "@home"}, intent.Builtins...) {
		if Describe[n] == "" {
			t.Errorf("no description for %s", n)
		}
	}
}

type scenario struct {
	name string
	// say is the human's request the steps are recorded under.
	say   string
	steps []intent.Action
	setup func(*Draft)
}

func scenarios() []scenario {
	return []scenario{
		{name: "rw-target", say: "give me write access here", steps: []intent.Action{act(intent.OpNameProfile, "name", "webapp"), act(intent.OpUseProfile, "name", "@target-rw")}},
		{name: "readonly-target", say: "read-only here", steps: []intent.Action{act(intent.OpNameProfile, "name", "review"), act(intent.OpGrantPath, "path", "{target}", "access", "ro")}},
		{name: "net-git-identity", say: "needs internet and my git name", steps: []intent.Action{act(intent.OpNameProfile, "name", "work"), act(intent.OpUseProfile, "name", "@net"), act(intent.OpUseProfile, "name", "@git")},
			setup: func(d *Draft) {
				d.SetSSH("/home/alice/.ssh/id_work.pub")
				d.SetGH("github.com", "alice-corp")
				d.SetGit("Alice Doe", "alice@corp.example")
			}},
		{name: "signing-key", say: "push and sign as alice", steps: []intent.Action{act(intent.OpNameProfile, "name", "signer"), act(intent.OpUseProfile, "name", "@net")},
			setup: func(d *Draft) {
				d.SetSSH("/home/alice/.ssh/id_auth.pub")
				d.SetGit("Alice Doe", "alice@corp.example")
				if !d.SetSigningKey("/home/alice/.ssh/id_sign.pub") {
					panic("signing key refused with ssh and git pinned")
				}
				d.SetGH("github.com", "alice-corp")
			}},
		{name: "podman-build", say: "build images with podman, online", steps: []intent.Action{act(intent.OpNameProfile, "name", "images"), act(intent.OpUseProfile, "name", "@podman-socket"), act(intent.OpUseProfile, "name", "@podman-build"), act(intent.OpUseProfile, "name", "@net")}},
		{name: "env-and-path", say: "add ~/go/bin to PATH, vim, my pager, scratch /work", steps: []intent.Action{
			act(intent.OpNameProfile, "name", "tools"),
			act(intent.OpGrantPath, "path", "~/go/bin", "access", "ro"),
			act(intent.OpSetEnv, "name", "PATH", "verb", "prepend", "value", "~/go/bin"),
			act(intent.OpSetEnv, "name", "EDITOR", "verb", "set", "value", "vim"),
			act(intent.OpSetEnv, "name", "PAGER", "verb", "inherit"),
			act(intent.OpGrantPath, "path", "/work", "access", "tmpfs"),
		}},
		{name: "door", say: "serve my web app", steps: []intent.Action{act(intent.OpNameProfile, "name", "serve"), act(intent.OpUseProfile, "name", "@net"), act(intent.OpOpenDoor, "name", "web")}},
		{name: "layering", say: "~/data read-only but ~/data/out writable", steps: []intent.Action{act(intent.OpNameProfile, "name", "data"), act(intent.OpGrantPath, "path", "~/data", "access", "ro"), act(intent.OpGrantPath, "path", "~/data/out", "access", "rw")}},
		{name: "claude-parent", say: "run claude, read the siblings, my gh", steps: []intent.Action{act(intent.OpNameProfile, "name", "agent"), act(intent.OpUseProfile, "name", "@claude"), act(intent.OpUseProfile, "name", "@parent-ro"),
			act(intent.OpStageBinary, "host", "~/bin/gh", "name", "gh")}},
		{name: "compose", say: "podman online with /mnt/pg and /mnt/uploads", steps: []intent.Action{act(intent.OpNameProfile, "name", "stack"), act(intent.OpUseProfile, "name", "@podman-socket"), act(intent.OpUseProfile, "name", "@net"),
			act(intent.OpGrantPath, "path", "/mnt/pg", "access", "ro"), act(intent.OpGrantPath, "path", "/mnt/uploads", "access", "rw")}},
		{name: "ledger-conflict", say: "keep it offline", steps: []intent.Action{act(intent.OpNameProfile, "name", "offline"), act(intent.OpDropProfile, "name", "@net"),
			act(intent.OpGrantPath, "path", "/mnt/pg", "access", "ro")},
			setup: func(d *Draft) {
				d.Propose(act(intent.OpUseProfile, "name", "@podman-build"), SourceFile, "README.md", 2)
				for _, accept := range []bool{false, true} {
					a := act(intent.OpUseProfile, "name", "@net")
					if accept {
						a = act(intent.OpGrantPath, "path", "/mnt/pg", "access", "rw")
					}
					if _, p := d.Propose(a, SourceFile, "README.md", 2); p != nil {
						d.Decide(*p, accept)
					}
				}
			}},
	}
}

func build(t *testing.T, s scenario) *Draft {
	d := New(testHost())
	for _, a := range s.steps {
		if o, _ := d.Propose(a, SourceUser, s.say, 1); o.Refused != "" {
			t.Fatalf("%s: %+v refused: %+v", s.name, a, o)
		}
	}
	if s.setup != nil {
		s.setup(d)
	}
	return d
}

func TestGolden(t *testing.T) {
	for _, s := range scenarios() {
		got := build(t, s).Render()
		path := filepath.Join("testdata", s.name+".toml")
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s:\n%s", s.name, path, got)
		}
	}
}

// TestGoldenParsesInSnug builds snug from the root module and has it read every
// golden file as a user profile. It is skipped, loudly, when the build is
// impossible; the golden files are then unchecked against snug's parser.
func TestGoldenParsesInSnug(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "snug")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/snug")
	cmd.Dir = "../../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build snug from the root module: %v\n%s", err, out)
	}
	for _, s := range scenarios() {
		xdg := t.TempDir()
		dir := filepath.Join(xdg, "snug", "profiles.d")
		os.MkdirAll(dir, 0o755)
		d := build(t, s)
		if err := os.WriteFile(filepath.Join(dir, d.Name+".toml"), []byte(d.Render()), 0o644); err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin, "profile", "show", d.Name)
		c.Env = append(os.Environ(), "XDG_CONFIG_HOME="+xdg, "HOME="+t.TempDir())
		out, err := c.CombinedOutput()
		if err != nil {
			var ee *exec.ExitError
			errors.As(err, &ee)
			t.Errorf("%s: snug profile show %s: %v\n%s\n--- file ---\n%s", s.name, d.Name, err, out, d.Render())
		}
	}
}

// TestProfileTextCannotHideWhatItSays: a path or an environment value the
// model chose is written into the profile a human reads before selecting it.
// A bidi override, a zero-width space or a C1 control there renders as text
// the file does not contain, so it is refused like a C0 control.
func TestProfileTextCannotHideWhatItSays(t *testing.T) {
	for _, bad := range []string{"\U0000202E", "\U00002066", "\U0000200B", "\U0000FEFF", "\U000E0041", "\U00002028", "\u009b"} {
		d := New(testHost())
		if o := d.Apply(act(intent.OpGrantPath, "path", "/srv/a"+bad+"b", "access", "ro")); o.Refused != CodeBadValue {
			t.Errorf("grant_path with %U: %+v", []rune(bad)[0], o)
		}
		if o := d.Apply(intent.Action{Op: intent.OpSetEnv, Name: "EDITOR", Verb: "set", Value: "vim" + bad, HasValue: true}); o.Refused != CodeBadValue {
			t.Errorf("set_env with %U: %+v", []rune(bad)[0], o)
		}
		if !d.Empty() {
			t.Errorf("%U reached the profile:\n%s", []rune(bad)[0], d.Render())
		}
	}
}

// TestRenderedFileCarriesNoAbuseText: the user's file has one header line and
// plain descriptions; the cost of a grant is snug's to show, not a warning
// written into a file the user owns. It also covers the gh-only identity that
// once carried the ssh signing-oracle sentence.
func TestRenderedFileCarriesNoAbuseText(t *testing.T) {
	d := New(Host{Home: "/home/u", Target: "/home/u/p"})
	d.Apply(act(intent.OpUseProfile, "name", "@git"))
	d.Apply(act(intent.OpOpenDoor, "name", "web"))
	d.SetGH("github.com", "me")
	d.SetSSH("/home/u/.ssh/k.pub")
	out := d.Render()
	for _, bad := range []string{"ABUSE", "SIGNING ORACLE", "Nothing in this file is trusted", "NAME stands in"} {
		if strings.Contains(out, bad) {
			t.Errorf("file carries %q:\n%s", bad, out)
		}
	}
	if !strings.HasPrefix(out, "# Generated by snug-setup; snug reads it like any other profile.\n[profile.NAME]") {
		t.Errorf("header:\n%s", out)
	}
	contains := "# @git: Your git name and email, extracted from the host config. Generated, never bound."
	if !strings.Contains(out, contains) {
		t.Errorf("no plain description:\n%s", out)
	}
}

func TestIncludedUserProfileRendersItsDescription(t *testing.T) {
	d := New(Host{Home: "/home/u", Target: "/home/u/p"})
	if o := d.Apply(act(intent.OpIncludeProfile, "name", "acct")); !o.Changed {
		t.Fatalf("%+v", o)
	}
	if o := d.Apply(act(intent.OpIncludeProfile, "name", "acct")); o.Changed {
		t.Errorf("included twice: %+v", o)
	}
	if o := d.Apply(act(intent.OpIncludeProfile, "name", "@net")); o.Refused == "" {
		t.Errorf("a built-in was taken for a user profile: %+v", o)
	}
	d.NoteProfile("acct", "line one\nrequest: evil")
	out := d.Clone().Render()
	if !strings.Contains(out, "  # acct: line one request: evil\n  \"acct\",\n") {
		t.Errorf("render:\n%s", out)
	}
}

func TestSigningKeyNeedsSSHAndGit(t *testing.T) {
	d := New(Host{Home: "/home/u", Target: "/home/u/p"})
	d.SetGit("A", "a@x.org")
	if d.SetSigningKey("/home/u/.ssh/s.pub") || d.Git.SigningKey != "" {
		t.Error("signing key pinned without an ssh key")
	}
	d.SetSSH("/home/u/.ssh/k.pub")
	d.ClearIdentity()
	d.SetSSH("/home/u/.ssh/k.pub")
	if d.SetSigningKey("/home/u/.ssh/s.pub") {
		t.Error("signing key pinned without a git author")
	}
}

// TestHostSystemDirsAreNotWritable fails if a rw grant on a system directory
// of the host, or on anything under one, is accepted. Read-only on the same
// paths is not refused here, and a path inside the target is not a system
// directory even when the target itself sits under /srv.
func TestHostSystemDirsAreNotWritable(t *testing.T) {
	for _, p := range []string{"/etc", "/etc/ssh", "/usr", "/usr/local", "/usr/local/bin", "/bin", "/sbin", "/lib", "/lib64", "/libexec",
		"/opt", "/opt/tool", "/var", "/var/lib/x", "/boot", "/srv", "/srv/www"} {
		d := New(testHost())
		o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "rw"))
		if o.Refused != CodeHostSystem {
			t.Errorf("grant rw %s: refused=%q (%s), want %s", p, o.Refused, o.Msg, CodeHostSystem)
		}
		if !d.Empty() {
			t.Errorf("grant rw %s changed the draft", p)
		}
	}
	if o := New(testHost()).Apply(act(intent.OpGrantPath, "path", "/etc", "access", "tmpfs")); o.Refused != "" {
		t.Errorf("a scratch tmpfs on /etc writes nothing to the host: %+v", o)
	}
	h := testHost()
	h.Target = "/srv/proj"
	if o := New(h).Apply(act(intent.OpGrantPath, "path", "{target}/out", "access", "rw")); o.Refused != "" {
		t.Errorf("rw inside the target refused: %+v", o)
	}
	if o := New(h).Apply(act(intent.OpGrantPath, "path", "/srv", "access", "rw")); o.Refused != CodeHostSystem {
		t.Errorf("rw on a directory above the target: %+v", o)
	}
}

// TestBaseReadOnlyNeedsNoCard fails if a read-only grant on what @sys already
// binds is recorded in the draft instead of being said, or if the sentence
// stops naming @sys.
func TestBaseReadOnlyNeedsNoCard(t *testing.T) {
	for _, p := range []string{"/usr", "/usr/local", "/usr/share/doc", "/opt", "/opt/tool"} {
		d := New(testHost())
		o := d.Apply(act(intent.OpGrantPath, "path", p, "access", "ro"))
		if o.Changed || o.Refused != "" || !strings.Contains(o.Msg, "@sys") || !d.Empty() {
			t.Errorf("ro %s: %+v, draft empty %v", p, o, d.Empty())
		}
	}
	if o := New(testHost()).Apply(act(intent.OpGrantPath, "path", "/etc", "access", "ro")); !o.Changed {
		t.Errorf("@sys binds only some /etc entries; ro /etc is still a grant: %+v", o)
	}
}

func TestBaseReadOnlyIsStillInBaseToml(t *testing.T) {
	raw, err := os.ReadFile("../../../internal/profile/profiles/base.toml")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), "[profile.sys]")
	if !ok {
		t.Fatal("no [profile.sys] in base.toml")
	}
	_, ro, _ := strings.Cut(after, "ro = [")
	ro, _, _ = strings.Cut(ro, "]")
	for _, b := range baseReadOnly {
		if !strings.Contains(ro, `"`+b+`"`) {
			t.Errorf("@sys no longer binds %s read-only", b)
		}
	}
}
