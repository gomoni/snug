package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// runDirPID normalises this run's process id out of the socket bind line
// (`runDirName`, runtimedir.go) before a byte-exact golden comparison. Without
// it this golden could never pass twice: os.Getpid() differs on every test
// invocation, so the raw argv is not reproducible and is not what "golden"
// means. The bind line itself — a host socket path under
// $XDG_RUNTIME_DIR/snug/run-N/ — stays fully visible for review; only the
// digits that vary per-process are collapsed to a fixed placeholder.
var runDirPID = regexp.MustCompile(`run-\d+`)

// ── the review artifact for a pinned signing key's ARGV (#453) ──────────────
//
// internal/policy's *.bwrap.txt goldens (TestGoldenBwrapArgs) are built from a
// FAKE registry that defines no [identity] block at all, and no builtin ships
// one either (base.toml documents the template but is never selected by
// default) — so before this file, nothing pinned what a signing key actually
// does to the argv. The one reviewable claim is invariant 7: the staged
// signing key must appear as a --ro-bind-data row at SigningKeyGuest, a guest
// path with content behind an fd, and NOTHING in the argv may name a host
// ~/.ssh path — a KindData mount carries no host path at all, which is the
// structural reason a carried host key can never appear here, and this golden
// is what would show a diff if that ever stopped being true.
//
// It goes through the REAL staging code (startIdentity), the same mechanism
// claudeargvgolden_test.go uses for @claude's mounts, with dryRun = true: the
// key-staging in startIdentity runs unconditionally before the agent-proxy
// switch, so no live ssh-agent is needed to produce the mounts under review.
func TestGoldenIdentityArgv(t *testing.T) {
	// A FIXED base for the socket bind line, deterministic across machines
	// and CI users — otherwise plannedSocket falls back to $TMPDIR and
	// "snug-<uid>", and the uid varies exactly as unhelpfully as the pid
	// runDirPID normalises below.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// Two SEPARATE directories (t.TempDir() returns a fresh one per call):
	// writePinnedPubKey always names its file "id.pub", and a shared
	// directory would make the second call silently overwrite the first,
	// leaving both fields pinned to the same key blob.
	authPath, _ := writePinnedPubKey(t, t.TempDir())
	signPath, _ := writePinnedPubKey(t, t.TempDir())

	// GhUser/GhHost are deliberately ABSENT: stageGhConfig only runs at all
	// once either is set, and it then shells out to the real `gh` on THIS
	// host for a token — whatever that returns (or fails to) would make this
	// golden depend on whether the machine running the suite has `gh`
	// installed and logged in, which has nothing to do with what #453 changed.
	reg["signed"] = &policy.Profile{
		Name: "signed",
		Identity: &policy.Identity{
			SSH: policy.IdentitySSH{Agent: policy.SSHAgentProxy, Key: authPath},
			Git: policy.IdentityGit{SigningKey: signPath, Name: "Some One", Email: "some.one@example.com"},
		},
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "signed")
	ctx := envGoldenCtx()

	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	// dryRun = true: startIdentity's key-staging runs before the agent-proxy
	// switch and needs no live upstream, so this reaches the exact mounts a
	// real run would stage without dialling anything.
	cleanup, err := startIdentity(p, false, true)
	if err != nil {
		t.Fatalf("startIdentity: %v", err)
	}
	defer cleanup()

	got := runDirPID.ReplaceAllString(goldenFormat(p.BwrapArgs(1000, 1000)), "run-N")

	guestSigning := ctx.Home + "/" + policy.SigningKeyGuest
	if !strings.Contains(got, "--ro-bind-data") || !strings.Contains(got, guestSigning) {
		t.Fatalf("argv has no --ro-bind-data row naming the staged signing key at %s:\n%s",
			guestSigning, got)
	}

	// THE NEGATIVE, and the whole point of this file: no line anywhere in the
	// argv may bind a host ~/.ssh path. --ro-bind-data rows carry no host path
	// at all (content is behind an fd), so this is a structural guarantee
	// rather than a coincidence of this fixture — and it is the line that
	// must fail loudly, never get baselined, if that ever stops holding.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "--ro-bind-data") {
			continue
		}
		if strings.Contains(line, "/.ssh/") {
			t.Fatalf("argv binds a host ~/.ssh path directly, which invariant 7 forbids: %q\n%s",
				line, got)
		}
	}

	// #454 NESTED THE Go FIXTURE ABOVE INTO SSH/Git/Gh BLOCKS BUT MUST NOT MOVE
	// THIS FILE: the fd numbers 14-18 are ORDERING-sensitive (they are assigned
	// by the order startIdentity stages mounts in, not by anything about the
	// identity schema), and nothing about staging changed with the nesting. A
	// diff here means the refactor changed staging order or content, which it
	// must not — go back and find what moved.
	path := filepath.Join("testdata", "identity.bwrap.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -run TestGoldenIdentityArgv -update, then "+
			"READ the diff: this is the argv for a profile that may sign commits and tags)", err)
	}
	if got != string(want) {
		t.Errorf("argv changed — this is a change to the sandbox boundary for a profile that "+
			"may sign commits and tags.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
