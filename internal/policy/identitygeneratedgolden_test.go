package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── the review artifact for #454's host split ────────────────────────────────
//
// No prior golden ever rendered the BYTES of a generated ~/.gitconfig,
// ~/.ssh/config or ~/.ssh/known_hosts with identity.ssh.host and identity.gh.host
// set to DIFFERENT values: the *.bwrap.txt argv goldens carry a --ro-bind-data
// row naming the guest path and an fd, never the content behind it, so a bug
// that swapped which host feeds which artifact would produce zero argv diff.
//
// WHAT THIS GOLDEN CANNOT SEE, stated rather than left to be discovered: the gh
// half. identity.gh.host does not reach a file Resolve generates — it reaches
// `gh auth token --hostname`, the hosts.yml top key and GH_HOST, all produced in
// internal/cli AFTER resolution and behind an exec, so nothing in this package
// renders them. That is the half that MOVES A CREDENTIAL, and it is covered by
// internal/cli's ghhostsplit_test.go through the tokenMinter seam, plus the
// end-to-end runs in test/integration/identity_test.go. Neither half is
// assertable from the other.
//
// ctx.KnownHosts is INJECTED by the caller (internal/cli's knownHostsFor) and
// Resolve carries it through to the mount UNMODIFIED — it does not read a host
// filesystem to build it — so setting it to a fixture value here keeps this
// test as pure as every other one in this package while still pinning that the
// known_hosts mount carries exactly what ssh.host's caller handed it.
func TestGoldenGeneratedIdentityFiles(t *testing.T) {
	const knownHostsFixture = "# entries for ssh.example, filtered by the caller before Resolve sees them\n" +
		"ssh.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIQ==\n"

	reg := testRegistry()
	reg["pinned"] = &Profile{Name: "pinned", Identity: &Identity{
		SSH: IdentitySSH{Host: "ssh.example", Key: "~/.ssh/id_ed25519.pub", Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "Some One", Email: "some.one@example.com"},
		Gh:  IdentityGh{Host: "gh.example", User: "some-one"},
	}}

	ctx := testCtx()
	ctx.KnownHosts = []byte(knownHostsFixture)

	p, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "pinned"), ctx, newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	content := func(guest string) string {
		t.Helper()
		for _, m := range p.Mounts {
			if m.Guest == guest {
				return string(m.Content)
			}
		}
		t.Fatalf("no generated mount at %s", guest)
		return ""
	}

	gitconfig := content(ctx.Home + "/.gitconfig")
	sshconfig := content(ctx.Home + "/.ssh/config")
	knownHosts := content(ctx.Home + "/.ssh/known_hosts")

	// THE ASSERTION #454 EXISTS FOR: ssh.example (identity.ssh.host) feeds the
	// ~/.ssh/config Host line, git's insteadOf and (via the injected fixture)
	// known_hosts — and gh.example (identity.gh.host) feeds none of these three
	// files at all, since it only ever reaches the gh token/GH_CONFIG_DIR that
	// stageGhConfig stages, not Resolve's own generated identity files.
	if !strings.Contains(sshconfig, "Host ssh.example") {
		t.Errorf("~/.ssh/config does not carry \"Host ssh.example\":\n%s", sshconfig)
	}
	if !strings.Contains(gitconfig, `insteadOf = https://ssh.example/`) {
		t.Errorf("~/.gitconfig does not rewrite https://ssh.example/, want git@ssh.example: over "+
			"the pinned key:\n%s", gitconfig)
	}
	if !strings.Contains(knownHosts, "ssh.example") {
		t.Errorf("~/.ssh/known_hosts does not carry the ssh.example fixture — Resolve must carry "+
			"ctx.KnownHosts through UNMODIFIED:\n%s", knownHosts)
	}
	for _, f := range []struct{ name, content string }{
		{"~/.ssh/config", sshconfig}, {"~/.gitconfig", gitconfig}, {"~/.ssh/known_hosts", knownHosts},
	} {
		if strings.Contains(f.content, "gh.example") {
			t.Errorf("%s names gh.example, which feeds only the gh token/GH_CONFIG_DIR, never "+
				"a file Resolve generates:\n%s", f.name, f.content)
		}
	}

	got := fmt.Sprintf("── %s/.gitconfig ──\n%s\n── %s/.ssh/config ──\n%s\n"+
		"── %s/.ssh/known_hosts ──\n%s",
		ctx.Home, gitconfig, ctx.Home, sshconfig, ctx.Home, knownHosts)

	path := filepath.Join("testdata", "identity-generated.txt")
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
		t.Fatalf("%v (run: go test ./internal/policy -run TestGoldenGeneratedIdentityFiles "+
			"-update, then READ the diff)", err)
	}
	if got != string(want) {
		t.Errorf("the generated identity files changed:\n--- got\n%s\n--- want\n%s", got, string(want))
	}
}
