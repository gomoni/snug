//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSymlinkedGeneratedParentCreatesNoHostFile is the end-to-end regression
// for the containment arm rejectGeneratedOntoHost gained for #576: a host
// symlink at a directory component INSIDE a read-only grant used to let
// bwrap's mkdir_with_parents walk the generated file's destination straight
// out of the grant meant to cover it, and create the file on the host with no
// error and no bwrap refusal to catch it — measured, bwrap 0.12.0, `ro
// {home}/.config` plus a host `~/.config/git -> <elsewhere>` produced a 0-byte
// read-only allowed_signers file on the host, snug exit 0.
//
// The unit half (internal/policy/generatedontohost_test.go) exercises the
// predicate directly; this half is what the unit test cannot show — a real
// bwrap run against a real symlink, and whether the file it names actually
// exists on the host afterwards.
func TestSymlinkedGeneratedParentCreatesNoHostFile(t *testing.T) {
	budget(t)
	requireSandbox(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	// escape stands in for the reported shape (a symlink pointing into the
	// sandboxed repository) — any host directory outside the grant that
	// covers {home}/.config demonstrates the same divergence.
	escape := t.TempDir()
	if err := os.Symlink(escape, filepath.Join(home, ".config", "git")); err != nil {
		t.Fatal(err)
	}
	wantHostFile := filepath.Join(escape, "allowed_signers")

	// {home} itself is a tmpfs, exactly like @home's own — only .config is a
	// real host directory, so the identity band's OTHER generated files
	// (~/.gitconfig, ~/.ssh/config, ~/.ssh/known_hosts) land on the ephemeral
	// tmpfs and only allowed_signers, nested under the symlinked directory,
	// is at risk. --no-defaults is used because @cwd-rw includes @home, whose
	// own tmpfs already claims {home}/.config exactly — this profile has to
	// be the one that claims it, as a real read-only bind, or the reproduction
	// does not exist.
	repro := "[profile.repro]\n" +
		"description = \"reproduction: {home}/.config read-only, {home} itself a tmpfs\"\n" +
		"tmpfs = [\"{home}\"]\n" +
		"ro = [\"{home}/.config\"]\n" +
		"rw = [\"{target}\"]\n"
	identity := "[profile.pinned]\n" +
		"description = \"one throwaway key, so allowed_signers is generated\"\n" +
		"[profile.pinned.identity.ssh]\n" +
		"agent = \"proxy\"\n" +
		"key = \"" + pub + "\"\n" +
		"[profile.pinned.identity.git]\n" +
		"signing_key = \"" + pub + "\"\n" +
		"name = \"Snug Integration\"\n" +
		"email = \"snug-signing-integration@example.invalid\"\n"

	env := writeProfiles(t, map[string]string{"repro": repro, "pinned": identity},
		"HOME="+home, "SSH_AUTH_SOCK="+sock)

	out, code := cli(t, env, "--no-defaults", "-p", "@sys", "-p", "repro", "-p", "pinned",
		proj, "--", "true")

	// (a) is the diagnostic, not the assertion — see (b) below for why.
	if code == 0 {
		t.Errorf("snug ACCEPTED a policy where a host symlink takes the generated "+
			"allowed_signers destination outside the read-only grant that covers it:\n%s", out)
	}
	for _, want := range []string{"repro", "symlink", "OUTSIDE"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not carry %q:\n%s", want, out)
		}
	}

	// (b) IS the test: whatever snug printed, the host must not have gained a
	// file. bwrap's mkdir_with_parents follows a symlink when it creates a
	// mountpoint, with no error of its own — the filesystem is the only
	// witness.
	if _, err := os.Stat(wantHostFile); !os.IsNotExist(err) {
		t.Fatalf("the generated allowed_signers file exists on the HOST at %s (stat err=%v) — "+
			"this is the write #576's containment arm exists to refuse", wantHostFile, err)
	}
}
