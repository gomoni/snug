//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #186, end to end: a writable grant covering a path snug GENERATES into
// turns snug's own setup write into a host overwrite.
//
// The unit half lives in internal/policy (generatedontohost_test.go) and pins
// the rule. This half exists because the unit test cannot observe the thing that
// actually went wrong: real bytes in a real home directory, written by bwrap's
// --file before any payload ran. It uses the IDENTITY generator rather than
// @claude — the same defect, the profile that is easiest to stand up here, and a
// standing reminder that the fix is not @claude-shaped.
//
// The synthetic HOME is not a nicety. The incident happened because a red-team
// run was pointed at a real one.
func TestSnugRefusesToWriteItsGeneratedFilesOntoTheHost(t *testing.T) {
	requireSandbox(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)

	// A synthetic home with the two files the identity band generates, carrying
	// content nothing else would produce. t.TempDir() is a sibling of the
	// target's root rather than inside it, so @parent-ro does not reach it and
	// @home's tmpfs does not mask it.
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const sentinel = "HOST-ORIGINAL-CONTENT-MUST-SURVIVE"
	files := map[string]string{
		filepath.Join(sshDir, "config"):      "# " + sentinel + "\nHost example.invalid\n",
		filepath.Join(sshDir, "known_hosts"): "example.invalid ssh-ed25519 " + sentinel + "\n",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unchanged := func(t *testing.T, when string) {
		t.Helper()
		for path, body := range files {
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %s no longer exists on the host: %v", when, path, err)
			}
			if string(got) != body {
				t.Errorf("%s: snug rewrote the HOST's %s.\nwant: %q\ngot:  %q\n"+
					"This is issue #186: bwrap's --file copies generated content onto its "+
					"destination, and a writable grant covering that path makes the destination "+
					"a host file. Nothing escaped and no grant was exceeded — snug did the "+
					"writing, during setup, and there is no undo.", when, path, body, got)
			}
		}
	}

	identity := "[profile.pinned]\n" +
		"description = \"one throwaway key, so the identity files are generated\"\n" +
		"[profile.pinned.identity.ssh]\n" +
		"agent = \"proxy\"\n" +
		"key = \"" + pub + "\"\n"
	sshrw := "[profile.sshrw]\n" +
		"description = \"the reproduction: rw over the directory snug generates into\"\n" +
		"# ABUSE: with this grant snug writes its own generated ssh config onto the host's.\n" +
		"rw = [\"{home}/.ssh\"]\n"

	env := writeProfiles(t, map[string]string{"pinned": identity, "sshrw": sshrw,
		"pwlink": passwdHomeLink(t, home)},
		"HOME="+home, "SSH_AUTH_SOCK="+sock)

	t.Run("the policy is refused and nothing is written", func(t *testing.T) {
		out, code := cli(t, env, "-p", "pinned", "-p", "sshrw", "-p", "pwlink", proj, "--", "true")
		if code == 0 {
			// Errorf, not Fatalf, deliberately: when the rule is missing the run
			// really happens and the host files really are rewritten, and the
			// assertion below is the one that shows the damage. Stopping here
			// would leave the interesting half of the failure unreported — and
			// would leave nothing proving that half can fire at all.
			t.Errorf("snug ACCEPTED a policy that writes its generated identity files onto "+
				"the host:\n%s", out)
		}
		// The refusal has to name the choice, not just the fact. Two grants are
		// in tension and snug cannot know which one the human meant.
		for _, want := range []string{"sshrw", "on the HOST", "drop the rw grant", "deselect"} {
			if !strings.Contains(out, want) {
				t.Errorf("the refusal does not carry %q, so it does not say which line to "+
					"delete:\n%s", want, out)
			}
		}
		unchanged(t, "after the refused run")
	})

	// The positive control, and it carries the weight here: without it, a snug
	// that generated nothing at all would pass the assertion above for the
	// wrong reason. This proves the generator really does produce a file at
	// exactly the path the rw grant covered — so the refusal is about a write
	// that would genuinely have happened.
	t.Run("without the rw grant the same run generates the file INSIDE", func(t *testing.T) {
		in := runEnv(t, env, []string{"-p", "pinned", "-p", "pwlink"}, proj,
			"cat "+"$HOME/.ssh/config").mustRun(t)
		if !strings.Contains(in.out, "IdentitiesOnly") {
			t.Fatalf("the identity band generated no ~/.ssh/config inside the sandbox, so the "+
				"refusal above proves nothing about a real write:\n%s", in.out)
		}
		if strings.Contains(in.out, sentinel) {
			t.Errorf("the sandbox is reading the HOST's ~/.ssh/config, not a generated one — "+
				"the fixture is not exercising what it claims:\n%s", in.out)
		}
		unchanged(t, "after the accepted run")
	})
}

// ── the same write, steered by a HOST SYMLINK the sandbox reads differently ──
//
// Both cases below were MEASURED to write the host before their fixes landed:
// snug exit 0, the payload ran, and a 0444 file that no line of --dry-run named
// appeared under an unrelated writable grant. They are here rather than only in
// internal/policy because what went wrong each time was a DISAGREEMENT between
// what snug believed about the host and what bwrap then did to it, and a fake
// host cannot hold both halves of that.

// steeringFixture builds the shape both cases share: a PATH-TRANSLATING
// read-only cover over the target — guest and host differ, which is what makes
// a host-side and a sandbox-side reading of the same symlink land in different
// places — a writable grant somewhere else, and @claude generating
// {target}/.claude/settings.json inside the cover.
//
// links is the chain planted under the cover, as {name: link text}: the TEXT is
// what bwrap reads, so a relative one resolves against the GUEST directory.
func steeringFixture(t *testing.T, name string, links map[string]string) (env []string, proj, hostWritable string) {
	t.Helper()

	root := t.TempDir()
	cover := filepath.Join(root, "cover") // the cover's HOST side
	proj = filepath.Join(root, "proj")    // the cover's GUEST side, and the target
	guestWritable := filepath.Join(root, "wtarget")
	hostWritable = filepath.Join(root, "realhost") // where a write actually lands
	for _, d := range []string{cover, proj, guestWritable, hostWritable, filepath.Join(proj, ".claude")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// @claude projects a project-scope settings.json only where the target has
	// one, so the fixture ships it.
	if err := os.WriteFile(filepath.Join(proj, ".claude", "settings.json"),
		[]byte(`{"permissions":{"allow":["Bash"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file at the literal host path an Lstat would examine, so that a guard
	// asking the HOST gets the reassuring answer — "a regular file is there,
	// bind over it, nothing is written" — while bwrap resolves the same name
	// inside the sandbox and creates a file somewhere else entirely.
	if err := os.WriteFile(filepath.Join(guestWritable, "settings.json"),
		[]byte(`{"HOST":"untouched"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	for at, text := range links {
		if err := os.Symlink(text, filepath.Join(cover, at)); err != nil {
			t.Fatal(err)
		}
	}

	toml := "[profile." + name + "]\n" +
		"description = \"a translating cover over the target, plus a writable grant\"\n" +
		"# ABUSE: a host symlink under the cover steers snug's generated file into the\n" +
		"# writable grant, where bwrap creates it ON THE HOST before the payload exists.\n" +
		"include = [\"@sys\", \"@claude\"]\n" +
		"ro = [\"" + cover + ":" + proj + "\"]\n" +
		"rw = [\"" + hostWritable + ":" + guestWritable + "\"]\n"
	return writeProfiles(t, map[string]string{name: toml}), proj, hostWritable
}

// refusedWithoutTouchingTheHost is the three-part assertion, because any one
// part alone passes for the wrong reason: snug says no, the host directory is
// still empty, and the sentence on the screen is snug's rather than bwrap's.
func refusedWithoutTouchingTheHost(t *testing.T, screen string, code int, hostWritable string) {
	t.Helper()

	if code == 0 {
		t.Errorf("snug ACCEPTED a policy whose generated file resolves, INSIDE the sandbox, "+
			"into an unrelated writable grant:\n%s", screen)
	}
	entries, err := os.ReadDir(hostWritable)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("snug WROTE THE HOST during setup: %s now holds %s. The writer is snug itself, "+
			"before the sandbox exists, so no mitigation aimed at the payload applies — this is "+
			"issue #186's own shape", hostWritable, strings.Join(names, ", "))
	}
	if !strings.Contains(screen, "OUTSIDE that grant") {
		t.Errorf("the refusal is not the containment arm's: a run that dies on bwrap's own "+
			"message names neither snug, nor the profile, nor a fix, which is the whole reason "+
			"this guard exists:\n%s", screen)
	}
	if strings.Contains(screen, "bwrap: Can't") {
		t.Errorf("bwrap refused this, not snug — the guard was supposed to answer first:\n%s", screen)
	}
}

// TestAHostSymlinkUnderATranslatingCoverCannotSteerAGeneratedFileOntoTheHost is
// the one-hop case: the cover's `.claude` is a relative link that stays inside
// the cover on the HOST and lands in the writable grant inside the SANDBOX.
func TestAHostSymlinkUnderATranslatingCoverCannotSteerAGeneratedFileOntoTheHost(t *testing.T) {
	budget(t)
	requireSandbox(t)

	env, proj, hostWritable := steeringFixture(t, "steer1", map[string]string{
		".claude": "../wtarget",
	})
	screen, code := cli(t, env, "--no-defaults", "-p", "steer1", proj, "--", "true")
	refusedWithoutTouchingTheHost(t, screen, code, hostWritable)
}

// TestTheSecondHopOfAHostSymlinkChainIsFollowedToo is the same escape one hop
// deeper, and it is the shape a walk that follows ONE link per component
// misses: the first hop stays inside the cover, the second leaves it.
func TestTheSecondHopOfAHostSymlinkChainIsFollowedToo(t *testing.T) {
	budget(t)
	requireSandbox(t)

	env, proj, hostWritable := steeringFixture(t, "steer2", map[string]string{
		".claude": "inner",      // hop 1: stays inside the cover
		"inner":   "../wtarget", // hop 2: leaves it
	})
	screen, code := cli(t, env, "--no-defaults", "-p", "steer2", proj, "--", "true")
	refusedWithoutTouchingTheHost(t, screen, code, hostWritable)
}

// TestAWholeEtcGrantIsRefusedWhereResolvConfIsASymlink is the case CI caught
// and this machine could not: base.toml names `ro = ["/etc"]` as the one-line
// escape hatch for anyone who wants more than the curated fourteen entries, and
// on a systemd-resolved host — every GitHub runner — /etc/resolv.conf is a
// SYMLINK to ../run/systemd/resolve/stub-resolv.conf.
//
// snug GENERATES /etc/resolv.conf on every run, so that grant puts a generated
// file onto a symlink, and bubblewrap refuses to mount one there:
//
//	bwrap: Can't mount on symlink destination /etc/resolv.conf
//
// The run therefore does not start either way. What changed with issue #580 is
// WHOSE sentence the human reads, and that is the whole point of the guard: the
// refusal has to name the grant and the generator, which bwrap's cannot.
//
// The test skips where /etc/resolv.conf is a regular file, because there the
// same grant WORKS and refusing would be a false positive — a developer host
// with a plain resolv.conf is the shape this whole suite passed on while CI was
// red.
func TestAWholeEtcGrantIsRefusedWhereResolvConfIsASymlink(t *testing.T) {
	budget(t)

	fi, err := os.Lstat("/etc/resolv.conf")
	if err != nil {
		t.Skipf("this host has no /etc/resolv.conf at all (%v), so there is no destination "+
			"to judge", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Skip("this host's /etc/resolv.conf is a regular file, so a whole-/etc grant is " +
			"legitimate here and bwrap mounts over the inode — nothing to refuse")
	}

	proj, _ := target(t)
	env := writeProfiles(t, map[string]string{"etcall": "[profile.etcall]\n" +
		"description = \"base.toml's documented escape hatch: the whole of /etc\"\n" +
		"ro = [\"/etc\"]\n"})

	screen, code := cli(t, env, "--dry-run", "-p", "etcall", proj)
	if code == 0 {
		t.Fatalf("accepted a whole-/etc grant on a host whose /etc/resolv.conf is a symlink. "+
			"snug generates that file, bwrap will not mount a generated file onto a symlink, "+
			"and the run dies on bwrap's own message instead of on one naming the grant:\n%s",
			screen)
	}
	for _, want := range []string{
		"/etc/resolv.conf",
		"a symlink",
		"Can't mount on symlink destination", // what bwrap would have said
		"drop the ro grant on /etc",          // and what to do about it
	} {
		if !strings.Contains(screen, want) {
			t.Errorf("the refusal does not carry %q:\n%s", want, screen)
		}
	}
}
