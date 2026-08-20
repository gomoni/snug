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
		"[profile.pinned.identity]\n" +
		"ssh_mode = \"agent-proxy\"\n" +
		"ssh_key = \"" + pub + "\"\n"
	sshrw := "[profile.sshrw]\n" +
		"description = \"the reproduction: rw over the directory snug generates into\"\n" +
		"# ABUSE: with this grant snug writes its own generated ssh config onto the host's.\n" +
		"rw = [\"{home}/.ssh\"]\n"

	env := writeProfiles(t, map[string]string{"pinned": identity, "sshrw": sshrw},
		"HOME="+home, "SSH_AUTH_SOCK="+sock)

	t.Run("the policy is refused and nothing is written", func(t *testing.T) {
		out, code := cli(t, env, "-p", "pinned", "-p", "sshrw", proj, "--", "true")
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
		in := runEnv(t, env, []string{"-p", "pinned"}, proj,
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
