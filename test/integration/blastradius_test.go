//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The in-sandbox half of bin/blast-radius. The host half (test/guard) runs
// everywhere and asserts the refusal; this one needs a real sandbox.
//
// The second subtest is the whole reason this script exists in its current form.
// Its predecessor asked "am I inside a snug sandbox?", answered yes here, and the
// host's private key was destroyed by the next command. A guard that says yes
// where the assets are reachable is worse than none: it launders a lethal policy
// as a verified one.

func guardInTarget(t *testing.T, proj string) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "bin", "blast-radius"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("bin/blast-radius is missing (%v); redteam.md's instruction to guard every "+
			"destructive payload with it would be pointing at nothing", err)
	}
	dst := filepath.Join(proj, "blast-radius")
	if err := os.WriteFile(dst, body, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestBlastRadiusInsideASandbox(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)
	guard := guardInTarget(t, proj)

	// A sandbox with the default selection reaches no host asset: $HOME is a
	// fresh tmpfs and the only host tree is the target. This must PASS, or every
	// guarded payload becomes a silent no-op — which reads as safety and is not.
	t.Run("a confined sandbox reaches nothing", func(t *testing.T) {
		in := run(t, nil, proj, guard+" -v; echo guard-exit=$?").mustRun(t)
		if !strings.Contains(in.out, "guard-exit=0") {
			t.Fatalf("the guard refused inside an ordinary sandbox, where $HOME is a fresh "+
				"tmpfs and nothing of the host's is reachable:\n%s", in.out)
		}
	})

	// THE CASE THE OLD GUARD PASSED. A real sandbox — every "am I inside?"
	// signal true — whose policy hands the payload the host's ssh directory,
	// writable. No identity profile, so nothing is generated there and #186's
	// Validate rule does not apply: the grant is honoured exactly as written.
	t.Run("a real sandbox with a lethal policy is refused", func(t *testing.T) {
		fakeHome := t.TempDir()
		if err := os.MkdirAll(filepath.Join(fakeHome, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		const key = "HOST-PRIVATE-KEY-MATERIAL\n"
		keyPath := filepath.Join(fakeHome, ".ssh", "id_ed25519")
		if err := os.WriteFile(keyPath, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}
		env := writeProfile(t, "[profile.sshrw]\n"+
			"description = \"a plain rw grant over the host's ssh directory\"\n"+
			"# ABUSE: the payload can read and destroy the host's key material.\n"+
			"rw = [\"{home}/.ssh\"]\n", "HOME="+fakeHome)

		in := runEnv(t, env, []string{"-p", "sshrw"}, proj,
			guard+"; echo guard-exit=$?").mustRun(t)
		if strings.Contains(in.out, "guard-exit=0") {
			t.Fatalf("the guard said proceed inside a sandbox whose policy hands over the "+
				"host's private key, writable. This is the exact case its predecessor passed: "+
				"\"inside\" is not a safety property, the mount policy is:\n%s", in.out)
		}
		if !strings.Contains(in.out, "id_ed25519") {
			t.Errorf("refused, but without naming the key that is at risk:\n%s", in.out)
		}

		// The positive control on the fixture itself: the key really IS
		// destroyable from in there. Without this, a sandbox that failed to
		// grant anything would produce the same refusal and prove nothing.
		in = runEnv(t, env, []string{"-p", "sshrw"}, proj,
			`echo PWNED > "$HOME/.ssh/id_ed25519"; echo wrote=$?`).mustRun(t)
		after, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) == key {
			t.Fatalf("the payload could not actually reach the host's key, so the refusal "+
				"above was free and this test does not exercise the case it claims:\n%s", in.out)
		}
	})
}
