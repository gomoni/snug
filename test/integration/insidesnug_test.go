//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The inside half of bin/inside-snug's proof. The host half (test/guard) runs
// everywhere and asserts the refusal; this one needs a real sandbox and asserts
// the only case where the guard may say yes.
//
// Both are required, and neither is redundant. A guard that always refuses would
// pass every host-side test and quietly make `inside-snug && <destructive>` a
// no-op that never runs its second half — which looks like safety and is
// actually an agent's guarded command silently doing nothing.

// guardInTarget copies bin/inside-snug into the target directory, which is the
// one host tree a sandbox can see. Copied rather than bound: the point is to
// exercise the script snug's own repo ships, from inside, with no extra grant.
func guardInTarget(t *testing.T, proj string) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "bin", "inside-snug"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("bin/inside-snug is missing (%v); the instruction in every agent file to "+
			"guard destructive commands with it would be pointing at nothing", err)
	}
	dst := filepath.Join(proj, "inside-snug")
	if err := os.WriteFile(dst, body, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestTheSandboxGuardSaysYesOnlyInsideASandbox(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)
	guard := guardInTarget(t, proj)

	// The one case that may pass, and it must pass for the RIGHT reasons —
	// verbose output names each family, so a guard that shortcut two of them
	// would be visible here rather than green.
	t.Run("inside, all three families", func(t *testing.T) {
		in := run(t, nil, proj, guard+" -v; echo guard-exit=$?").mustRun(t)
		if !strings.Contains(in.out, "guard-exit=0") {
			t.Fatalf("bin/inside-snug refused INSIDE a real sandbox. Every guarded destructive "+
				"command an agent writes then silently does nothing, which reads as safety "+
				"and is not:\n%s", in.out)
		}
		for _, family := range []string{"ok — A:", "ok — B:", "ok — C:"} {
			if !strings.Contains(in.out, family) {
				t.Errorf("family %q did not report passing; the verdict rests on fewer "+
					"families than the guard claims:\n%s", family, in.out)
			}
		}
	})

	// Each family flipped in turn, from inside, where every other family still
	// holds. This is the mutation check the guard's own design asks for: a
	// family that cannot be made to fail is a family that is not being read.
	for _, tc := range []struct {
		name, prefix, want string
	}{
		{
			// Family A. Necessary, never sufficient — the host-side twin of
			// this asserts the other direction.
			name:   "A: the environment snug authors is gone",
			prefix: "unset SNUG; ",
			want:   "SNUG is not 1",
		},
		{
			// Family A's other half. Mutation showed that removing the
			// SNUG_PROFILES check changed no test: the host-side twin asserts A
			// is not SUFFICIENT, and only a case from inside can assert it is
			// read at all.
			name:   "A: SNUG_PROFILES is gone",
			prefix: "unset SNUG_PROFILES; ",
			want:   "SNUG_PROFILES is unset",
		},
		{
			// Family B, the canary. The strongest single test in the guard,
			// and the only one whose evidence snug does not produce. Creating
			// the file inside is exactly the forgery a hostile payload would
			// attempt — and it flips the verdict to REFUSE, which is the
			// fail-closed direction.
			name:   "B: the host canary is visible",
			prefix: "touch \"$HOME/.snug-host-canary\"; ",
			want:   "host canary",
		},
		{
			// Family B, the filesystem shape. /usr is bound from the host and
			// is therefore the one thing reliably NOT a tmpfs inside — unlike
			// the target bind, which looks like a tmpfs whenever the target
			// happens to live under /tmp, as it does for every test here. That
			// was this row's first fixture and it passed the guard for a
			// reason that had nothing to do with the guard.
			name:   "B: HOME is not a tmpfs",
			prefix: "export HOME=/usr; ",
			want:   "the sandbox's home is a tmpfs",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := run(t, nil, proj, tc.prefix+guard+"; echo guard-exit=$?").mustRun(t)
			if strings.Contains(in.out, "guard-exit=0") {
				t.Fatalf("the guard still said yes with this family broken, so it is not "+
					"reading it:\n%s", in.out)
			}
			if !strings.Contains(in.out, tc.want) {
				// Not fatal: any refusal is safe. But a refusal for the WRONG
				// reason means this row is no longer exercising the family it
				// names, and the next person would not know.
				t.Errorf("refused, but not for the reason this row exists to exercise "+
					"(wanted %q):\n%s", tc.want, in.out)
			}
		})
	}
}

// TestAHandBuiltNamespaceDoesNotSatisfyTheGuard is family C's isolation test,
// and it exists because nothing else could break C and see a failure: from
// inside a real sandbox every other family holds, and on the host every other
// family refuses first, so removing the /proc/1 checks changed no result. A
// family nothing can break is a family nothing is reading.
//
// So it builds the adversary's version directly — bwrap namespaces with a tmpfs
// root, a tmpfs home and snug's own environment variables forged, so families A
// and B are SATISFIED and only C can refuse. Three of them, because one
// counterfeit only exercises one check: with no /proc at all every C check fails
// together, which proves the family is read and says nothing about its parts.
func TestAHandBuiltNamespaceDoesNotSatisfyTheGuard(t *testing.T) {
	requireSandbox(t)
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		skipOrFail(t, "no bwrap on PATH to build the counterfeit with")
	}
	guardDir, err := filepath.Abs(filepath.Join("..", "..", "bin"))
	if err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")
	if home == "" {
		skipOrFail(t, "no HOME to hand the counterfeit")
	}

	base := []string{
		"--tmpfs", "/",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "usr/sbin", "/sbin",
		"--dev", "/dev",
		"--tmpfs", home,
		"--ro-bind", guardDir, "/guardbin",
		"--setenv", "SNUG", "1",
		"--setenv", "SNUG_PROFILES", "@sys,@home,@cwd-rw",
		"--setenv", "HOME", home,
		"--setenv", "PATH", "/usr/bin",
	}

	for _, tc := range []struct {
		name  string
		extra []string
		env   []string
		want  string
	}{
		{
			// No /proc at all. The whole family fails, which is the blunt
			// version of the claim: A and B together are not enough.
			name: "no procfs: the family as a whole",
			want: "/proc/1",
		},
		{
			// A procfs that is the HOST's, because there is no pid namespace.
			// Everything else about this namespace looks right, and PID 1 is
			// the host's init — which is the counterfeit an attacker actually
			// builds, and the check that catches it.
			name:  "the host's procfs: PID 1 is not bwrap",
			extra: []string{"--proc", "/proc"},
			want:  "PID 1 is",
		},
		{
			// PID 1 really IS bwrap here, so the comm check passes and only the
			// environ check can refuse. snug sets cmd.Env = []string{} for its
			// own bwrap precisely so this file is empty (it once leaked 106
			// host variables); a bwrap started the ordinary way does not.
			name:  "bwrap as PID 1, but its environ is not empty",
			extra: []string{"--unshare-pid", "--proc", "/proc"},
			env:   []string{"FORGED=this-would-be-host-state"},
			want:  "/proc/1/environ is",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
			defer cancel()
			args := append(append(append([]string{}, base...), tc.extra...),
				"--", "/bin/sh", "-c", "/guardbin/inside-snug -v; echo guard-exit=$?")
			cmd := exec.CommandContext(ctx, bwrap, args...)
			cmd.Env = tc.env
			cmd.WaitDelay = waitDelay
			out, _ := cmd.CombinedOutput()
			got := string(out)

			if strings.Contains(got, "guard-exit=0") {
				t.Fatalf("the guard accepted a hand-built bwrap namespace as a snug sandbox. "+
					"Forged environment variables and a tmpfs root were enough, which means "+
					"families A and B are carrying the whole verdict:\n%s", got)
			}
			// It must have got PAST A and B, or the row proves nothing about C:
			// a counterfeit rejected at family A leaves C exactly as untested as
			// before.
			for _, family := range []string{"ok — A:", "ok — B:"} {
				if !strings.Contains(got, family) {
					t.Fatalf("the counterfeit failed at %s, so it never reached the "+
						"process-tree checks and this row does not isolate family C:\n%s",
						family, got)
				}
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("refused, but not on the check this row exists to exercise "+
					"(wanted %q):\n%s", tc.want, got)
			}
		})
	}
}
