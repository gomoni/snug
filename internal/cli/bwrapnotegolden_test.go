package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// bwrapNoteArgv is a STUB argv, and that is the point of this golden rather than
// a shortcut. What is under review here is the frame — what --dry-run says
// around the argv about what the argv cannot express — and the real argv is
// seventy host-dependent lines that would bury it and make the file rebase on
// every unrelated mount change. The real argv already has its own review
// artifact in internal/policy/testdata/*.bwrap.txt.
//
// Two flags, so the golden still shows WHERE the note sits relative to the argv,
// which is the whole design decision (see describeBwrap): before it, after it,
// or both.
//
// It carries no --unshare-* ON PURPOSE. A stub containing a
// namespace flag would sit four lines under a note that talks about which
// namespace flags are present, and a golden that contradicts itself is worse
// than no golden — the reader cannot tell the stub from the claim.
var bwrapNoteArgv = []string{"--ro-bind", "/usr", "/usr", "--", "/bin/sh"}

// TestGoldenBwrapNote is the review artifact for the honesty note on the bwrap
// block, and the diff it produces is the security-relevant one: it says, per
// topology, whether the printed command determines the sandbox's network
// posture on its own.
//
// It exists because under NetnsStage it does not, and nothing said so. MEASURED
// on this host before the fix: the argv printed for a '@net' policy, run exactly
// as printed, put the payload in the HOST network namespace (byte-identical
// readlink) with a live 127.0.0.1 listener answering from inside, while the real
// snug run of the same policy reported a different namespace id and refused the
// connection. Both runs emitted a marker first, so neither negative is a
// sandbox that never started.
//
// The three cases are the three NetnsOwner values, because that — not NetMode —
// is what decides whether the argv is self-contained: it is a fact about which
// process calls fork, which is exactly what an argv cannot carry.
func TestGoldenBwrapNote(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"isolated", []policy.ProfileName{"@sys", "@cwd-rw"}},
		{"egress", []policy.ProfileName{"@sys", "@cwd-rw", "@net"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f io.Writer) { describeBwrap(f, p, bwrapNoteArgv, nil) })

			path := filepath.Join("testdata", "bwrap-note."+tc.name+".txt")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/cli -update)", err)
			}
			if got != string(want) {
				t.Errorf("the bwrap block's honesty note changed — this is what stands between a\n"+
					"reviewer and a hand-run command whose network namespace is not the sandbox's.\n"+
					"--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

// TestTheStagedArgvIsNotPrintedAsSelfContained is the behavioural half, and it
// is written so it cannot pass vacuously: every assertion is paired with the
// same assertion inverted on a topology where the argv IS self-contained.
//
// The golden above pins the wording. This pins the PROPERTY, so a future edit
// that regenerates the golden with the warning deleted still goes red.
func TestTheStagedArgvIsNotPrintedAsSelfContained(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	render := func(sel []policy.ProfileName) (string, []string) {
		t.Helper()
		p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			t.Fatalf("Resolve(%v): %v", sel, err)
		}
		// The REAL argv, not the stub: the claim is about what snug prints for a
		// run, and the note has to travel with the argv it is about.
		argv := p.BwrapArgs(0, 0)
		return captureFile(t, func(f io.Writer) { describeBwrap(f, p, argv, nil) }), argv
	}
	has := func(argv []string, flag string) bool {
		for _, a := range argv {
			if a == flag {
				return true
			}
		}
		return false
	}

	staged, stagedArgv := render([]policy.ProfileName{"@sys", "@cwd-rw", "@net"})
	isolated, isolatedArgv := render([]policy.ProfileName{"@sys", "@cwd-rw"})

	// CONTROL for the premise: the staged argv really does omit --unshare-net,
	// and the isolated one really does carry its own netns flag. Without this the
	// assertions below could be describing a defect that no longer exists.
	//
	// Asked of the argv SLICE, never of the rendered text — the note itself says
	// the word "--unshare-net" on both branches (present in the isolated argv's
	// prose, absent from the staged argv's own flag list), so a substring
	// search over the screen answers a question about the prose instead of
	// about the command.
	if has(stagedArgv, "--unshare-net") {
		t.Fatal("the staged argv now carries --unshare-net, so the note below describes " +
			"a boundary that has moved — re-read describeBwrap before touching this test")
	}
	if !has(isolatedArgv, "--unshare-net") {
		t.Fatal("control: the isolated argv does not create its own netns either, so " +
			"'self-contained' means nothing here")
	}

	// The note must say the command is incomplete, name the consequence in the
	// words the NETWORK block uses, and name a check that does work.
	for _, want := range []string{
		"INCOMPLETE ON ITS OWN",
		"host loopback",
		"abstract sockets",
		"readlink /proc/self/ns/net",
	} {
		if !strings.Contains(staged, want) {
			t.Errorf("the bwrap block for a staged netns does not say %q. Run as printed, that\n"+
				"command has the HOST network namespace, and VERIFY.md's reader reproduces it\n"+
				"by hand:\n%s", want, staged)
		}
	}

	// …and the same warning must NOT appear where the argv genuinely is
	// self-contained, or it is noise that teaches the reader to skip it — which
	// is how this screen loses on the one topology where it matters.
	if strings.Contains(isolated, "INCOMPLETE ON ITS OWN") {
		t.Error("the isolated argv creates its own netns with --unshare-all and is complete; " +
			"warning about it trains the reader to ignore the warning that counts")
	}
}
