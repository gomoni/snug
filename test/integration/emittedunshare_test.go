//go:build integration

package integration

import (
	"strings"
	"testing"
	"time"
)

// emittedBwrapFlags returns the bwrap argv snug PRINTS for a selection, one
// token per element, read out of `snug --dry-run`.
//
// Read from the SCREEN rather than from internal/policy, and that is the whole
// point of this file: a test that imported Topology.UnshareFlags would agree
// with the emitter by construction and both sides would move together. This
// package deliberately links none of snug's packages (see sandbox_test.go's
// package doc) — it drives the built binary, so what it sees is what a human
// reading --dry-run sees, and what bwrap is handed.
func emittedBwrapFlags(t *testing.T, args ...string) []string {
	t.Helper()
	proj, _ := target(t)
	out, code := cli(t, nil, append(append([]string{"--dry-run"}, args...), proj)...)
	if code != 0 {
		t.Fatalf("snug --dry-run %s exited %d:\n%s", strings.Join(args, " "), code, out)
	}
	var tokens []string
	inBwrap := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "── bwrap") {
			inBwrap = true
			continue
		}
		if inBwrap && strings.HasPrefix(line, "── ") {
			break
		}
		if !inBwrap {
			continue
		}
		tokens = append(tokens, strings.Fields(line)...)
	}

	// THE BLOCK IS NOT THE ARGV. Under the stage topology snug wraps the
	// command in prose explaining that the network namespace is not in it —
	// and that prose contains the STRING "--unshare-net" ("no --unshare-net
	// appears below"). A test that scanned the whole block would therefore
	// have found the flag it is asserting is absent, in a sentence saying it
	// is absent. So cut to the command itself: the `bwrap` token that starts
	// the argv is the one followed by an unshare flag, and the argv ends at
	// the `--` separating bwrap's flags from the payload.
	start := -1
	for i := 0; i < len(tokens)-1; i++ {
		if tokens[i] == "bwrap" && strings.HasPrefix(tokens[i+1], "--unshare-") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("no `bwrap --unshare-…` command in the --dry-run bwrap block for %s, so every "+
			"assertion about the argv would be about an empty list:\n%s", strings.Join(args, " "), out)
	}
	end := -1
	for i := start; i < len(tokens); i++ {
		if tokens[i] == "--" {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatalf("no `--` in the bwrap command for %s, so the argv has no end and the absence "+
			"assertions would be about a truncated list:\n%s", strings.Join(args, " "), out)
	}
	return tokens[start : end+1]
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// TestTheEmittedArgvUnsharesWhatEachTopologyRequires closes the half
// TestBwrapUnshareSetIsExhaustive cannot reach (issue #277).
//
// That test compares a LITERAL set in the test against `bwrap --help`, which
// catches one direction — a namespace a future bwrap grows that snug does not
// cover. It never reads snug's own argv, so deleting `--unshare-pid` from
// internal/policy/bwrap.go leaves it green: the literal still names pid, the
// help text still advertises pid, and nothing compares either against what is
// emitted. The only current catch is a golden diff, which is a reviewer
// noticing a changed line rather than an assertion — necessary, not
// sufficient, and exactly the "verify a security feature is ACTIVE, not merely
// requested" shape.
//
// So this asserts the emitted argv, per topology, in both directions.
//
// THE ABSENT FLAG IS THE INTERESTING ONE. Under the stage topology (@net) the
// STAGE creates the network namespace and forks bwrap already inside it, so
// bwrap must NOT unshare its own — if it did, the sandbox would sit in a fresh
// empty netns and pasta would be attached to one nothing is in. That is a
// process-topology fact with no other machine check: no golden diff forces a
// reviewer to notice its absence, because an absence is what a golden shows
// least well.
//
// The offline arm is the positive control for it. `--unshare-net` must be
// PRESENT there — otherwise "absent under @net" is equally true of a build
// that stopped emitting it everywhere, which would be the most serious
// regression this file could miss.
func TestTheEmittedArgvUnsharesWhatEachTopologyRequires(t *testing.T) {
	budget(t, 60*time.Second)

	// Every topology unshares these five. Written here as the property the
	// argv must satisfy, not imported from the code that produces it.
	required := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts",
	}

	for _, tc := range []struct {
		name       string
		args       []string
		unshareNet bool
		why        string
	}{
		{
			name:       "offline",
			args:       nil,
			unshareNet: true,
			why: "an offline sandbox creates and keeps its OWN empty network namespace; " +
				"nothing else makes one for it",
		},
		{
			name:       "stage (@net)",
			args:       []string{"-p", "@net"},
			unshareNet: false,
			why: "the STAGE creates N and forks bwrap already inside it, so bwrap unsharing " +
				"net would put the sandbox in a fresh empty namespace and leave pasta attached " +
				"to one nothing is in",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := emittedBwrapFlags(t, tc.args...)

			for _, want := range required {
				if !hasFlag(flags, want) {
					t.Errorf("the emitted bwrap argv does not contain %s. A namespace that is "+
						"not unshared is not isolated, and the only other check on this is a "+
						"golden diff — which is a reviewer noticing a line, not an assertion "+
						"(issue #277). Emitted: %v", want, flags)
				}
			}

			// cgroup is deliberately the -try spelling and user is deliberately
			// NOT (issue #24): asserted here as the exact tokens, because the
			// difference between them is the whole of that issue.
			if !hasFlag(flags, "--unshare-cgroup-try") {
				t.Errorf("the emitted argv does not contain --unshare-cgroup-try: %v", flags)
			}
			if hasFlag(flags, "--unshare-cgroup") {
				t.Errorf("the emitted argv contains the STRICT --unshare-cgroup. Issue #24's "+
					"measurement: cgroup's -try is a kernel-support check rather than a "+
					"resource check, so strict refuses a host built without CONFIG_CGROUPS "+
					"and buys nothing: %v", flags)
			}
			if hasFlag(flags, "--unshare-user-try") {
				t.Errorf("the emitted argv contains --unshare-user-TRY, which exits 0 having "+
					"created no user namespace when the ucount is exhausted (issues #24, "+
					"#98): %v", flags)
			}

			// The net flag, in whichever direction this topology needs.
			switch got := hasFlag(flags, "--unshare-net"); {
			case tc.unshareNet && !got:
				t.Errorf("the emitted argv does not contain --unshare-net, and %s. Without it "+
					"the sandbox shares whatever namespace snug was started in: %v", tc.why, flags)
			case !tc.unshareNet && got:
				t.Errorf("the emitted argv contains --unshare-net, and %s: %v", tc.why, flags)
			}

			// CONTROL: this is the real argv rather than a fragment that
			// happens to hold the tokens above. `--` separates bwrap's flags
			// from the payload, and its absence would mean the block was cut
			// short — which would make every "not present" assertion above
			// pass for the wrong reason.
			if !hasFlag(flags, "--") {
				t.Errorf("no `--` in the emitted argv, so the bwrap block on the screen is "+
					"truncated and the absence assertions above prove nothing: %v", flags)
			}
		})
	}
}
