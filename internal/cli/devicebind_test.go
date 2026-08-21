package cli

import (
	"slices"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// argvContainsDevBind reports whether args contains either bwrap flag that
// can put a real device node behind a bind — `--dev-bind` or its `-try`
// spelling. Factored out so the positive control below (which does NOT go
// through a resolved Policy — see its own comment for why one cannot) is
// checking the SAME comparison the sweep uses, not a second copy of it that
// could quietly diverge.
func argvContainsDevBind(args []string) bool {
	return slices.Contains(args, "--dev-bind") || slices.Contains(args, "--dev-bind-try")
}

// TestBwrapArgvNeverAllowsDeviceAccess is what makes validate.go's device
// exclusion a CHECKED property instead of a claim.
//
// rejectEndpointSource's own doc comment (internal/policy/validate.go)
// explains WHY a device node is deliberately outside its predicate: bwrap sets
// `nosuid,nodev` on every bind it creates, so a device node reached through an
// ordinary bind is already unusable as a device — measured, `--ro-bind` of
// /dev/null gives `Permission denied`. That argument is sound only as long as
// snug's own argv never asks bwrap for the opposite: `--dev-bind` (or
// `--dev-bind-try`) is the ONE bwrap flag that reintroduces device nodes on a
// bind, and if either ever appeared in what BwrapFlags or BwrapArgs emits,
// "devices are handled by nodev" would be false for that mount specifically
// while the comment kept asserting it for every mount.
//
// SWEPT OVER EVERY REAL BUILTIN, one profile at a time layered onto the
// default selection — the same shape internal/cli/graft_test.go's
// TestNoProfileCanAuthorAGraft already uses for the same reason: a fake
// registry (internal/policy's testRegistry) describes a sandbox no user gets,
// and the review artifact this pins is about the ARGV snug actually ships.
func TestBwrapArgvNeverAllowsDeviceAccess(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	names := make([]policy.ProfileName, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	slices.Sort(names)

	checked := 0
	for _, name := range names {
		sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), name)
		p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			t.Logf("skipped %s: %v", name, err)
			continue
		}
		checked++

		if flags := p.BwrapFlags(1000, 1000, func(string) int { return 9 }); argvContainsDevBind(flags) {
			t.Errorf("builtin %s: BwrapFlags allows device access (--dev-bind/--dev-bind-try) — a "+
				"real device node would be reachable through this bind, which bwrap's own "+
				"`nosuid,nodev` (the property rejectEndpointSource's doc comment leans on to leave "+
				"devices out of its own predicate) does not protect against once THIS flag is the "+
				"one asking:\n%v", name, flags)
		}
		if args := p.BwrapArgs(1000, 1000); argvContainsDevBind(args) {
			t.Errorf("builtin %s: BwrapArgs allows device access (--dev-bind/--dev-bind-try)", name)
		}
	}

	if checked < len(names)/2 {
		t.Fatalf("only %d of %d builtins resolved on the fake host; the sweep is not covering "+
			"enough to mean anything", checked, len(names))
	}
}

// TestArgvContainsDevBindDetectsBothSpellings is the positive control for the
// sweep above, and it deliberately does NOT go through a resolved Policy.
//
// There is no code path that makes one: BwrapFlags's Kind switch
// (internal/policy/bwrap.go) has exactly one case that can touch /dev at all
// — KindBind, which always emits `--ro-bind` or `--bind` (with a `-try` suffix
// for Optional), never `--dev-bind`. That is not a fixture gap to route
// around; it is the fact under test; there is nowhere in the model today to
// hang a "make it emit --dev-bind" fixture from, and building one would mean
// adding the very capability this file exists to keep absent.
//
// So the positive control is one level down: it proves the COMPARISON the
// sweep runs — argvContainsDevBind — actually matches when fed a slice that
// does contain the flag, for both spellings, rather than a fixed string that
// can never match anything (the "grep 'a|b' without -E" shape CLAUDE.md
// warns about). Without this, a typo in argvContainsDevBind's own strings
// would make TestBwrapArgvNeverAllowsDeviceAccess pass regardless of what
// snug's argv actually contains.
func TestArgvContainsDevBindDetectsBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"plain --dev-bind", []string{"--ro-bind", "/usr", "/usr", "--dev-bind", "/dev/null", "/dev/probe"}, true},
		{"the -try spelling", []string{"--dev-bind-try", "/dev/null", "/dev/probe"}, true},
		{"ordinary argv, neither spelling present", []string{"--ro-bind", "/usr", "/usr", "--tmpfs", "/tmp"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := argvContainsDevBind(tc.args); got != tc.want {
				t.Errorf("argvContainsDevBind(%v) = %v, want %v — if this fails, the sweep above "+
					"cannot detect the flag it claims to be checking for", tc.args, got, tc.want)
			}
		})
	}
}
