package policy

import (
	"strings"
	"testing"
)

// ── §2.5, the grant-coupling rule ────────────────────────────────────────────
//
// Read envcoupling.go's opening comment before adding to this file. The rule is
// a COUPLING rule and not a boundary: it stops a profile naming a path it never
// granted, which is a lie a reviewer would have to leave the file to catch. It
// does not stop anything reaching, and no test here may be written as though it
// did.

// A profile's own grant is enough, and coverage is downward with no depth
// limit: ro=["/usr"] is what makes SHELL=/usr/bin/bash legal.
func TestCouplingAcceptsAPathCoveredByTheProfilesOwnGrant(t *testing.T) {
	reg := testRegistry()
	reg["deep"] = &Profile{Name: "deep", RO: []string{"/opt/tools/bin"}, Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/opt/tools/bin/inner/deeper"}}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "deep"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("a path below the profile's own grant was refused: %v", err)
	}
}

// The include closure counts, which is how the shipped @claude satisfies the
// rule: it names {home}/.local/bin on PATH and grants only the FILE inside it,
// but it includes @home, whose tmpfs covers all of $HOME. §2.5 accepts that
// @home is a rubber stamp for $HOME — the profile did bring it, on an `include`
// line --dry-run renders.
func TestCouplingCountsTheIncludeClosure(t *testing.T) {
	reg := testRegistry()
	reg["viainclude"] = &Profile{Name: "viainclude", Include: []ProfileName{"@home"}, Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"{home}/.local/bin"}}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "viainclude"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("a path covered by an INCLUDED profile's grant was refused: %v", err)
	}
}

// THE ONE THAT MUST NOT DRIFT. If the selected set counted, Resolve([a]) could
// refuse what Resolve([a,b]) admits — one profile would change another
// profile's verdict. That is not a visibility break, but it is one edit away
// from being one, and the edit is a two-word change nobody would notice in
// review. §2.5 asks for it to be refused BY NAME, with a test.
func TestCouplingVerdictDoesNotDependOnTheSelectedSet(t *testing.T) {
	reg := testRegistry()
	// `namer` names a directory it does not grant.
	reg["namer"] = &Profile{Name: "namer", Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/opt/tools/bin"}}}}
	// `granter` grants exactly that directory — but it is a different profile,
	// and selecting it must not launder `namer`'s claim.
	reg["granter"] = &Profile{Name: "granter", RO: []string{"/opt/tools/bin"}}

	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "namer"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("a profile naming a path it does not grant was accepted")
	}
	_, err2 := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "namer", "granter"}, testCtx(), newFakeEnv())
	if err2 == nil {
		t.Fatal("selecting another profile that grants the path made namer's claim legal — " +
			"the verdict on a profile must be a property of that profile's own text, or " +
			"adding a profile changes another profile's legality")
	}
	if err.Error() != err2.Error() {
		t.Errorf("the refusal changed when an unrelated profile was selected:\n  %v\n  %v", err, err2)
	}

	// POSITIVE CONTROL: the same grant reached through `include` IS enough, so
	// the refusal above is about coupling and not about the path being
	// unreachable in principle.
	reg["namer-including"] = &Profile{Name: "namer-including", Include: []ProfileName{"granter"},
		Environ: EnvGrants{Merge: map[string][]string{"PATH": {"/opt/tools/bin"}}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "namer-including"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: an INCLUDED grant must satisfy the rule: %v", err)
	}
}

// A symlink is resolved first and is never a grant itself. On a usr-merged host
// /bin is a symlink snug creates, so a profile granting /usr and naming /bin has
// named the path the sandbox will actually see — refusing it would be the check
// judging a path that does not exist inside.
func TestCouplingResolvesThroughTheProfilesOwnSymlinks(t *testing.T) {
	reg := testRegistry()
	// @sys grants /usr and creates /bin -> usr/bin.
	reg["binny"] = &Profile{Name: "binny", Include: []ProfileName{"@sys"}, Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/bin"}}}}
	if _, err := Resolve(reg, []ProfileName{"@cwd-rw", "binny"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("/bin was refused for a profile that grants /usr and creates the symlink: %v", err)
	}

	// CONTROL: without the symlink and the /usr grant, /bin is not covered by
	// anything and the same value is refused. Otherwise the test above would
	// pass on an implementation that accepts every path.
	reg["binny-alone"] = &Profile{Name: "binny-alone", Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/bin"}}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binny-alone"}, testCtx(), newFakeEnv()); err == nil {
		t.Fatal("control: a profile granting nothing had /bin accepted")
	}
}

// inherit and sanitise are exempt: the value is the HOST's, not the profile's,
// and sanitise has its own filter for exactly this question. A rule applied to
// them would be refusing a profile for what somebody's shell happened to export.
func TestCouplingDoesNotApplyToInheritOrSanitise(t *testing.T) {
	env := newFakeEnv()
	env.env["PKG_CONFIG_PATH"] = "/srv/nothing-grants-this"
	// `sanity` sanitises PKG_CONFIG_PATH and grants nothing at all.
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatalf("sanitise was subjected to the coupling rule: %v", err)
	}
	if _, ok := p.EnvValue("PKG_CONFIG_PATH"); ok {
		t.Error("every host element was ungranted, so the variable must be UNSET")
	}
}

// A non-path scalar is out of scope entirely: EDITOR=vim is not a claim about
// the filesystem and there is nothing to couple it to.
func TestCouplingIgnoresANonPathScalar(t *testing.T) {
	reg := testRegistry()
	// MY_EDITOR is on no roster, which is the second half of what this test
	// covers: an unrostered name has no `path` fact either, so the coupling rule
	// leaves it alone for the same reason it leaves EDITOR=vim alone
	// (envcoupling.go's isPathValued).
	reg["ed"] = &Profile{Name: "ed", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "vim"}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "ed"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("a non-path scalar was subjected to the coupling rule: %v", err)
	}
}

// The refusal has to name the profile, the variable and the value, or the
// reader is left grepping for which of a dozen profiles wrote the line.
func TestCouplingRefusalNamesTheProfileAndTheValue(t *testing.T) {
	err := refusalUncoupledSet(t)
	if err == nil {
		t.Fatal("a profile set a path-valued variable to something it does not grant")
	}
	for _, want := range []string{"broken", "XDG_DATA_HOME", "/home/u/.local/share", "ro/rw/tmpfs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// ── F3: a relative startup file is refused, and why that is a TYPE refusal ───
//
// REGRESSION (redteam, issue #44 follow-up). checkCoupled refuses a relative
// value and names the hazard precisely — "a relative one is resolved against
// whatever directory the payload happens to be in, which is not something a
// profile can know" — and it was reached ONLY through isPathValued, which is
// false for BASH_ENV, ENV and PYTHONSTARTUP. That flag was set false
// deliberately, to keep the grant-COUPLING clause unenforced, and it switched
// off the absolute-path rule at the same time without anyone noticing. Measured
// on the base commit: `set BASH_ENV = ".snug-init.sh"` resolved clean while
// `set CARGO_HOME = "cargo"` was refused with a message naming exactly the
// hazard the first one has. Inside snug the cwd is `--chdir <target>`, the one
// writable thing the payload controls; measured on the host, with the control:
//
//	cd cwd1; BASH_ENV=.snug-init.sh bash -c 'echo body'  -> sourced from cwd1
//	cd cwd2; BASH_ENV=.snug-init.sh bash -c 'echo body'  -> nothing
//
// The argument for this being a TYPE refusal rather than a permission one is at
// valueIsAPath, where the next reader meets it. The short form: a relative value
// is not something a profile can MEAN, and the same intent has an accepted
// spelling — which is the test this codebase applies to any refusal.
func TestARelativeStartupFileIsRefused(t *testing.T) {
	resolve := func(g EnvGrants) error {
		reg := testRegistry()
		reg["startup"] = &Profile{Name: "startup", Environ: g}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "startup"}, testCtx(), newFakeEnv())
		return err
	}

	for _, name := range []string{"BASH_ENV", "ENV", "PYTHONSTARTUP"} {
		err := resolve(EnvGrants{Set: map[string]string{name: ".snug-init.sh"}})
		if err == nil {
			t.Errorf("environ.set %s = \".snug-init.sh\" was accepted. The file it names is "+
				"whichever one happens to be in the directory the payload was last in — inside "+
				"snug, the target — so there is no value snug can hand over that means what the "+
				"profile said. Thirteen other path-valued names already refuse this", name)
			continue
		}
		for _, want := range []string{name, "absolute path"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal for %s does not name %q: %v", name, want, err)
			}
		}
		// THE ACCEPTED SPELLING, which is what makes the refusal a type verdict
		// rather than a denial: the author's intent is expressible.
		if err := resolve(EnvGrants{Set: map[string]string{name: "{target}/init"}}); err != nil {
			t.Errorf("environ.set %s = \"{target}/init\" was refused: %v. A refusal with no "+
				"accepted spelling of the same intent IS a denial, and snug does not have "+
				"those over a human's own profile", name, err)
		}
	}

	// THE CONTROLS THAT STOP THE FIX OVER-REACHING, and they are measured rather
	// than assumed. These two sat in the same bucket and are NOT paths:
	//
	//   PYTHONBREAKPOINT=bpmod.hook   python3 -c 'breakpoint()' -> the callable ran
	//   PYTHONBREAKPOINT=/tmp/x.py    python3 -c 'breakpoint()'
	//        -> RuntimeWarning: Ignoring unimportable $PYTHONBREAKPOINT
	//   LESSOPEN="|$D/lo.sh %s" less -F f.txt                   -> lo.sh ran
	//
	// python REFUSES a path where PYTHONBREAKPOINT wants a module:callable, and
	// LESSOPEN's value is a command line whose leading '|' selects the pipe form.
	// A path rule for either would refuse the only correct spelling — which is
	// the real reason all five carried `path: false`, and it applies to two of
	// the five rather than to all of them.
	for name, value := range map[string]string{
		"PYTHONBREAKPOINT": "mod:fn",
		"LESSOPEN":         "|/usr/bin/lesspipe %s",
	} {
		if err := resolve(EnvGrants{Set: map[string]string{name: value}}); err != nil {
			t.Errorf("environ.set %s = %q was refused: %v. Its value is not a path, measured, and "+
				"the absolute-path rule must not have been widened to every name that used to "+
				"share a bucket with the startup files", name, value, err)
		}
	}
}
