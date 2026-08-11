package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// No shipped profile may put a directory the payload can WRITE TO on the PATH
// snug hands over.
//
// THE RULE, stated so the next person does not have to re-derive it: a writable
// directory ahead of /usr/bin is a SHADOW SLOT. The payload writes a file called
// `git` into it and the next `git` a human or another agent runs inside the
// sandbox is that file. Nothing stops a payload from rewriting its own PATH and
// nothing can — the property being defended is narrower and is entirely snug's
// to keep: **the environment snug itself hands over must not ship the slot
// pre-installed.** A human's own profile doing this is their declaration and is
// an accepted residual (TODO.md); snug doing it is a defect.
//
// This is not hypothetical. @claude carried exactly this for a milestone:
//
//	ro    = ["{home}/.local/bin/claude"]      # a read-only bind of ONE file
//	merge PATH = ["{home}/.local/bin"]        # …in a directory that is a WRITABLE tmpfs
//
// The bind was sound; the directory it lived in was not, and `sanitise` cannot
// reach it — that filter only ever inspects the HOST's value for a variable a
// profile imported, and a `merge` entry is written in the file. It was found by
// reading, which is why the rule now has a test. The repair was to stage the
// binary in policy.StagedBinDir, which sits on the root tmpfs and is covered by
// --remount-ro / (measured: `touch` and `echo >` both EROFS).
//
// The predicate is policy.IsShadowSlot, which shares coveringMount with the
// sanitise filter so there is one answer to "what is at this path".
func TestNoBuiltinPutsAWritableDirectoryOnPATH(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	names := make([]string, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	sort.Strings(names)

	checked := 0
	for _, name := range names {
		sel := append(append([]string{}, profile.BuiltinDefaults()...), name)
		p, err := policy.Resolve(map[string]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			// A selection this fake host cannot resolve says nothing either
			// way, but it must be VISIBLE: a sweep that silently skipped every
			// profile would pass on a binary with no profiles at all.
			t.Logf("skipped %s: %v", name, err)
			continue
		}
		checked++
		for _, e := range p.Env["PATH"].Entries {
			if p.IsShadowSlot(e.Value) {
				t.Errorf("builtin %s puts %s on PATH, and it is WRITABLE from inside "+
					"(verb %s, from %v).\n"+
					"A writable directory ahead of /usr/bin is a shadow slot: the payload writes "+
					"a file called `git` into it and the next `git` anything in this sandbox runs "+
					"is that file. snug must not hand over an environment with that slot already "+
					"installed.\n"+
					"Stage the executable in %s instead — it is on the root tmpfs, so --remount-ro "+
					"/ makes it unwritable, and snug puts it on PATH itself when anything is "+
					"staged there. See policy.StagedBinDir and @claude in base.toml.",
					name, e.Value, e.Verb, e.From, policy.StagedBinDir)
			}
		}
	}

	// A sweep is only as good as the number of selections it actually resolved.
	if checked < len(names)/2 {
		t.Fatalf("only %d of %d builtins resolved on the fake host; the sweep is not "+
			"covering enough to mean anything", checked, len(names))
	}
}

// The positive control for the test above: the predicate must actually FIRE on
// the arrangement @claude used to have, or "no builtin has a shadow slot" is a
// sentence about a function that always answers false.
func TestShadowSlotPredicateFiresOnAWritableHomeDirectory(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*policy.Profile(reg)

	// @claude's old shape, spelled out: a read-only bind of one file, plus the
	// directory it lives in merged onto PATH. That directory is @home's tmpfs.
	m["shadow"] = &policy.Profile{
		Name:     "shadow",
		Include:  []string{"@sys", "@home"},
		RO:       []string{"/home/u/.local/bin/claude"},
		Optional: []string{"/home/u/.local/bin/claude"},
		Environ: policy.EnvGrants{
			Merge: map[string][]string{"PATH": {"/home/u/.local/bin"}},
		},
	}

	p, err := policy.Resolve(m, append(append([]string{}, profile.BuiltinDefaults()...), "shadow"),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, e := range p.Env["PATH"].Entries {
		if e.Value == "/home/u/.local/bin" {
			found = true
			if !p.IsShadowSlot(e.Value) {
				t.Errorf("IsShadowSlot(%s) = false, but it is inside @home's writable tmpfs; "+
					"the rule above is then being enforced by a predicate that cannot say no",
					e.Value)
			}
		}
	}
	if !found {
		t.Fatal("the fixture profile's PATH entry never reached the policy, so this control " +
			"is not controlling anything")
	}

	// …and the directory snug stages into must NOT trip it, or the rule would
	// forbid its own repair.
	if p.IsShadowSlot(policy.StagedBinDir) {
		t.Errorf("IsShadowSlot(%s) = true; snug's own staged-bin directory must be unwritable "+
			"from inside", policy.StagedBinDir)
	}
	if strings.HasPrefix(policy.StagedBinDir, "/tmp") {
		t.Errorf("StagedBinDir = %s, which is under a writable tmpfs", policy.StagedBinDir)
	}
}
