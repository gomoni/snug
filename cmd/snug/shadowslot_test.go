package main

import (
	"slices"
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
// an accepted residual; snug doing it is a defect.
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
	m := map[policy.ProfileName]*policy.Profile(reg)

	// @claude's old shape, spelled out: a read-only bind of one file, plus the
	// directory it lives in merged onto PATH. That directory is @home's tmpfs.
	m["shadow"] = &policy.Profile{
		Name:     "shadow",
		Include:  []policy.ProfileName{"@sys", "@home"},
		RO:       []string{"/home/u/.local/bin/claude"},
		Optional: []string{"/home/u/.local/bin/claude"},
		Environ: policy.EnvGrants{
			Merge: map[string][]string{"PATH": {"/home/u/.local/bin"}},
		},
	}

	p, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "shadow"),
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
	//
	// Read what this measures, because the earlier version of these three lines
	// measured something else. Nothing is mounted at StagedBinDir — it is a plain
	// directory on the root tmpfs, made with bwrap's `--dir` — so coveringMount
	// finds nothing and IsShadowSlot answers false through its "nothing is there"
	// branch. That is the RIGHT answer for the right reason (an uncovered path is
	// the root tmpfs, and --remount-ro / covers that), but it is the answer this
	// assertion would give for ANY path in the policy, which made it unfalsifiable
	// at the one path it names. The control below is what makes it mean something.
	if p.IsShadowSlot(policy.StagedBinDir) {
		t.Errorf("IsShadowSlot(%s) = true; snug's own staged-bin directory must be unwritable "+
			"from inside", policy.StagedBinDir)
	}
	if strings.HasPrefix(policy.StagedBinDir, "/tmp") {
		t.Errorf("StagedBinDir = %s, which is under a writable tmpfs", policy.StagedBinDir)
	}

	// The control: mount a tmpfs at StagedBinDir and the predicate must say yes.
	// This is the arrangement a profile could once write — `tmpfs =
	// ["/run/snug/bin"]` plus one staged bind, measured as WROTE-OK with the
	// shadowed git running — and Validate refuses it now (snugsOwn), which is why
	// it has to be constructed here rather than resolved.
	p.Mounts[policy.StagedBinDir] = policy.Mount{
		Guest: policy.StagedBinDir, Kind: policy.KindTmpfs,
		Access: policy.AccessRW, From: []string{"control"},
	}
	if !p.IsShadowSlot(policy.StagedBinDir) {
		t.Errorf("IsShadowSlot(%s) = false with a writable tmpfs mounted there. The assertion "+
			"above is then vacuous, and so is the one in TestWritableMarkIsPathOnly...: both "+
			"would keep passing on a policy that hands the payload a writable directory first "+
			"on PATH", policy.StagedBinDir)
	}
}

// A profile may not mount anything AT policy.StagedBinDir, and this is the
// regression test for the finding that made it a rule.
//
// The route was indirect, which is why nothing caught it. The profile writes no
// PATH declaration at all: it mounts a tmpfs at /run/snug/bin and stages one
// file inside, HasStagedBin sees the staged file, and SNUG then puts the
// directory first on PATH in its own `(snug)` provenance. Measured before the
// fix: `echo > /run/snug/bin/git` succeeded and the shadowed git ran. The rw-bind
// spelling was worse — the shadowed command persisted to the host directory.
//
// That is the case CLAUDE.md's staging rule says cannot happen ("a profile
// cannot pick a writable directory by accident, because it does not pick one at
// all"), and it is not the accepted-residual class either, because no human ever
// read a line saying a writable directory would go on PATH.
func TestProfileMayNotMountAtStagedBinDir(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		prof *policy.Profile
		want bool // want a refusal
	}{
		{"tmpfs at the directory", &policy.Profile{
			Name: "p", Include: []policy.ProfileName{"@sys", "@home"},
			Tmpfs: []string{policy.StagedBinDir},
			RO:    []string{"/etc/passwd:" + policy.StagedBinDir + "/tool"},
		}, true},
		{"rw bind of the directory", &policy.Profile{
			Name: "p", Include: []policy.ProfileName{"@sys", "@home"},
			RW: []string{"/usr:" + policy.StagedBinDir},
		}, true},
		{"ro bind of the directory", &policy.Profile{
			Name: "p", Include: []policy.ProfileName{"@sys", "@home"},
			RO: []string{"/usr:" + policy.StagedBinDir},
		}, true},
		// The positive control, and the reason the rule is keyed on the EXACT
		// guest path: staging one executable INSIDE the directory is what the
		// directory is for, and @claude does it on every run.
		{"a file staged inside — the legitimate shape", &policy.Profile{
			Name: "p", Include: []policy.ProfileName{"@sys", "@home"},
			RO: []string{"/etc/passwd:" + policy.StagedBinDir + "/tool"},
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[policy.ProfileName]*policy.Profile(reg)
			m["p"] = tc.prof
			_, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "p"),
				envGoldenCtx(), newEnvFakeEnv())
			switch {
			case tc.want && err == nil:
				t.Errorf("Resolve accepted a profile grant at %s. snug puts that directory "+
					"FIRST on PATH, and a mount there is not covered by --remount-ro /, so "+
					"the payload gets a writable directory ahead of /usr/bin without any "+
					"profile ever naming PATH", policy.StagedBinDir)
			case tc.want && !strings.Contains(err.Error(), policy.StagedBinDir):
				t.Errorf("refused, but the message does not name %s: %v", policy.StagedBinDir, err)
			case !tc.want && err != nil:
				t.Errorf("Resolve refused the legitimate shape — one executable staged INSIDE "+
					"%s, which is what the directory exists for and what @claude does: %v",
					policy.StagedBinDir, err)
			}
		})
	}
}
