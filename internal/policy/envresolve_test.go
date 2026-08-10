package policy

import (
	"strings"
	"testing"
)

// entryValues renders one variable's entries in band order, for assertions
// about ORDER rather than about the joined string.
func entryValues(p *Policy, name string) []string {
	var out []string
	for _, e := range p.Env[name].Entries {
		out = append(out, e.Value)
	}
	return out
}

func entryVerbs(p *Policy, name string) []string {
	var out []string
	for _, e := range p.Env[name].Entries {
		out = append(out, e.Verb.String())
	}
	return out
}

// ── bands ────────────────────────────────────────────────────────────────────

// The bands are structural: nothing a profile writes chooses which one its
// entry lands in. This asserts the whole §2.4 diagram in one policy, in order,
// with every band populated — a band nobody exercises is a band the ordering
// tests cannot see.
func TestListBandsResolveInOrder(t *testing.T) {
	sel := []string{"@sys", "@cwd-rw", "firsty", "envy", "cwd-ro", "@podman-socket"}
	p, err := Resolve(testRegistry(), sel, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"/opt/first/bin",                         // prepend
		"/home/u/.local/bin",                     // merge, sorted by value
		"/opt/tools/bin",                         // merge
		PodmanStubDir,                            // snug's own, generated
		"/usr/bin", "/bin", "/usr/sbin", "/sbin", // snug's own, base
	}
	got := entryValues(p, "PATH")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("PATH bands out of order:\n  got  %v\n  want %v", got, want)
	}

	wantVerbs := []string{"prepend", "merge", "merge", "(snug)", "(snug)", "(snug)", "(snug)", "(snug)"}
	if strings.Join(entryVerbs(p, "PATH"), " ") != strings.Join(wantVerbs, " ") {
		t.Errorf("verbs = %v, want %v", entryVerbs(p, "PATH"), wantVerbs)
	}
}

// The sanitise band sits after merge, because a merge is a declaration by a
// profile the human selected and a sanitise is a filtered copy of ambient host
// state. A declaration must beat ambient state, or the host's environment
// arbitrates between two profiles.
func TestSanitiseBandComesAfterMerge(t *testing.T) {
	reg := testRegistry()
	reg["pkg"] = &Profile{Name: "pkg", Environ: EnvGrants{
		Merge: map[string][]string{"PKG_CONFIG_PATH": {"/usr/share/pkgconfig"}},
	}}
	p, err := Resolve(reg, []string{"@sys", "@cwd-rw", "pkg", "sanity"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/share/pkgconfig", "/usr/lib64/pkgconfig"}
	if got := entryValues(p, "PKG_CONFIG_PATH"); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("PKG_CONFIG_PATH = %v, want %v — the profile's own declaration first", got, want)
	}
}

// ── sanitise ─────────────────────────────────────────────────────────────────

// The filter keeps what policy grants, in the HOST's order, and names what it
// dropped rather than counting it.
func TestSanitiseKeepsGrantedElementsInHostOrder(t *testing.T) {
	env := newFakeEnv()
	// Deliberately NOT sorted, and deliberately interleaved with ungranted
	// entries: if survivors were sorted, /usr/lib64 would come before /usr/share
	// and this would fail.
	env.env["PKG_CONFIG_PATH"] = "/usr/share/pkgconfig:/srv/a:/usr/lib64/pkgconfig:/srv/b"

	p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"/usr/share/pkgconfig", "/usr/lib64/pkgconfig"}
	if got := entryValues(p, "PKG_CONFIG_PATH"); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("survivors = %v, want %v in the host's own order — sorting would be a "+
			"second, silent transformation nobody asked for, and §3.3 documents a variable "+
			"where position is semantic", got, want)
	}

	var dropped []string
	for _, d := range p.Env["PKG_CONFIG_PATH"].Dropped {
		dropped = append(dropped, d.Value)
	}
	if strings.Join(dropped, " ") != "/srv/a /srv/b" {
		t.Errorf("dropped = %v, want both ungranted entries NAMED — a filter that silently "+
			"removes two of four elements is the exact shape of failure this model exists "+
			"to avoid, and \"2 of 4 kept\" does not let anyone check it", dropped)
	}
}

// THE §4.3 CASE, and the one place in this whole feature where getting it wrong
// ADDS a hole rather than failing to close one.
//
// When nothing survives the filter, the variable must be UNSET — absent from
// the argv entirely — and never set to the empty string. An empty PATH element
// is the current working directory, which inside snug is the target: the one
// writable thing a hostile payload controls. A feature sold as tightening the
// environment would then let it drop a file named `git` in the project root and
// have it run.
func TestSanitiseToNothingLeavesTheVariableUnset(t *testing.T) {
	env := newFakeEnv()
	env.env["PKG_CONFIG_PATH"] = "/srv/a:/srv/b" // nothing granted

	p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := p.EnvValue("PKG_CONFIG_PATH"); ok {
		t.Errorf("PKG_CONFIG_PATH = %q; nothing survived the filter, so it must be UNSET, "+
			"not set to the empty string", v)
	}
	// And it must not reach the argv at all — an empty --setenv would be worse
	// than useless, and snug never emits --unsetenv either.
	args := p.BwrapFlags(1000, 1000, func(string) int { return 10 })
	for i, a := range args {
		if a == "PKG_CONFIG_PATH" {
			t.Errorf("PKG_CONFIG_PATH reached the argv at %d: %v", i, args[i-1:])
		}
		if a == "--unsetenv" {
			t.Error("--unsetenv is in the argv; after --clearenv there is nothing to unset, " +
				"and a subtraction in the argv is a subtraction in the model")
		}
	}

	// POSITIVE CONTROL: with one granted element the variable IS present, so
	// the assertion above cannot pass on a resolver where sanitise never runs.
	env.env["PKG_CONFIG_PATH"] = "/srv/a:/usr/lib64/pkgconfig"
	q, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := q.EnvValue("PKG_CONFIG_PATH"); !ok || v != "/usr/lib64/pkgconfig" {
		t.Errorf("control: PKG_CONFIG_PATH = %q (present=%v), want /usr/lib64/pkgconfig", v, ok)
	}
}

// An empty element in the HOST's value must never be carried through. This is
// the same hazard from the other side: snug does not write empty elements, and
// it does not pass on the ones it is handed either.
func TestSanitiseNeverCarriesAnEmptyElement(t *testing.T) {
	env := newFakeEnv()
	env.env["PKG_CONFIG_PATH"] = ":/usr/lib64/pkgconfig::/srv/a:"

	p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := p.EnvValue("PKG_CONFIG_PATH")
	if !ok {
		t.Fatal("control: one element was granted, so the variable must be present")
	}
	if v != "/usr/lib64/pkgconfig" {
		t.Errorf("PKG_CONFIG_PATH = %q, want exactly the one granted element", v)
	}
	for _, part := range strings.Split(v, ":") {
		if part == "" {
			t.Errorf("PKG_CONFIG_PATH = %q contains an empty element, which resolves to the "+
				"current directory — inside snug, the target", v)
		}
	}
}

// Unset and empty both mean absent, FOR LISTS. The inverse — a flag scalar
// where empty is a value — is asserted by TestSetButEmptyHostVariableReaches
// TheSandbox, and the two must not be unified into one helper.
func TestSanitiseTreatsUnsetAndEmptyAlike(t *testing.T) {
	for _, host := range []struct {
		name string
		set  bool
	}{{"unset", false}, {"empty", true}} {
		env := newFakeEnv()
		delete(env.env, "PKG_CONFIG_PATH")
		if host.set {
			env.env["PKG_CONFIG_PATH"] = ""
		}
		p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.EnvValue("PKG_CONFIG_PATH"); ok {
			t.Errorf("host %s: the variable reached the sandbox anyway", host.name)
		}
	}
}

// sanitise is a TRUTHFULNESS filter, not a capability filter, and the honest
// scope is narrower than the name. `ro` is enough, no mode bits, no stat — so a
// surviving element may name a bind that is empty. Pinning it here stops anyone
// citing sanitise as a guarantee that a surviving PATH entry contains anything.
func TestSanitiseAcceptsAReadOnlyGrant(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/opt/roonly"] = true
	env.env["PKG_CONFIG_PATH"] = "/opt/roonly/lib/pkgconfig"

	reg := testRegistry()
	reg["ro-opt"] = &Profile{Name: "ro-opt", RO: []string{"/opt/roonly"}}

	p, err := Resolve(reg, []string{"@sys", "@cwd-rw", "ro-opt", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p.EnvValue("PKG_CONFIG_PATH"); v != "/opt/roonly/lib/pkgconfig" {
		t.Errorf("PKG_CONFIG_PATH = %q; a read-only grant is enough to keep an element", v)
	}
}

// ── dedup ────────────────────────────────────────────────────────────────────

// §4.6(c), measured on main: `path = ["/nonexistent/bin", "/bin"]` resolved to
// /bin:/nonexistent/bin:/usr/bin:/bin:/usr/sbin:/sbin — /bin twice, once from
// the profile and once from the base. A duplicated entry means the rendered
// value depends on how many profiles happened to name a directory, which is a
// fold artifact and not a decision anybody made.
func TestDuplicateEntriesCollapseToTheEarliestBand(t *testing.T) {
	p := mustResolve(t, "@sys", "@cwd-rw", "dupe-path")

	path, _ := p.EnvValue("PATH")
	if n := strings.Count(":"+path+":", ":/usr/bin:"); n != 1 {
		t.Errorf("PATH = %q contains /usr/bin %d times, want exactly 1", path, n)
	}
	// And the survivor is the PROFILE's entry, not the base's: the earliest
	// band wins, which is what makes prepend's guarantee literally true.
	if got := p.Env["PATH"].Entries[0]; got.Value != "/usr/bin" || got.Verb != VerbMerge {
		t.Errorf("first entry = %+v, want /usr/bin from the merge band", got)
	}
	// CONTROL: the rest of the base survives, so the assertion above is not
	// passing because dedup ate everything.
	for _, want := range []string{"/bin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(":"+path+":", ":"+want+":") {
			t.Errorf("PATH = %q lost the base entry %q", path, want)
		}
	}
}

// ── conflicts ────────────────────────────────────────────────────────────────

func TestSecondPrependIsRefused(t *testing.T) {
	err := refusalTwoPrepends(t)
	if err == nil {
		t.Fatal("two profiles both took the front of PATH; only one may hold it")
	}
	for _, want := range []string{"mytools", "othertools", "/opt/bin", "/srv/bin", "environ.merge"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: identical claims AGREE. Two profiles naming the same
	// directory do not disagree about who is first, and the resolved policy is
	// byte-identical either way — refusing that would refuse a non-conflict.
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Environ: EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/bin"}}}}
	reg["b"] = &Profile{Name: "b", Environ: EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/bin"}}}}
	p, err := Resolve(reg, []string{"@sys", "@cwd-rw", "a", "b"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: two profiles prepending the SAME value must agree: %v", err)
	}
	if got := p.Env["PATH"].Entries[0]; got.Value != "/opt/bin" || strings.Join(got.From, "+") != "a+b" {
		t.Errorf("agreeing prepends = %+v, want one entry credited to both profiles", got)
	}
}

// Equality is over the WHOLE ORDERED SEQUENCE, so two profiles naming the same
// directories in different orders still disagree about order and still fail.
func TestPrependOrderDisagreementIsRefused(t *testing.T) {
	err := refusalPrependOrder(t)
	if err == nil {
		t.Fatal("two profiles prepending the same directories in different orders were " +
			"silently resolved; the whole point of prepend is which one is first")
	}
	for _, want := range []string{"ordera", "orderb"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestConflictingScalarSetsAreRefused(t *testing.T) {
	err := refusalTwoSets(t)
	if err == nil {
		t.Fatal("two profiles set one scalar to different values and one of them was " +
			"silently discarded")
	}
	for _, want := range []string{"seta", "setb", "vim", "emacs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: the same value from two profiles is fine.
	// Independently-authored duplication is plausible and harmless.
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Environ: EnvGrants{Set: map[string]string{"MY_MODE": "fast"}}}
	reg["b"] = &Profile{Name: "b", Environ: EnvGrants{Set: map[string]string{"MY_MODE": "fast"}}}
	if _, err := Resolve(reg, []string{"@sys", "@cwd-rw", "a", "b"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: two profiles agreeing on a scalar must join, not conflict: %v", err)
	}
}

// CALL 2: `set` and `inherit` on one scalar name are one slot, not two.
// "set beats inherit" would be a priority field wearing a verb's clothes, which
// the model does not have — so they join the rule `set` already follows.
func TestSetAndInheritOnOneScalarMustAgree(t *testing.T) {
	err := refusalSetVsInherit(t)
	if err == nil {
		t.Fatal("a profile's `set` and another's `inherit` disagreed about one scalar and " +
			"snug picked one; there is no priority between verbs")
	}
	for _, want := range []string{"emacsy", "envy", "environ.set", "environ.inherit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: agreeing claims resolve, and BOTH profiles are credited
	// — `setty` sets EDITOR=vim, `envy` inherits the fake host's EDITOR=vim.
	p := mustResolve(t, "@sys", "@cwd-rw", "setty", "envy")
	if v, _ := p.EnvValue("EDITOR"); v != "vim" {
		t.Errorf("EDITOR = %q, want vim", v)
	}
	if got := entryVerbs(p, "EDITOR"); strings.Join(got, " ") != "set inherit" {
		t.Errorf("EDITOR entries = %v, want both claims recorded — a human reading "+
			"--dry-run should see that two profiles asked for this", got)
	}

	// And an inherit of a name the host does not have contributes nothing, so it
	// can never take part in a conflict.
	env := newFakeEnv()
	delete(env.env, "EDITOR")
	reg := testRegistry()
	reg["emacsy"] = &Profile{Name: "emacsy", Environ: EnvGrants{Set: map[string]string{"EDITOR": "emacs"}}}
	q, err := Resolve(reg, []string{"@sys", "@cwd-rw", "emacsy", "envy"}, testCtx(), env)
	if err != nil {
		t.Fatalf("an inherit of a name the host does not have must contribute nothing, not "+
			"conflict: %v", err)
	}
	if v, _ := q.EnvValue("EDITOR"); v != "emacs" {
		t.Errorf("EDITOR = %q, want emacs", v)
	}
}

// ── monotonicity, both halves ────────────────────────────────────────────────

// The ENTRY SET of a list variable is monotone: adding a profile can only add
// entries. sanitise's predicate is "is this path granted", and grants only ever
// grow, so adding a profile can only make MORE host elements survive.
func TestEnvIsMonotoneAsASet(t *testing.T) {
	base := []string{"@sys", "@cwd-rw"}
	basePol := mustResolve(t, base...)

	for name := range testRegistry() {
		with, err := Resolve(testRegistry(), append(append([]string{}, base...), name), testCtx(), newFakeEnv())
		if err != nil {
			continue // a conflict is a symmetric error, not a tightening
		}
		for varName, was := range basePol.Env {
			now, ok := with.Env[varName]
			if !ok {
				t.Errorf("adding %q REMOVED the variable %s entirely", name, varName)
				continue
			}
			have := map[string]bool{}
			for _, e := range now.Entries {
				have[e.Value] = true
			}
			for _, e := range was.Entries {
				// snug's OWN entries are exempt, and the exemption is the same
				// one Mount.Authored carries: SNUG_PROFILES legitimately changes
				// when a profile is added, because reporting the selection is
				// its entire job. What must only ever grow is what PROFILES
				// contributed.
				if e.Verb == VerbSnug {
					continue
				}
				if !have[e.Value] {
					t.Errorf("adding %q REMOVED the %s entry %q — the entry set must only grow",
						name, varName, e.Value)
				}
			}
		}
	}
}

// ...and the ORDER is not monotone, which is the half the test above must not
// be read as covering.
//
// A prepend pushes another profile's merged entry one place later. That is a
// tightening of precedence rather than an escalation — the same shape CLAUDE.md
// already carves out for mount depth — but it has to be said out loud, and this
// test is where it is said.
func TestPrependReordersWithoutRemoving(t *testing.T) {
	without := mustResolve(t, "@sys", "@cwd-rw", "envy")
	with := mustResolve(t, "@sys", "@cwd-rw", "envy", "firsty")

	if entryValues(without, "PATH")[0] != "/opt/tools/bin" {
		t.Fatalf("control: without the prepend, envy's merged entry is first: %v",
			entryValues(without, "PATH"))
	}
	got := entryValues(with, "PATH")
	if got[0] != "/opt/first/bin" {
		t.Errorf("PATH = %v, want the prepended entry first", got)
	}
	// The demoted entry is still THERE — that is the monotone half.
	found := false
	for _, v := range got {
		if v == "/opt/tools/bin" {
			found = true
		}
	}
	if !found {
		t.Error("adding a prepend removed another profile's entry; only its POSITION may move")
	}
}
