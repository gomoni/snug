package cli

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── issue #44: the roster sweep, and the "unchecked" mark at every sink ─────
//
// The roster (internal/policy/envtypes.go) is what a shipped profile is held
// to: internal/profile's `mark` refuses a builtin that hands over a name the
// screen would mark `← unchecked`, so every name a builtin writes must have a
// row. This file is the regression test that makes the NEXT roster deletion
// fail loudly — a name deleted from envtypes.go while a builtin still inherits
// or sets it — instead of shipping quietly and breaking at runtime the way
// §44's own history (three red-team rounds, each closing names the last one
// missed) shows it otherwise would.
//
// It also covers the other half of the design: an unrostered name a USER
// profile writes has to be VISIBLE, at every sink that renders an environment
// name, not just the one somebody remembered — the same "assert the SET of
// sinks" shape as TestNoSnugScreenEmitsARawControlCharacter in visible_test.go,
// whose own comment records what happens when a fixture only ever drove one of
// them.

// TestEveryBuiltinEnvVarHasARosterRow resolves every shipped profile at once
// (mirroring TestResolvedPolicyAuthorsOnlyOwnedNames's fixture) and asserts
// that nothing in the result reads as "unchecked". `mark` refuses a builtin
// that writes such a name, so an unchecked entry here can only mean a roster
// row was deleted out from under a profile that still relies on it — and this
// sweep runs over the RESOLVED policy rather than over the grant blocks, so it
// also covers a name that reaches the environment by some route mark() does
// not see.
func TestEveryBuiltinEnvVarHasARosterRow(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	var sel []policy.ProfileName
	for name, p := range reg {
		// @net-host wants the host network namespace and @tmp-shared wants a
		// host directory the caller allocates; neither touches the
		// environment and both would make Resolve fail for reasons unrelated
		// to this sweep.
		if p.Network == "host" || name == "@tmp-shared" {
			continue
		}
		sel = append(sel, name)
	}
	slices.Sort(sel)

	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}

	checked := 0
	for name, v := range p.Env {
		for _, e := range v.Entries {
			checked++
			if policy.IsUncheckedEnv(name, e.Verb) {
				t.Errorf("%s (environ.%s, from %v) has no roster row. internal/profile's "+
					"mark refuses a builtin that writes one, so this is either a roster row "+
					"deleted out from under a profile that still writes this name, or "+
					"IsUncheckedEnv itself misreporting a snug-authored entry",
					name, e.Verb, e.From)
			}
		}
	}

	// POSITIVE CONTROL: a sweep over zero entries would pass vacuously. This
	// selection includes @claude, which writes EDITOR/VISUAL/PAGER/NO_COLOR/
	// ANTHROPIC_BASE_URL through `inherit` — all rows this PR added — so the
	// sweep is exercising exactly the roster the flip depends on.
	if checked == 0 {
		t.Fatal("no environment entries were resolved at all; this sweep checked nothing")
	}
}

// leakyEnvRegistry builds a builtin-plus-one-user-profile registry, where the
// user profile sets a name with no roster row. Shared by the two sink tests
// below so both drive the identical fixture.
func leakyEnvRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["leaky"] = &policy.Profile{
		Name:    "leaky",
		Include: []policy.ProfileName{"@sys", "@home", "@cwd-rw"},
		Environ: policy.EnvGrants{
			Set: map[string]string{"MY_TOOL_MODE": "fast"},
		},
	}
	return m
}

// TestDryRunMarksAnUnrosteredNameAsUnchecked drives the real --dry-run
// rendering path (describeEnvironment -> envLines -> policy.IsUncheckedEnv),
// the same function envgolden_test.go's goldens exercise, rather than a
// re-implementation of it.
func TestDryRunMarksAnUnrosteredNameAsUnchecked(t *testing.T) {
	m := leakyEnvRegistry(t)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky", "@claude")
	p, err := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	got := captureFile(t, func(f io.Writer) { describeEnvironment(f, p) })

	// POSITIVE CONTROL: the value actually reached the screen. Without this, a
	// fixture that never resolved the "leaky" profile at all would pass the
	// assertions below on an empty ENVIRONMENT block.
	if !strings.Contains(got, "MY_TOOL_MODE") {
		t.Fatalf("MY_TOOL_MODE never reached the ENVIRONMENT block, so this test measures "+
			"nothing:\n%s", got)
	}
	if !strings.Contains(got, "unchecked: snug has no type for this name") {
		t.Errorf("an unrostered name was not marked unchecked in --dry-run:\n%s", got)
	}

	// NEGATIVE CONTROL: EDITOR is a roster row (@claude inherits it, and the
	// fake host supplies a value for it), so its row must NOT carry the
	// mark. A version of the mark that fired for every user-writable name —
	// rather than only for a genuinely unrostered one — would pass the
	// positive assertion above too.
	//
	// THIS CONTROL WAS ONE COMMIT FROM BEING UNFAILABLE. It used to scan for a
	// LINE containing both "EDITOR" and "unchecked", which was the right
	// question while every mark was concatenated onto its row. Once each mark
	// became its own indented line (dryrun.go's markIndent) no line can contain
	// both, so the loop would have reported "not marked" for every possible
	// build — including one that marked every name in the table. rowFor is what
	// keeps the question askable: the row plus everything indented under it.
	// See rowFor's comment; this is the case it was written for.
	editor := rowFor(t, got, "EDITOR")
	if !strings.Contains(editor, "the value is a command") {
		t.Fatalf("EDITOR's row carries no annotation at all, so the negative control below "+
			"cannot distinguish a working mark from a missing one:\n%s", editor)
	}
	if strings.Contains(editor, "unchecked") {
		t.Errorf("EDITOR, a rostered name, was marked unchecked:\n%s", editor)
	}
}

// ── the unchecked mark JOINS the grant mark, it does not replace it ─────────
//
// REGRESSION (redteam + independent review, 2026-08-15): dryrun.go's envLines
// used to REPLACE grantMark's verdict with the unchecked mark for an
// unrostered name. Measured on the base commit, the identical profile text rendered
// `← not granted` before the roster flip and only `← unchecked` after it — the
// screen LOST the statement that a declared name's value does not resolve to
// anything inside the sandbox. It also inverted the pair between two kinds of
// entry: a ROSTERED code-carrying scalar (`set BASH_ENV = "/var/lib/x"`) kept
// its "not granted" verdict, while the UNROSTERED sibling lost its own. The fix
// concatenates: the unchecked mark first, then whatever grantMark returns.
//
// markJoinRegistry builds one profile that exercises every combination this
// test needs, so all of it is checked against a single --dry-run render:
//   - MY_TOOL_UNGRANTED: unrostered, value is an absolute path nothing grants
//   - MY_TOOL_GRANTED:   unrostered, value IS granted (the fixture $HOME, via @home)
//   - MY_TOOL_MODE:      unrostered, value is not path-shaped at all ("fast")
//   - BASH_ENV:          ROSTERED and ANNOTATED, same ungranted value as
//     MY_TOOL_UNGRANTED. This is the
//     POSITIVE CONTROL: it is what distinguishes "both marks fire correctly"
//     from "the mark string happens to contain both substrings" — a rostered
//     name must show `not granted` with no `unchecked` anywhere on its line, on
//     the SAME value that produces both marks for an unrostered name.
//   - GIT_SSH_COMMAND:   UNROSTERED, ANNOTATED and ungranted: the only row that
//     carries all THREE statements, which is what fixes their order.
//   - PATH:              merged with the fixture $HOME, a writable tmpfs, so the
//     shadow-slot mark fires. PATH has a roster row, so IsUncheckedEnv can never
//     be true for it, and this line asserts the writable mark is not doubled up
//     with an unchecked mark it structurally cannot carry.
func markJoinRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["markjoin"] = &policy.Profile{
		Name:    "markjoin",
		Include: []policy.ProfileName{"@sys", "@home", "@cwd-rw"},
		Environ: policy.EnvGrants{
			Set: map[string]string{
				"MY_TOOL_UNGRANTED": "/var/lib/nowhere",
				"MY_TOOL_GRANTED":   "{home}",
				"MY_TOOL_MODE":      "fast",
				"BASH_ENV":          "/var/lib/nowhere",
				// UNROSTERED, ANNOTATED and UNGRANTED all at once — the only row
				// that exercises all three marks together. It is legal for a
				// user profile to write it (snug has only allowlists), which is
				// precisely why the row has to say three things.
				"GIT_SSH_COMMAND": "/var/lib/nowhere/ssh",
				// A POINTER, aimed at a path this profile's includes grant, so
				// grantMark is silent and the row carries exactly one mark: the
				// `authored` sentence saying what the file it names IS. That is
				// the F1 case — before it, all five pointers rendered NOTHING at
				// the verb that aims them, including when aimed inside the one
				// directory a hostile payload can write. The row must NOT carry
				// the CARGO_* family sentence: authoring a pointer is still the
				// mechanism "generate, don't bind" asks for.
				"CARGO_HOME": "{home}/.cargo",
			},
			Merge: map[string][]string{"PATH": {"{home}"}},
		},
	}
	return m
}

// rowFor returns the whole ENVIRONMENT-block ROW naming want: the data line
// plus every continuation line under it — the marks, their wrapped remainder,
// and any drop lines. Fails the test if the data line is not found exactly once,
// so a typo in the fixture value fails loudly instead of silently comparing
// "" == "".
//
// IT REPLACED lineFor, AND THAT IS NOT A REFACTOR — IT IS THE POINT. While every
// mark was concatenated onto the row, "the line naming X" and "everything snug
// says about X" were the same string. Now that each mark is its own indented
// line (see dryrun.go's markIndent), a line-based helper reads the data line
// alone, and every assertion of the form "this row carries mark M" would have
// gone one of two ways: fail, or — far worse — become UNFAILABLE. The negative
// controls are the unfailable half: `no line contains both "EDITOR" and
// "unchecked"` is trivially true once the two are never on one line, so the
// assertion that EDITOR is NOT marked would have passed on a build that marked
// every name in the table. A test that cannot fail is worse than no test.
//
// A continuation line is any line indented at least 19 columns (a mark sits at
// 21, a drop line and a continuation BAND at 19); the next row starts at column
// 3 with its own name.
func rowFor(t *testing.T, rendered, want string) string {
	t.Helper()
	lines := strings.Split(rendered, "\n")
	var rows []string
	for i, line := range lines {
		if !strings.Contains(line, want) || strings.HasPrefix(line, strings.Repeat(" ", 19)) {
			continue
		}
		row := []string{line}
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(next, strings.Repeat(" ", 19)) {
				break
			}
			row = append(row, next)
		}
		rows = append(rows, strings.Join(row, "\n"))
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one ENVIRONMENT row naming %q, found %d:\n%s",
			want, len(rows), rendered)
	}
	return rows[0]
}

func TestUncheckedMarkJoinsRatherThanReplacesTheGrantMark(t *testing.T) {
	m := markJoinRegistry(t)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "markjoin")
	p, err := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f io.Writer) { describeEnvironment(f, p) })

	// 1. Unrostered name, ungranted absolute-path value: BOTH marks, in order.
	// The order is now LINE order — the marks are separate lines under the row
	// (dryrun.go's markIndent) — and strings.Index over the joined row reads it
	// the same way a human does, top to bottom.
	ungranted := rowFor(t, got, "MY_TOOL_UNGRANTED")
	if !strings.Contains(ungranted, "unchecked") || !strings.Contains(ungranted, "not granted") {
		t.Errorf("unrostered+ungranted row lost one of the two marks:\n%s", ungranted)
	}
	if i, j := strings.Index(ungranted, "unchecked"), strings.Index(ungranted, "not granted"); i < 0 || j < 0 || i > j {
		t.Errorf("want `unchecked` before `not granted` on the unrostered+ungranted row, got:\n%s", ungranted)
	}

	// 2. Unrostered name, GRANTED value: unchecked, and no "not granted" — proves
	// the join is a real rendering of grantMark's actual verdict, not a constant
	// pair of marks that happens to contain both substrings.
	granted := rowFor(t, got, "MY_TOOL_GRANTED")
	if !strings.Contains(granted, "unchecked") {
		t.Errorf("unrostered+granted row lost the unchecked mark:\n%s", granted)
	}
	if strings.Contains(granted, "not granted") {
		t.Errorf("unrostered+granted row wrongly claims not granted:\n%s", granted)
	}

	// 3. Unrostered name, non-path value: unchecked alone.
	mode := rowFor(t, got, "MY_TOOL_MODE")
	if !strings.Contains(mode, "unchecked") {
		t.Errorf("unrostered+non-path line lost the unchecked mark:\n%s", mode)
	}
	if strings.Contains(mode, "not granted") || strings.Contains(mode, "writable") {
		t.Errorf("unrostered+non-path line acquired a grant verdict it cannot have "+
			"(grantMark never judges a value that is not spelled like an absolute path):\n%s", mode)
	}

	// 4. POSITIVE CONTROL: rostered scalar (BASH_ENV), same ungranted value as
	// case 1. Must show `not granted` and NO `unchecked` — this is what proves
	// cases 1-3 are not passing because the mark string is a constant that
	// happens to contain "unchecked" and "not granted" together.
	bashEnv := rowFor(t, got, "BASH_ENV")
	if !strings.Contains(bashEnv, "not granted") {
		t.Errorf("control: rostered BASH_ENV with an ungranted path must show not-granted:\n%s", bashEnv)
	}
	if strings.Contains(bashEnv, "unchecked") {
		t.Errorf("control: rostered BASH_ENV must never carry the unchecked mark:\n%s", bashEnv)
	}
	// …and it carries the THIRD statement, the annotation, beside the grant
	// verdict rather than instead of it. BASH_ENV is the ideal witness: rostered
	// (so no unchecked mark), annotated (bash sources the file), and pointed at a
	// path nothing grants (so grantMark fires). Two marks on one line, and the
	// annotation first.
	if !strings.Contains(bashEnv, "SOURCES this file") {
		t.Errorf("rostered+annotated BASH_ENV lost its annotation; the grant mark must not "+
			"displace it:\n%s", bashEnv)
	}
	if i, j := strings.Index(bashEnv, "SOURCES this file"), strings.Index(bashEnv, "not granted"); i > j {
		t.Errorf("want the annotation before the grant mark on the BASH_ENV line, got:\n%s", bashEnv)
	}

	// 6. ALL THREE AT ONCE, which is the case no single line above covers and the
	// one the ordering rule exists for. GIT_SSH_COMMAND has no roster row
	// (unchecked), has an annotation (git runs it as the transport), and its
	// value is an absolute path nothing grants (not granted). The order is fixed:
	// unchecked, then the annotation, then the grant verdict — widest claim
	// first. Anything that REPLACES rather than appends loses one of the three,
	// which is the defect two independent reviews already found once on this
	// exact line of code.
	three := rowFor(t, got, "GIT_SSH_COMMAND")
	iU := strings.Index(three, "unchecked")
	iN := strings.Index(three, "git runs this as the transport")
	iG := strings.Index(three, "not granted")
	if iU < 0 || iN < 0 || iG < 0 {
		t.Fatalf("the three-statement row lost one of them (unchecked=%d note=%d grant=%d):\n%s",
			iU, iN, iG, three)
	}
	if !(iU < iN && iN < iG) {
		t.Errorf("want unchecked < annotation < grant mark on the three-statement row, got "+
			"%d/%d/%d:\n%s", iU, iN, iG, three)
	}

	// 5. PATH's shadow-slot mark still fires, and is not doubled with an
	// unchecked mark it structurally cannot carry (PATH has a roster row).
	//
	// Anchored on the NAME, not on the mark text. It used to be the other way
	// round — `lineFor(t, got, "writable from inside")` — which was fine while a
	// mark lived on the row it belonged to and is now a lookup that would find a
	// continuation line with no name on it at all. Anchoring on the mark also
	// could not tell WHICH variable carried it, which is the one thing this case
	// is about.
	pathRow := rowFor(t, got, "PATH")
	if !strings.Contains(pathRow, "writable from inside") {
		t.Fatalf("expected the writable-from-inside mark under the PATH row, got:\n%s", pathRow)
	}
	if strings.Contains(pathRow, "unchecked") {
		t.Errorf("PATH is rostered, so IsUncheckedEnv can never fire for it; the writable mark "+
			"must not be joined with one anyway:\n%s", pathRow)
	}
}

// TestProfileShowMarksAnUnrosteredNameAsUnchecked drives showEnviron directly —
// the same entry point TestProfileShowRendersEveryEnvironVerb in config_test.go
// uses — with a grant block carrying both unrostered and rostered names, in two
// different verbs, so the mark can be shown to be selective rather than blanket.
//
// This is the SECOND sink, and it is here because the mark used to live only on
// a block `snug profile show` no longer renders: when `environ.declare` was
// removed, a mark attached to that block would have vanished from this screen
// while --dry-run kept it. Both screens now read the same predicate
// (policy.IsUncheckedEnv) through the same wording.
func TestProfileShowMarksAnUnrosteredNameAsUnchecked(t *testing.T) {
	g := policy.EnvGrants{
		Set:     map[string]string{"MY_TOOL_MODE": "fast", "XDG_DATA_HOME": "{home}/.local/share"},
		Inherit: []string{"EDITOR", "MY_TOOL_TOKEN"},
	}
	got := map[string][]string{}
	showEnviron(g, func(label string, vals []string) {
		if len(vals) > 0 {
			got[label] = vals
		}
	})

	// One line per (label, name) so the assertions below can be made per name
	// rather than per block — a block holds both kinds at once, which is the
	// whole point of the fixture.
	line := func(label, name string) string {
		t.Helper()
		for _, v := range got[label] {
			if strings.HasPrefix(v, name) {
				return v
			}
		}
		t.Fatalf("%s did not render %s at all; got %q", label, name, got[label])
		return ""
	}

	// POSITIVE: an unrostered name carries the mark, at both scalar verbs.
	if v := line("environ.set", "MY_TOOL_MODE"); !strings.Contains(v, "unchecked") {
		t.Errorf("environ.set rendered %q with no unchecked mark", v)
	}
	if v := line("environ.inherit", "MY_TOOL_TOKEN"); !strings.Contains(v, "unchecked") {
		t.Errorf("environ.inherit rendered %q with no unchecked mark", v)
	}

	// NEGATIVE CONTROL, and it is what tells a selective mark apart from a
	// blanket one: a ROSTERED name in each of the same two blocks must NOT
	// carry it. A version of the mark that fired for every profile-written
	// name would pass both assertions above.
	if v := line("environ.set", "XDG_DATA_HOME"); strings.Contains(v, "unchecked") {
		t.Errorf("environ.set marked the rostered XDG_DATA_HOME unchecked: %q", v)
	}
	if v := line("environ.inherit", "EDITOR"); strings.Contains(v, "unchecked") {
		t.Errorf("environ.inherit marked the rostered EDITOR unchecked: %q", v)
	}

	// The value survives the mark: the row still says what it grants.
	if v := line("environ.set", "MY_TOOL_MODE"); !strings.Contains(v, "= fast") {
		t.Errorf("environ.set lost the value while adding the mark: %q", v)
	}
}

// TestBothScreensSpellTheUncheckedMarkIdentically compares the two sinks' output
// against each other rather than against policy.UncheckedEnvNote, which would be
// tautological now that both call it: what is being pinned is that neither sink
// may go back to holding its own copy of the string.
//
// It is written because both DID hold one, and the comment at one of them
// asserted the opposite — "both strings come from internal/policy, so `snug
// profile show` renders the identical text" — which was true of the annotation
// beside it and false of this mark. The wording then diverged from the code
// comment describing it rather than from the other screen, so no comparison
// between the screens could have failed either. The literal below is the third
// party to that comparison and is what makes this a ratchet rather than a
// consistency check between two copies of the same mistake.
func TestBothScreensSpellTheUncheckedMarkIdentically(t *testing.T) {
	const want = "  ← unchecked: snug has no type for this name"

	// The wording is load-bearing and not free to churn: a row for an
	// unrostered-but-annotated name carries this mark AND a sentence about what
	// the tool does with the value, so this half must not read as a denial that
	// the other half exists. "no entry for this name" did, and that is what it
	// replaced. See policy.UncheckedEnvNote.
	if got := policy.UncheckedEnvNote("MY_TOOL_MODE", policy.VerbSet); got != want {
		t.Errorf("policy.UncheckedEnvNote = %q, want %q", got, want)
	}

	var showLine string
	showEnviron(policy.EnvGrants{Set: map[string]string{"MY_TOOL_MODE": "fast"}},
		func(label string, vals []string) {
			for _, v := range vals {
				if strings.HasPrefix(v, "MY_TOOL_MODE") {
					showLine = v
				}
			}
		})
	if showLine == "" {
		t.Fatal("`snug profile show` never rendered MY_TOOL_MODE, so this test measures nothing")
	}
	if !strings.Contains(showLine, want) {
		t.Errorf("`snug profile show` rendered %q, which does not carry %q", showLine, want)
	}

	m := leakyEnvRegistry(t)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky")
	p, err := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	// The whole ROW, not the line naming the variable: --dry-run puts each mark
	// on its own indented line, so a line-based lookup here would compare the
	// data row — which carries no mark at all — against `want` and fail for a
	// reason that has nothing to do with the two screens agreeing. The two
	// screens still agree on the TEXT, which is what this test is about; the
	// geometry differs because one is an aligned table and the other is prose.
	dryRow := rowFor(t, captureFile(t, func(f io.Writer) { describeEnvironment(f, p) }), "MY_TOOL_MODE")
	if !strings.Contains(dryRow, want) {
		t.Errorf("--dry-run rendered %q, which does not carry %q", dryRow, want)
	}
}

// TestProfileShowRendersTheAnnotation is the SECOND sink for the annotation, and
// it exists for the reason this file already records about the unchecked mark: a
// mark added to --dry-run and forgotten on `snug profile show` leaves the two
// screens saying different things about the identical profile text, and this
// screen is the one read BEFORE selecting a profile — the earlier of the two
// decisions.
//
// It also pins the per-verb split at this sink, which is where it is most
// visible: the same name in `environ.set` and in `environ.inherit` must not
// render the same sentence, because the difference between them is where the
// value comes from.
func TestProfileShowRendersTheAnnotation(t *testing.T) {
	got := map[string][]string{}
	showEnviron(policy.EnvGrants{
		Set:     map[string]string{"BASH_ENV": "{home}/init", "XDG_DATA_HOME": "{home}/.local/share"},
		Inherit: []string{"BASH_ENV", "NO_COLOR"},
	}, func(label string, vals []string) {
		if len(vals) > 0 {
			got[label] = vals
		}
	})

	find := func(label, name string) string {
		t.Helper()
		for _, v := range got[label] {
			if strings.HasPrefix(v, name) {
				return v
			}
		}
		t.Fatalf("%s did not render %s at all; got %q", label, name, got[label])
		return ""
	}

	set := find("environ.set", "BASH_ENV")
	inherit := find("environ.inherit", "BASH_ENV")
	if !strings.Contains(set, "SOURCES this file") || !strings.Contains(inherit, "SOURCES this file") {
		t.Errorf("BASH_ENV is annotated on --dry-run and not here:\n  set:     %s\n  inherit: %s\n"+
			"Two screens reading the same predicate is the whole point of policy.EnvNote", set, inherit)
	}
	if !strings.Contains(inherit, "chosen on the host") {
		t.Errorf("environ.inherit BASH_ENV rendered %q, which does not say the file is chosen on "+
			"the HOST. That is the one thing `inherit` adds over `set`, and it is the half the "+
			"old forbidInheritOnly refusal used to carry for free", inherit)
	}
	if strings.Contains(set, "chosen on the host") {
		t.Errorf("environ.set BASH_ENV rendered the inherit sentence (%q); a value written in the "+
			"profile file is not chosen on the host, and a screen that says so is teaching the "+
			"reader to ignore the mark", set)
	}

	// NEGATIVE CONTROLS, both directions. A rostered pointer authored by the
	// profile carries nothing at `set` (authoring it is the recommended
	// mechanism), and a flag that names no program carries nothing at all.
	if v := find("environ.set", "XDG_DATA_HOME"); strings.Contains(v, "←") {
		t.Errorf("environ.set XDG_DATA_HOME is annotated: %q. @home does exactly this on every "+
			"run; a mark here fires on the ordinary case and stops meaning anything", v)
	}
	if v := find("environ.inherit", "NO_COLOR"); strings.Contains(v, "←") {
		t.Errorf("environ.inherit NO_COLOR is annotated: %q. It changes what tools PRINT and "+
			"names no program", v)
	}
}
