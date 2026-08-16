package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestGoldenEnvAnnotations pins the EXACT text of every annotation snug renders,
// at every verb, and it is the review artifact for this table the way
// refusals.txt is for the resolver's refusals and the .bwrap.txt files are for
// the argv.
//
// IT EXISTS BECAUSE THE REFUSALS BECAME SENTENCES. While these names were
// refused, the review artifact was refusals.txt: a change to the boundary showed
// up as a changed refusal, and a human read it. Now the boundary moved into the
// thing a human READS, so the sentence IS the artifact — and a sentence with no
// golden is prose that drifts silently away from the measurement it was written
// from. Five refusal rows left refusals.txt in the same commit this file
// appeared; that is not a net loss of assertions only because this file exists.
//
// Regenerate with `go test ./internal/policy -update`, then READ the diff. Ask
// of every changed line the question the sentence exists to answer: what does
// the tool DO with this value, and would a human deciding whether to trust this
// sandbox act differently having read it?
func TestGoldenEnvAnnotations(t *testing.T) {
	verbs := []EnvVerb{VerbSet, VerbMerge, VerbPrepend, VerbInherit, VerbSanitise}

	// ONLY PAIRS A PROFILE CAN ACTUALLY WRITE are listed, and that filter is the
	// difference between an artifact and a dump. EDITOR is a scalar, so
	// `environ.merge EDITOR` is refused on TYPE grounds and its annotation can
	// never reach a screen; printing it would pad this file with 200 lines
	// nobody can act on and would hide the pairs that matter. What the filter
	// leaves is exactly the set of things a human may write and the sentence they
	// get for writing it — which is also why a line VANISHING from this file is
	// worth reading: it means a type rule started refusing a verb it used to
	// allow.
	legal := func(name string, verb EnvVerb) bool {
		var g EnvGrants
		switch verb {
		case VerbSet:
			g = EnvGrants{Set: map[string]string{name: "/opt/x"}}
		case VerbMerge:
			g = EnvGrants{Merge: map[string][]string{name: {"/opt/x"}}}
		case VerbPrepend:
			g = EnvGrants{Prepend: map[string][]string{name: {"/opt/x"}}}
		case VerbInherit:
			g = EnvGrants{Inherit: []string{name}}
		case VerbSanitise:
			g = EnvGrants{Sanitise: []string{name}}
		}
		return ValidateEnvGrants(g) == nil
	}

	var b strings.Builder
	b.WriteString("# Environment annotations — every (name, verb) pair snug has something to say\n")
	b.WriteString("# about, and the exact text it says. Regenerate with:\n")
	b.WriteString("#   go test ./internal/policy -update\n")
	b.WriteString("#\n")
	b.WriteString("# NONE OF THESE IS A REFUSAL. Every pair below is ACCEPTED — a profile's author\n")
	b.WriteString("# is a human on the trusted side of snug's boundary, and snug has only\n")
	b.WriteString("# allowlists. What the table buys is that the row says what the tool will DO,\n")
	b.WriteString("# on --dry-run and on `snug profile show`. A name missing from this file hands\n")
	b.WriteString("# over its value with nothing said about it.\n")
	b.WriteString("#\n")
	b.WriteString("# Only pairs a profile can actually WRITE are listed: a verb the variable's\n")
	b.WriteString("# TYPE refuses (environ.merge on a scalar, environ.sanitise on MANPATH) can\n")
	b.WriteString("# never reach a screen, and a type refusal is snug declining an operation\n")
	b.WriteString("# rather than denying anyone anything. See internal/policy/testdata/\n")
	b.WriteString("# refusals.txt for those.\n\n")

	b.WriteString("## exact names\n\n")
	names := make([]string, 0, len(envNotes))
	for k := range envNotes {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, verb := range verbs {
			if s := EnvNote(name, verb); s != "" && legal(name, verb) {
				fmt.Fprintf(&b, "%-24s %-9s %s\n", name, verb, strings.TrimSpace(s))
			}
		}
	}

	// The prefix half, driven through a PROBE name rather than through the table
	// directly: what a reader sees is the rendered sentence for a concrete name,
	// including the canonical prefix label noteFor prepends, and that label is
	// the half a table dump would not show. The folded spellings are here for
	// npm_config_ because the canonical label must be identical for all three.
	b.WriteString("\n## prefixes, rendered for one name under each\n\n")
	probes := []string{
		"LD_TRACE_LOADED_OBJECTS",
		"BASH_FUNC_build",
		"GIT_CONFIG_KEY_0",
		"PIP_INDEX_URL",
		"CARGO_BUILD_RUSTC_WRAPPER",
		"npm_config_script_shell",
		"NPM_CONFIG_SCRIPT_SHELL",
		"Npm_Config_Script_Shell",
	}
	for _, name := range probes {
		for _, verb := range verbs {
			if s := EnvNote(name, verb); s != "" && legal(name, verb) {
				fmt.Fprintf(&b, "%-28s %-9s %s\n", name, verb, strings.TrimSpace(s))
			}
		}
	}

	// THE POINTERS, and this section is the review artifact for the whole
	// distinction. A pointer is exempt from its FAMILY's sentence — authoring one
	// is the mechanism "generate, don't bind" asks for, and warning about it with
	// the family's wording at the verb that authors it would be snug arguing with
	// its own rule (that was the PIP_ defect). It is NOT exempt from saying what
	// the file it names IS.
	//
	// For a milestone "exempt" meant "silent", and these rows read "(nothing)" at
	// `set`. Measured: a profile aiming all five inside `rw = ["{target}"]` — the
	// one directory a hostile payload writes — rendered no mark on four of five,
	// with each one config file from exec as the sandbox's uid. So a `(nothing)`
	// appearing here again is a REGRESSION, not a tidy-up, and the two shapes
	// this section must show are: a sentence at `set` that does NOT carry a
	// `PREFIX*:` label, and the family sentence (or the exact `host` one) at
	// `inherit`.
	b.WriteString("\n## pointers: the FAMILY sentence is suppressed; an authored one says what the file IS\n\n")
	for _, p := range inlineConfigPointers {
		for _, verb := range []EnvVerb{VerbSet, VerbInherit} {
			s := strings.TrimSpace(EnvNote(p.name, verb))
			switch {
			case !legal(p.name, verb):
				// GIT_CONFIG_GLOBAL and GH_CONFIG_DIR are in SnugOwnedEnv, so
				// ownership refuses them at every verb and no sentence about them
				// can reach a screen. Printing one unqualified would read as a
				// live warning about a name no profile can write; printing nothing
				// would hide that the row is covered by something else entirely.
				s = "(no profile may write this name — ownership, or its type)"
			case s == "":
				s = "(nothing)"
			}
			fmt.Fprintf(&b, "%-24s %-9s %s\n", p.name, verb, s)
		}
	}

	// WHAT THE VALUE IS, for every name snug holds any fact about — the review
	// artifact for round 3's finding, and the only defence against the one thing
	// the shape sweep cannot check.
	//
	// TestEveryAnnotationSaysWhatItsValueIS makes a new row ANSWER the question;
	// nothing can make it answer TRUTHFULLY. GIT_TEMPLATE_DIR written down as
	// `opaque` would compile, pass every test, and hand over a relative value
	// again. So the classification is rendered per name, beside the two tables it
	// has to agree with, and a wrong one is a line in a diff a human reads rather
	// than an absence nobody can see.
	//
	// Read the `relative` column as the security-relevant output: it is
	// valueIsAPath, the predicate itself, not a restatement of the shape column —
	// a name can reach REFUSED through the roster or through the pointer table
	// with no annotation at all, and GIT_CONFIG_GLOBAL/GH_CONFIG_DIR do.
	b.WriteString("\n## what the VALUE is, and therefore whether a relative one is refused\n")
	b.WriteString("#\n")
	b.WriteString("# shape:    the annotation's own column (path / program / opaque), '-' for a\n")
	b.WriteString("#           name with no annotation.\n")
	b.WriteString("# roster:   what envTypes says, which is what the grant-COUPLING rule reads.\n")
	b.WriteString("# relative: valueIsAPath — REFUSED means `environ.set NAME = \"x\"` cannot be\n")
	b.WriteString("#           written, because a relative path means whatever is in the directory\n")
	b.WriteString("#           the payload was last in, which inside snug is --chdir <target>.\n\n")
	facts := map[string]bool{}
	for k := range envNotes {
		facts[k] = true
	}
	for k := range envTypes {
		facts[k] = true
	}
	for _, p := range inlineConfigPointers {
		facts[p.name] = true
	}
	factNames := make([]string, 0, len(facts))
	for k := range facts {
		factNames = append(factNames, k)
	}
	sort.Strings(factNames)
	for _, name := range factNames {
		shape := "-"
		if n, ok := noteExact(name); ok {
			shape = n.shape.String()
		}
		roster := "(no row)"
		if ty, ok := typeOf(name); ok {
			switch {
			case ty.path:
				roster = "path"
			case ty.pathNoGrant:
				roster = "pathNoGrant"
			default:
				roster = "-"
			}
		}
		rel := "accepted"
		if valueIsAPath(name) {
			rel = "REFUSED"
		}
		fmt.Fprintf(&b, "%-24s %-9s %-12s %s\n", name, shape, roster, rel)
	}

	got := b.String()
	path := filepath.Join("testdata", "annotations.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/policy -update)", err)
	}
	if got != string(want) {
		t.Errorf("annotation text changed — this is a change to what a human is told about the "+
			"sandbox they are about to trust.\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// Every name in the annotation table must actually SAY something, at some verb.
//
// An envNote with both fields empty is a row that exists, passes review as a row,
// and renders nothing — the exact shape of "a rule written once and applied to
// one of its two halves" this file's history keeps recording, met at the level of
// a table entry. It cannot be caught by the golden above, because a silent row
// simply produces no line there and no line is what a missing name looks like too.
func TestEveryAnnotatedNameSaysSomething(t *testing.T) {
	for name, n := range envNotes {
		if n.authored == "" && n.host == "" {
			t.Errorf("envNotes[%q] carries no sentence at either verb class. A row that renders "+
				"nothing is worse than no row: it reads, in review, as a name snug has considered",
				name)
		}
	}
	for _, p := range envNotePrefixes {
		if p.note.authored == "" && p.note.host == "" {
			t.Errorf("envNotePrefixes %q carries no sentence at either verb class", p.prefix)
		}
	}
}

// EVERY ANNOTATION MUST SAY WHAT ITS VALUE IS, not only what the tool does with
// it — and this test is the whole mechanism by which round 3's finding cannot
// recur under a name nobody has thought of yet.
//
// The finding was not "four git names were missed". It was that snug HELD the
// fact — "the hooks in this directory", "git finds its own subcommands here" —
// printed it on --dry-run, and then decided the absolute-path refusal from two
// tables that had never heard of those names. A fix that added the four names to
// something would be the fifth table in a file whose recorded failure mode is
// one fact in two tables drifting apart.
//
// So the fact went into a COLUMN of the table that already holds the sentence,
// with no valid zero value. A new row cannot be written without answering "what
// does a RELATIVE value mean here", because `envNote{authored: …, host: …}`
// leaves shapeUnset and fails right here. That is the property the round asked
// for: the test fails for a FUTURE annotated code-path name, not for today's
// four.
//
// WHAT IT DOES NOT ASSERT, said so nobody reads it as more: nothing checks that
// a row's shape is TRUE. GIT_DIR written down as shapeOpaque would pass. The
// defence against that is the same one the sentences have — every classification
// is rendered per name in testdata/annotations.txt, so a wrong one is a line in
// the review artifact rather than an absence.
func TestEveryAnnotationSaysWhatItsValueIS(t *testing.T) {
	for name, n := range envNotes {
		switch n.shape {
		case shapePath, shapeProgram, shapeOpaque:
		case shapeUnset:
			t.Errorf("envNotes[%q] has no valueShape. snug is about to tell a human what a tool "+
				"DOES with this value, so it must also say what the value IS: shapePath if a "+
				"relative one would be resolved against the payload's cwd (and is therefore "+
				"refused), shapeProgram if the consumer looks it up the way a shell does, "+
				"shapeOpaque if it is not a path at all. GIT_TEMPLATE_DIR and GIT_EXEC_PATH "+
				"were both measured running attacker code out of a relative value while this "+
				"column did not exist", name)
		case shapeFamily:
			t.Errorf("envNotes[%q] is shapeFamily, which is envNotePrefixes' value: it means "+
				"\"the shape differs name by name and this row cannot say\". An EXACT row is "+
				"about one name and must answer for it", name)
		}
	}
	// The prefix table answers the OTHER way, and must: GIT_CONFIG_GLOBAL is a
	// path and GIT_CONFIG_KEY_0 is a setting, both under one prefix. A family that
	// claimed a shape would be read by valueIsAPath as a fact about every name
	// matching it — which is why valueIsAPath reads noteExact and never noteFor.
	for _, p := range envNotePrefixes {
		if p.note.shape != shapeFamily {
			t.Errorf("envNotePrefixes[%q] claims a per-name shape. A prefix names an unbounded "+
				"family whose members do not share one — say shapeFamily and let each name "+
				"answer for itself", p.prefix)
		}
	}
}

// The roster and the annotation must not disagree about what a value IS.
//
// They are two tables holding one fact for the names that appear in both, which
// is the shape this file has recorded three times over case rules. valueIsAPath
// takes the UNION, so a disagreement does not open a hole — it produces
// something worse to review: a row that says "opaque" in one table and is
// refused as a path by the other, with no way to tell which one a reader should
// believe.
//
// The direction that matters is `path`/`pathNoGrant` on the roster versus
// shapePath here. A name the roster calls path-valued and the annotation calls
// opaque is the drift; a name with no roster row is outside this test, because
// the annotation is then the ONLY table that holds the fact — which is exactly
// the case round 3 was about.
func TestTheRosterAndTheAnnotationAgreeAboutTheValueShape(t *testing.T) {
	both := 0
	for name, n := range envNotes {
		ty, rostered := typeOf(name)
		if !rostered {
			continue
		}
		both++
		rosterSaysPath := ty.path || ty.pathNoGrant
		if rosterSaysPath && n.shape != shapePath {
			t.Errorf("%s: the roster calls it path-valued, the annotation calls it %v. One of "+
				"the two is wrong and a reader cannot tell which", name, n.shape)
		}
		if !rosterSaysPath && n.shape == shapePath {
			t.Errorf("%s: the annotation calls it shapePath, the roster does not. If the value "+
				"really is a path, the roster row is the one to fix — it also switches on the "+
				"grant-coupling rule, which shapePath deliberately does not", name)
		}
	}
	if both < 20 {
		t.Fatalf("only %d names are in both tables; this test is measuring almost nothing", both)
	}

	// A POINTER is a path by definition (inlineConfigPointer's own doc), so any
	// pointer carrying an annotation must say so. The two that carry none are
	// snug's own (SnugOwnedEnv), and valueIsAPath keeps its namesAPointerFile
	// clause precisely so that fact does not depend on someone writing a sentence.
	for _, p := range inlineConfigPointers {
		n, ok := noteExact(p.name)
		if !ok {
			continue
		}
		if n.shape != shapePath {
			t.Errorf("%s is in inlineConfigPointers — a POINTER is a path to a file snug or a "+
				"profile generated — but its annotation calls it %v", p.name, n.shape)
		}
	}
}

// An annotation is NOT a permission bit, and this is the assertion that keeps it
// from becoming one by accident.
//
// The failure mode is specific and was measured while this change was being
// made: internal/profile's checkBuiltinEnvRoster is written on IsUncheckedEnv,
// and IsUncheckedEnv used to answer from the roster OR the (then forbidden, now
// annotated) exact-name table. Folding the annotation table in there after it
// stopped refusing would have made every annotated name — sixty of them,
// GIT_SSH_COMMAND and RUSTC_WRAPPER included — a name a profile snug SHIPS may
// write, in the same commit that stopped refusing them for everybody else.
// Annotation must not become grant.
func TestAnAnnotationDoesNotMakeANameCheckedForABuiltin(t *testing.T) {
	for _, name := range []string{"GIT_SSH_COMMAND", "RUSTC_WRAPPER", "PS4", "MAKEFLAGS", "LD_AUDIT"} {
		if EnvNote(name, VerbSet) == "" {
			t.Fatalf("fixture: %s is supposed to be annotated; this test measures nothing", name)
		}
		if !IsUncheckedEnv(name, VerbSet) {
			t.Errorf("IsUncheckedEnv(%s, set) = false, but %s has no ROSTER row. The predicate "+
				"must answer from the roster alone: internal/profile's checkBuiltinEnvRoster is "+
				"written on it, so a name that reads as `checked` here is a name a profile snug "+
				"SHIPS may hand to the payload", name, name)
		}
	}
	// The control: a rostered name is checked whether or not it is annotated.
	// EDITOR is both — a roster row (scalar) and a sentence (git runs it) — and
	// @claude inherits it, so if this side broke, every shipped profile would
	// fail at Builtins().
	for _, name := range []string{"EDITOR", "BASH_ENV", "CARGO_HOME"} {
		if IsUncheckedEnv(name, VerbSet) {
			t.Errorf("IsUncheckedEnv(%s, set) = true; it has a roster row, and an annotation "+
				"beside a row must not remove the row", name)
		}
	}
}

// The two exemption sets must be the SAME SET, and this asserts it rather than
// asking for it in a comment.
//
// envNotePrefixes' `exempt` and inlineConfigPointers answer the same question in
// two vocabularies: which names under a tool's prefix are a POINTER at a file
// snug or a profile authored, rather than the setting itself. A name in one and
// not the other is the "one fact, two tables, they drift" defect this file has
// already recorded twice over case rules — and it had genuinely drifted here
// while the note table was a REFUSAL table: PIP_ carried no exempt list at all,
// because `set PIP_CONFIG_FILE` was legal through PIP_'s forbidKind rather than
// through an exemption. The moment the kind stopped refusing, PIP_CONFIG_FILE
// started rendering a warning at the verb that authors it — measured, and the
// reason PIP_ has an exempt list today.
func TestPointerExemptionsAgreeBetweenTheTwoTables(t *testing.T) {
	exempt := map[string]bool{}
	for _, p := range envNotePrefixes {
		for _, e := range p.exempt {
			exempt[e] = true
		}
	}
	pointer := map[string]bool{}
	for _, p := range inlineConfigPointers {
		// A PREFIX-LESS POINTER IS NOT PART OF THIS AGREEMENT, and asserting the
		// reason is what keeps it from becoming one silently. DOCKER_CONFIG and
		// GH_CONFIG_DIR belong to no annotated family, so there is no family
		// sentence for them to be exempt from — but if one of them ever came to
		// match a prefix (a DOCKER_ family, say), it would start rendering that
		// family's wording at the verb that AUTHORS it, which is the defect PIP_
		// already produced once. So: a prefix-less pointer must match no prefix.
		if p.prefix == "" {
			for _, np := range envNotePrefixes {
				if matchesPrefix(p.name, np.prefix) {
					t.Errorf("%s is listed as a pointer with no family, but it matches the "+
						"annotated prefix %q. It now renders that family's sentence at `set` — "+
						"the verb that authors it — so it needs an exempt entry there and a "+
						"prefix here", p.name, np.prefix)
				}
			}
			continue
		}
		pointer[p.name] = true
	}
	for name := range pointer {
		if !exempt[name] {
			t.Errorf("%s is a pointer to inlineConfigPointers but carries its prefix's family "+
				"annotation anyway. Authoring a pointer is the mechanism 'generate, don't bind' "+
				"asks for; warning about it at the verb that authors it makes the mark mean "+
				"nothing, and disagreeing with the other table is how both come to be wrong", name)
		}
	}
	for name := range exempt {
		if !pointer[name] {
			t.Errorf("%s is exempt from its prefix's annotation but IsInlineConfigEnv does not "+
				"call it a pointer. One of the two is wrong about what this name IS", name)
		}
	}
	// The positive control: the sets are non-empty, so a build with both tables
	// emptied would not pass this vacuously.
	if len(exempt) == 0 || len(pointer) == 0 {
		t.Fatal("one of the exemption sets is empty; this test compared nothing")
	}
}

// ── F1: a pointer must say what the file it names IS ─────────────────────────
//
// REGRESSION (redteam, issue #44 follow-up). The pointer exemption was
// justified on the grounds that a pointer "is the mechanism, not the hazard",
// and that "a profile pointing git's system scope at a file IT AUTHORED" is
// what generate-don't-bind asks for. Nothing enforces "it authored": the
// coupling rule only checks that the path is GRANTED, and `rw = ["{target}"]`
// is a grant. So the pointer can be aimed inside the one directory the payload
// owns, and the sentence that would have said what the file does was exempted
// away — measured, four of five names rendering NO mark at all and the fifth
// only `← unchecked`:
//
//	CARGO_HOME/config.toml  [build] rustc-wrapper   -> ran, cargo 1.97.1, uid 1000
//	DOCKER_CONFIG/config.json {"credsStore":"evil"} -> docker-credential-evil ran
//	                                                   on `docker pull`, before the
//	                                                   daemon socket (docker 29.4)
//	GIT_CONFIG_SYSTEM -> [alias] st = "!echo RAN"   -> ran, git 2.55.0
//	GIT_CONFIG_SYSTEM -> core.sshCommand            -> EXECUTED as the transport
//
// The fix is NOT to delete the exemption — re-annotating a pointer with its
// FAMILY's wording at the verb that authors it is the PIP_ defect this branch
// already fixed once. It is that "exempt" means "no family sentence" rather than
// "no sentence".
//
// IT CHECKS ONE VERB, and that was itself a gap: `set` alone. A pointer with an
// `authored` sentence and no `host` one passes here and renders its family's
// sentence at `inherit` — which is what GIT_CONFIG_SYSTEM did, with a sentence
// measured to be FALSE of it. The other verb is
// TestNoPointerEverRendersItsFamilysSentence, below.
func TestEveryPointerSaysWhatTheFileItNamesIs(t *testing.T) {
	// The same predicate the golden above uses: a pair no profile can write can
	// have nothing to say to anybody.
	writable := func(name string) bool {
		return ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "/opt/x"}}) == nil
	}

	checked, owned := 0, 0
	for _, p := range inlineConfigPointers {
		if !writable(p.name) {
			owned++
			continue
		}
		checked++
		note := EnvNote(p.name, VerbSet)
		if note == "" {
			t.Errorf("%s is a pointer a profile may `set`, and the screen says NOTHING about it. "+
				"Measured: aimed inside a granted, payload-writable directory, each of these is "+
				"one config file from exec as the sandbox's own uid. Give it an `authored` "+
				"sentence saying what the file it names IS — not the family's sentence", p.name)
			continue
		}
		// It must NOT be the family sentence: noteFor labels those with the
		// canonical prefix, which is the one thing that tells the two apart.
		if p.prefix != "" && strings.Contains(note, p.prefix+"*:") {
			t.Errorf("%s renders its FAMILY's sentence at `set`: %q. That is snug warning about "+
				"the mechanism it recommends, and it is why the exemption exists", p.name, note)
		}
	}

	// The ownership arm is an assertion, not a skip. GIT_CONFIG_GLOBAL and
	// GH_CONFIG_DIR are in SnugOwnedEnv — snug authors them itself — so no
	// profile reaches them at any verb and they carry no annotation by the rule
	// that snug's own names stay out of that table. If a THIRD pointer ever lands
	// here, someone has either made a writable pointer owned or made an owned one
	// writable, and both are worth stopping to think about.
	if owned != 2 {
		t.Errorf("%d pointers are unwritable by any profile, want 2 (GIT_CONFIG_GLOBAL and "+
			"GH_CONFIG_DIR, both in SnugOwnedEnv). A pointer that quietly stopped being "+
			"writable no longer needs its sentence; one that started being writable needs one", owned)
	}
	// POSITIVE CONTROL: the loop actually examined the pointers rather than
	// finding an empty list.
	if checked < 5 {
		t.Fatalf("only %d writable pointers were checked; this test measures almost nothing", checked)
	}
}

// ── F2 (redteam host round 2): a pointer never renders its FAMILY's sentence ──
//
// TestEveryPointerSaysWhatTheFileItNamesIs checks ONE VERB and one half of the
// property: that `set` says something, and that what it says is not the family's
// wording. The other half was unchecked, and it was false. GIT_CONFIG_SYSTEM
// carried an `authored` sentence and no `host` one, so at `inherit` noteFor fell
// through to the GIT_CONFIG_ family sentence — "git reads this at the
// command-line scope, above the global file, above the repository's own
// .git/config, and above any include". Measured INSIDE a sandbox, that is FALSE
// of this name: it renames git's SYSTEM file, the LOWEST scope, and .git/config
// beat it in the same session while GIT_CONFIG_KEY_0 — the name the family
// sentence WAS measured on — entered at `command line:` as the control.
//
// The mechanism generalises past this name, which is why the assertion is over
// the table: an exact entry with one of its two fields empty does not render
// nothing at that verb, it renders its FAMILY's sentence, and a family sentence
// is by construction a claim about a different name. So a writable pointer needs
// BOTH fields — and the `inherit` half is the one that matters most, because
// taking the host's file is exactly what "generate, don't bind" exists to stop.
func TestNoPointerEverRendersItsFamilysSentence(t *testing.T) {
	verbs := []EnvVerb{VerbSet, VerbMerge, VerbPrepend, VerbInherit, VerbSanitise}

	checked := 0
	for _, p := range inlineConfigPointers {
		// Ownership refuses the two snug writes itself at every verb, so no
		// sentence about them can reach a screen. Same carve-out as the sibling
		// test, which asserts that this arm holds exactly two names.
		if ValidateEnvGrants(EnvGrants{Set: map[string]string{p.name: "/opt/x"}}) != nil {
			continue
		}
		checked++

		n, ok := noteExact(p.name)
		if !ok || n.authored == "" || n.host == "" {
			t.Errorf("%s is a writable pointer with authored=%q host=%q. A pointer needs BOTH: "+
				"an empty field does not render silence at that verb, it falls through to the "+
				"family table and renders a sentence about a DIFFERENT name. GIT_CONFIG_SYSTEM "+
				"is the measured case — it was told it enters at git's command-line scope when "+
				"it is git's system file, the lowest scope there is", p.name, n.authored, n.host)
			continue
		}
		for _, verb := range verbs {
			note := EnvNote(p.name, verb)
			if p.prefix != "" && strings.Contains(note, p.prefix+"*:") {
				t.Errorf("%s renders its family's sentence at %s: %q. That sentence is about the "+
					"family's INLINE spelling (GIT_CONFIG_KEY_n, PIP_INDEX_URL, …); this name "+
					"points at a FILE and needs its own", p.name, verb, note)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d writable pointers were checked; this test measures almost nothing", checked)
	}
	// POSITIVE CONTROL for the detector: the family label really is what a
	// non-exempt name under the same prefix renders, at the same verb. Without
	// this, a change to noteFor's label would make the loop above vacuous.
	if got := EnvNote("GIT_CONFIG_KEY_0", VerbInherit); !strings.Contains(got, "GIT_CONFIG_*:") {
		t.Fatalf("GIT_CONFIG_KEY_0 no longer renders the family label at inherit (%q), so the "+
			"assertion above is looking for a string nothing produces", got)
	}
}

// ── F2: four search paths that yield code execution ──────────────────────────
//
// Each is a ROSTERED list, so a profile snug SHIPS may write it
// (checkBuiltinEnvRoster), and each was silent while its measured sibling
// PYTHONPATH carried a sentence. Measured on this host, with the control:
//
//	XDG_DATA_DIRS  -> bash-completion SOURCES <elem>/bash-completion/completions/<cmd>
//	                  (bash-completion 2.12.0, uid 1000; nothing with it unset)
//	PERL5LIB       -> Text::Abbrev shadowed ahead of the system module (perl 5.44.0)
//	NODE_PATH      -> the module's top-level code ran (node 26.4.0; control:
//	                  MODULE_NOT_FOUND)
//	CLASSPATH      -> documented, not measured: no JVM on this host
func TestEverySearchPathThatExecutesIsAnnotated(t *testing.T) {
	for _, name := range []string{"XDG_DATA_DIRS", "PERL5LIB", "NODE_PATH", "CLASSPATH"} {
		for _, verb := range []EnvVerb{VerbMerge, VerbPrepend, VerbSanitise} {
			if EnvNote(name, verb) == "" {
				t.Errorf("EnvNote(%s, %s) is empty. An element of this list is searched ahead of "+
					"the system directories and what is found there is SOURCED or loaded — "+
					"measured — so a profile contributing one hands over an exec surface with "+
					"nothing said about it", name, verb)
			}
		}
	}
	// NEGATIVE CONTROL, and it is what stops this test being satisfied by
	// annotating every list in the roster. TERMINFO_DIRS and INFOPATH are
	// rostered path lists that were swept in the same pass and deliberately left
	// silent: nothing was measured to execute out of either. If a measurement
	// ever changes that, this line is the one to delete — consciously.
	for _, name := range []string{"TERMINFO_DIRS", "INFOPATH"} {
		if got := EnvNote(name, VerbMerge); got != "" {
			t.Errorf("%s is annotated %q, and nothing measured executes from it. Either a "+
				"measurement exists and belongs in the comment beside the row, or the sentence "+
				"is the kind of noise that teaches a reader to skip marks", name, got)
		}
	}
}

// ── F4: three sentences that did not survive a measurement ───────────────────
//
// All three OVERSTATED, so nothing was reachable through them — and that is
// exactly why they mattered. A reader who checks one sentence in a table of 148
// and finds it wrong has no way to tell which of the other 147 to trust.
//
// This is a named assertion rather than only a golden diff so that a revert to
// the old wording fails by NAME, saying what was measured.
func TestTheFalsifiedAnnotationsStayFalsified(t *testing.T) {
	ps3 := EnvNote("PS3", VerbSet)
	if strings.Contains(ps3, "command substitution on this prompt") {
		t.Errorf("PS3 claims command substitution again: %q. Measured, bash 5.3.15: `select` "+
			"prints PS3 VERBATIM — `[$(echo …)]` and `${PWD}` both came out literally — while "+
			"PS0, PS2 and PS4 substituted in the same run", ps3)
	}
	if !strings.Contains(ps3, "VERBATIM") {
		t.Errorf("PS3 = %q, which no longer says the thing that was measured", ps3)
	}
	// THE CONTROLS, and they are the point: PS0 and PS2 DID substitute in the
	// same run, so a blanket search-and-replace over this block would break them
	// and this test would say so.
	for _, name := range []string{"PS0", "PS2", "PS4"} {
		if !strings.Contains(EnvNote(name, VerbSet), "command substitution") {
			t.Errorf("%s no longer claims command substitution, and it was measured to perform "+
				"it — the PS3 correction must not have been applied to its own controls", name)
		}
	}

	mt := EnvNote("MALLOC_TRACE", VerbSet)
	for _, want := range []string{"mtrace()", "libc_malloc_debug"} {
		if !strings.Contains(mt, want) {
			t.Errorf("MALLOC_TRACE = %q, which does not name %q. Measured, glibc 2.43: "+
				"MALLOC_TRACE has 0 hits in libc.so.6 and 1 in libc_malloc_debug.so.0, and "+
				"/bin/echo wrote no file even under the preload — BOTH preconditions are "+
				"required, and the old sentence claimed the file was 'created by every "+
				"process that runs'", mt, want)
		}
	}

	ha := EnvNote("HOSTALIASES", VerbSet)
	if !strings.Contains(ha, "DOT-FREE") {
		t.Errorf("HOSTALIASES = %q, which does not say the limit that was measured: glibc 2.43 "+
			"rewrote `myhost` and left `example.invalid` alone, and the mapping is name -> "+
			"NAME rather than name -> address", ha)
	}

	// LOCPATH, added by the F4 labelling pass — the fourth sentence not to survive
	// being measured. It claimed "a locale object is code". Measured, glibc 2.43,
	// with two controls: the locale DATA is honoured (/usr/bin/printf '%.2f' 1.5
	// prints 1,50 with LOCPATH set and 1.50 without), and a shared object dropped
	// into the same directory is never loaded — its constructor, which fires
	// reliably under LD_PRELOAD, printed nothing. GCONV_PATH two rows up IS the
	// code one, and keeping the two apart is the whole value of both rows.
	lp := EnvNote("LOCPATH", VerbSet)
	if strings.Contains(lp, "locale object is code") {
		t.Errorf("LOCPATH claims a locale object is code again: %q. glibc mmaps compiled locale "+
			"DATA; nothing in the directory is dlopen'd (measured, glibc 2.43, with the "+
			"control). GCONV_PATH is the row where a module really is loaded", lp)
	}
	if !strings.Contains(lp, "data") {
		t.Errorf("LOCPATH = %q, which no longer says the thing that was measured — that what "+
			"comes out of this directory is data rather than code", lp)
	}
	// The CONTROL for that correction, and it is the row next door: GCONV_PATH
	// must still say the opposite, because a search-and-replace over "is code" in
	// this block would silently take the true claim with the false one.
	if gc := EnvNote("GCONV_PATH", VerbSet); !strings.Contains(gc, "code") {
		t.Errorf("GCONV_PATH = %q, and a module loaded from there IS code — measured, glibc "+
			"2.43: a constructor in the module ran on the first conversion, with the control "+
			"failing to convert at all", gc)
	}

	// CLASSPATH, the third correction of this pass. No CI can run a JVM, so the
	// sentence itself is the artifact and this is the assertion that makes a
	// revert to the overstated wording fail BY NAME rather than only as a golden
	// diff. Measured in a container (temurin 21) with controls: -cp overrides
	// $CLASSPATH entirely, -jar ignores it outright, and a JDK class is not
	// shadowed (loader of Objects=null).
	cp := EnvNote("CLASSPATH", VerbMerge)
	for _, want := range []string{"-cp", "-jar", "not shadowed"} {
		if !strings.Contains(cp, want) {
			t.Errorf("CLASSPATH = %q, which does not carry the qualification %q. Without it the "+
				"row says a class here replaces the real one — true only for an application "+
				"class, only without -cp and without -jar, and never for a platform class. "+
				"NODE_PATH's row already carries the equivalent limit", cp, want)
		}
	}
	if np := EnvNote("NODE_PATH", VerbMerge); !strings.Contains(np, "not shadowed") {
		t.Errorf("NODE_PATH = %q, and it is the row CLASSPATH was corrected to match — core "+
			"modules are not shadowed, measured, node 26.4, with the control", np)
	}
}
