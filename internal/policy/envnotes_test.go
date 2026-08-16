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
}
