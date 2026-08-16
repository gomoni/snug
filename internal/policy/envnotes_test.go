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

	// The pointer exemptions, as EXPLICIT rows saying nothing, because "no
	// sentence" is a decision here rather than an omission: authoring a pointer
	// is the mechanism "generate, don't bind" asks for, so a warning at the verb
	// that authors it would be snug arguing with its own rule. A future edit that
	// drops an exemption shows up here as a line gaining text.
	b.WriteString("\n## pointers: no annotation at the verbs that AUTHOR them\n\n")
	for _, p := range inlineConfigPointers {
		for _, verb := range []EnvVerb{VerbSet, VerbInherit} {
			s := strings.TrimSpace(EnvNote(p.name, verb))
			switch {
			case !legal(p.name, verb):
				// GIT_CONFIG_GLOBAL is in SnugOwnedEnv, so ownership refuses it
				// at every verb and its family sentence can never reach a screen.
				// Printing the sentence unqualified would read as a live warning
				// about a name no profile can write; printing nothing would hide
				// that the row is covered by something else entirely.
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
