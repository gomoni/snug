package profile

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// mark is the one door a profile passes through to become @-marked, and it is
// also where the roster is an ALLOWLIST for a profile snug ships (see mark's own
// doc comment for the argument: "@ means snug ships it" and "a profile snug
// ships writes no name snug has no entry for" are established by the same
// construction). This is a WHITE-BOX test — mark is unexported — because
// Builtins() itself cannot exercise this path: every name in profiles/*.toml has
// a roster row, by construction, so a black-box sweep over Builtins() would find
// nothing to report either way.
//
// This is exactly the shape CLAUDE.md records getting wrong three review rounds
// running for nested bind masking: "the rule and its test were written together,
// against one spelling". The positive control below is what tells "refused
// because the name is not on the roster" apart from "the fixture never loaded at
// all" — an IDENTICAL fixture with only the name changed to a rostered one must
// mark cleanly, prove it published under the sigil, and carry the grant that was
// never in question.
func TestMarkRefusesABuiltinThatWritesAnUnrosteredName(t *testing.T) {
	leaky := Registry{
		"leaky": &policy.Profile{
			Name: "leaky",
			Environ: policy.EnvGrants{
				Set: map[string]string{"MY_TOOL_MODE": "fast"},
			},
		},
	}
	if _, err := mark(leaky); err == nil {
		t.Fatal("mark() accepted a profile writing a name snug's roster has no entry for; a " +
			"profile snug SHIPS may not hand over a name the screen would mark `← unchecked` — " +
			"that mark says a human took responsibility, and there is no human for a " +
			"compiled-in profile")
	} else if !strings.Contains(err.Error(), "MY_TOOL_MODE") {
		t.Errorf("the refusal does not name the variable, which is the thing a "+
			"contributor needs to find in base.toml: %v", err)
	} else if !strings.Contains(err.Error(), "leaky") {
		t.Errorf("the refusal does not name the profile that wrote it: %v", err)
	}

	// The same rule at `inherit`, because a builtin taking an unrostered name
	// from the HOST is the shape @claude actually has, and a rule applied to one
	// of its two halves is this project's most-recorded defect.
	inheriting := Registry{
		"leaky": &policy.Profile{
			Name:    "leaky",
			Environ: policy.EnvGrants{Inherit: []string{"MY_TOOL_TOKEN"}},
		},
	}
	if _, err := mark(inheriting); err == nil {
		t.Error("mark() accepted a builtin that INHERITS an unrostered name; the rule is about " +
			"what a shipped profile hands over, not about which verb it used")
	}

	// POSITIVE CONTROL: change ONLY the name to one the roster carries, keep
	// everything else about the fixture identical (same key, same struct shape,
	// a real environ grant of its own). If this is refused too, the failure
	// above proves nothing about the roster specifically — it could be an
	// unrelated defect in mark() or in the fixture's construction.
	clean := Registry{
		"leaky": &policy.Profile{
			Name:    "leaky",
			Environ: policy.EnvGrants{Set: map[string]string{"EDITOR": "vim"}},
		},
	}
	marked, err := mark(clean)
	if err != nil {
		t.Fatalf("control: an otherwise-identical builtin writing a ROSTERED name was refused: %v", err)
	}
	got, ok := marked[policy.ProfileName("leaky").Marked()]
	if !ok {
		t.Fatalf("control: mark() did not publish %q under its @-marked name; got keys %v",
			"leaky", markedKeys(marked))
	}
	if got.Name != policy.ProfileName("leaky").Marked() {
		t.Errorf("control: the marked profile's own Name field reads %q, want %q",
			got.Name, policy.ProfileName("leaky").Marked())
	}
	if got.Environ.Set["EDITOR"] != "vim" {
		t.Errorf("control: the marked profile lost its own environ.set grant; got %#v", got.Environ)
	}
}

func markedKeys(r Registry) []policy.ProfileName {
	out := make([]policy.ProfileName, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	return out
}

// TestBuiltinsItselfWritesOnlyRosteredNames is the black-box half: the REAL,
// compiled-in profile set (profiles/*.toml) must load through Builtins() without
// tripping the refusal above. It cannot prove the refusal fires — see the
// white-box test — but it does prove nobody has since added a name to a shipped
// profile without adding the roster row that owes the abuse sentence, which
// would otherwise fail this build the moment it happened rather than being
// noticed by review.
func TestBuiltinsItselfWritesOnlyRosteredNames(t *testing.T) {
	if _, err := Builtins(); err != nil {
		t.Fatalf("Builtins() failed: %v", err)
	}
}

// ── the residual the roster rule leaves, pinned as an inventory ──────────────
//
// THE RESIDUAL, stated plainly. Since the second pass over issue #44, snug's
// annotation table refuses nothing: `set GIT_SSH_COMMAND` in a HUMAN's profile
// is legal and annotated. What still keeps that name out of a profile snug SHIPS
// is checkBuiltinEnvRoster — and it holds only because GIT_SSH_COMMAND has no
// ROSTER row, not because anyone decided a builtin may not write it. The day
// someone adds a roster row to an annotated name (to give it a type so a list
// verb works, which is the plausible reason), the builtin gate opens for that
// name silently and the annotation stays exactly as it was.
//
// WHAT WAS CONSIDERED AND REJECTED: extending the rule to "nor a name snug would
// annotate". CHECKED against the real profiles before rejecting it, which is why
// it is rejected — @claude's `[profile.claude.environ.inherit]` carries PAGER
// and ANTHROPIC_BASE_URL, both of which ARE annotated, so a blanket refusal
// fails at Builtins() and takes every snug command down with it. The annotation
// on those two is not a defect to close: it is what issues #35 and #45 asked
// for, and it is what makes a grant like PAGER readable at the point it is
// made rather than refused.
//
// WHAT IS DONE INSTEAD: this inventory. The (name, verb) pairs a shipped profile
// writes that carry an annotation are enumerated here, by hand. Adding one moves
// this list, which puts it in a diff a human reads — the project's stated review
// mechanism for a change to the boundary, the same argument as the golden argv
// files. It is not a gate and does not pretend to be; it is the thing that makes
// opening the gate a conscious act rather than a side effect.
//
// If you are here because this test failed: a builtin now hands the payload a
// variable snug has a warning about. Read the warning. Then either take the
// grant back out of base.toml, or add the pair here with a sentence saying why a
// shipped profile needs it.
func TestAnnotatedEnvPairsAShippedProfileWritesArePinned(t *testing.T) {
	// The inventory. Each entry says why snug ships it, because that is the
	// review the pinning exists to force.
	want := map[string]string{
		// @claude, so that a human behind a gateway or a proxy keeps working
		// inside the sandbox. Names no program; what it redirects is where the
		// agent's own traffic goes.
		"ANTHROPIC_BASE_URL (inherit)": "@claude",
		// @claude, so `git log` pages the way the human expects. It is the
		// only survivor of git's exec class here: EDITOR and VISUAL were
		// withdrawn by issue #530 because no editor exists inside that
		// profile's sandbox, while `command -v less` does — base.toml carries
		// the measurement. A line for either of them belongs in base.toml
		// only with a reason that survives that measurement.
		"PAGER (inherit)": "@claude",
	}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for name, p := range reg {
		sweep := func(n string, verb policy.EnvVerb) {
			if policy.EnvNote(n, verb) == "" {
				return
			}
			key := n + " (" + verb.String() + ")"
			got[key] = true
			if _, ok := want[key]; !ok {
				t.Errorf("builtin %s hands over %s, which snug ANNOTATES:\n    %s\n"+
					"Nothing refuses it — the roster rule only refuses a name with no TYPE, and "+
					"this one has a row. That is the residual this inventory exists to make "+
					"visible: read the sentence, decide whether a profile snug SHIPS should carry "+
					"it, and either remove the grant or add the pair to `want` above with the "+
					"reason.", name, key, strings.TrimSpace(policy.EnvNote(n, verb)))
			}
		}
		for n := range p.Environ.Set {
			sweep(n, policy.VerbSet)
		}
		for n := range p.Environ.Merge {
			sweep(n, policy.VerbMerge)
		}
		for n := range p.Environ.Prepend {
			sweep(n, policy.VerbPrepend)
		}
		for _, n := range p.Environ.Inherit {
			sweep(n, policy.VerbInherit)
		}
		for _, n := range p.Environ.Sanitise {
			sweep(n, policy.VerbSanitise)
		}
	}

	// The other direction, and it is the half that keeps the list honest: a pair
	// listed here that no builtin writes any more is a stale entry, and a stale
	// allowlist entry is a hole waiting for a name to be re-added under it
	// without review.
	for key, why := range want {
		if !got[key] {
			t.Errorf("%s is pinned here (%s) but no builtin writes it any more. Remove the entry: "+
				"an inventory that lists more than reality pre-approves the next grant", key, why)
		}
	}
}

// TestNoBuiltinInheritsAnEditorVariable is issue #530's regression, and it is
// deliberately narrower than the inventory above: that one asks whether a
// shipped grant of an ANNOTATED name has been reviewed, and would go green
// again the moment somebody added `EDITOR (inherit)` back to `want` with a
// sentence. This one asks the question the measurement settled.
//
// git's exec class reaches a sandbox by fallback — GIT_EDITOR -> core.editor ->
// VISUAL -> EDITOR — so `inherit EDITOR` hands git whatever command string the
// host has. MEASURED inside @claude's own sandbox: `command -v vi vim nano`
// finds nothing, `command -v less more` finds /usr/bin/less and /usr/bin/more.
// So the editor half of the class names a program that is not in there and git
// fails identically with the variable and without it, while PAGER names one
// that is. base.toml carries the same measurement beside the grant.
//
// PAGER is asserted PRESENT in the same test rather than in one of its own,
// because "no builtin inherits an editor" is satisfied by a base.toml that
// inherits nothing at all, and a profile that stopped inheriting the whole
// exec class would pass a test that only looked for absence.
//
// `set` is untouched here and must stay that way: a profile that wants an
// editor inside authors a fixed value and binds the program, which is an
// ordinary grant a human reads on --dry-run. What this pins is the HOST's
// value arriving unread.
func TestNoBuiltinInheritsAnEditorVariable(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}

	pagerSeen := false
	for name, p := range reg {
		for _, n := range p.Environ.Inherit {
			switch n {
			case "EDITOR", "VISUAL":
				t.Errorf("builtin %s inherits %s. That is the host's own command string "+
					"reaching git inside the sandbox through GIT_EDITOR -> core.editor -> "+
					"VISUAL -> EDITOR, and issue #530 withdrew it on a measurement: no "+
					"editor exists inside @claude's sandbox, so the grant buys nothing. If "+
					"a profile needs an editor, `set` a fixed value and bind the program.",
					name, n)
			case "PAGER":
				pagerSeen = true
			}
		}
	}

	if !pagerSeen {
		t.Error("no builtin inherits PAGER any more. The absence check above passes " +
			"vacuously on a profile set that inherits nothing of git's exec class, so " +
			"this half is what keeps it honest: @claude inherits PAGER because " +
			"/usr/bin/less IS in that sandbox. If the withdrawal was deliberate, move " +
			"this assertion rather than deleting it.")
	}
}
