package profile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// T1. Every builtin's own name, and every name it includes, must pass the same
// grammar a user file is held to — nameFault, the ONE place that grammar is
// written (see its doc comment).
//
// The sweep is DERIVED from Builtins() rather than a hand-written list of
// names: a hand-written list drifts the moment a profile is renamed or added,
// and would then silently stop covering the thing it was written to cover —
// the exact shape of "the count in prose is a copy of state held somewhere
// else" CLAUDE.md warns about for the writable-surface count.
func TestEveryBuiltinNamePassesTheNameGrammar(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// CONTROL 1: the registry actually loaded something. Without this, every
	// assertion below is vacuously true because the loop body never runs — the
	// exact shape of the pasta.avx2 scar in CLAUDE.md.
	if len(reg) == 0 {
		t.Fatal("no builtins loaded, so this sweep cannot fail — the embed is broken")
	}
	// CONTROL 2: @cwd-rw is present, so the sweep actually exercises a hyphen
	// (nameFault's rest-of-name branch) rather than passing on a builtin set
	// that happens to contain none.
	if _, ok := reg[policy.Sigil+"cwd-rw"]; !ok {
		t.Fatal("@cwd-rw is missing; this sweep would never exercise the hyphen and could not " +
			"tell a correct grammar from one that silently dropped it")
	}

	for key, p := range reg {
		bare, ok := strings.CutPrefix(key, policy.Sigil)
		if !ok {
			t.Errorf("builtin key %q does not carry the sigil %q", key, policy.Sigil)
			continue
		}
		if i := nameFault(bare); i >= 0 {
			t.Errorf("builtin %q fails the name grammar at byte offset %d (%s)", key, i, nameByteDesc(bare[i]))
		}
		for _, inc := range p.Include {
			incBare, ok := strings.CutPrefix(inc, policy.Sigil)
			if !ok {
				t.Errorf("builtin %q includes %q, which does not carry the sigil %q", key, inc, policy.Sigil)
				continue
			}
			if i := nameFault(incBare); i >= 0 {
				t.Errorf("builtin %q includes %q, which fails the name grammar at byte offset %d (%s)",
					key, inc, i, nameByteDesc(incBare[i]))
			}
		}
	}
}

// rejectedNames is shared by T2 (checkName refuses each, and says why) and T3
// (none of those refusals renders a raw control character). Keeping one table
// is deliberate: a spelling added to test refusal should automatically be
// checked for a clean message too, rather than needing to be added twice.
var rejectedNames = []struct {
	desc       string
	name       string
	wantSubstr string
}{
	{"empty", "", "empty name"},
	{"leading-hyphen", "-x", "flag"},
	{"leading-sigil", "@x", "snug ships"},
	{"bare-sigil", "@", "snug ships"},
	{"underscore", "my_profile", `"my-profile"`},
	{"dot", "my.tool", nameByteDesc('.')},
	{"comma", "a,b", nameByteDesc(',')},
	{"colon", "a:b", nameByteDesc(':')},
	{"space", "a b", nameByteDesc(' ')},
	{"tab", "a\tb", nameByteDesc('\t')},
	{"nul", "a\x00b", nameByteDesc(0)},
	{"esc-sequence", "a\x1b[1A\rb", nameByteDesc(0x1b)},
	{"utf8-e-acute", "café", nameByteDesc(0xc3)},
	{"slash", "a/b", nameByteDesc('/')},
	{"backslash", "a\\b", nameByteDesc('\\')},
	{"asterisk", "a*b", nameByteDesc('*')},
	{"dollar", "a$b", nameByteDesc('$')},
	{"single-quote", "a'b", nameByteDesc('\'')},
	{"double-quote", `a"b`, nameByteDesc('"')},
	{"at-mid", "x@y", nameByteDesc('@')},
	{"invalid-utf8", "a\xffb", nameByteDesc(0xff)},
}

// T2. checkName is an ALLOWLIST: table-driven over what it must accept and what
// it must refuse, with the refusal message pinned to a substring so a future
// rewrite cannot quietly stop explaining WHY.
func TestProfileNameAllowlist(t *testing.T) {
	sixtyFour := strings.Repeat("a", 64)
	accepted := []string{"a", "Z", "0", "sys", "cwd-rw", "a-b-c", "x9", "ABC-123", "a--b", sixtyFour}
	for _, name := range accepted {
		t.Run("accept/"+name, func(t *testing.T) {
			if err := checkName(name, "test.toml"); err != nil {
				t.Errorf("checkName(%q) = %v, want nil", name, err)
			}
		})
	}

	for _, tc := range rejectedNames {
		t.Run("reject/"+tc.desc, func(t *testing.T) {
			err := checkName(tc.name, "test.toml")
			if err == nil {
				t.Fatalf("checkName(%q) accepted; want refused", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("checkName(%q) = %v, want it to contain %q", tc.name, err, tc.wantSubstr)
			}
		})
	}
}

// T3. This is table-driven for the same reason
// TestNoSnugScreenEmitsARawControlCharacter (cmd/snug) sweeps a SET of sinks
// rather than asserting one: a guard applied at one call site (or to one
// rejected spelling) looks identical to a guard applied everywhere, right up
// until the spelling that was missed reaches production. checkName has three
// distinct refusal paths (empty, leading '@', leading '-', and the general
// nameFault loop) and every one of them formats a message from the offending
// name — each needs its own row here, not one representative case.
func TestProfileNameRefusalNeverRendersARawControlCharacter(t *testing.T) {
	for _, tc := range rejectedNames {
		t.Run(tc.desc, func(t *testing.T) {
			err := checkName(tc.name, "test.toml")
			if err == nil {
				t.Fatalf("checkName(%q) accepted; this is the rejection table, so this case is broken", tc.name)
			}
			msg := err.Error()
			for i := 0; i < len(msg); i++ {
				if c := msg[i]; c < 0x20 || c == 0x7f {
					t.Fatalf("checkName(%q) error contains raw control byte 0x%02x at offset %d: %q",
						tc.name, c, i, msg)
				}
			}
		})
	}

	// The positive control, and it is load-bearing: without it, an
	// implementation that silently DROPPED the offending byte from the message
	// (rather than escaping it) would also produce a message with no raw
	// control bytes in it, and every case above would pass for the wrong
	// reason. The ESC fixture's message must carry the literal four
	// characters backslash-x-1-b — nameByteDesc's escaped spelling.
	err := checkName("a\x1b[1A\rb", "test.toml")
	if err == nil || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("checkName's message for the ESC fixture does not contain the literal `\\x1b`, "+
			"so this test cannot distinguish \"escaped\" from \"silently dropped\": %v", err)
	}
}

// T4. Through the real `parse`, for the spellings TOML can actually express.
// All four rejected spellings LOADED before nameFault existed, so this is a
// genuine regression test and not a restatement of T2.
func TestNameGrammarIsEnforcedByParse(t *testing.T) {
	rejects := []string{
		"[profile.my_profile]\nro = [\"/usr\"]\n",
		"[profile.\"my.tool\"]\nro = [\"/usr\"]\n",
		// TOML's \u escape, not Go's — this is what a file on disk containing
		// a literal ESC byte in a basic string decodes to. \r is TOML's own
		// escape for carriage return.
		"[profile.\"a\\u001b[1A\\rb\"]\nro = [\"/usr\"]\n",
		"[profile.\"@x\"]\nro = [\"/usr\"]\n",
	}
	for i, src := range rejects {
		if _, err := parse([]byte(src), "test.toml", true); err == nil {
			t.Errorf("case %d: %s\nparsed cleanly; the name grammar must be enforced at parse time", i, src)
		}
	}

	// CONTROL: builtin-shaped names still parse, so the refusals above are
	// about the grammar and not about parse() rejecting everything.
	for _, src := range []string{
		"[profile.\"cwd-rw\"]\nro = [\"/usr\"]\n",
		"[profile.sys]\nro = [\"/usr\"]\n",
	} {
		if _, err := parse([]byte(src), "test.toml", true); err != nil {
			t.Errorf("%s\nwas refused: %v", src, err)
		}
	}
}

// T5. include targets go through checkRef, not checkName — one character
// looser (an optional leading sigil), and checked at parse time so the error
// names the FILE that is wrong.
func TestIncludeTargetMustBeALegalName(t *testing.T) {
	const source = "test.toml"

	mustRefuseNaming := func(t *testing.T, src, wantFrom string) {
		t.Helper()
		_, err := parse([]byte(src), source, true)
		if err == nil {
			t.Fatalf("%s\nparsed cleanly; the include names no legal profile", src)
		}
		if !strings.Contains(err.Error(), wantFrom) || !strings.Contains(err.Error(), source) {
			t.Errorf("error does not name both the including profile (%q) and the file (%q): %v",
				wantFrom, source, err)
		}
	}

	// Plain-ASCII cases: %q agrees with TOML's own escaping for characters
	// that need none, so the source can be built directly from the Go value.
	for _, inc := range []string{"@@net", "", "-x", "@"} {
		src := fmt.Sprintf("[profile.x]\ninclude = [%q]\n", inc)
		mustRefuseNaming(t, src, "x")
	}

	// The ESC-containing include needs TOML's own \u escape, same as T4's ESC
	// case — this is what a literal ESC byte in the file decodes to.
	mustRefuseNaming(t, "[profile.x]\ninclude = [\"a\\u001b[1A\\rb\"]\n", "x")

	// CONTROLS: a builtin-shaped include and an undefined-but-legal one both
	// still parse — cross-file references (a profile including a name some
	// OTHER file defines) must keep working; checkRef only judges the
	// spelling, never looks the name up.
	for _, inc := range []string{"@net", "y"} {
		src := fmt.Sprintf("[profile.x]\ninclude = [%q]\n", inc)
		if _, err := parse([]byte(src), source, true); err != nil {
			t.Errorf("include = [%q] was refused: %v", inc, err)
		}
	}
}

// T6. The two functions disagree on purpose: a DEFINITION may never carry the
// sigil (checkName refuses it), a REFERENCE may (checkRef accepts it) — that
// is the whole reason `include = ["@net"]` works from a user's own profile.
func TestMarkedNameIsNotAFileNameButIsALegalReference(t *testing.T) {
	// Every registry key is either nameFault-legal on its own, or Sigil
	// followed by a nameFault-legal name — never anything else. checkName and
	// checkRef are the two sides of that single invariant.
	for _, n := range []string{"@sys", "@net", "@claude"} {
		if err := checkName(n, "test.toml"); err == nil || !strings.Contains(err.Error(), "snug ships") {
			t.Errorf(`checkName(%q) = %v, want a "snug ships" refusal`, n, err)
		}
		if err := checkRef(n, "user-profile", "test.toml"); err != nil {
			t.Errorf("checkRef(%q, ...) = %v, want nil — a reference may carry a mark a definition may not",
				n, err)
		}
	}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg["@sys"]; !ok {
		t.Fatal("@sys is missing; the registry failed to load, so the sweep below proves nothing")
	}
	for key := range reg {
		if nameFault(strings.TrimPrefix(key, policy.Sigil)) >= 0 {
			t.Errorf("builtin key %q is not Sigil followed by a legal name", key)
		}
	}
}

// T7. checkName's leading-'-' and leading-'@' checks exist ONLY to give a
// better message than the generic nameFault refusal would — nameFault itself
// already refuses both spellings on its own. If either of these assertions
// starts failing, deleting the corresponding bespoke branch in checkName would
// silently WIDEN what parses, rather than merely cost a worse error message —
// which is exactly the "grammar spelled out twice" hazard nameFault's own doc
// comment names.
func TestNameGrammarLivesInOneFunction(t *testing.T) {
	if i := nameFault("-x"); i != 0 {
		t.Errorf(`nameFault("-x") = %d, want 0 — deleting checkName's bespoke leading-hyphen `+
			"branch above the loop must cost a good error, not widen the accepted set", i)
	}
	if i := nameFault("@x"); i != 0 {
		t.Errorf(`nameFault("@x") = %d, want 0 — deleting checkName's bespoke leading-sigil `+
			"branch above the loop must cost a good error, not widen the accepted set", i)
	}
}
