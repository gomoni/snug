package policy

import (
	"fmt"
	"strings"
	"testing"
)

// sprintf is fmt.Sprintf under a local name, so that
// TestProfileNameRendersAsItsUnderlyingString reads as a comparison of two
// renderings rather than as a wall of fmt calls.
func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

// NewProfileName's grammar is a REFERENCE: NameFault's set behind an optional
// sigil. That is wider than internal/profile's checkName by exactly one
// character, and the difference is deliberate — a builtin's registry key IS
// "@sys", so a constructor that refused the mark could not build the values
// snug's own registry is made of.
func TestNewProfileNameAppliesTheGrammar(t *testing.T) {
	accepted := []string{
		"a", "Z", "0", "sys", "cwd-rw", "a-b-c", "x9", "ABC-123", "a--b",
		strings.Repeat("a", 64),
		// The mark, on every shape a bare name can take.
		"@sys", "@cwd-rw", "@a", "@0",
	}
	for _, s := range accepted {
		t.Run("accept/"+s, func(t *testing.T) {
			got, err := NewProfileName(s)
			if err != nil {
				t.Fatalf("NewProfileName(%q) = %v, want nil", s, err)
			}
			if string(got) != s {
				t.Errorf("NewProfileName(%q) returned %q — the constructor must not rewrite "+
					"the name it was given", s, got)
			}
		})
	}

	rejected := []struct{ desc, name, want string }{
		{"empty", "", "may not be empty"},
		{"bare-sigil", "@", "nothing but the"},
		{"double-sigil", "@@net", NameByteDesc('@')},
		{"leading-hyphen", "-x", NameByteDesc('-')},
		{"underscore", "my_profile", NameByteDesc('_')},
		{"dot", "my.tool", NameByteDesc('.')},
		{"comma", "a,b", NameByteDesc(',')},
		{"colon", "a:b", NameByteDesc(':')},
		{"space", "a b", NameByteDesc(' ')},
		{"tab", "a\tb", NameByteDesc('\t')},
		{"nul", "a\x00b", NameByteDesc(0)},
		{"esc-sequence", "a\x1b[1A\rb", NameByteDesc(0x1b)},
		{"slash", "a/b", NameByteDesc('/')},
		{"utf8", "café", NameByteDesc(0xc3)},
		{"invalid-utf8", "a\xffb", NameByteDesc(0xff)},
		{"mark-mid", "x@y", NameByteDesc('@')},
		// The mark is stripped once, so the grammar still applies to the rest.
		{"marked-then-bad", "@a b", NameByteDesc(' ')},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.desc, func(t *testing.T) {
			got, err := NewProfileName(tc.name)
			if err == nil {
				t.Fatalf("NewProfileName(%q) = %q, want a refusal", tc.name, got)
			}
			if got != "" {
				t.Errorf("NewProfileName(%q) returned %q alongside its error; a refused name "+
					"must come back as the zero value, or a caller that ignores err gets a "+
					"ProfileName the grammar rejected", tc.name, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("NewProfileName(%q) = %v, want it to contain %q", tc.name, err, tc.want)
			}
		})
	}
}

// NameHint is the one sentence a reader acts on, and it is SHARED with
// internal/profile's checkName so the fix for an underscore reads the same
// whether the name came from a file or from `-p`. Written twice it would be
// improved in one place only.
func TestNewProfileNameSuggestsTheHyphenSpelling(t *testing.T) {
	_, err := NewProfileName("my_profile")
	if err == nil {
		t.Fatal("my_profile was accepted")
	}
	if !strings.Contains(err.Error(), `"my-profile"`) {
		t.Errorf("the underscore refusal does not offer the hyphen spelling, which is the "+
			"only part of it a reader can paste: %v", err)
	}

	_, err = NewProfileName("café")
	if err == nil {
		t.Fatal("café was accepted")
	}
	if !strings.Contains(err.Error(), "ASCII") {
		t.Errorf("the non-ASCII refusal does not explain that the byte named is the first of "+
			"several: %v", err)
	}

	// The negative half: a byte with no known fix must add NO sentence, or
	// callers concatenating unconditionally would emit a dangling one.
	if h := NameHint("a b", 1); h != "" {
		t.Errorf("NameHint added %q for a space, which has no suggested spelling", h)
	}
	if h := NameHint("ok", -1); h != "" {
		t.Errorf("NameHint added %q for a legal name (offset -1)", h)
	}
	// An underscore whose hyphen spelling is ALSO illegal gets no suggestion:
	// offering a name the grammar would refuse in turn is worse than silence.
	if h := NameHint("_a.b", 0); h != "" {
		t.Errorf("NameHint suggested %q, but replacing the underscore still leaves an "+
			"illegal name", h)
	}
}

// The refusal messages are rendered on a terminal, so they are held to the same
// rule as every other snug screen (CLAUDE.md: "name every sink that value can
// reach, and assert the set rather than the site"). A message that echoed the
// offending bytes raw would let the very name being refused forge a row in the
// refusal.
//
// The positive control is load-bearing: an implementation that silently DROPPED
// the offending byte would also emit no control characters, and every case
// above would pass for the wrong reason.
func TestNewProfileNameRefusalNeverRendersARawControlCharacter(t *testing.T) {
	for _, name := range []string{
		"", "@", "a\x00b", "a\x1b[1A\rb", "a\tb", "a\x7fb", "a\xffb", "@a\x1bb",
	} {
		_, err := NewProfileName(name)
		if err == nil {
			t.Fatalf("NewProfileName(%q) was accepted; this is the rejection table", name)
		}
		msg := err.Error()
		for i := 0; i < len(msg); i++ {
			if c := msg[i]; c < 0x20 || c == 0x7f {
				t.Fatalf("NewProfileName(%q) error carries raw control byte 0x%02x at offset %d: %q",
					name, c, i, msg)
			}
		}
	}
	_, err := NewProfileName("a\x1b[1A\rb")
	if err == nil || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("the ESC fixture's message does not contain the literal `\\x1b`, so this test "+
			"cannot tell \"escaped\" from \"silently dropped\": %v", err)
	}
}

// NewProfileNames reports WHICH entry is wrong. A `defaults = [...]` line or a
// repeated -p otherwise leaves the reader to work it out.
func TestNewProfileNamesNamesTheOffendingEntry(t *testing.T) {
	got, err := NewProfileNames([]string{"@sys", "@home"})
	if err != nil {
		t.Fatalf("NewProfileNames of two legal names: %v", err)
	}
	if len(got) != 2 || got[0] != "@sys" || got[1] != "@home" {
		t.Fatalf("NewProfileNames returned %v, want [@sys @home]", got)
	}

	_, err = NewProfileNames([]string{"@sys", "bad name", "@home"})
	if err == nil {
		t.Fatal("NewProfileNames accepted a list containing an illegal name")
	}
	if !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("error %v does not say which entry is wrong; a list refusal that does not "+
			"point at the entry makes the reader diff the list by eye", err)
	}

	// nil in, nil out: an absent list and an empty one must stay distinguishable
	// at the CALLER (internal/cli's `defaults = []` depends on it), so the
	// constructor must not invent a slice.
	if out, err := NewProfileNames(nil); err != nil || out != nil {
		t.Errorf("NewProfileNames(nil) = %v, %v; want nil, nil", out, err)
	}
}

// Bare, Marked and CutMark are closed over the grammar: applied to a legal
// name they yield a legal name, which is why they live beside the constructor
// instead of being a conversion at each call site. If that stops holding, the
// sigil helpers become a second door.
func TestSigilHelpersStayInsideTheGrammar(t *testing.T) {
	for _, s := range []string{"sys", "@sys", "cwd-rw", "@cwd-rw", "a", "@a"} {
		n, err := NewProfileName(s)
		if err != nil {
			t.Fatalf("fixture %q is not a legal name: %v", s, err)
		}
		for label, got := range map[string]ProfileName{
			"Bare":          n.Bare(),
			"Marked":        n.Marked(),
			"Bare().Marked": n.Bare().Marked(),
			"Marked().Bare": n.Marked().Bare(),
		} {
			if _, err := NewProfileName(string(got)); err != nil {
				t.Errorf("%s(%q) = %q, which the constructor refuses (%v) — the helper is not "+
					"closed over the grammar", label, s, got, err)
			}
		}
		if n.Marked().Marked() != n.Marked() {
			t.Errorf("Marked() is not idempotent on %q: %q — \"@@net\" is a name nothing can "+
				"define", s, n.Marked().Marked())
		}
		bare, marked := n.CutMark()
		if marked != strings.HasPrefix(s, Sigil) {
			t.Errorf("CutMark(%q) reported marked=%v", s, marked)
		}
		if bare != n.Bare() {
			t.Errorf("CutMark(%q) and Bare() disagree: %q vs %q", s, bare, n.Bare())
		}
	}
}

// The zero value is the invalid name, and that is what makes an unset field
// safe: it can never be mistaken for a profile anything defines.
func TestZeroProfileNameIsInvalid(t *testing.T) {
	var zero ProfileName
	if _, err := NewProfileName(string(zero)); err == nil {
		t.Fatal("the zero ProfileName passes the grammar; an unset field would then be a " +
			"legal name, and the type's doc comment is wrong")
	}
	if NameFault(string(zero)) < 0 {
		t.Fatal("NameFault accepts the empty name")
	}
}

// ProfileName must render exactly as the string it wraps, through every verb a
// snug screen uses. This is the OTHER half of "there is deliberately no
// String() method": the absence is only free if printing stays ordinary, and a
// method added later would move every golden — which is precisely the cost the
// decision was made to avoid. Failing here means someone added one.
func TestProfileNameRendersAsItsUnderlyingString(t *testing.T) {
	const raw = "@cwd-rw"
	n, err := NewProfileName(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%s", "%v", "%q"} {
		got := sprintf(verb, n)
		want := sprintf(verb, raw)
		if got != want {
			t.Errorf("%s on a ProfileName gives %s, on the string it wraps %s — a rendering "+
				"method has been added, which moves every golden that prints a profile name "+
				"and buys nothing the grammar does not already give", verb, got, want)
		}
	}
	if got := sprintf("%v", []ProfileName{"@sys", "@home"}); got != "[@sys @home]" {
		t.Errorf("%%v on a []ProfileName gives %s, want [@sys @home]", got)
	}
}
