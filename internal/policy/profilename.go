package policy

import (
	"fmt"
	"strings"
)

// ProfileName is a profile name that has been through the grammar. The ZERO
// VALUE IS INVALID — "" fails the grammar (NameFault("") == 0), so an unset
// field is never a legal name and never silently becomes one.
//
// # Why the type exists at all
//
// The grammar landed as an allowlist inside one function (issue #20), which made
// it a fact about THAT FUNCTION'S CALLERS rather than a property of the value.
// Every profile name was a `string`: the registry key, Policy.Profiles,
// Policy.Selected, Profile.Name, Profile.Include, -p's flag values, engine.New's
// store key. Nothing in any of those signatures said the value was validated,
// so every new path that built a name was one review away from building an
// unvalidated one, with the compiler silent. This is the shape issue #51 named
// for policy.Secret: "no sink reads this field" is a fact about callers, not a
// property of a value.
//
// # Why string and not []byte
//
// A defined type over `string` is NOT assignable to `string` in either
// direction — Go's assignability rule needs one of the two types to be unnamed,
// and `string` is predeclared and named. So every escape out of this type is
// conversion-shaped and therefore greppable in a diff, and every runtime value
// entering it must pass through NewProfileName. That is precisely the property
// Secret could not have: `[]byte` is a type literal, so `var raw []byte = sec`
// compiles clean (secret.go records this as its own known limit).
//
// A name is also immutable, comparable, and used as a MAP KEY, which `[]byte`
// is not.
//
// # There is deliberately NO String, Format or MarshalText method
//
// Note first what that does NOT cost: fmt falls back to the underlying kind, so
// `%s`, `%v` and `%q` on a ProfileName print exactly what they printed when it
// was a string, with no method and no conversion at the call site. Printing a
// profile name stays ordinary. If you ever find yourself writing
// `string(name)` merely to print it, a rendering method has been added that
// should not have been — remove the method, not the print.
//
// Adding one is tempting, because it would escape control characters at every
// screen the way Secret redacts at every sink. Two reasons not to, and the
// second is the load-bearing one. It would change `%s`/`%v` output at every
// existing print site and therefore every golden file, which under CLAUDE.md's
// "a change to a golden file is a change to the security boundary" is a large
// diff spent on nothing; and post-allowlist there is nothing left to escape,
// because the grammar admits only [a-zA-Z0-9-] behind an optional sigil, and no
// character in that set can forge a row, split a NUL-separated flag list or
// close a quote. If a future grammar widens — an underscore is additive and
// harmless, but a dot or a colon would not be — revisit this decision at the
// same time, not afterwards. Do not file the absence as an oversight.
//
// # The one door this type does not close
//
// Reflection. A decoder writing into a ProfileName-typed struct field never
// calls NewProfileName, so no TOML/JSON struct in this module may declare one —
// the raw decode structs in internal/profile hold plain strings and convert
// afterwards. TestNoDecodedStructFieldIsAProfileName asserts that mechanically.
type ProfileName string

// NewProfileName is THE ONLY DOOR. It applies the grammar to a name that may
// arrive from anywhere — a TOML table key, a `-p` flag, a `defaults` list, an
// `include` entry — and refuses everything the allowlist does not name.
//
// The accepted shape is a REFERENCE, not a definition: an optional leading
// Sigil, then NameFault's set. That is deliberate and is the wider of the two
// grammars snug uses, because it is the one every name-shaped value obeys — the
// registry key for a builtin IS "@sys", Policy.Profiles carries it, and
// `include = ["@net"]` is a supported spelling from a user's own file. The
// narrower DEFINITION grammar (no sigil, because the mark means "snug ships
// this" and snug adds it itself) belongs to whoever is reading a file and can
// name it: internal/profile.checkName, which runs first and whose refusal names
// the source path.
//
// A caller outside this file may not write ProfileName(s): the conversion
// exists in exactly one file, and TestOnlyTheConstructorConvertsToAProfileName
// in cmd/snug asserts it stays there.
func NewProfileName(s string) (ProfileName, error) {
	bare := strings.TrimPrefix(s, Sigil)
	i := NameFault(bare)
	if i < 0 {
		return ProfileName(s), nil
	}
	if s == "" {
		return "", fmt.Errorf("a profile name may not be empty. It is [a-zA-Z0-9] followed by " +
			"[a-zA-Z0-9-], optionally behind a leading " + Sigil + " marking one snug ships")
	}
	if bare == "" {
		return "", fmt.Errorf("profile name %q is nothing but the %s mark. That mark means "+
			"\"snug ships this profile\"; it needs a name after it", s, Sigil)
	}
	return "", fmt.Errorf("profile name %q contains %s at byte offset %d. A profile name is "+
		"[a-zA-Z0-9] followed by [a-zA-Z0-9-], optionally behind a leading %s marking one snug "+
		"ships — an ALLOWLIST, so a character snug has not been taught about is refused rather "+
		"than carried into $SNUG_PROFILES, --dry-run provenance and every message that renders "+
		"a name.%s", s, NameByteDesc(bare[i]), i, Sigil, NameHint(bare, i))
}

// NameHint is the extra sentence a refusal adds when the offending byte has a
// known fix. It returns "" — no sentence — for a byte that has none, so a
// caller can concatenate it unconditionally.
//
// It is here, exported, for the same reason NameFault is: internal/profile's
// checkName gives the FILE version of this refusal and this is the CLI's, and
// the hint is the part a reader acts on. Written twice it would drift, and a
// rule applied to one of its two halves is the failure this project keeps
// meeting (CLAUDE.md: checkEnvName vs checkEnvValue).
//
// The underscore hint is the one that earns its keep: eight of snug's own
// profiles are hyphenated (@cwd-rw, @parent-ro, …), so "why not underscore" is
// the question the grammar actually provokes, and the answer is a name the
// reader can paste.
func NameHint(bare string, i int) string {
	if i < 0 || i >= len(bare) {
		return ""
	}
	switch c := bare[i]; {
	case c == '_':
		if alt := strings.ReplaceAll(bare, "_", "-"); NameFault(alt) < 0 {
			return fmt.Sprintf(" Underscore is not in the set and the hyphen is, which is "+
				"the spelling snug's own names use (@cwd-rw, @parent-ro): %q", alt)
		}
	case c >= 0x80:
		return " A profile name is ASCII; a non-ASCII character is several bytes in the " +
			"file and the byte above is the first of them."
	}
	return ""
}

// NewProfileNames applies NewProfileName to a list, and reports the first
// refusal with the position of the offending entry — a `defaults = [...]` line
// or a repeated `-p` says nothing about WHICH name is wrong otherwise.
func NewProfileNames(ss []string) ([]ProfileName, error) {
	if ss == nil {
		return nil, nil
	}
	out := make([]ProfileName, 0, len(ss))
	for i, s := range ss {
		n, err := NewProfileName(s)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// Bare strips the sigil, and Marked adds one. Both are closed over the grammar
// — "@" followed by a legal bare name is legal, and a legal name with the mark
// removed still is — so they belong here beside the constructor rather than
// being spelled out as a conversion at each call site. They are the reason
// internal/profile.mark and policy.UnknownProfile need no conversion of their
// own.
func (n ProfileName) Bare() ProfileName { return ProfileName(strings.TrimPrefix(string(n), Sigil)) }

// Marked returns the name wearing the sigil, adding one only if it has none.
// Never two: "@@net" is a name nothing can define.
func (n ProfileName) Marked() ProfileName {
	if strings.HasPrefix(string(n), Sigil) {
		return n
	}
	return ProfileName(Sigil + string(n))
}

// CutMark is strings.CutPrefix over the sigil: the bare name, and whether the
// mark was there to begin with.
func (n ProfileName) CutMark() (ProfileName, bool) {
	bare, ok := strings.CutPrefix(string(n), Sigil)
	return ProfileName(bare), ok
}

// NameStrings renders a list for a sink that takes []string — a store key, a
// join. It is the SAFE direction (out of the type, not into it) and needs no
// validation; it exists so the conversion stays in this file.
func NameStrings(names []ProfileName) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, string(n))
	}
	return out
}

// JoinNames is strings.Join for a list of names. Every rendering of a profile
// SET goes through it — $SNUG_PROFILES, the --dry-run PROFILES line, Validate's
// refusal, engine.New's store key — so the separator is a decision made at the
// call site and the conversion is not.
func JoinNames(names []ProfileName, sep string) string {
	return strings.Join(NameStrings(names), sep)
}

// NameFault reports the byte offset of the first character the profile-name
// grammar refuses, or -1 when every character is legal.
//
//	first byte   [a-zA-Z0-9]
//	rest         [a-zA-Z0-9-]
//
// THIS IS THE ONLY PLACE THE GRAMMAR IS WRITTEN. NewProfileName above and
// internal/profile's checkName and checkRef all call it; none re-implements it.
// A rule spelled out twice in this project has twice been fixed in one of its
// two halves (CLAUDE.md: checkEnvName vs checkEnvValue; visibleValue in one
// block and not the one four lines below).
//
// It lives in package policy rather than internal/profile — where it was
// written — because NewProfileName needs it and internal/profile imports this
// package, not the other way round. It is EXPORTED so that internal/profile can
// still build the file-naming errors that make a bad profile file diagnosable;
// exporting a PREDICATE is not a second door, because it returns an int and
// constructs nothing.
//
// A BYTE loop, not `for _, r := range name`, and that is a decision rather than
// a habit: ranging over invalid UTF-8 yields U+FFFD and loses the byte that is
// actually in the file, so the error would describe a character nobody wrote.
// Every legal byte is ASCII, so a byte loop refuses multi-byte UTF-8 at its
// FIRST byte and can name that byte exactly.
//
// The EMPTY name faults at offset 0 — it is not legal, and a caller testing only
// the sign cannot mistake it for legal. Any caller that renders name[offset]
// must handle "" before calling.
func NameFault(name string) int {
	if name == "" {
		return 0
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		switch {
		case alnum:
		case c == '-' && i > 0:
		default:
			return i
		}
	}
	return -1
}

// NameByteDesc names one offending byte for an error message, and it must not
// lie about what is in the file.
//
// string(byte(0xc3)) is "Ã" — the byte-to-string conversion goes through a rune
// and MANGLES anything >= 0x80, so a UTF-8 name would be refused with a
// character the author never typed (internal/policy/envtypes.go:681 has this
// bug today; do not copy it). Printable ASCII is quoted, everything else is the
// hex byte, which is what a hex editor would show.
func NameByteDesc(c byte) string {
	if c >= 0x20 && c <= 0x7e {
		return fmt.Sprintf("%q", string(rune(c))) // exact: c < 0x80
	}
	return fmt.Sprintf(`the byte \x%02x`, c)
}
