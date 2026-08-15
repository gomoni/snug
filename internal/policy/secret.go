package policy

import (
	"fmt"
	"io"
	"strconv"
)

// Secret is the type of Mount.Content — the bytes of every file snug generates
// or stages. It renders as "<redacted N bytes>" at every formatting and
// serialisation sink, but that guard stops IMPLICIT rendering only. Secret and
// []byte share an underlying type and []byte is unnamed, so plain ASSIGNMENT
// reaches the bytes with nothing conversion-shaped in the diff: `var raw []byte
// = m.Content`, `buf.Write(m.Content)`, and `os.WriteFile(path, m.Content,
// 0o600)` all compile today and hand over the plaintext, none of them a
// conversion a reviewer would notice. A deliberate conversion
// (`string(m.Content)`, `[]byte(m.Content)`) reaches the bytes too, and at
// least LOOKS like what it is.
//
// # Why this exists
//
// The field carries the host's Claude credentials for a BUILTIN profile with no
// user config at all: `snug --dry-run -p @claude` puts 508 bytes containing
// accessToken, refreshToken and an sk-ant key into Mount.Content, and the gh
// token joins it under an identity profile. Before this type, nothing printed
// them — repo-wide there were exactly two readers of the field — so the
// protection was "no current sink reads this", a fact about today's callers
// rather than a property of the value. CLAUDE.md records that shape failing
// twice (visibleValue guarded one block of one screen while four other sinks
// rendered the same text; checkEnvName refused a NUL in the name and not in the
// value). The guard therefore lives on the TYPE, so a sink that has not been
// written yet inherits it.
//
// # Why a field type and not Mount.MarshalJSON
//
// A MarshalJSON on Mount closes json.Marshal(mount) and nothing else — not
// `%+v` (resolve_test.go already does that on failure), not a future struct
// that holds these bytes on its own. Closing `%+v` that way would mean a
// hand-written Mount.String() enumerating every field, which is a copy of the
// struct definition kept in sync by hand: add a field, and it silently stops
// appearing in every diagnostic. Putting the guard on the field's type leaves
// `%+v` on a Mount printing all its other fields automatically, for ever, and
// replaces exactly the one field that must not be printed.
//
// # Why redaction and not an error
//
// A MarshalJSON that returns an error is louder in the abstract and quieter in
// practice: it fires only when Content is non-empty, i.e. only under the
// credential-carrying profiles, i.e. never in a golden test whose policy has no
// KindData mount. That is a guard that passes review and then fails in a user's
// terminal. A fixed placeholder is emitted on the happy path, is visible in the
// first output a new renderer's author looks at, and names itself — so it is
// discovered at authoring time, which is the only time the decision "should
// this content be here?" can still be made. It also cannot turn a diagnostic
// path into a second failure, which matters because `%+v` is used on the
// error path.
//
// # Why every value and not just the secret ones
//
// /etc/resolv.conf is not a secret and is rendered redacted anyway. Classifying
// per instance would put the decision at each of the nine construction sites,
// where "this one is harmless" is exactly the judgement that was wrong about
// ~/.gitconfig. Uniform is the property that survives a new construction site
// written by someone who has not read this comment.
//
// # What it does not cover
//
// A byte-level encoder (gob); a deliberate conversion; a plain assignment into
// a []byte-typed field or variable, which is the gap the previous section
// exists to name; or a future struct that copies these bytes into a plain
// []byte field. The sinks closed here are the implicit RENDERING ones: fmt
// (every verb, via Formatter), encoding/json, and encoding.TextMarshaler —
// which is what log/slog's TextHandler reaches for.
//
// One more, and it is a gap in fmt itself rather than in this type: fmt's
// printValue calls handleMethods — which is what checks for Formatter and
// Stringer — only when reflect.Value.CanInterface() is true, and that is FALSE
// for anything reached beneath an UNEXPORTED struct field. So a Mount (or
// Secret) sitting behind an unexported field is never handed to Format or
// String at all; fmt falls back to reflecting over the raw slice and prints the
// credential in decimal. A POINTER under an unexported field is safe — it
// prints as a bare address, not through Format — so this is live only for a
// BY-VALUE field, and only when it is unexported; an exported field, at any
// depth, still goes through Format normally. Go gives no hook on the type to
// close this; the standing defence is a reflect sweep over every struct in the
// tree asserting no unexported by-value field reaches a Mount or Secret without
// going through it, not this comment or this file.
type Secret []byte

// String is the single rendering, used by every sink below so there is one text
// to reason about rather than one per encoder. The length is kept because it is
// what a reviewer legitimately wants ("the generated gitconfig is 246 bytes")
// and a length is not a credential; no digest, because that would be a second
// thing to argue about and it can be added later without removing anything.
func (s Secret) String() string {
	if len(s) == 0 {
		return "<no content>"
	}
	return "<redacted " + strconv.Itoa(len(s)) + " bytes>"
}

// GoString covers %#v.
func (s Secret) GoString() string { return s.String() }

// Format is what makes the fmt guard total. Stringer alone would cover only
// %v, %s, %q, %x and %X — `fmt.Sprintf("%d", content)` on a []byte prints the
// byte values, which is the credential in decimal. fmt checks Formatter before
// Stringer and for every verb, so implementing it leaves no verb uncovered.
// Width and precision flags are deliberately ignored: there is one rendering.
func (s Secret) Format(f fmt.State, verb rune) { io.WriteString(f, s.String()) }

// MarshalJSON keeps the bytes out of any JSON document, present or future.
// json.Marshal renders a []byte as base64, so without this a credential would
// appear in a machine-readable --dry-run as "eyJhY2Nlc3NUb2tlbiI6..." —
// unrecognisable in the golden diff that is this project's review artifact.
//
// Measured, so a golden diff does not surprise anyone: encoding/json
// HTML-escapes what a MarshalJSON implementation returns before embedding it,
// so the two angle brackets appear in the document as their six-character
// unicode escapes rather than literally. It decodes back to exactly String(),
// and keeping ONE text across all sinks is worth more than a prettier
// JSON-only spelling.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(s.String())), nil
}

// MarshalText covers encoding.TextMarshaler consumers, log/slog's TextHandler
// among them.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }
