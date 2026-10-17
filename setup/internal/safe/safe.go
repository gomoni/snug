// Package safe is the one way text from outside snug-setup — a key comment, a
// gh login, a git author, a file digest, anything the model wrote — reaches a
// screen. A terminal obeys what it is sent: ESC ] 0 retitles it, ESC [ 2 J
// clears it, and a bidi override renders a line as text it does not contain.
package safe

import (
	"strings"
	"unicode"
)

// Text is a string that has been through Clean.
type Text string

// Clean returns s with nothing a terminal would act on or render as something
// else: every control character except newline (C0, DEL and C1), every Unicode
// format character (category Cf: the bidi embeddings, overrides and isolates,
// LRM, RLM, ALM, zero-width space and joiners, U+FEFF, the tag characters),
// and the line and paragraph separators U+2028 and U+2029 are removed; invalid
// UTF-8 becomes U+FFFD; a tab becomes two spaces.
func Clean(s string) Text {
	s = strings.ToValidUTF8(s, "\ufffd")
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		switch {
		case c == '\n':
			b.WriteRune(c)
		case c == '\t':
			b.WriteString("  ")
		case unicode.IsControl(c), unicode.Is(unicode.Cf, c), c == '\u2028', c == '\u2029':
		default:
			b.WriteRune(c)
		}
	}
	return Text(b.String())
}

// Inline is Clean for a fragment placed inside a sentence snug-setup writes: a
// newline becomes a space as well, so the fragment cannot start a line of its
// own that reads as one of snug-setup's.
func Inline(s string) string {
	return strings.ReplaceAll(string(Clean(s)), "\n", " ")
}
