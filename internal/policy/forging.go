package policy

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The one set of runes snug refuses in text it will render, and the argument for
// where the edge of that set is.
//
// IT IS ONE FUNCTION BECAUSE IT WAS FOUR COPIES AND THEY DID NOT AGREE. The
// question "can this rune make a line read as something other than what snug
// wrote" was asked in four places, each with its own spelling:
//
//	checkEnvValue (envtypes.go)   unicode.IsControl + U+2028/U+2029
//	isForgingRune (internal/cli)      unicode.IsControl + U+2028/U+2029
//	Validate      (validate.go)   r < 0x20 || r == 0x7f      <- still ASCII-only
//	Identity.CheckText            c < 0x20 || c == 0x7f      <- a BYTE loop
//
// The first two were widened together when a red team put U+0085 and U+009B
// through them; the third and fourth were not, and nothing could notice, because
// each site had its own test asserting its own spelling. That is this project's
// most-repeated defect — one rule, applied to one of its halves — arriving for
// the third time in this file's subject. The predicate now owns the question and
// every sink asks it, so a rune added here is added everywhere at once.
//
// TWO KINDS OF DAMAGE, KEPT APART, because the messages have to name which one:
//
//   - A NUL AUTHORS A MOUNT. The bwrap flag list is NUL-separated, so a NUL
//     inside a value ends the value and everything after it is read as further
//     flags — measured, mounting ~/.ssh from an `environ.set` line that no Mount
//     existed for. That is checkEnvValue's own arm and is not weakened here.
//   - EVERYTHING ELSE AUTHORS A LIE, in the artifact a human reads to decide
//     whether to trust the sandbox. A newline forges a row in the FILESYSTEM
//     block; ESC[1A CR erases one from `snug profile show`; U+009B is the
//     single-character CSI that does the same on a terminal in 8-bit mode; and
//     U+202E reverses the rest of the row so it reads as different content than
//     its bytes.
//
// ── WHERE THE EDGE IS, AND WHY IT IS THERE ───────────────────────────────────
//
// IN, and this is the whole of what was added for the bidi finding: the NINE
// EXPLICIT DIRECTIONAL FORMATTING CHARACTERS of UAX #9 — LRE, RLE, PDF, LRO, RLO
// (U+202A-U+202E) and LRI, RLI, FSI, PDI (U+2066-U+2069). They are category Cf,
// not Cc, so unicode.IsControl is false for every one of them and the previous
// set could not see them. They are IN because they are the mechanism by which
// text is REORDERED: a value or a grant path carrying one displays in an order
// its bytes do not have, which is the same class of defect as a forged row and
// is invisible in review. Naming them as a SPEC-DEFINED SET rather than as a
// list of characters someone noticed is the point — UAX #9 closes the set, so
// this is not another enumeration waiting for a sixth character to beat it.
//
// OUT, deliberately, and this is the judgement rather than the rule:
//
//   - The implicit direction MARKS — U+200E LRM, U+200F RLM, U+061C ALM. They
//     steer the direction of ADJACENT NEUTRALS only; they cannot reorder strong
//     characters, so they cannot make a latin path or a latin value read as
//     another one. They also occur in legitimate bidirectional text, where the
//     overrides above do not.
//   - The INVISIBLE characters — U+200B ZWSP, U+00AD SHY, U+200C ZWNJ, U+200D
//     ZWJ, U+2060 WJ, U+FEFF. These are a DIFFERENT hazard and snug does not
//     claim to close it: they do not reorder a row, they make two DIFFERENT
//     strings render alike, so a grant for `/usr/bin/gi<ZWSP>t` reads as one for
//     /usr/bin/git. That hazard is UNBOUNDED — a Cyrillic U+0430 where the `a`
//     is spells a different word that renders identically, with no format
//     character in it at all (written as a codepoint rather than as itself, for
//     the same reason U+2028 is: a confusable in a source comment is a trap for
//     the next reader rather than an illustration), and no
//     rune predicate closes homoglyphs. Refusing ZWNJ would additionally refuse
//     a correct path: it is load-bearing in Persian, Hindi and Arabic text, and
//     a profile may legitimately name a directory containing one. A rule that
//     closed ZWSP while a homoglyph walked past would tell a reader this screen
//     is trustworthy when it is not, which is worse than the honest statement:
//     snug guarantees that a rendered line reads in the ORDER of its bytes, and
//     does not guarantee that two different lines look different.
//
// ONE SET FOR BOTH DIRECTIONS, TODAY. A profile's value is REFUSED at parse time
// and a host's value is ESCAPED at render time (visibleValue), and both ask this
// same predicate. Escaping strictly more than snug refuses would be defensible —
// escaping is display-only and cannot break a correct configuration — and if
// that day comes it wants TWO predicates with two arguments, not a second
// spelling of this one. It is not needed yet: every rune in here is one no
// environment value and no guest path has a legitimate use for.
func IsForgingRune(r rune) bool {
	switch {
	case unicode.IsControl(r):
		// C0, DEL and C1 in one predicate. The ASCII-only spelling this replaced
		// could not see U+0085 (NEL) or U+009B (CSI), and %q hid the gap in
		// review: mix in ONE ASCII control and Go's quoting escapes the C1
		// characters too, so only a PURE-C1 value shows which half was narrow.
		return true
	case r == '\u2028' || r == '\u2029':
		// LINE SEPARATOR and PARAGRAPH SEPARATOR. Zl and Zp rather than Cc, and
		// every block on every snug screen is a table whose rows are one line.
		return true
	case (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069'):
		// UAX #9's explicit directional formatting characters. Written as ranges
		// against the two spec blocks rather than as five plus four constants, so
		// that "did someone forget PDI" is not a question a reader has to answer.
		return true
	}
	return false
}

// forgingRuneReason is the CLAUSE naming what this particular rune does to a
// line, for the refusal that carries it.
//
// It exists because one message could not stay honest across the set. "A control
// character forges rows in it or erases them from the terminal" is exactly right
// for ESC and NEL and exactly wrong for RLO, which adds no row and erases none —
// it reverses one. A refusal whose reason does not match the character is a
// refusal the author cannot act on, and this file's history says an author who
// cannot see the character in their editor is the normal case rather than the
// exception.
func forgingRuneReason(r rune) string {
	if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
		return "a control character forges rows in it or erases them from the terminal"
	}
	return "a directional formatting character reverses the rest of the line, so it " +
		"renders as content it does not contain"
}

// VisibleText renders text snug did not write so that it cannot author, erase or
// reverse a line — the RENDER half of IsForgingRune, where refusing is not
// available.
//
// Refusing is not available for a HOST path. A file on this machine may legally
// be named with a newline in it, and refusing to bind it would be snug inventing
// a rule about someone else's filesystem (Validate says so, and refuses only the
// GUEST side). So the host side is escaped instead, wherever it is rendered.
//
// INCLUDING IN A REFUSAL, which is the sink this was written for and the one
// that had been missed. Measured on this branch, before this function existed,
// with a host directory whose name carries U+202E:
//
//	ro = ["/tmp/host<RLO>OLR:/opt/x"]
//	  FILESYSTEM block   ro /opt/x (from /tmp/host<RLO>OLR)   <- escaped
//	  --ro-bind line     /tmp/host<RLO>OLR /opt/x             <- escaped
//	  the masking REFUSAL that same run printed:
//	    profile hostbidi puts a bind of /tmp/host<RLO>OLR at /opt/x…   <- RAW
//
// An error message is a screen, and this project's own rule is to name every
// sink a value reaches rather than to fix the one it was found at. A refusal is
// the sink a human reads most carefully, since it is the one that stopped them.
//
// Invalid UTF-8 is escaped wholesale for the reason internal/cli's visibleValue
// gives: a raw 0x9b byte decodes to RuneError, so no rune predicate can see it,
// while on a terminal in 8-bit mode it IS the CSI introducer. Text with nothing
// to escape is returned unchanged, so ordinary output and every golden are
// untouched.
func VisibleText(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, IsForgingRune) {
		return s
	}
	return strings.Trim(fmt.Sprintf("%q", s), `"`)
}
