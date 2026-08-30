package cli

import (
	"fmt"
	"io"
	"strings"
)

// A note is something snug says about THIS run that is not a refusal. Five of
// them existed before this file did, each writing to os.Stderr from wherever
// it was discovered, and together they were a wall of text nobody read: issue
// #541 pasted the real one, five blocks deep, in front of a TUI that erased it
// a moment later. Text that is always printed and never read is worse than
// text that is printed when asked for — it trains the human to skip the place
// snug says important things.
//
// So notes are COLLECTED here and printed by ONE rule, and the rule turns on a
// distinction the five sites already made in prose but could not make in code:
//
//   - noteEscape names a hole in the sandbox. The human is told whether or not
//     they asked, on every run, because the alternative is that the only
//     people who learn about the hole are the ones who typed -v.
//   - noteAside is a run detail: a capability that degraded, a host limit, a
//     setting of theirs that did not carry. Real and worth saying; not worth
//     saying before the human has asked. -v, --dry-run and --explain ask.
//
// The TEXT of every note is unchanged from what its site printed before,
// prefix and continuation indent included. This file decides WHEN a note is
// seen, never WHAT it says — a rewording here would be a security-relevant
// edit hiding inside a plumbing change.
type noteKind int

const (
	// noteEscape: the sandbox's boundary has a named hole and the human owns
	// the decision to open it. Unconditional. Today there is exactly one
	// producer, announceHTTPDoors, and its own doc comment carries the
	// argument for why stderr specifically: the same warning is written into
	// the generated CLAUDE.md, which lives in a writable project tree that
	// snug's threat model assumes a hostile payload may edit. stderr is the
	// channel that payload cannot reach, so silencing it by default would
	// leave the warning only in the place it cannot be trusted.
	noteEscape noteKind = iota

	// noteAside: true, useful, and not urgent. Quiet by default.
	noteAside
)

// note holds the finished text, not a format string and its arguments. The
// sites below build multi-line, hand-wrapped English with a six-space
// continuation indent; re-wrapping it here would put snug in the business of
// laying out prose it did not write.
type note struct {
	kind noteKind
	text string
}

// notes is the collector. One per run, owned by run().
//
// It does two jobs at once because the alternative — accumulate everything,
// flush at the end — would move each note away from the moment it was
// discovered, and a note about a step that then FAILS would never be printed
// at all. So an unsuppressed note still goes out immediately, exactly where it
// used to, and the accumulated copy exists for the screens that render a whole
// run.
type notes struct {
	// live is where a note goes the moment it is added, or nil for a run
	// that prints no notes as it goes. --dry-run and --explain set nil: they
	// render the collected set into their own screen, and a note landing on
	// stderr in the middle of that would be the same wall in a new place.
	live io.Writer

	// verbose is -v: every note prints live, asides included.
	verbose bool

	n []note
}

// newNotes builds the collector for a run.
func newNotes(live io.Writer, verbose bool) *notes {
	return &notes{live: live, verbose: verbose}
}

// escape records a hole in the sandbox. Always printed.
func (n *notes) escape(format string, args ...any) { n.add(noteEscape, format, args...) }

// aside records a run detail. Printed with -v, and on the --dry-run and
// --explain screens.
func (n *notes) aside(format string, args ...any) { n.add(noteAside, format, args...) }

func (n *notes) add(kind noteKind, format string, args ...any) {
	if n == nil {
		return
	}
	text := fmt.Sprintf(format, args...)
	n.n = append(n.n, note{kind: kind, text: text})
	if n.live == nil {
		return
	}
	if kind == noteEscape || n.verbose {
		fmt.Fprint(n.live, text)
	}
}

// isVerbose is -v, read through the collector so the sites that still print
// their own -v-only lines have one source for the answer. Those lines are NOT
// notes and deliberately stay where they are: --dry-run's CLAUDE block already
// renders the same names unconditionally, so routing them through aside would
// print them twice on the one screen that matters most.
func (n *notes) isVerbose() bool { return n != nil && n.verbose }

// all reports every note collected, in the order they were discovered. The
// order is the run's own and is not sorted: a note about the engine's
// resolver comes after the one about the settings file because that is when
// each became true, and reordering them would describe a startup that did not
// happen.
func (n *notes) all() []note {
	if n == nil {
		return nil
	}
	return n.n
}

// render writes every collected note into a screen. Used by --explain and by
// --dry-run's NOTES block, which are the two places a human has asked for the
// whole picture.
//
// IT IS NOT A COMPLETE LIST AND THE HEADING MUST NOT CLAIM TO BE. A screen
// collects only the notes its own path reached, and both screens stop early on
// purpose: startContainers returns at its --dry-run branch before
// warnAboutPodmanClient and before the /etc/resolv.conf probe, because those
// belong to an engine that is not being started. So `--dry-run -p
// @podman-socket` renders no NOTES block at all while the real run under -v
// prints two. That is the "starts nothing" promise being kept, not a bug — but
// a heading reading "everything snug would say" would be false, and a
// completeness claim on a security screen is worse than no heading.
//
// A run that produced no notes renders nothing at all — not an empty heading.
// "NOTES (none)" is a line that teaches the reader to expect a block that is
// usually empty, and the block's whole value is that its presence means
// something.
func (n *notes) render(w io.Writer) {
	if len(n.all()) == 0 {
		return
	}
	fmt.Fprintln(w, "NOTES  (these also print on a real run under -v)")
	for _, nt := range n.all() {
		for line := range strings.SplitSeq(strings.TrimRight(nt.text, "\n"), "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
	// Trailing blank, not a leading one: every block above this ends with a
	// blank line already, so leading it would double the gap on a screen that
	// has notes and leave none on the one below.
	fmt.Fprintln(w)
}
