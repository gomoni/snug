package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// One unparseable file in profiles.d used to take the WHOLE registry down,
// builtins included — so `snug --dry-run -p @sys .` failed and `snug profile
// list`, the one command that would have said what still worked, failed too.
// A file the user may not have edited disabled @sys.
//
// The registry now keeps what loaded and reports what did not, and this file is
// the two halves of what callers do with that. The split is by CONSEQUENCE:
//
//   - running a sandbox is FATAL on any bad file (refuseBadFiles). The file that
//     did not parse may be the one granting what was asked for, so continuing
//     would assemble a sandbox out of whatever happened to load — a silent
//     downgrade, which is invariant 5's exact shape.
//   - a diagnostic command reports and continues (reportBadFiles), because "what
//     still works" is the question it is being asked.

// refuseBadFiles is the fatal half. It names every file, the error, and the
// diagnostic that still works — the last part matters, because the person
// reading this needs somewhere to go that is not "snug is broken".
func refuseBadFiles(bad []profile.BadFile) error {
	if len(bad) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d profile file(s) in the search path did not load:\n", len(bad))
	for _, f := range bad {
		fmt.Fprintf(&b, "         %s\n", policy.VisibleText(f.Path))
		for _, line := range badFileErrorLines(f) {
			fmt.Fprintf(&b, "           %s\n", line)
		}
	}
	b.WriteString("       snug will not start a sandbox while a profile file is unreadable: the file\n")
	b.WriteString("       that failed may be the one granting what you asked for, and a sandbox built\n")
	b.WriteString("       from whatever happened to load is a guess.\n")
	b.WriteString("       Fix or move the file. `snug profile list` and `snug doctor` still work and\n")
	b.WriteString("       show what did load.")
	return fmt.Errorf("%s", b.String())
}

// reportBadFiles is the diagnostic half: loud on stderr, and the command carries
// on with what did load. It returns whether anything was wrong, so the caller
// can still exit non-zero — the output is worth printing, and the exit code must
// not claim everything is fine.
func reportBadFiles(bad []profile.BadFile) bool {
	if len(bad) == 0 {
		return false
	}
	for _, f := range bad {
		fmt.Fprintf(os.Stderr, "snug: %s did not load, and every profile it defines is missing "+
			"from what follows:\n       %s\n", policy.VisibleText(f.Path),
			strings.Join(badFileErrorLines(f), "\n       "))
	}
	fmt.Fprintln(os.Stderr, "snug: continuing with the profiles that did load. A command that runs a "+
		"sandbox will refuse until this is fixed.")
	return true
}

// badFileErrorLines is a parser error, made safe to print, WITH ITS LINE
// STRUCTURE INTACT.
//
// Both callers render this text and both render a PATH beside it, and neither is
// snug's: the path comes from listing the profiles.d directory, and the error is
// go-toml's, which quotes the offending line of the file back at you. So this is
// the invariant-7 case — text a profile wrote arriving at a screen — at a sink
// that predates the rule.
//
// PER LINE, NOT WHOLE-STRING, and the reason is the diagram. go-toml's error is
// several lines with a caret under the offending column, and %q of the lot would
// turn the single most useful diagnostic snug prints into one unreadable string.
// Escaping each line keeps it.
//
// SAY WHAT THAT DOES NOT CLOSE, because it is the honest half: splitting on '\n'
// LAUNDERS a newline the error text carries — an injected line comes out as its
// own line rather than escaped. What contains that is the INDENTATION both
// callers apply: every line of this text is printed 11 or 7 spaces in, and the
// attacker does not choose the prefix, so a forged line cannot imitate one of
// snug's own. That is a weaker guarantee than the environment values get and it
// is the one available here; if it ever needs to be stronger, the answer is to
// stop embedding a foreign multi-line string, not to escape it twice.
func badFileErrorLines(f profile.BadFile) []string {
	lines := strings.Split(strings.TrimRight(f.Err.Error(), "\n"), "\n")
	for i, l := range lines {
		lines[i] = policy.VisibleText(l)
	}
	return lines
}

// unknownProfile is policy.UnknownProfile plus the skipped-file record, and
// without that second half the whole change would be a silent downgrade: a name
// defined in the file that failed to parse would come back as "unknown profile",
// which is a lie — snug does not know whether it exists, and the difference
// between "you typed it wrong" and "the file defining it is broken" is the whole
// of what the user needs.
func unknownProfile(reg profile.Registry, name policy.ProfileName, bad []profile.BadFile) error {
	err := policy.UnknownProfile(reg, name)
	if len(bad) == 0 {
		return err
	}
	var paths []string
	for _, f := range bad {
		paths = append(paths, f.Path)
	}
	return fmt.Errorf("%w\n       Note that %d file(s) did not load, so snug cannot say whether one of "+
		"them defines %q: %s", err, len(bad), name, strings.Join(paths, " "))
}
