package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// A profile file that does not load is kept out of the registry and reported;
// the rest of the registry is still good. This file is what callers do with
// that, split by CONSEQUENCE:
//
//   - a command that runs a sandbox refuses when its selection, or anything
//     that selection includes, names a profile a bad file defines
//     (refuseBadSelection). That file may be the one granting what was asked
//     for, and a sandbox assembled without it is a silent downgrade —
//     invariant 5's exact shape. A run whose selection lies entirely in files
//     that loaded runs, and says which files did not (noteBadFiles).
//   - a diagnostic command reports and continues (reportBadFiles), because "what
//     still works" is the question it is being asked.

// refuseBadSelection walks the selection's include closure through the
// registry. The first name the registry does not hold is refused through
// unknownProfile, which says whether a file that did not load defines it; a
// closure that lies entirely in the registry is not refused, whatever else
// failed to load. The walk is the same one policy.Expand makes, done here
// because only this package has the bad files to name.
func refuseBadSelection(reg profile.Registry, selected []policy.ProfileName, bad []profile.BadFile) error {
	if len(bad) == 0 {
		return nil
	}
	seen := map[policy.ProfileName]bool{}
	queue := slices.Clone(selected)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if seen[n] {
			continue
		}
		seen[n] = true
		p, ok := reg[n]
		if !ok {
			return unknownProfile(reg, n, bad)
		}
		queue = append(queue, p.Include...)
	}
	return nil
}

// noteBadFiles is the run that goes ahead: its selection is whole, and a file
// it did not ask for is broken. Said on every run, not only under -v, because
// the file is somebody's profile that no run can select until it is fixed, and
// the one place its owner would otherwise learn that is the refusal.
func noteBadFiles(n *notes, bad []profile.BadFile) {
	if len(bad) == 0 {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "snug: %d profile file(s) did not load; every profile this run selects loaded from other files:\n", len(bad))
	for _, f := range bad {
		fmt.Fprintf(&b, "       %s\n", policy.VisibleText(f.Path))
		for _, line := range badFileErrorLines(f) {
			fmt.Fprintf(&b, "         %s\n", line)
		}
	}
	b.WriteString("       A run selecting a profile from one of them refuses until it is fixed. " +
		"`snug doctor` reports the same.\n")
	n.broken("%s", b.String())
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
	fmt.Fprintln(os.Stderr, "snug: continuing with the profiles that did load. A run selecting a "+
		"profile from a file that did not load refuses until it is fixed.")
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
// without that second half a name defined in a file that failed to load would
// come back as "unknown profile", which is a lie. Three answers, most precise
// first:
//
//   - a bad file defines the name: say which file, and its error, because that
//     error is the fix;
//   - a bad file's names are unrecoverable (not TOML, or not readable): snug
//     cannot say whether it defines the name, and says so;
//   - every bad file's names are known and none is this one: the resolver's
//     own message, with no speculation — an unconditional footnote would train
//     people to skip it.
func unknownProfile(reg profile.Registry, name policy.ProfileName, bad []profile.BadFile) error {
	for _, f := range bad {
		if slices.Contains(f.Defines, name) {
			return fmt.Errorf("profile %q is defined in %s, which did not load:\n       %s\n"+
				"       snug will not start a sandbox without a profile it was asked for. Fix "+
				"the file, or leave %q out of the selection. If the file was written for a "+
				"newer snug, this one does not understand it",
				name, policy.VisibleText(f.Path),
				strings.Join(badFileErrorLines(f), "\n       "), name)
		}
	}
	err := policy.UnknownProfile(reg, name)
	var paths []string
	for _, f := range bad {
		if !f.NamesKnown {
			paths = append(paths, policy.VisibleText(f.Path))
		}
	}
	if len(paths) == 0 {
		return err
	}
	return fmt.Errorf("%w\n       Note that %d file(s) did not load, so snug cannot say whether one of "+
		"them defines %q: %s", err, len(paths), name, strings.Join(paths, " "))
}
