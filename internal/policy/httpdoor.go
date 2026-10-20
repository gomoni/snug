package policy

import (
	"fmt"
	"strings"
)

// MaxHTTPDoorNameLen bounds a door name. The name reaches three places that
// each have their own limit or hazard, and this is the smallest of them: it is a
// path component of the run's unix socket, where AF_UNIX gives 107 usable bytes
// for the WHOLE path (test/guard/runtimedirlengthsweep_test.go is the ratchet
// and the scratchpad path alone already exceeds it); it is a LISTEN_FDNAMES
// element, which is colon-separated; and it is what a human types after
// `snug proxy`. 32 leaves room for every legible name and cannot be the reason a
// socket path overruns.
const MaxHTTPDoorNameLen = 32

// checkHTTPDoorName enforces the name grammar.
//
// Lowercase ASCII letters, digits and single interior dashes. The set is narrow
// on purpose rather than "anything without a slash": the name becomes a
// filesystem path component AND a colon-separated LISTEN_FDNAMES element, so a
// colon, a slash, a dot-dot or a leading dash each turn one grant into a
// different one somewhere downstream. Refusing the whole class is one rule;
// escaping it correctly in three places is three rules and a future bug.
//
// An unrecognised name REFUSES and is never narrowed to the nearest thing it
// resembles — the same rule ParseNetMode and ParseSSHMode follow, and the reason
// the accepted set can be read as the whole set.
func checkHTTPDoorName(name ProfileName, raw string) error {
	bad := func(why string) error {
		return fmt.Errorf("profile %q: listen_names door name %s %s.\n"+
			"       A door name is lowercase letters, digits and interior dashes, at most %d "+
			"characters —\n"+
			"       it becomes a path component of this run's socket and an entry in "+
			"LISTEN_FDNAMES, so\n"+
			"       the narrow set is what keeps one grant from meaning something else "+
			"downstream. Try \"web\".",
			name, VisibleText(raw), why, MaxHTTPDoorNameLen)
	}
	switch {
	case raw == "":
		return bad("is empty")
	case len(raw) > MaxHTTPDoorNameLen:
		return bad(fmt.Sprintf("is %d characters", len(raw)))
	case strings.HasPrefix(raw, "-"), strings.HasSuffix(raw, "-"):
		return bad("starts or ends with a dash")
	case strings.Contains(raw, "--"):
		return bad("contains a double dash")
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return bad(fmt.Sprintf("contains %s", VisibleText(string(r))))
		}
	}
	return nil
}
