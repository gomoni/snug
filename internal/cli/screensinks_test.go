package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// rawForgingRune is the assertion every screen sweep in this package shares:
// nothing on a snug screen may alter how the rest of its line reads. '\n' is
// exempt because snug's own messages are legitimately several lines — which is
// also why every caller checks for the poisoned text VERBATIM as well, since a
// newline smuggled in through host text is the one spelling this predicate
// cannot see.
func rawForgingRune(screen string) (rune, bool) {
	i := strings.IndexFunc(screen, func(r rune) bool { return r != '\n' && policy.IsForgingRune(r) })
	if i < 0 {
		return 0, false
	}
	return []rune(screen[i:])[0], true
}

// THE CONTAINER AUDIT LINE IS THE ONLY SCREEN IN SNUG THAT RENDERS TEXT THE
// PAYLOAD WROTE.
//
// Every other sink swept in this package renders HOST text — a profile file, a
// gitconfig, an environment value chosen outside the sandbox. The proxy's -v
// channel renders strings derived from requests the SANDBOX made:
// `mount source %s resolves to %s` (internal/dockerproxy/create.go) puts a path
// the payload chose on the host user's terminal. A payload that wants a human to
// misread that line is not an edge case, it is the threat model.
//
// The escape is at the sink (containerAudit), so this test drives the sink and
// not the dozen dockerproxy call sites: a message added upstream tomorrow is
// covered by the same line of code, and by this test, without either being
// touched.
func TestTheContainerAuditLineEscapesPayloadText(t *testing.T) {
	const marker = "OLR-DEGROF"
	poisoned := "mount source /srv/a\u202e" + marker + " resolves to /srv/b\u009b1A"

	got := captureStdout(t, func() { containerAudit(true)(poisoned) })

	if !strings.Contains(got, marker) {
		t.Fatalf("the audit line never reached the screen, so this test measures nothing: %q", got)
	}
	if r, ok := rawForgingRune(got); ok {
		t.Errorf("the container audit line rendered %q raw. This is text the PAYLOAD chose: %q", r, got)
	}
	if strings.Contains(got, "\u202e") || strings.Contains(got, "\u009b") {
		t.Errorf("payload text reached the terminal unescaped: %q", got)
	}

	// Two controls. An ordinary message renders as itself — a sink that quoted
	// everything would pass the assertions above and make -v useless — and the
	// non-verbose sink prints nothing at all, which is what makes the audit
	// channel opt-in.
	plain := captureStdout(t, func() { containerAudit(true)("container create: 2 mount(s) allowed") })
	if !strings.Contains(plain, "snug: containers: container create: 2 mount(s) allowed") {
		t.Errorf("an ordinary audit message was mangled: %q", plain)
	}
	if quiet := captureStdout(t, func() { containerAudit(false)(poisoned) }); quiet != "" {
		t.Errorf("the audit channel printed without -v: %q", quiet)
	}
}

// A profile file that does not PARSE is still text a profile wrote, and it
// reaches two screens: `snug profile list` warns and continues, and anything
// that would start a sandbox refuses. Both render the FILE PATH (listed from the
// profiles.d directory, so snug did not choose it) and the parser's error (which
// quotes the offending line of the file back at you).
//
// This is the sink that predates the rule: the escaping guard was written for
// --dry-run's blocks, and a file that fails to parse never reaches a Policy, so
// no amount of sweeping the resolved-policy screens could ever have covered it.
func TestABadProfileFileCannotForgeALineOnTheScreen(t *testing.T) {
	const marker = "OLR-DEGROF"
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/snug/profiles.d", 0o755); err != nil {
		t.Fatal(err)
	}
	// The PATH carries the override and the CONTENT carries a C1 in a string the
	// parser will complain about, so both channels are poisoned in one fixture.
	path := dir + "/snug/profiles.d/broken\u202e" + marker + ".toml"
	if err := os.WriteFile(path, []byte("[profile.x\ndescription = \"a\u009b1A\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := captureStdout(t, func() { profileCmd([]string{"list"}) })
	if !strings.Contains(got, "did not load") {
		t.Fatalf("the bad file was not reported at all, so this test measures nothing:\n%s", got)
	}
	if !strings.Contains(got, marker) {
		t.Fatalf("the poisoned path never reached the screen:\n%s", got)
	}
	if r, ok := rawForgingRune(got); ok {
		t.Errorf("`profile list` rendered %q raw while reporting an unparseable file:\n%q", r, got)
	}
	if strings.Contains(got, "\u202e") {
		t.Errorf("the file path reached the screen unescaped:\n%q", got)
	}
}
