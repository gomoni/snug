package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── issue #223: a profile can take over /tmp and nothing said so ────────────
//
// yieldTo() installs snug's own mount only if nothing already claims that guest
// path. That is deliberate — it is how @tmp-shared works. What is not deliberate
// is @parent-ro reaching /tmp by accident of where the target sits: `snug
// /tmp/proj` makes the target's parent /tmp, so the private tmpfs never lands and
// the sandbox runs with the HOST's /tmp read-only, $TMPDIR pointing into it, no
// refusal and nothing on screen.
//
// Two things stop being true for that run, and the first is a documented count.
// CLAUDE.md says the writable surface is EIGHT paths with /tmp among them; here
// it is seven, and nothing said the guarantee changed. That is invariant 5's
// subject exactly.
//
// SAID RATHER THAN REFUSED, deliberately: `snug /tmp/x` is ordinary — `mktemp -d`
// targets are how VERIFY.md and the whole integration suite build theirs — so a
// refusal would break snug's own workflow unless it could tell "the yield was
// asked for" from "the yield happened by accident", and this layer cannot.
//
// WHY THIS IS NOT A GOLDEN. The change moved no golden at all, because every
// dry-run fixture in this package uses a synthetic target that is not under /tmp.
// A golden nobody's fixture exercises proves nothing about the row it renders —
// the same gap issue #59 turned up in NOT GRANTED.

// renderFilesystem builds a policy with one mount at guest and returns the
// FILESYSTEM block. authored mirrors what yieldTo() sets on snug's own mounts.
func renderFilesystem(t *testing.T, guest string, kind policy.Kind, access policy.Access, authored bool, from string) string {
	t.Helper()
	p := &policy.Policy{
		Target: "/home/u/proj",
		Home:   "/home/u",
		Mounts: map[string]policy.Mount{
			guest: {
				Kind: kind, Guest: guest, Host: guest,
				Access: access, Authored: authored, From: []string{from},
			},
		},
	}
	return dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)
}

func TestDryRunSaysWhenAProfileTookOverSnugsOwnTmp(t *testing.T) {
	got := renderFilesystem(t, "/tmp", policy.KindBind, policy.AccessRO, false, "@parent-ro")

	for _, want := range []struct{ text, why string }{
		{"HOST's /tmp", "the fact: it is not snug's private one"},
		{"never landed", "why — the tmpfs snug would have installed did not"},
		{"$TMPDIR points inside it", "the practical consequence, and the one that breaks builds"},
		{"READ-ONLY", "this row is a ro bind, so the tmpdir is read-only too"},
	} {
		if !strings.Contains(got, want.text) {
			t.Errorf("the /tmp row does not say %q — %s\n%s", want.text, want.why, got)
		}
	}
}

// A rw takeover (@tmp-shared's shape) is a deliberate, documented profile doing
// its job. It still gets the "this is the host's" note, because that is true and
// worth knowing — but not the read-only warning, which would be false.
func TestAWritableTakeoverIsNotCalledReadOnly(t *testing.T) {
	got := renderFilesystem(t, "/tmp", policy.KindBind, policy.AccessRW, false, "@tmp-shared")
	if !strings.Contains(got, "HOST's /tmp") {
		t.Errorf("a writable takeover still replaces snug's private tmpfs and must say so:\n%s", got)
	}
	if strings.Contains(got, "READ-ONLY") {
		t.Errorf("a rw bind was described as READ-ONLY, which is simply false:\n%s", got)
	}
}

// THE POSITIVE CONTROL, and the one that makes the test above mean anything.
// snug's own tmpfs at /tmp must render with no mark at all — otherwise every
// ordinary run carries a warning, and a warning on every run is one nobody reads.
func TestSnugsOwnTmpCarriesNoMark(t *testing.T) {
	got := renderFilesystem(t, "/tmp", policy.KindTmpfs, policy.AccessRW, true, "(snug)")
	for _, unwanted := range []string{"HOST's /tmp", "never landed", "READ-ONLY"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("snug's OWN /tmp was marked as a takeover (%q). The mark keys on "+
				"Mount.Authored, which yieldTo() sets; if that stopped being set, every "+
				"default run now carries this warning:\n%s", unwanted, got)
		}
	}
}

// /proc and /dev go through the same yieldTo() and have the same blind spot.
// Asserting the set rather than the site, per CLAUDE.md.
func TestTheOtherYieldablePathsAreCoveredToo(t *testing.T) {
	for _, guest := range []string{"/proc", "/dev"} {
		got := renderFilesystem(t, guest, policy.KindBind, policy.AccessRO, false, "@probe")
		if !strings.Contains(got, "a profile claimed "+guest) {
			t.Errorf("a profile took over %s and the screen did not say so. yieldTo() treats "+
				"/proc, /dev and /tmp identically, so a mark for one of the three and not the "+
				"others is the 'rule applied to one of its halves' shape:\n%s", guest, got)
		}
	}
}

// An ordinary row must not gain a mark. Without this, a mark that fired on
// everything would satisfy every assertion above.
func TestAnUnrelatedRowIsNotMarked(t *testing.T) {
	got := renderFilesystem(t, "/usr", policy.KindBind, policy.AccessRO, false, "@sys")
	for _, unwanted := range []string{"HOST's /tmp", "a profile claimed"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("an ordinary /usr row was marked (%q):\n%s", unwanted, got)
		}
	}
}
