package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The ladder's four outcomes, each driven for real through a fake bwrap that
// refuses exactly one flag. A host cannot be put into three of these four
// states on demand — the whole reason the ladder exists is that two of them
// were first seen in a CI container — so the fake is what makes the SET
// testable rather than the one outcome this machine happens to produce.
func TestLocateBwrapFailureFindsTheNarrowestRefusal(t *testing.T) {
	for _, tc := range []struct {
		name        string
		refuse      string // fail when this string appears in argv; "" = never
		want        bwrapBlocker
		wantLadder  string
		alsoRefuses string // a second flag refused at the same time
	}{
		{
			name:       "userns itself is refused",
			refuse:     "--unshare-user",
			want:       blockerUserns,
			wantLadder: "userns alone was refused",
		},
		{
			// MEASURED shape: GitHub Actions job container with
			// kernel.apparmor_restrict_unprivileged_userns=1, where bwrap
			// created the namespace and then said
			// "loopback: Failed RTM_NEWADDR: Operation not permitted".
			name:       "the netns is refused and the userns is not",
			refuse:     "--unshare-net",
			want:       blockerNetns,
			wantLadder: "adding --unshare-net is what fails",
		},
		{
			// MEASURED shape: the same container with the sysctl fixed, where
			// bwrap said "Can't mount proc on /newroot/proc: Operation not
			// permitted" because docker masks entries under /proc.
			name:       "the proc mount is refused and the namespaces are not",
			refuse:     "--proc",
			want:       blockerProcMount,
			wantLadder: "mounting /proc is what fails",
		},
		{
			// The honest answer, and the one that must NOT name a cause: every
			// rung passes and the full topology still failed.
			name:       "every rung passes",
			refuse:     "",
			want:       blockerUnknown,
			wantLadder: "each work on their own",
		},
		{
			// Ordering, which is bwrap's own: namespaces before mounts, and
			// the netns is created with the userns. A host refusing both must
			// report the netns, because that is the one a reader hits first.
			name:        "both the netns and the proc mount are refused",
			refuse:      "--unshare-net",
			alsoRefuses: "--proc",
			want:        blockerNetns,
			wantLadder:  "adding --unshare-net is what fails",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakeBwrap(t, tc.refuse, tc.alsoRefuses)
			got, ladder := locateBwrapFailure(fake)
			if got != tc.want {
				t.Errorf("locateBwrapFailure = %v (%q), want %v", got, ladder, tc.want)
			}
			if !strings.Contains(ladder, tc.wantLadder) {
				t.Errorf("ladder record = %q, does not contain %q", ladder, tc.wantLadder)
			}
		})
	}
}

// fakeBwrap writes a script that exits 1 when any refused flag appears in its
// argv and 0 otherwise. It is a stand-in for the KERNEL's answer, not for
// bwrap: what the ladder measures is which invocation is refused, and a script
// refuses on command.
func fakeBwrap(t *testing.T, refuse ...string) string {
	t.Helper()
	var conds []string
	for _, r := range refuse {
		if r != "" {
			conds = append(conds, "*"+r+"*) exit 1 ;;")
		}
	}
	script := "#!/bin/sh\ncase \" $* \" in\n" + strings.Join(conds, "\n") + "\nesac\nexit 0\n"
	path := filepath.Join(t.TempDir(), "bwrap")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// Positive control: with nothing refused the script must exit 0, or every
	// case above would read as "refused" and the test would pass vacuously.
	if _, ladder := locateBwrapFailure(path); len(conds) == 0 && !strings.Contains(ladder, "each work on their own") {
		t.Fatalf("control: a fake bwrap refusing nothing produced %q", ladder)
	}
	return path
}

// The advice is the half a human acts on, so it is asserted rather than
// assumed. Each blocker names its own fix and none of them names another's:
// the two CI failures this ladder exists for both printed the USERNS sysctls
// as their fix, which is what sent a reader to the wrong knob.
func TestEachBlockerNamesItsOwnFixAndNotAnothers(t *testing.T) {
	for _, tc := range []struct {
		blocker  bwrapBlocker
		mustSay  []string
		mustNot  []string
		headline string
	}{
		{
			blocker:  blockerUserns,
			mustSay:  []string{"kernel.unprivileged_userns_clone", "user.max_user_namespaces", "apparmor_restrict_unprivileged_userns"},
			mustNot:  []string{"systempaths", "unmask"},
			headline: "cannot create a user namespace",
		},
		{
			blocker: blockerNetns,
			// It must say the namespace was CREATED — that sentence is the
			// whole correction over the old single label.
			mustSay:  []string{"CREATED", "apparmor_restrict_unprivileged_userns", "HOST sysctl"},
			mustNot:  []string{"systempaths", "unmask"},
			headline: "network namespace does not",
		},
		{
			blocker:  blockerProcMount,
			mustSay:  []string{"systempaths=unconfined", "unmask=/proc", "masks entries under /proc"},
			mustNot:  []string{"unprivileged_userns_clone", "max_user_namespaces"},
			headline: "/proc cannot be mounted",
		},
	} {
		t.Run(tc.headline, func(t *testing.T) {
			body := tc.blocker.headline() + "\n" + strings.Join(tc.blocker.advice(), "\n")
			if !strings.Contains(tc.blocker.headline(), tc.headline) {
				t.Errorf("headline = %q, want it to contain %q", tc.blocker.headline(), tc.headline)
			}
			for _, want := range tc.mustSay {
				if !strings.Contains(body, want) {
					t.Errorf("%v does not name %q:\n%s", tc.blocker, want, body)
				}
			}
			for _, never := range tc.mustNot {
				if strings.Contains(body, never) {
					t.Errorf("%v names %q, which belongs to a different blocker:\n%s", tc.blocker, never, body)
				}
			}
		})
	}
}

// blockerUnknown is the one that must stay silent about causes. A probe that
// cannot tell must say it cannot tell — inventing a fix here is how the two
// measured misdiagnoses happened.
func TestTheUnrecognisedBlockerClaimsNoCauseAndOffersNoFix(t *testing.T) {
	if advice := blockerUnknown.advice(); advice != nil {
		t.Errorf("blockerUnknown.advice() = %q, want none", advice)
	}
	h := blockerUnknown.headline()
	if !strings.Contains(h, "not one this probe recognises") {
		t.Errorf("blockerUnknown.headline() = %q, want it to admit the probe cannot tell", h)
	}
	for _, never := range []string{"sysctl", "apparmor", "systempaths"} {
		if strings.Contains(strings.ToLower(h), never) {
			t.Errorf("blockerUnknown.headline() names %q, which is a cause it did not measure: %q", never, h)
		}
	}
}
