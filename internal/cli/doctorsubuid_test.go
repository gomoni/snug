package cli

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestDoctorWarnsAboutAMissingSubuidRangeAndDoesNotCondemnTheHost is issue
// #483's regression. doctor ran eleven checks on a host with no delegated
// range, printed none of them about /etc/subuid, and finished with
// `🎉 This host can run snug` — while every `-p @podman-*` run on that host
// died in container preflight P2.
//
// Both directions matter and the second is the one that would be a NEW bug: a
// missing range must warn, and it must not fail, because an offline sandbox
// maps one uid with no helper and never asks for a delegated range at all.
func TestDoctorWarnsAboutAMissingSubuidRangeAndDoesNotCondemnTheHost(t *testing.T) {
	const distroboxMap = "         0          1       1000\n" +
		"      1000          0          1\n" +
		"      1001       1001      64535\n"

	absent := func() error {
		return errors.New("/etc/subuid has no range for tester (id 1000); add one")
	}

	host := subuidHost{
		idMap:     distroboxMap,
		uid:       1000,
		name:      "tester",
		container: "running inside a container (distrobox/podman)",
	}

	out := captureStdout(t, func() { reportSubuidDelegation(absent, host) })
	if !strings.Contains(out, "⚠️") {
		t.Fatalf("a missing range printed no warning:\n%s", out)
	}
	if strings.Contains(out, "❌") {
		t.Fatalf("a missing range was reported as a failure; it gates the container engine only:\n%s", out)
	}
	// The detail has to reach the reader: the checker names WHICH of the four
	// things it looks at was missing, and "no range" and "newuidmap not
	// installed" are different fixes.
	if !strings.Contains(out, "/etc/subuid has no range for tester") {
		t.Fatalf("the checker's own detail was swallowed:\n%s", out)
	}
	if !strings.Contains(out, "goes away on every") {
		t.Fatalf("inside a container the report must say /etc/subuid is part of the image:\n%s", out)
	}

	out = captureStdout(t, func() { reportSubuidDelegation(func() error { return nil }, host) })
	if !strings.Contains(out, "✅") || strings.Contains(out, "⚠️") {
		t.Fatalf("a present range did not read as a tick:\n%s", out)
	}

	// The exit code is unchanged BY CONSTRUCTION: the report answers nothing a
	// caller could fold into doctor's `ok`. Asserted rather than trusted,
	// because "make it return whether it warned" is a one-line change that
	// would silently turn every rangeless host red.
	if n := reflect.TypeOf(reportSubuidDelegation).NumOut(); n != 0 {
		t.Fatalf("reportSubuidDelegation returns %d value(s); a WARN check must give doctor "+
			"nothing to fail on (issue #483)", n)
	}
}

// TestTheSuggestedSubuidRangeIsOneThisNamespaceCanActuallyMap is the half of
// #483 that the conventional advice gets wrong. `100000:65536` is what
// subuid(5), useradd and the checker's own message all say, and inside a
// keep-id distrobox it names nothing: the uid_map ends at 65535, so newuidmap
// cannot map an id at 100000 and the run fails exactly as it did before the
// line was added. A doctor that prints a fix which does not work is the same
// confident-wrong shape the ticket is about.
func TestTheSuggestedSubuidRangeIsOneThisNamespaceCanActuallyMap(t *testing.T) {
	for _, tc := range []struct {
		name      string
		idMap     string
		ownID     uint64
		wantBase  uint64
		wantSize  uint64
		wantFound bool
	}{
		{
			// MEASURED on this project's distrobox, podman keep-id, and the
			// line that works there is michal:1001:64535.
			name: "keep-id distrobox",
			idMap: "         0          1       1000\n" +
				"      1000          0          1\n" +
				"      1001       1001      64535\n",
			ownID: 1000, wantBase: 1001, wantSize: 64535, wantFound: true,
		},
		{
			// A bare host maps the whole space. The largest free run starts at
			// 0 and suggesting its start would delegate real host uids, so the
			// convention has to win wherever it fits.
			name:  "bare host",
			idMap: "         0          0 4294967295\n",
			ownID: 1000, wantBase: 100000, wantSize: 65536, wantFound: true,
		},
		{
			// Adjacent lines are one run, and own id is punched out of it: the
			// namespace-0 line of the child map already spends it.
			name: "adjacent lines coalesce around the caller",
			idMap: "0 0 1000\n" +
				"1000 5000 1\n" +
				"1001 6000 999\n",
			ownID: 1000, wantBase: 1001, wantSize: 999, wantFound: true,
		},
		{
			// The suggestion is capped: nothing here asks for more than the
			// conventional width.
			name:  "a wide run is capped at the conventional size",
			idMap: "200000 0 1000000\n",
			ownID: 1000, wantBase: 200000, wantSize: 65536, wantFound: true,
		},
		{
			// The map names one id and it is ours. Nothing to suggest, and the
			// report prints no 🔧 line rather than an unusable one.
			name:  "nothing left to delegate",
			idMap: "1000 1000 1\n",
			ownID: 1000, wantFound: false,
		},
		{
			// A read that failed, or a file that is not a map. A probe that
			// could not look must not answer — parseNetDev's rule.
			name:  "not a uid_map",
			idMap: "cat: /proc/self/uid_map: Permission denied\n",
			ownID: 1000, wantFound: false,
		},
		{
			// Namespace id 0 is root here and is never handed to a container,
			// so the run starting at 0 is offered from 1.
			name:  "namespace id 0 is never suggested",
			idMap: "0 0 500\n",
			ownID: 1000, wantBase: 1, wantSize: 499, wantFound: true,
		},
		{
			// A low run is passed over for a higher one even when it is wider:
			// ns 999 in a keep-id box is the user's own host uid, and a wider
			// suggestion down there delegates more real accounts, not fewer.
			name:  "the highest run wins, not the widest",
			idMap: "1 1 60000\n70000 70000 100\n",
			ownID: 1000, wantBase: 70000, wantSize: 100, wantFound: true,
		},
		{name: "empty", idMap: "", ownID: 1000, wantFound: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, size, ok := subuidSuggestion(tc.idMap, tc.ownID)
			if ok != tc.wantFound {
				t.Fatalf("subuidSuggestion ok = %v, want %v", ok, tc.wantFound)
			}
			if !ok {
				return
			}
			if base != tc.wantBase || size != tc.wantSize {
				t.Fatalf("subuidSuggestion = %d:%d, want %d:%d", base, size, tc.wantBase, tc.wantSize)
			}
			if base == 0 {
				t.Fatalf("suggested a range starting at namespace id 0 (%d:%d)", base, size)
			}
			if base <= tc.ownID && tc.ownID < base+size {
				t.Fatalf("suggested %d:%d contains the caller's own id %d, which the child map's "+
					"namespace-0 line already maps", base, size, tc.ownID)
			}
		})
	}
}

// TestTheSubuidReportNamesTheUnconventionalBaseAsUnconventional keeps the two
// halves above honest together. When the suggestion is not 100000 it disagrees
// with the example the checker's own error carries, and an unexplained
// disagreement between two lines of the same report is worse than either.
func TestTheSubuidReportNamesTheUnconventionalBaseAsUnconventional(t *testing.T) {
	absent := func() error { return errors.New("no range") }

	out := captureStdout(t, func() {
		reportSubuidDelegation(absent, subuidHost{
			idMap: "0 1 1000\n1000 0 1\n1001 1001 64535\n", uid: 1000, name: "tester",
		})
	})
	if !strings.Contains(out, "tester:1001:64535") {
		t.Fatalf("the report did not suggest the range this namespace can map:\n%s", out)
	}
	if !strings.Contains(out, "100000") {
		t.Fatalf("the report suggested an unconventional base without saying so:\n%s", out)
	}

	out = captureStdout(t, func() {
		reportSubuidDelegation(absent, subuidHost{idMap: "0 0 4294967295\n", uid: 1000, name: "tester"})
	})
	if !strings.Contains(out, "tester:100000:65536") {
		t.Fatalf("a bare host must get the conventional line:\n%s", out)
	}
	if strings.Contains(out, "cannot map it") {
		t.Fatalf("the conventional base was reported as unconventional:\n%s", out)
	}
}
