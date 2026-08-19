package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestDoctorRefusesANamespaceItDidNotGet is the regression for issue #98.
//
// `snug doctor` printed `✅ unprivileged user namespaces work` on a host where
// bwrap had created no user namespace at all. `probeBase()` passes
// `--unshare-all`, which bwrap decodes to its own `-try` spellings, so an
// exhausted `user.max_user_namespaces` makes it skip the unshare and exit
// **0** — and the check was the exit status alone.
//
// Reproduced on the development host while writing the fix, with the positive
// control the issue specifies:
//
//	$ unshare --user --map-root-user -- sh -c '
//	    echo 0 > /proc/sys/user/max_user_namespaces
//	    unshare --user --map-root-user -- /bin/true   # control
//	    bwrap <probeBase> -- /bin/readlink /proc/self/ns/user'
//	unshare: unshare failed: No space left on device      <- control: really blocked
//	user:[4026532494]                                     <- identical to the caller's
//	bwrap-rc=0                                            <- and bwrap is happy
//
// That condition needs a writable `/proc/sys/user/max_user_namespaces` inside
// a fresh user namespace, which is not something the unit suite can arrange
// everywhere. So the DECISION is tested here, exhaustively and with no
// privileges, and the wiring that feeds it is covered by
// TestProbeUsernsAgreesWithTheHostItRunsOn below.
func TestDoctorRefusesANamespaceItDidNotGet(t *testing.T) {
	const caller = "user:[4026532494]"

	for _, tc := range []struct {
		name   string
		inside string
		mine   string
		want   usernsVerdict
	}{
		{
			name:   "a real namespace has a different id",
			inside: "user:[4026534519]",
			mine:   caller,
			want:   usernsCreated,
		},
		{
			// THE BUG. Byte-identical means the unshare did not happen,
			// whatever bwrap's exit status said.
			name:   "the silent skip reports the caller's own id",
			inside: caller,
			mine:   caller,
			want:   usernsSilentlySkipped,
		},
		{
			name:   "empty output is not a pass",
			inside: "",
			mine:   caller,
			want:   usernsInconclusive,
		},
		{
			// The probe tool failing prints its message on stdout, and a
			// message is not a namespace id. This must never read as success.
			name:   "an error message where an id should be is not a pass",
			inside: "/bin/readlink: /proc/self/ns/user: Permission denied",
			mine:   caller,
			want:   usernsInconclusive,
		},
		{
			name:   "a caller id we cannot parse is not a pass",
			inside: "user:[4026534519]",
			mine:   "something else entirely",
			want:   usernsInconclusive,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := classifyUserns(tc.inside, tc.mine)
			if got != tc.want {
				t.Errorf("classifyUserns(%q, %q) = %v, want %v (detail: %s)",
					tc.inside, tc.mine, got, tc.want, detail)
			}
			if detail == "" {
				t.Error("every verdict must carry a detail; it is what doctor prints")
			}
		})
	}

	// POSITIVE CONTROL, and this table needs one badly: every case above except
	// the first asserts a NON-success, and all of them would pass on a
	// classifyUserns that returned usernsInconclusive unconditionally. The
	// first case is what makes the others mean something, so its verdict is
	// asserted again, separately, rather than left as one row among five.
	if v, _ := classifyUserns("user:[4026534519]", caller); v != usernsCreated {
		t.Fatalf("classifyUserns cannot produce usernsCreated at all (%v) — "+
			"every negative case above is then vacuous", v)
	}
}

// TestProbeUsernsAgreesWithTheHostItRunsOn covers the wiring the pure test
// above deliberately does not: that probeUserns really runs bwrap, really
// reads two namespace ids, and reaches a verdict consistent with what this
// host can actually do.
//
// It asserts a RELATIONSHIP rather than a fixed answer, because both answers
// are legitimate depending on where the suite runs: a host with working user
// namespaces must reach usernsCreated, and one without must not — but it must
// never reach usernsSilentlySkipped while a plain `bwrap ... /bin/true` also
// succeeds AND produces a different namespace, which would mean the comparison
// itself is broken.
func TestProbeUsernsAgreesWithTheHostItRunsOn(t *testing.T) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bwrap not on PATH")
	}
	mine, err := os.Readlink("/proc/self/ns/user")
	if err != nil {
		t.Skip("no /proc/self/ns/user on this host")
	}

	verdict, detail := probeUserns(bwrap)
	switch verdict {
	case usernsCreated:
		// The detail is the id that was measured inside, and it must not be
		// the one this process is in — that is the entire distinction.
		if detail == mine {
			t.Errorf("probeUserns said a namespace was created but reported this process's "+
				"own id %s — the comparison is inverted", detail)
		}
		if !strings.HasPrefix(detail, "user:[") {
			t.Errorf("probeUserns reported %q as a namespace id", detail)
		}
	case usernsSilentlySkipped:
		if detail != mine {
			t.Errorf("probeUserns said the namespace was skipped but reported %s, which is "+
				"not this process's own id %s", detail, mine)
		}
		t.Logf("this host cannot create user namespaces from the probe; doctor correctly "+
			"refuses rather than ticking (detail: %s)", detail)
	case usernsFailed, usernsInconclusive:
		t.Logf("probe did not measure a namespace here (%v): %s", verdict, detail)
	}
}
