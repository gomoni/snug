package attach

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestAttachJoinsExactlySevenNamespacesInOneCall is §13.2 test 10: a golden
// on the exact CLONE_NEW* bit pattern SevenNamespaceFlags carries into the
// ONE setns(2) call child.go's step 5 makes. A change to this value is a
// change to the security boundary — either a namespace stops being joined
// (§3's table says what that costs) or one starts being joined that §3 never
// argued for — so this test spells out the exact seven flags rather than
// merely asserting a bit count, and fails on ANY of: a flag missing, an
// extra flag present, or CLONE_NEWUSER's bit swapped for CLONE_NEWTIME's
// neighbour by a typo.
func TestAttachJoinsExactlySevenNamespacesInOneCall(t *testing.T) {
	want := unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID |
		unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP

	if SevenNamespaceFlags != want {
		t.Fatalf("SevenNamespaceFlags = %#x, want %#x — a change here is a change to which "+
			"namespaces attach joins and must be read as a change to the security boundary "+
			"(design §3's table)", SevenNamespaceFlags, want)
	}

	// Individually, so a future edit that drops exactly one flag (the failure
	// mode §3's table warns about per-flag) names WHICH one rather than just
	// "the golden changed".
	for name, flag := range map[string]int{
		"CLONE_NEWUSER":   unix.CLONE_NEWUSER,
		"CLONE_NEWNS":     unix.CLONE_NEWNS,
		"CLONE_NEWPID":    unix.CLONE_NEWPID,
		"CLONE_NEWNET":    unix.CLONE_NEWNET,
		"CLONE_NEWIPC":    unix.CLONE_NEWIPC,
		"CLONE_NEWUTS":    unix.CLONE_NEWUTS,
		"CLONE_NEWCGROUP": unix.CLONE_NEWCGROUP,
	} {
		if SevenNamespaceFlags&flag == 0 {
			t.Errorf("SevenNamespaceFlags is missing %s", name)
		}
	}

	// CLONE_NEWTIME is deliberately absent (the package doc's own reasoning:
	// bwrap creates no time namespace, and CLONE_NEWTIME applies to children
	// only in any case) — a positive control that this test can actually
	// detect an EXTRA flag, not merely a missing one.
	if SevenNamespaceFlags&unix.CLONE_NEWTIME != 0 {
		t.Error("SevenNamespaceFlags includes CLONE_NEWTIME, which the package doc says is " +
			"deliberately never joined")
	}

	// Exactly seven bits set — catches an extra flag this enumeration did not
	// think to name explicitly.
	bits := 0
	for b := uint(0); b < 32; b++ {
		if SevenNamespaceFlags&(1<<b) != 0 {
			bits++
		}
	}
	if bits != 7 {
		t.Errorf("SevenNamespaceFlags has %d bits set, want exactly 7", bits)
	}
}
