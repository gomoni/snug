package fdseal

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSealingClosesTheSOURCEDescriptorsExecPassesDown is the unit-level
// regression for review finding F1, and it needs no privileges, no namespaces
// and no bwrap — which is the point: the fact it pins is a fact about Go's
// fork/exec, and it is the fact the whole "a payload holds no descriptor it
// can open" property rests on.
//
// Go installs a child's descriptors with dup3(source, target, 0) and does NOT
// close the source. So whenever a source number is HIGHER than the target it
// is dup'd onto — the normal case in a process that received its descriptors
// from someone else — the source survives into the child at its old number as
// a second, fully usable copy. In the stage that meant the payload holding the
// snug-args memfd, read-write, at fd 9: its own complete resolved boundary.
//
// The negative half asserts sealing removes them. The POSITIVE CONTROL is the
// other half of the same test: without the seal the child must still see them,
// because an assertion about descriptors that were never inherited in the
// first place would pass on any Go version, including one that started closing
// its sources and made this whole package unnecessary.
func TestSealingClosesTheSOURCEDescriptorsExecPassesDown(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("no /proc; this test is about /proc/<pid>/fd by construction")
	}

	// Sources deliberately high, so exec has to move them DOWN to 3/4/5 and
	// the leak has somewhere to survive.
	const sourceBase = 30
	var extra []*os.File
	for i := range 3 {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		// Dup3 with flags 0 reproduces exactly what an inherited ExtraFiles
		// descriptor looks like in a child: a fixed number, not CLOEXEC.
		if err := unix.Dup3(int(r.Fd()), sourceBase+i, 0); err != nil {
			t.Fatal(err)
		}
		f := os.NewFile(uintptr(sourceBase+i), "leaky-"+strconv.Itoa(i))
		defer f.Close()
		extra = append(extra, f)
	}

	run := func(seal bool) map[int]bool {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", "ls /proc/self/fd")
		cmd.ExtraFiles = extra
		cmd.Env = []string{}
		if seal {
			if err := SealFor(cmd); err != nil {
				t.Fatal(err)
			}
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("running the probe (seal=%v): %v", seal, err)
		}
		got := map[int]bool{}
		for _, f := range strings.Fields(string(out)) {
			if n, err := strconv.Atoi(f); err == nil {
				got[n] = true
			}
		}
		return got
	}

	// POSITIVE CONTROL first, per the house rule: the hazard is real here and
	// now, on this Go version, or the negative below means nothing.
	unsealed := run(false)
	leaked := 0
	for i := range 3 {
		if unsealed[sourceBase+i] {
			leaked++
		}
	}
	if leaked == 0 {
		t.Fatalf("PRECONDITION: an UNSEALED fork leaked none of the source descriptors "+
			"%d..%d into the child, so this test cannot detect the thing it exists to "+
			"detect. Either Go changed its fork/exec (check syscall/exec_linux.go's "+
			"\"Pass 2\") or the probe is broken. Child saw: %v",
			sourceBase, sourceBase+2, unsealed)
	}

	sealed := run(true)
	for i := range 3 {
		if sealed[sourceBase+i] {
			t.Errorf("fd %d survived into the child after SealFor — the source descriptor "+
				"was passed down as a second copy at its original number, which is exactly "+
				"how the payload came to hold the args memfd", sourceBase+i)
		}
	}
	// And the descriptors the fork was actually ASKED to install must still be
	// there: a seal that broke the hand-off would "pass" the assertion above.
	for i := range 3 {
		if !sealed[3+i] {
			t.Errorf("fd %d is MISSING from the child after SealFor — sealing must not "+
				"disturb the descriptors exec installs, which it re-clears CLOEXEC on. "+
				"Child saw: %v", 3+i, sealed)
		}
	}
}

// TestSealForRefusesAClosedExtraFile: in a long-lived forker a stale
// *os.File in ExtraFiles is not a nil-pointer panic, it is a child handed a
// descriptor number that now means something else — and every later number in
// that list shifts with it. Fail loudly at the fork instead.
func TestSealForRefusesAClosedExtraFile(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r.Close()

	cmd := exec.Command("/bin/true")
	cmd.ExtraFiles = []*os.File{r}
	if err := SealFor(cmd); err == nil {
		t.Error("SealFor accepted an already-closed ExtraFiles entry")
	}
}
