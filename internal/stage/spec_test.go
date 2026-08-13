package stage

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestGoldenStageSpec is the review artifact for the parts of this package's
// shape that a bwrap argv diff cannot show at all (SUPERVISOR-DESIGN.md
// §4 Step 4, exit criterion 2's "golden argv is necessary and not sufficient
// here"): the clone(2) flags P1 is created with, the single-uid/gid map, the
// fixed descriptor numbers nothing in an environment variable ever carries
// (fds.go's doc comment explains why), and — for cross-check, because these
// two sets are chosen together even though they live in different packages —
// the bwrap --unshare-* set internal/policy/bwrap.go emits under
// policy.NetnsStage.
//
// Every value below is read from the SAME symbols the real code paths use
// (stageCloneflags, the fd constants, and policy.Policy.BwrapFlags itself)
// rather than re-typed as literals, so this test fails the moment either
// package's shape drifts from the other's — which is the whole point of a
// golden that spans two packages describing one topology.
func TestGoldenStageSpec(t *testing.T) {
	got := spec()

	path := "testdata/stage.spec.txt"
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/stage -update)", err)
	}
	if got != string(want) {
		t.Errorf("the stage's spec changed — this is the shape a bwrap argv diff "+
			"cannot show at all (no process in this topology has an argv that names "+
			"a clone flag or a uid map).\n--- got\n%s\n--- want\n%s", got, string(want))
	}
}

// spec renders the fixed shape in a stable, host-independent form: real uids
// would make the golden differ by whoever runs the test, so the map lines are
// templated rather than filled in.
func spec() string {
	var b strings.Builder

	fmt.Fprintln(&b, "CLONE FLAGS (P1, __stage-setup — stageCloneflags)")
	for _, f := range cloneflagNames(stageCloneflags) {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "UID MAP")
	fmt.Fprintln(&b, "  0 <hostuid> 1")
	fmt.Fprintln(&b, "GID MAP")
	fmt.Fprintln(&b, "  0 <hostgid> 1  (GidMappingsEnableSetgroups=false)")
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "DESCRIPTORS (fixed; nothing travels in the environment — fds.go)")
	fmt.Fprintf(&b, "  fd %-4d control       SOCK_SEQPACKET socketpair, P1's end\n", fdControl)
	fmt.Fprintf(&b, "  fd %-4d lifeline      read end of an anonymous pipe; P0 holds the write end\n", fdLife)
	fmt.Fprintf(&b, "  fd %-4d.. sandbox     K descriptors, dup3'd to 3..3+K-1 in the bwrap child\n", fdSandboxBase)
	fmt.Fprintf(&b, "  fd %-4d N-socket      AF_INET socket CREATED IN N; still answers for N after the move\n", fdNetSock)
	fmt.Fprintf(&b, "  fd %-4d netns-N       the descriptor P1 pins on N before it leaves (not CLOEXEC until __stage-serve)\n", fdNetnsN)
	fmt.Fprintf(&b, "  budget        K <= %d, checked on BOTH sides of the control socket (checkFDBudget)\n", maxPassthrough)
	fmt.Fprintln(&b)

	fmt.Fprintln(&b, "BWRAP UNSHARE SET under policy.NetnsStage (internal/policy/bwrap.go)")
	for _, f := range bwrapStageUnshareFlags() {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	fmt.Fprintln(&b, "  (omits --unshare-net: N already exists, pinned by P1 and handed to bwrap")
	fmt.Fprintln(&b, "   by the __innetns setns shim, before bwrap ever runs)")

	return b.String()
}

// cloneflagNames renders a Cloneflags value as the CLONE_NEW* symbols it is
// made of, in a fixed, deterministic order — never range over a map, whose
// iteration order Go deliberately randomises.
func cloneflagNames(flags uintptr) []string {
	named := []struct {
		bit  uintptr
		name string
	}{
		{syscall.CLONE_NEWUSER, "CLONE_NEWUSER"},
		{syscall.CLONE_NEWNET, "CLONE_NEWNET"},
		{syscall.CLONE_NEWNS, "CLONE_NEWNS"},
		{syscall.CLONE_NEWCGROUP, "CLONE_NEWCGROUP"},
		{syscall.CLONE_NEWPID, "CLONE_NEWPID"},
		{syscall.CLONE_NEWIPC, "CLONE_NEWIPC"},
		{syscall.CLONE_NEWUTS, "CLONE_NEWUTS"},
	}
	var out []string
	seen := uintptr(0)
	for _, n := range named {
		if flags&n.bit != 0 {
			out = append(out, n.name)
			seen |= n.bit
		}
	}
	if rest := flags &^ seen; rest != 0 {
		// A bit this table does not name — fail loudly in the golden rather
		// than silently omitting it, the same discipline
		// TestBwrapUnshareSetIsExhaustive applies one package over.
		out = append(out, fmt.Sprintf("UNKNOWN(0x%x)", rest))
	}
	return out
}

// bwrapStageUnshareFlags asks internal/policy for the REAL argv a stage-topology
// policy produces and returns just the leading --unshare-* run, so this golden
// is reading the same code path bwrap.go's own comment and
// TestBwrapUnshareSetIsExhaustive describe, not a second copy of the list.
func bwrapStageUnshareFlags() []string {
	p := &policy.Policy{Topology: policy.Topology{Netns: policy.NetnsStage}}
	flags := p.BwrapFlags(0, 0, func(string) int { return 0 })
	var out []string
	for _, f := range flags {
		if !strings.HasPrefix(f, "--unshare-") {
			break
		}
		out = append(out, f)
	}
	return out
}
