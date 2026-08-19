package policy

import (
	"slices"
	"testing"
)

// allNetnsOwners is every value of the lattice, iterated rather than listed at
// each call site: a fourth NetnsOwner is then covered by these tests the day it
// is added, instead of the day someone remembers to extend a table.
var allNetnsOwners = []NetnsOwner{NetnsSandbox, NetnsStage, NetnsHost}

// TestUnshareFlagsUserIsAlwaysStrict pins issue #24's ruling at the authority
// rather than inside one branch of an if.
//
// --unshare-user-try silently swallows a narrow but real case: a uid-0 caller
// whose own namespace's max_user_namespaces reads "0" gets no user namespace
// and NO ERROR. The stage's own topology puts every @net run's bwrap in exactly
// that bucket, because P1 runs bwrap as uid 0 in its own user namespace,
// regardless of the human's uid. Strict makes that failure fatal (invariant 5)
// with bwrap's own message naming the sysctl.
//
// Issue #98 is what happens when something asks for -try anyway: snug doctor
// printed a green tick for a host where the sandbox had no user namespace.
func TestUnshareFlagsUserIsAlwaysStrict(t *testing.T) {
	for _, owner := range allNetnsOwners {
		t.Run(owner.String(), func(t *testing.T) {
			got := Topology{Netns: owner}.UnshareFlags()
			if !slices.Contains(got, "--unshare-user") {
				t.Errorf("netns=%s does not ask for --unshare-user at all: %v", owner, got)
			}
			if slices.Contains(got, "--unshare-user-try") {
				t.Errorf("netns=%s asks for --unshare-user-TRY, which exits 0 having created "+
					"no user namespace when the ucount is exhausted (issues #24, #98): %v", owner, got)
			}
		})
	}
}

// TestUnshareFlagsCgroupStaysTry guards the asymmetry, which looks like an
// oversight and is not.
//
// cgroup's -try is only a stat("/proc/self/ns/cgroup") KERNEL-SUPPORT check,
// not a resource check, and any resource failure already takes the whole
// clone() down loudly regardless of it. Going strict would trade a risk
// measurement found not to exist for a real one: refusing a host built without
// CONFIG_CGROUPS. The failure message carries that reasoning so a future
// "consistency" cleanup reads why before it proceeds.
func TestUnshareFlagsCgroupStaysTry(t *testing.T) {
	for _, owner := range allNetnsOwners {
		t.Run(owner.String(), func(t *testing.T) {
			got := Topology{Netns: owner}.UnshareFlags()
			if !slices.Contains(got, "--unshare-cgroup-try") {
				t.Errorf("netns=%s does not ask for --unshare-cgroup-try: %v", owner, got)
			}
			if slices.Contains(got, "--unshare-cgroup") {
				t.Errorf("netns=%s asks for the STRICT --unshare-cgroup. The -try here is a "+
					"kernel-support check, not a resource check (issue #24's measurement), so "+
					"strict buys nothing and refuses a host built without CONFIG_CGROUPS: %v",
					owner, got)
			}
		})
	}
}

// TestStageTopologyNeverUnsharesNet is the negative, and it is the one with
// teeth: under the stage, N already exists — P1 created it, pinned it with a
// descriptor and a setns shim put bwrap back into it before bwrap ever ran. A
// bwrap that unshares net discards that N and makes a second, unpinned one
// pasta was never aimed at. Measured: that is exactly what left pasta unable to
// bring up an interface.
func TestStageTopologyNeverUnsharesNet(t *testing.T) {
	got := Topology{Netns: NetnsStage}.UnshareFlags()
	if slices.Contains(got, "--unshare-net") {
		t.Errorf("the stage topology asks bwrap to unshare net, which would discard the "+
			"pinned N that pasta is already attached to: %v", got)
	}
}

// TestEveryNonStageTopologyUnsharesNet is TestStageTopologyNeverUnsharesNet's
// positive control, and without it that test passes on a UnshareFlags that
// returns nil.
//
// It is also the assertion in its own right: dropping net here would silently
// restore host networking, the worst outcome available from this function.
func TestEveryNonStageTopologyUnsharesNet(t *testing.T) {
	for _, owner := range []NetnsOwner{NetnsSandbox, NetnsHost} {
		t.Run(owner.String(), func(t *testing.T) {
			got := Topology{Netns: owner}.UnshareFlags()
			if !slices.Contains(got, "--unshare-net") {
				t.Errorf("netns=%s does not unshare net, which silently restores HOST "+
					"networking: %v", owner, got)
			}
		})
	}
	// The host arm gets --unshare-net here and --share-net later in BwrapFlags,
	// and that is deliberate: relaxing a namespace snug created is a different
	// decision from never creating one, and only the first is visible in the
	// argv a human reads.
	//
	// Note which field gates the relaxation. --share-net is emitted for
	// Net.Mode == NetHost, NOT for Topology.Netns == NetnsHost — the two travel
	// together through deriveTopology but are separate fields, and asserting
	// the wrong one is how this test failed when it was first written. A
	// Topology alone does not reopen the network.
	host := &Policy{
		Net:      NetPolicy{Mode: NetHost},
		Topology: Topology{Netns: NetnsHost},
	}
	if !slices.Contains(host.BwrapFlags(0, 0, nil), "--share-net") {
		t.Error("NetHost does not emit --share-net, so unsharing net above is not relaxed anywhere")
	}
	// The control for that: the same policy WITHOUT NetHost must not relax it,
	// or the assertion above passes on a BwrapFlags that always emits it.
	offline := &Policy{Topology: Topology{Netns: NetnsSandbox}}
	if slices.Contains(offline.BwrapFlags(0, 0, nil), "--share-net") {
		t.Error("an offline policy emits --share-net, which reopens the host network")
	}
}

// TestUnshareFlagsReturnsAFreshSlice guards the obvious refactor — turning this
// into an exported []string var — which would hand every caller a handle to
// shared, writable state that decides what the sandbox unshares.
func TestUnshareFlagsReturnsAFreshSlice(t *testing.T) {
	first := Topology{Netns: NetnsSandbox}.UnshareFlags()
	if len(first) == 0 {
		t.Fatal("UnshareFlags returned nothing; every assertion here is vacuous")
	}
	first[0] = "--CLOBBERED"

	second := Topology{Netns: NetnsSandbox}.UnshareFlags()
	if second[0] == "--CLOBBERED" {
		t.Error("two calls share backing storage, so a caller can rewrite what the sandbox " +
			"unshares for everyone else")
	}
}
