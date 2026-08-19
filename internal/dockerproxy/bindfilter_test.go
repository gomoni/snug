package dockerproxy

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestContainerBindFilterMatchesPolicyVisibility is the invariant-6 gate for
// issue #63, Tier B (TIER-B.md §4). Tier B gives the engine its own
// private COPY of the whole host tree — structurally two mount authors — so
// what stops a container mounting a path the sandbox cannot see is THIS
// filter, hostPathVisible, and it must be provably the same predicate as the
// resolved Policy's own visibility. Tier C is what makes the engine's VIEW
// itself structural instead of enforced; this test is what makes the
// enforcement in Tier B an ASSERTED boundary rather than an unverified hope.
//
// Positive control, in the same table: a granted path is accepted. Negative:
// an adjacent SIBLING directory — not a random unrelated path, but one that
// shares a parent with a grant — is refused. A filter that matched on prefix
// of the parent rather than on the mount's own boundary would pass a coarser
// check and still fail this one.
//
// NOT covered here, and flagged rather than silently asserted either way:
// hostPathVisible only walks policy.KindBind mounts, so a snug-GENERATED
// KindData grant (the identity files — ~/.gitconfig, ~/.ssh/config,
// known_hosts, /etc/resolv.conf) is invisible to a container's bind request
// even though the sandbox itself can read it. That is a NARROWING relative
// to the package comment's literal "the sandbox itself can see it", not a
// widening — safe by default, but undecided, and out of Tier B's brief
// (issue #63). Left for a policy decision rather than silently made here
// either by fixing hostPathVisible or by asserting the current behaviour as
// correct.
func TestContainerBindFilterMatchesPolicyVisibility(t *testing.T) {
	pol := &policy.Policy{
		Target: "/home/u/proj",
		Mounts: map[string]policy.Mount{
			"/usr":         {Guest: "/usr", Host: "/usr", Kind: policy.KindBind, Access: policy.AccessRO},
			"/home/u/proj": {Guest: "/home/u/proj", Host: "/home/u/proj", Kind: policy.KindBind, Access: policy.AccessRW},
		},
	}
	p := &Proxy{pol: pol}

	cases := []struct {
		name      string
		host      string
		needWrite bool
		want      bool
	}{
		// Positive controls: exactly what the policy grants.
		{"granted RO exact path, read", "/usr", false, true},
		{"granted RW target, read", "/home/u/proj", false, true},
		{"granted RW target, write", "/home/u/proj", true, true},
		{"below a granted directory", "/usr/bin/ls", false, true},
		{"below the granted RW target, write", "/home/u/proj/src/main.go", true, true},

		// Negatives — the sandbox does not see these, so a container must not
		// either.
		{"a RO grant asked for as writable", "/usr", true, false},
		{"below a RO grant asked for as writable", "/usr/bin/ls", true, false},
		// The sibling case: shares a parent with a grant, but is not itself
		// one, and is not a descendant of one either.
		{"adjacent sibling of the granted target, not itself granted",
			"/home/u/other-project", false, false},
		{"adjacent sibling under /usr's parent, not granted",
			"/opt/not-granted", false, false},
		{"an ungranted path entirely", "/etc/shadow", false, false},
		{"an ungranted path entirely, write", "/etc/shadow", true, false},
		// A prefix-string match without a path-boundary check would wrongly
		// accept this: "/home/u/proj-evil" has "/home/u/proj" as a STRING
		// prefix but is not a child of it.
		{"string-prefix lookalike of the granted target, not a real child",
			"/home/u/proj-evil", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.hostPathVisible(tc.host, tc.needWrite)
			if got != tc.want {
				t.Errorf("hostPathVisible(%q, needWrite=%v) = %v, want %v — "+
					"the proxy's bind filter must accept a host path IFF the policy exposes it",
					tc.host, tc.needWrite, got, tc.want)
			}
		})
	}
}
