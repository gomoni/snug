package policy

import (
	"strings"
	"testing"
)

// The two symlink entry points ask two different questions of one map, and both
// used to be one function that answered neither reliably. These tests pin the
// difference so nobody re-folds them.

// usrMerged is the shipped shape: /bin, /sbin and /lib all point into /usr, and
// /lib is a PREFIX of /lib64. That last pair is what made map iteration order
// observable.
func usrMerged() map[string]string {
	return map[string]string{
		"/bin":   "/usr/bin",
		"/sbin":  "/usr/sbin",
		"/lib":   "/usr/lib",
		"/lib64": "/usr/lib64",
	}
}

// The deepest link decides, every time. Repeated because the defect this
// replaces was a map range returning whichever key it felt like: a single call
// would have passed roughly half the time, which is the worst kind of green.
func TestResolveViaDeepestIsDeterministicWhenOneLinkPrefixesAnother(t *testing.T) {
	for i := 0; i < 200; i++ {
		via, resolved := resolveViaDeepest(usrMerged(), "/lib64/tls/libc.so")
		if via != "/lib64" || resolved != "/usr/lib64/tls/libc.so" {
			t.Fatalf("iteration %d: got via=%q resolved=%q, want /lib64 and /usr/lib64/tls/libc.so "+
				"— /lib prefixes /lib64, so a first-match walk answers this differently on "+
				"different runs", i, via, resolved)
		}
	}
}

// A grant AT the link path is the link itself; there is no mountpoint being
// created at a symlink destination, so there is nothing to refuse.
func TestResolveViaDeepestSkipsTheLinkItself(t *testing.T) {
	if via, _ := resolveViaDeepest(usrMerged(), "/bin"); via != "" {
		t.Fatalf("a grant at the link path itself was reported as passing through %q", via)
	}
}

func TestResolveViaDeepestIgnoresAnUnrelatedPath(t *testing.T) {
	if via, _ := resolveViaDeepest(usrMerged(), "/opt/tools/bin"); via != "" {
		t.Fatalf("an unrelated path was reported as passing through %q", via)
	}
}

// The environment question is the other one: a PATH element can be literally
// /bin, and on a usr-merged host that IS a symlink. Refusing to rewrite it would
// judge a profile against a path the sandbox never sees.
func TestResolveLinkForEnvMatchesTheLinkItself(t *testing.T) {
	if got := resolveLinkForEnv(usrMerged(), "/bin"); got != "/usr/bin" {
		t.Fatalf("resolveLinkForEnv(/bin) = %q, want /usr/bin", got)
	}
}

func TestResolveLinkForEnvIsDeterministicWhenOneLinkPrefixesAnother(t *testing.T) {
	for i := 0; i < 200; i++ {
		if got := resolveLinkForEnv(usrMerged(), "/lib64/pkgconfig"); got != "/usr/lib64/pkgconfig" {
			t.Fatalf("iteration %d: got %q, want /usr/lib64/pkgconfig", i, got)
		}
	}
}

// No link applies, so the caller gets the path back unchanged and has exactly
// one value to compare.
func TestResolveLinkForEnvLeavesAnUnlinkedPathAlone(t *testing.T) {
	if got := resolveLinkForEnv(usrMerged(), "/usr/local/bin"); got != "/usr/local/bin" {
		t.Fatalf("resolveLinkForEnv rewrote a path no link covers: %q", got)
	}
}

// ── issue #604's follow-up: linkLanding's own ".." refusal ─────────────────
//
// followToDestination and guestLanding both join a host symlink's text
// LEXICALLY, which is only safe for the LEADING run of ".." a relative text
// may start with — those climb out of the walk's own, already-clean
// position. A ".." AFTER A NAME is a different claim: the kernel resolves
// that name FIRST, and if it is itself a symlink, ".." climbs out of
// wherever THAT lands, which a lexical join cannot know without doing the
// queue-based walk envresolve.go's walkLinks now does instead. Rather than
// share that model here too, linkLanding refuses — errLinkTextDotDotAfterName
// — whenever it sees the shape rather than guess.

// TestGeneratedDestinationRefusesDotDotAfterANameInLinkText is
// followToDestination's own case: a generated file's destination passes
// through a host symlink whose relative text names something and then climbs
// out of it.
func TestGeneratedDestinationRefusesDotDotAfterANameInLinkText(t *testing.T) {
	p := mustResolveDefaults(t)
	bind(p, "/srv/app", "/host/cover", AccessRO)
	generated(p, "/srv/app/link/gen.conf", AccessRO)

	env := newFakeEnv()
	// "sub/../real": a NAME ("sub") followed by "..", the shape linkLanding
	// refuses rather than resolve lexically.
	env.links["/host/cover/link"] = "sub/../real"

	err := p.Validate(env)
	if err == nil {
		t.Fatal("accepted a generated file whose destination passes through a host symlink " +
			"text \"sub/../real\" — the \"..\" follows a name that may itself be a symlink, and " +
			"snug does not guess where it leads")
	}
	for _, want := range []string{
		"evil", "/host/cover/link", `"sub/../real"`, "may itself be a", "refuses",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q:\n%v", want, err)
		}
	}

	// CONTROL: a pure LEADING ".." (no name before it) is unaffected — the
	// ordinary relative-link case every shipped dotfile layout can use,
	// landing back inside the same grant that covers it.
	t.Run("leading dotdot control", func(t *testing.T) {
		p := mustResolveDefaults(t)
		bind(p, "/srv/app", "/host/cover", AccessRO)
		// One real directory ("sub") between the grant's root and the link, so
		// a single leading ".." climbs out of "sub" and lands back at "real" —
		// still inside the grant — rather than out of the grant's own root.
		generated(p, "/srv/app/sub/link/gen.conf", AccessRO)

		env := newFakeEnv()
		env.dirs["/host/cover/sub"] = true
		env.links["/host/cover/sub/link"] = "../real" // lands at /host/cover/real, inside
		env.dirs["/host/cover/real"] = true
		env.files["/host/cover/real/gen.conf"] = true

		if err := p.Validate(env); err != nil {
			t.Fatalf("a link text of a pure leading \"..\" (no name before it) was refused: %v", err)
		}
	})
}

// TestRelocatedGrantRefusesDotDotAfterANameInLinkText is guestLanding's own
// case (issue #588's rule): a mount's destination, resolved the way bwrap
// resolves it, passes through a host symlink with the same "name then .."
// shape on the way to where a SEPARATE grant sits.
func TestRelocatedGrantRefusesDotDotAfterANameInLinkText(t *testing.T) {
	p := resolveDefaults(t)
	p.Mounts["/K"] = Mount{Guest: "/K", Host: "/hostK", Kind: KindBind, Access: AccessRO,
		From: []string{"cover"}}
	p.Mounts["/K/d/x"] = Mount{Guest: "/K/d/x", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}

	env := newFakeEnv()
	env.links["/hostK/d"] = "sub/../real"

	err := p.Validate(env)
	if err == nil {
		t.Fatal("accepted a grant whose landing walk passes through a host symlink text " +
			"\"sub/../real\" — the \"..\" follows a name that may itself be a symlink, and " +
			"snug does not guess where it leads")
	}
	for _, want := range []string{
		"grantee", "/K/d/x", "/hostK/d", `"sub/../real"`, "may itself be a", "refuses",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q:\n%v", want, err)
		}
	}

	// CONTROL: a pure LEADING ".." (no name before it) must not trip the NEW
	// refusal at all — this link genuinely diverts the mountpoint (it lands
	// at /K/real/x, not the declared /K/d/e/x), so it is still refused, but
	// by the ORDINARY relocation message (#588), never the "may itself be a
	// symlink" sentinel wording. Without this, a widened
	// dotDotFollowsAName that also caught a bare leading ".." would pass
	// unnoticed here.
	t.Run("leading dotdot control", func(t *testing.T) {
		p := resolveDefaults(t)
		p.Mounts["/K"] = Mount{Guest: "/K", Host: "/hostK", Kind: KindBind, Access: AccessRO,
			From: []string{"cover"}}
		p.Mounts["/K/d/e/x"] = Mount{Guest: "/K/d/e/x", Host: "/irrelevant", Kind: KindBind,
			Access: AccessRO, From: []string{"grantee"}}

		env := newFakeEnv()
		env.links["/hostK/d/e"] = "../real" // lands at /K/real/x, not the declared /K/d/e/x

		err := p.Validate(env)
		if err == nil {
			t.Fatal("a link that genuinely diverts the mountpoint was accepted — this control " +
				"is about WHICH message refuses it, not about it being accepted")
		}
		if strings.Contains(err.Error(), "may itself be a") {
			t.Errorf("a pure leading \"..\" (no name before it) tripped the NEW sentinel "+
				"refusal, which exists for a NAME followed by \"..\" specifically:\n%v", err)
		}
		if !strings.Contains(err.Error(), "not where it lands") {
			t.Errorf("refusal is not the ORDINARY relocation message (issue #588):\n%v", err)
		}
	})
}
