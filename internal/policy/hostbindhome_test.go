package policy

import (
	"strings"
	"testing"
)

// ── issue #220: a bind covering $HOME is the largest grant snug can emit ────
//
// It was reachable with builtins alone and started without a word:
//
//	snug --no-defaults -p @sys -p @parent-ro ~/myproject
//
// `@parent-ro` grants {target_parent}; for a target sitting directly in the home
// directory that parent IS $HOME. `--dry-run` rendered it as one unremarkable
// line, visually identical to `ro /etc/passwd`.
//
// MEASURED through it by `redteam`, against a scratch home: an ssh private key
// read, .netrc read, .aws read, a git alias from the host's ~/.gitconfig
// EXECUTED, ~/.bashrc executed by an interactive shell, and a host ssh-agent
// enumerated and used for a signature through the socket in ~/.ssh (issue #219)
// — the @ssh-agent filtering proxy's one-pinned-key design defeated by a mount.
//
// snug is deliberately permissive about foot-guns; it will not catch a typo in a
// profile variable name. This is not that. There is no narrower version of it a
// user could have meant, and no override flag, on #191's reasoning in the hook's
// own words: an override is a thing an agent talks itself into.

func homePolicy(t *testing.T, guest string, kind Kind) *Policy {
	t.Helper()
	p := &Policy{
		Target: "/home/u/proj",
		Home:   "/home/u",
		Mounts: map[string]Mount{
			guest: {Kind: kind, Guest: guest, Host: guest, Access: AccessRO, From: []string{"@probe"}},
		},
	}
	return p
}

func TestNoPolicyBindsTheHome(t *testing.T) {
	for _, tc := range []struct{ guest, why string }{
		{"/home/u", "the home directory itself — the measured case, via @parent-ro on a home-child target"},
		{"/home", "an ancestor: this home and every other user's"},
		{"/", "the root; caught here even though the root-bind rule reaches it first"},
	} {
		p := homePolicy(t, tc.guest, KindBind)
		err := p.rejectHostHomeBind()
		if err == nil {
			t.Errorf("a bind at %s was accepted — %s", tc.guest, tc.why)
			continue
		}
		// The refusal has to teach, or the next person works around it.
		for _, want := range []string{
			"COMMAND TABLES",               // read-only SUPPLIES rather than restrains
			"agent socket",                 // issue #219, the noun the rule did not name
			"There is no flag to allow it", // #191's call, restated
			"{home}/src",                   // the enumerate-instead answer, invariant 2's
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal for %s does not mention %q:\n%s", tc.guest, want, err)
			}
		}
	}
}

// POSITIVE CONTROLS. A rule that refused everything would satisfy the test above
// and destroy the tool. Each of these is a grant that must stay legal, and each
// is one somebody actually uses.
func TestTheHomeBindRuleIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		guest string
		kind  Kind
		why   string
	}{
		{"/home/u", KindTmpfs, "@home's tmpfs at {home} — this is the mechanism that makes a bind there unrepresentable in the default selection, not a violation of it"},
		{"/home/u", KindData, "snug's own generated files land under the home"},
		{"/home/u/src", KindBind, "a bind BELOW the home is the enumerate-instead answer the refusal itself recommends"},
		{"/home/u/proj", KindBind, "@cwd-rw's grant of a home-child target"},
		{"/tmp", KindBind, "@parent-ro on a /tmp target — unrelated, and the whole integration suite builds targets there"},
		{"/etc", KindBind, "@sys"},
		{"/home/other", KindBind, "another user's home is not this policy's Home"},
		{"/home/uu", KindBind, "the prefix boundary: /home/uu must not match /home/u"},
	} {
		p := homePolicy(t, tc.guest, tc.kind)
		if err := p.rejectHostHomeBind(); err != nil {
			t.Errorf("REFUSED a legitimate grant: %s at %s — %s\n%v", tc.kind, tc.guest, tc.why, err)
		}
	}
}

// A policy with no Home at all must not panic or refuse. Several unit tests
// build &Policy{} directly, and Home is the zero value there.
func TestTheHomeBindRuleIgnoresAnEmptyHome(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/": {Kind: KindBind, Guest: "/", Host: "/", From: []string{"@probe"}},
	}}
	if err := p.rejectHostHomeBind(); err != nil {
		t.Errorf("a policy with no Home was refused: %v", err)
	}
}

// THE STRUCTURAL HALF, and the one that matters most over time.
//
// The tmpfs at {home} is what makes a bind there unrepresentable in the default
// selection — the conflict a home-child target hits is `tmpfs (from @home) vs
// bind (from @parent-ro)`, and it only exists because @home claims that path
// with a different KIND.
//
// `redteam` measured what happens without it: with @home tmpfsing the CHILDREN
// instead of {home}, `snug ~` stops being refused, and a payload read a private
// key and WROTE ~/.ssh/authorized_keys onto the host — persistence outliving the
// sandbox, from a selection snug refuses today. So this is not a preference
// about where a tmpfs sits; it is load-bearing, and nothing else asserted it.
func TestHomeItselfIsAlwaysATmpfsUnderTheDefaults(t *testing.T) {
	reg := testRegistry()
	p, err := Resolve(reg, testDefaults, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("the default selection no longer resolves for %s: %v", testCtx().Target, err)
	}
	m, ok := p.Mounts[p.Home]
	if !ok {
		t.Fatalf("nothing is mounted at %s under the default selection. If @home stopped "+
			"claiming {home}, a bind there becomes representable — see the authorized_keys "+
			"measurement in this file's comment", p.Home)
	}
	if m.Kind != KindTmpfs {
		t.Errorf("%s is %s under the default selection, want %s. The tmpfs is what makes a "+
			"bind at the home unrepresentable; without it `snug ~` stops being refused",
			p.Home, m.Kind, KindTmpfs)
	}
}

// A rule Validate does not call is a rule that does not exist. Found by
// mutation: unhooking rejectHostHomeBind from Validate changed no test, because
// every case above calls it directly.
//
// This one drives the measured command end to end — Resolve, then Validate —
// so it fails if the rule is removed from the chain, if the chain stops running,
// or if @parent-ro ever stops granting {target_parent}.
func TestResolveRefusesTheMeasuredHomeBindSelection(t *testing.T) {
	reg := testRegistry()
	ctx := testCtx()
	ctx.Target = "/home/u/proj" // directly in the home: parent IS {home}

	// Resolve runs Validate itself, so this drives the whole chain: the rule is
	// reached the same way `snug --no-defaults -p @sys -p @parent-ro ~/myproject`
	// reaches it, not by calling the predicate directly.
	_, err := Resolve(reg, []ProfileName{"@sys", "@parent-ro"}, ctx, newFakeEnv())
	if err == nil {
		t.Fatal("ACCEPTED a policy binding the host's home directory.\n" +
			"This is the measured issue #220 case: that command started fine and handed the " +
			"payload every credential under $HOME — ssh keys, .netrc, .aws read; a " +
			"~/.gitconfig alias and ~/.bashrc EXECUTED; and a host ssh-agent enumerated and " +
			"used for a signature (#219).\n" +
			"If rejectHostHomeBind was unhooked from Validate, hook it back in.")
	}

	// It has to be refused for the RIGHT reason. Without this the test passes on
	// any refusal at all — including one from a future unrelated rule, at which
	// point it silently stops grading #220.
	for _, want := range []string{"@parent-ro", "/home/u", "home directory", "COMMAND TABLES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refused, but not as the home-bind rule: %q missing from\n%v", want, err)
		}
	}
}

// The other half of the same coin: a target one level down must still resolve.
// A rule that refused @parent-ro everywhere would satisfy the test above and
// break the profile's entire purpose.
func TestAParentOneLevelDownIsStillGranted(t *testing.T) {
	reg := testRegistry()
	ctx := testCtx() // Target /home/u/proj/sub, so the parent is /home/u/proj
	p, err := Resolve(reg, []ProfileName{"@sys", "@parent-ro"}, ctx, newFakeEnv())
	if err != nil {
		t.Fatalf("@parent-ro on a target one level down was refused: %v", err)
	}
	if m, ok := p.Mounts["/home/u/proj"]; !ok || m.Kind != KindBind {
		t.Errorf("@parent-ro no longer binds the parent for a normal layout: %+v (present=%v)", m, ok)
	}
}
