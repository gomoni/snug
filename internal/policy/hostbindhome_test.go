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
// — what `identity.ssh.agent = "proxy"` (one pinned key, no enumeration) exists to
// prevent, defeated by a mount.
//
// snug is deliberately permissive about foot-guns; it will not catch a typo in a
// profile variable name. This is not that. There is no narrower version of it a
// user could have meant, and no override flag, on #191's reasoning in the hook's
// own words: an override is a thing an agent talks itself into.

func homePolicy(t *testing.T, guest string, kind Kind) *Policy {
	t.Helper()
	return translatedHomePolicy(t, guest, guest, kind)
}

// translatedHomePolicy is homePolicy with the two sides told apart, which is
// what homePolicy could not express and is why issue #601 shipped: every
// fixture in this file was built with Host == Guest, so no table here had ever
// seen the spelling `ro = ["<host>:<guest>"]`. add() canonicalises the host and
// leaves the guest as written, so a rule reading only the guest asks about a
// path the grant no longer lands under.
func translatedHomePolicy(t *testing.T, host, guest string, kind Kind) *Policy {
	t.Helper()
	p := &Policy{
		Target: "/home/u/proj",
		Home:   "/home/u",
		Mounts: map[string]Mount{
			guest: {Kind: kind, Guest: guest, Host: host, Access: AccessRO, From: []string{"@probe"}},
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

// TestNoPolicyBindsTheHomeThroughATranslatedGuest is issue #601, and it is the
// spelling that shipped past #220's rule for a milestone.
//
// MEASURED on the real binary before the fix, with a throwaway home:
//
//	[profile.translatehome]
//	ro = ["/tmp/hbh/fakehome:/mnt/h"]
//
//	$ HOME=/tmp/hbh/fakehome snug --dry-run -p translatehome /tmp/hbh/proj
//	  ro     /mnt/h (from /tmp/hbh/fakehome)   translatehome     <- no refusal, exit 0
//	$ HOME=/tmp/hbh/fakehome snug -p translatehome /tmp/hbh/proj -- sh -c 'cat /mnt/h/.secret'
//	secret                                                       <- exit 0
//
// The direct spelling was refused on that host, but by the @home tmpfs
// collision rather than by this rule — a different rule, and one the translated
// guest sidesteps for the same reason this one did.
//
// The refusal must name BOTH ends. A message quoting only the guest reads
// "/mnt/h, which is your home directory", which looks like a bug in snug rather
// than like the grant the profile wrote.
func TestNoPolicyBindsTheHomeThroughATranslatedGuest(t *testing.T) {
	for _, tc := range []struct{ host, guest, why string }{
		{"/home/u", "/mnt/h", "the home itself, translated out from under {home} — the measured case"},
		{"/home", "/mnt/homes", "an ancestor, translated: this home and every other user's"},
		{"/", "/mnt/root", "the root, translated"},
	} {
		p := translatedHomePolicy(t, tc.host, tc.guest, KindBind)
		err := p.rejectHostHomeBind()
		if err == nil {
			t.Errorf("a bind of host %s at guest %s was accepted — %s", tc.host, tc.guest, tc.why)
			continue
		}
		for _, want := range []string{tc.host, tc.guest, "There is no flag to allow it"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal for %s:%s does not mention %q:\n%s",
					tc.host, tc.guest, want, err)
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
		{"/home/u/proj", KindBind, "@target-rw's grant of a home-child target"},
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

// TestABindAtTheHomeDoesNotClaimTheHomeWasHandedOver is the OTHER shape this
// rule refuses, and the two are not the same hazard.
//
// `ro = ["/etc:{home}"]` covers the home on its GUEST side. Refusing it is
// right — {home} inside is snug's own, and @home's ephemeral tmpfs and the
// generated .gitconfig, .ssh/config and .claude files live there — but it hands
// the sandbox nothing of the HOST's home, so the credential paragraph the other
// arm prints is simply untrue of it. The round that graded issue #601 found the
// sentence already wrong for this input BEFORE the change and newly explicit
// about it after, because the message now names /etc out loud.
//
// It is asserted here rather than as a refusals.txt row because Resolve cannot
// reach it: @sys pulls in @home, whose tmpfs at {home} makes the bind a KIND
// CONFLICT that is refused first ("conflict at /home/u: tmpfs (from @home) vs
// bind"). Measured, not assumed — a golden through Resolve pinned that other
// message instead.
func TestABindAtTheHomeDoesNotClaimTheHomeWasHandedOver(t *testing.T) {
	p := translatedHomePolicy(t, "/etc", "/home/u", KindBind)
	err := p.rejectHostHomeBind()
	if err == nil {
		t.Fatal("a bind AT {home} was accepted; that path is snug's own")
	}
	for _, want := range []string{"/etc", "/home/u"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}
	// THE POINT. A refusal that overstates is a false claim on the one artifact
	// a human reads to decide whether to trust snug, and this input exposes no
	// credential at all.
	for _, never := range []string{"every credential under it is", "agent socket"} {
		if strings.Contains(err.Error(), never) {
			t.Errorf("the refusal for a NON-home source claims %q, which is untrue of it:\n%v",
				never, err)
		}
	}
	// CONTROL: the arm that IS about the host's home must still say it, or the
	// assertion above is satisfied by a rule that stopped warning anybody.
	real := translatedHomePolicy(t, "/home/u", "/mnt/h", KindBind).rejectHostHomeBind()
	if real == nil || !strings.Contains(real.Error(), "every credential under it is") {
		t.Errorf("the host-home arm no longer carries the credential warning:\n%v", real)
	}
}

// POSITIVE CONTROLS for the host side (issue #601). Widening a rule to a second
// field is how a rule stops being narrow, and translation is ordinary: a
// profile writes `ro = ["<host>:<guest>"]` to put a directory somewhere the
// payload expects it. Every row here must stay legal.
func TestTheHomeBindRuleStaysNarrowAcrossTranslation(t *testing.T) {
	for _, tc := range []struct{ host, guest, why string }{
		{"/home/u/src", "/mnt/src", "a PART of the home, translated — the enumerate-instead answer, relocated"},
		{"/home/u/proj", "/work", "the target, translated; a home-child target is the ordinary shape"},
		{"/etc", "/mnt/etc", "@sys-shaped, translated"},
		{"/home/other", "/mnt/o", "another user's home is not this policy's Home, translated or not"},
		{"/home/uu", "/mnt/uu", "the prefix boundary survives translation: /home/uu is not /home/u"},
		{"/opt/x", "/home/u/x", "the REVERSE translation — a host path mounted INSIDE the home is a grant, not a cover"},
	} {
		p := translatedHomePolicy(t, tc.host, tc.guest, KindBind)
		if err := p.rejectHostHomeBind(); err != nil {
			t.Errorf("REFUSED a legitimate grant: %s at %s — %s\n%v", tc.host, tc.guest, tc.why, err)
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
