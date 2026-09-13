package policy

import (
	"strings"
	"testing"
)

// identity.ssh.key names the PUBLIC key file that pins which of the host
// agent's keys the sandbox may sign with — sshproxy.New reads it for the blob
// the proxy answers REQUEST_IDENTITIES with. It went through expandVars against
// the same vars map as every grant, `{target}` included, and then, unlike a
// ro/rw grant, skipped BOTH EvalSymlinks and underTargetIsLiteral. So a profile
// writing key = "{target}/deploy.pub" followed a symlink that a previous
// run of the sandbox had planted, and the proxy pinned whatever key that link
// pointed at.
//
// Found by comparing SECRETS.md against the code: what is now §4.2 asserted the rule "a
// secret reference must never be expandable from {…} variables the sandbox can
// influence" as though it already held. It did not. Not reachable from any
// builtin — nothing snug ships sets [identity] — which is why this was latent
// rather than live, and why the fixture below has to build the profile itself.
//
// The three tests are one rule seen from three sides, and the third is the one
// that keeps the fix honest: a rule that refuses everything under the target
// would pass the first two and break the ordinary case.

func identityRegistry(key string) map[ProfileName]*Profile {
	reg := testRegistry()
	reg["pinned"] = &Profile{
		Name:     "pinned",
		Identity: &Identity{SSH: IdentitySSH{Agent: SSHAgentProxy, Key: key}},
	}
	return reg
}

func TestIdentitySSHKeyUnderTargetCannotBeRedirectedBySymlink(t *testing.T) {
	env := newFakeEnv()
	// The link a previous run planted: inside the target, pointing at the key
	// the human did NOT name.
	env.links["/home/u/proj/sub/deploy.pub"] = "/home/u/.ssh/id_ed25519.pub"

	_, err := Resolve(identityRegistry("{target}/deploy.pub"),
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err == nil {
		t.Fatal("the pinned key under the target resolved through a symlink out of it; " +
			"the pinned identity is then whatever the sandbox last linked to")
	}
	if !strings.Contains(err.Error(), "ssh.key") {
		t.Errorf("error does not name the key that caused it: %v", err)
	}
	if !strings.Contains(err.Error(), "/home/u/.ssh/id_ed25519.pub") {
		t.Errorf("error does not name where the symlink went, which is the "+
			"whole point of reading it: %v", err)
	}
}

func TestIdentitySSHKeyUnderTargetIsAcceptedWhenItIsLiteral(t *testing.T) {
	// The positive control. Without it the test above passes on a fix that
	// refuses every pinned key under the target, which would be a different bug.
	env := newFakeEnv()
	env.links["/home/u/proj/sub/deploy.pub"] = "/home/u/proj/sub/deploy.pub"

	p, err := Resolve(identityRegistry("{target}/deploy.pub"),
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatalf("a real file under the target is a legitimate pinned key: %v", err)
	}
	if p.Identity == nil || p.Identity.SSH.Key != "/home/u/proj/sub/deploy.pub" {
		t.Fatalf("identity = %+v, want the literal path under the target", p.Identity)
	}
}

func TestIdentitySSHKeyOutsideTargetIsNotCanonicalised(t *testing.T) {
	// The second control, and it pins a DELIBERATELY narrower rule than add()
	// applies to a bind. Outside the target the path carries the same trust as
	// a grant's host side, and canonicalising it would make resolution depend
	// on the file existing — turning `snug profile show` and `--dry-run` into
	// hard failures for a profile whose key is merely absent. The key below
	// does not exist in the fake filesystem, and that must still resolve.
	//
	// `~/` is expanded by expandVars, not by the caller, so what survives is
	// the expanded path and not the tilde.
	env := newFakeEnv()

	p, err := Resolve(identityRegistry("~/.ssh/id_ed25519.pub"),
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatalf("a pinned key outside the target must not be canonicalised: %v", err)
	}
	if p.Identity == nil || p.Identity.SSH.Key != "/home/u/.ssh/id_ed25519.pub" {
		t.Fatalf("identity = %+v, want the expanded path, uncanonicalised", p.Identity)
	}
}

// ── git.signing_key (#453): the same treatment as ssh.key, since resolve.go's loop
// runs both fields through expandVars and the under-target symlink check
// identically. These three mirror the ssh.key tests above rather than
// reimplementing coverage of expandVars or underTargetIsLiteral themselves.

func identitySigningRegistry(sshKey, signingKey string, mode SSHMode) map[ProfileName]*Profile {
	reg := testRegistry()
	reg["pinned"] = &Profile{
		Name:     "pinned",
		Identity: &Identity{SSH: IdentitySSH{Agent: mode, Key: sshKey}, Git: IdentityGit{SigningKey: signingKey}},
	}
	return reg
}

func TestResolveExpandsSigningKeyVariables(t *testing.T) {
	p, err := Resolve(identitySigningRegistry("~/.ssh/id_ed25519.pub", "{home}/x.pub", SSHAgentProxy),
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("signing_key carrying a {home} variable was refused: %v", err)
	}
	if p.Identity == nil || p.Identity.Git.SigningKey != "/home/u/x.pub" {
		t.Fatalf("signing_key = %+v, want the expanded path /home/u/x.pub", p.Identity)
	}
}

// The symlink-redirect regression (issue #337's shape, applied to the second
// key field): signing_key resolved under the target follows a symlink a
// PREVIOUS run's own @cwd-rw could have planted there, and the proxy would then
// pin whatever key that link points at.
func TestResolveRefusesASigningKeySymlinkedOutOfTheTarget(t *testing.T) {
	env := newFakeEnv()
	env.links["/home/u/proj/sub/deploy-signing.pub"] = "/home/u/.ssh/id_ed25519.pub"

	_, err := Resolve(identitySigningRegistry("~/.ssh/id_auth.pub", "{target}/deploy-signing.pub", SSHAgentProxy),
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), env)
	if err == nil {
		t.Fatal("signing_key under the target resolved through a symlink out of it; the " +
			"pinned signing identity is then whatever the sandbox last linked to")
	}
	if !strings.Contains(err.Error(), "signing_key") {
		t.Errorf("error does not name the field that caused it: %v", err)
	}
	if !strings.Contains(err.Error(), "/home/u/.ssh/id_ed25519.pub") {
		t.Errorf("error does not name where the symlink went, which is the whole point of "+
			"reading it: %v", err)
	}
}

// The private half of a signing key never enters the sandbox by construction
// — it stays in the host agent — so signing_key with no agent proxy (either
// spelling: an explicit "none" or an omitted agent, which normalises to
// the same thing) is a config that can never work. Resolve refuses it rather
// than generating a ~/.gitconfig that fails every commit.
func TestSigningKeyRequiresTheAgentProxy(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode SSHMode
	}{
		{`agent = "none"`, SSHNone},
		{"agent omitted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Resolve(identitySigningRegistry("", "~/.ssh/id_signing.pub", tc.mode),
				append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), newFakeEnv())
			if err == nil {
				t.Fatal("signing_key with no agent proxy resolved; the private half never " +
					"enters the sandbox, so nothing inside could ever sign with it")
			}
			if !strings.Contains(err.Error(), "signing_key") {
				t.Errorf("error does not name signing_key: %v", err)
			}
			if !strings.Contains(err.Error(), "proxy") {
				t.Errorf("error does not name the fix (identity.ssh.agent = \"proxy\"): %v", err)
			}
		})
	}
}

// SSHConfig deliberately does not gain a second IdentityFile for signing_key
// — its own doc comment says why: ssh would OFFER an authentication attempt
// with a key that is typically authorized nowhere. This is the assertion
// that keeps that comment honest: with both keys pinned, the generated
// ~/.ssh/config still names exactly one IdentityFile, and it is PubKeyGuest
// (ssh.key's staged path), never SigningKeyGuest.
func TestSSHConfigDoesNotOfferTheSigningKeyForAuthentication(t *testing.T) {
	id := &Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy, Key: "/home/u/.ssh/id_ed25519.pub"},
		Git: IdentityGit{SigningKey: "/home/u/.ssh/id_ed25519_signing.pub"},
	}
	cfg := string(id.SSHConfig("/home/u"))

	n := strings.Count(cfg, "IdentityFile")
	if n != 1 {
		t.Fatalf("generated ~/.ssh/config has %d IdentityFile lines, want exactly 1:\n%s", n, cfg)
	}
	if !strings.Contains(cfg, "IdentityFile /home/u/"+PubKeyGuest) {
		t.Errorf("the one IdentityFile is not the staged ssh.key path:\n%s", cfg)
	}
	if strings.Contains(cfg, SigningKeyGuest) {
		t.Errorf("the signing key's staged path appears in ~/.ssh/config; ssh would then "+
			"offer it for authentication, which is exactly what SigningKeyGuest's absence "+
			"here is meant to prevent:\n%s", cfg)
	}
}
