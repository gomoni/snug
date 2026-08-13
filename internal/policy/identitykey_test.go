package policy

import (
	"strings"
	"testing"
)

// identity.ssh_key names the PUBLIC key file that pins which of the host
// agent's keys the sandbox may sign with — sshproxy.New reads it for the blob
// the proxy answers REQUEST_IDENTITIES with. It went through expandVars against
// the same vars map as every grant, `{target}` included, and then, unlike a
// ro/rw grant, skipped BOTH EvalSymlinks and underTargetIsLiteral. So a profile
// writing ssh_key = "{target}/deploy.pub" followed a symlink that a previous
// run of the sandbox had planted, and the proxy pinned whatever key that link
// pointed at.
//
// Found by comparing SECRETS.md §4 against the code: §4 asserted the rule "a
// secret reference must never be expandable from {…} variables the sandbox can
// influence" as though it already held. It did not. Not reachable from any
// builtin — nothing snug ships sets [identity] — which is why this was latent
// rather than live, and why the fixture below has to build the profile itself.
//
// The three tests are one rule seen from three sides, and the third is the one
// that keeps the fix honest: a rule that refuses everything under the target
// would pass the first two and break the ordinary case.

func identityRegistry(key string) map[string]*Profile {
	reg := testRegistry()
	reg["pinned"] = &Profile{
		Name:     "pinned",
		Identity: &Identity{SSHMode: SSHAgentProxy, SSHKey: key},
	}
	return reg
}

func TestIdentitySSHKeyUnderTargetCannotBeRedirectedBySymlink(t *testing.T) {
	env := newFakeEnv()
	// The link a previous run planted: inside the target, pointing at the key
	// the human did NOT name.
	env.links["/home/u/proj/sub/deploy.pub"] = "/home/u/.ssh/id_ed25519.pub"

	_, err := Resolve(identityRegistry("{target}/deploy.pub"),
		append(append([]string{}, testDefaults...), "pinned"), testCtx(), env)
	if err == nil {
		t.Fatal("ssh_key under the target resolved through a symlink out of it; " +
			"the pinned identity is then whatever the sandbox last linked to")
	}
	if !strings.Contains(err.Error(), "ssh_key") {
		t.Errorf("error does not name the key that caused it: %v", err)
	}
	if !strings.Contains(err.Error(), "/home/u/.ssh/id_ed25519.pub") {
		t.Errorf("error does not name where the symlink went, which is the "+
			"whole point of reading it: %v", err)
	}
}

func TestIdentitySSHKeyUnderTargetIsAcceptedWhenItIsLiteral(t *testing.T) {
	// The positive control. Without it the test above passes on a fix that
	// refuses every ssh_key under the target, which would be a different bug.
	env := newFakeEnv()
	env.links["/home/u/proj/sub/deploy.pub"] = "/home/u/proj/sub/deploy.pub"

	p, err := Resolve(identityRegistry("{target}/deploy.pub"),
		append(append([]string{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatalf("a real file under the target is a legitimate ssh_key: %v", err)
	}
	if p.Identity == nil || p.Identity.SSHKey != "/home/u/proj/sub/deploy.pub" {
		t.Fatalf("ssh_key = %+v, want the literal path under the target", p.Identity)
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
		append(append([]string{}, testDefaults...), "pinned"), testCtx(), env)
	if err != nil {
		t.Fatalf("an ssh_key outside the target must not be canonicalised: %v", err)
	}
	if p.Identity == nil || p.Identity.SSHKey != "/home/u/.ssh/id_ed25519.pub" {
		t.Fatalf("ssh_key = %+v, want the expanded path, uncanonicalised", p.Identity)
	}
}
