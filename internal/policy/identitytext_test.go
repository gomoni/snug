package policy

import (
	"strings"
	"testing"
)

// Every identity field is interpolated into a config file snug GENERATES —
// ~/.gitconfig, ~/.ssh/config, gh's hosts.yml — so a control character in one
// writes a directive snug did not author. None of it is a Mount, so Validate,
// rejectMasking and the provenance model cannot see it: the same shape as the
// NUL in environ.set, at a sink that did not exist when that rule was written.
//
// Found by review of this milestone's diff, not by a test, which is why the
// table below names every field rather than the two that reach a terminal.

func TestIdentityFieldsRefuseControlCharacters(t *testing.T) {
	for _, tc := range []struct {
		field string
		id    Identity
	}{
		{"git_name", Identity{SSHMode: SSHNone, GitName: "x\n[core]\n\tsshCommand = evil"}},
		{"git_email", Identity{SSHMode: SSHNone, GitEmail: "a@b\n[url \"x\"]"}},
		{"gh_host", Identity{SSHMode: SSHNone, GhHost: "a\nb: {oauth_token: stolen}"}},
		{"gh_user", Identity{SSHMode: SSHNone, GhUser: "nobody\x1b[1A\r  snug: FORGED"}},
		{"ssh_key", Identity{SSHMode: SSHAgentProxy, SSHKey: "~/.ssh/id.pub\x00--ro-bind"}},
		{"ssh_mode", Identity{SSHMode: SSHMode("none\n")}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			reg := testRegistry()
			id := tc.id
			reg["pinned"] = &Profile{Name: "pinned", Identity: &id}

			_, err := Resolve(reg, append(append([]string{}, testDefaults...), "pinned"),
				testCtx(), newFakeEnv())
			if err == nil {
				t.Fatalf("identity.%s with a control character resolved; it would be written "+
					"into a config file snug generates, and nothing downstream inspects it",
					tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the error does not name the field that caused it: %v", err)
			}
			if !strings.Contains(err.Error(), "pinned") {
				t.Errorf("the error does not name the profile that caused it: %v", err)
			}
		})
	}
}

func TestOrdinaryIdentityFieldsStillResolve(t *testing.T) {
	// The control. A rule that refuses every identity would pass the table above
	// and break the feature — and the fields below are exactly what the
	// two-account setup in VERIFY.md §13 writes.
	reg := testRegistry()
	reg["pinned"] = &Profile{Name: "pinned", Identity: &Identity{
		SSHMode:  SSHAgentProxy,
		SSHKey:   "~/.ssh/id_ed25519.pub",
		GitName:  "Some One",
		GitEmail: "some.one+tag@example.com",
		GhUser:   "some-one",
		GhHost:   "github.com",
	}}
	if _, err := Resolve(reg, append(append([]string{}, testDefaults...), "pinned"),
		testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("an ordinary identity was refused: %v", err)
	}
}

func TestResolveRecordsWhichProfilePinnedTheIdentity(t *testing.T) {
	// IdentityOwner exists so a mount staged AFTER resolution — the public key,
	// staged by startIdentity — carries the same `identity:<profile>`
	// provenance as the three files Resolve stages itself. It read `(identity)`
	// for one milestone, which put one of four sibling rows on the --dry-run
	// screen down to nobody.
	p, err := Resolve(identityRegistry("~/.ssh/id_ed25519.pub"),
		append(append([]string{}, testDefaults...), "pinned"), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if p.IdentityOwner != "pinned" {
		t.Fatalf("IdentityOwner = %q, want %q", p.IdentityOwner, "pinned")
	}
	for _, m := range p.Mounts {
		if m.Guest == "/home/u/.gitconfig" && m.From[0] != "identity:pinned" {
			t.Errorf("generated .gitconfig provenance = %q, want identity:pinned", m.From[0])
		}
	}
}
