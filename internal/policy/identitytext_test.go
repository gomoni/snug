package policy

import (
	"reflect"
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
		{"signing_key", Identity{SSHMode: SSHAgentProxy, SigningKey: "~/.ssh/id.pub\x00--ro-bind"}},
		{"ssh_mode", Identity{SSHMode: SSHMode("none\n")}},
		// C1 AND BIDI, AND THIS LOOP COULD NOT SEE EITHER UNTIL NOW. CheckText was
		// a BYTE loop over `c < 0x20 || c == 0x7f`, so it missed U+009B and — one
		// category out — U+202E, which reverses how the rest of a line reads. The
		// directive half of this rule really is ASCII (only a newline writes a
		// second git or YAML line), but these fields are ALSO interpolated into the
		// ~/.claude/CLAUDE.md the agent reads, with %s: the row naming the account
		// the sandbox pushes as could be spelled to render as a different account.
		// Found by asking what the OTHER sinks do with the same string, which is
		// the rule this project has now failed to apply three times.
		{"gh_user", Identity{SSHMode: SSHNone, GhUser: "nobody\u009b1A\u009b1G"}},
		{"gh_user", Identity{SSHMode: SSHNone, GhUser: "yranidro\u202eyxorp-tnega"}},
		{"git_name", Identity{SSHMode: SSHNone, GitName: "Some One\u2028[core]"}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			reg := testRegistry()
			id := tc.id
			reg["pinned"] = &Profile{Name: "pinned", Identity: &id}

			_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "pinned"),
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
	if _, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "pinned"),
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
		append(append([]ProfileName{}, testDefaults...), "pinned"), testCtx(), newFakeEnv())
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

// fieldTOMLKey maps every string-kinded Identity field to its TOML spelling —
// a SECOND, independent copy of CheckText's own table, deliberately. The test
// below walks reflect.TypeOf(Identity{}) rather than that table, so a future
// field present in the struct but missing FROM the table is exactly what
// TestCheckTextCoversEveryIdentityField exists to catch; if this map also had
// no entry for it, the loop still requires CheckText to refuse the forged
// value (a nil error is the failure either way) and additionally names the
// field so whoever adds it updates both places together instead of one
// silently trailing the other.
var fieldTOMLKey = map[string]string{
	"SSHKey":     "ssh_key",
	"SigningKey": "signing_key",
	"SSHMode":    "ssh_mode",
	"GitName":    "git_name",
	"GitEmail":   "git_email",
	"GhUser":     "gh_user",
	"GhHost":     "gh_host",
}

// TestCheckTextCoversEveryIdentityField is what makes #454's later refactor
// (replacing CheckText's hand-written field list with an enumeration) a
// mechanical change rather than a security one: it fails today, before that
// refactor exists, for any field CheckText's table does not check — the same
// class of gap the hand-written ssh_key/signing_key loop in resolve.go
// carries a comment about (#454). It must land WITH signing_key, not after,
// or the field that motivated it would itself have gone unchecked for one
// commit.
func TestCheckTextCoversEveryIdentityField(t *testing.T) {
	typ := reflect.TypeOf(Identity{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() != reflect.String {
			continue // every field today IS string-kinded (SSHMode included); a
			// non-string field would need its own sink review, not this test
		}
		t.Run(f.Name, func(t *testing.T) {
			tomlKey, known := fieldTOMLKey[f.Name]
			if !known {
				t.Fatalf("Identity gained a string field %q with no entry in this test's "+
					"fieldTOMLKey map — add one here AND a matching row in CheckText's table", f.Name)
			}

			id := Identity{SSHMode: SSHAgentProxy}
			reflect.ValueOf(&id).Elem().FieldByIndex(f.Index).SetString("x\u202eforged")

			err := id.CheckText("pinned")
			if err == nil {
				t.Fatalf("Identity.%s carrying a forging rune (U+202E) resolved with no "+
					"error — CheckText's table does not check this field", f.Name)
			}
			if !strings.Contains(err.Error(), tomlKey) {
				t.Errorf("error does not name %q: %v", tomlKey, err)
			}
		})
	}
}
