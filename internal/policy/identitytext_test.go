package policy

import (
	"reflect"
	"slices"
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
		{"git.name", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Git: IdentityGit{Name: "x\n[core]\n\tsshCommand = evil"}}},
		{"git.email", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Git: IdentityGit{Email: "a@b\n[url \"x\"]"}}},
		{"gh.host", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Gh: IdentityGh{Host: "a\nb: {oauth_token: stolen}"}}},
		{"gh.user", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Gh: IdentityGh{User: "nobody\x1b[1A\r  snug: FORGED"}}},
		{"ssh.key", Identity{SSH: IdentitySSH{Agent: SSHAgentProxy, Key: "~/.ssh/id.pub\x00--ro-bind"}}},
		{"git.signing_key", Identity{SSH: IdentitySSH{Agent: SSHAgentProxy},
			Git: IdentityGit{SigningKey: "~/.ssh/id.pub\x00--ro-bind"}}},
		{"ssh.agent", Identity{SSH: IdentitySSH{Agent: SSHMode("none\n")}}},
		// C1 AND BIDI, AND THIS LOOP COULD NOT SEE EITHER UNTIL NOW. CheckText was
		// a BYTE loop over `c < 0x20 || c == 0x7f`, so it missed U+009B and — one
		// category out — U+202E, which reverses how the rest of a line reads. The
		// directive half of this rule really is ASCII (only a newline writes a
		// second git or YAML line), but these fields are ALSO interpolated into the
		// ~/.claude/CLAUDE.md the agent reads, with %s: the row naming the account
		// the sandbox pushes as could be spelled to render as a different account.
		// Found by asking what the OTHER sinks do with the same string, which is
		// the rule this project has now failed to apply three times.
		{"gh.user", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Gh: IdentityGh{User: "nobody\u009b1A\u009b1G"}}},
		{"gh.user", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Gh: IdentityGh{User: "yranidro\u202eyxorp-tnega"}}},
		{"git.name", Identity{SSH: IdentitySSH{Agent: SSHNone},
			Git: IdentityGit{Name: "Some One\u2028[core]"}}},
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
		SSH: IdentitySSH{Agent: SSHAgentProxy, Key: "~/.ssh/id_ed25519.pub"},
		Git: IdentityGit{Name: "Some One", Email: "some.one+tag@example.com"},
		Gh:  IdentityGh{User: "some-one"},
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

// wantIdentityLeaves is every dotted TOML key CheckText must refuse a forging
// rune at, hard-coded rather than derived from identityFields a second time.
// That is deliberate duplication of the RIGHT kind: identityFields is derived
// from the Identity type, so a bug in the derivation (a leaf silently dropped,
// a struct tag typo that mis-spells the key) would pass a test that walked
// identityFields to build its own expectation. This list only fails when a
// leaf is ADDED — the prompt to go read whatever new sink it reaches — or
// when one is renamed, spelled differently, or removed.
var wantIdentityLeaves = []string{
	"ssh.host", "ssh.key", "ssh.agent",
	"git.name", "git.email", "git.signing_key",
	"gh.host", "gh.user",
}

// TestCheckTextRefusesAForgingRuneAtEveryIdentityLeaf replaces the hand-written
// {field, value} table CheckText used to carry with a walk over identityFields
// — the same enumeration Resolve's expand loop now drives — so a field added to
// Identity is checked here for free rather than only once someone remembers to
// add a row.
//
// It also pins the enumeration itself against wantIdentityLeaves: identityFields
// walking the WRONG set (too few keys, a stale spelling) would make this pass
// on an incomplete sweep, which is exactly the gap #549 asks CheckText to close.
func TestCheckTextRefusesAForgingRuneAtEveryIdentityLeaf(t *testing.T) {
	var got []string
	for _, f := range identityFields {
		got = append(got, f.Key)
	}
	if !slices.Equal(got, wantIdentityLeaves) {
		t.Fatalf("identityFields = %v, want exactly %v — a leaf was added, renamed or removed; "+
			"review whatever new sink it reaches before updating this list", got, wantIdentityLeaves)
	}

	for _, f := range identityFields {
		t.Run(f.Key, func(t *testing.T) {
			id := Identity{SSH: IdentitySSH{Agent: SSHAgentProxy}}
			reflect.ValueOf(&id).Elem().FieldByIndex(f.Index).SetString("x\u202eforged")

			err := id.CheckText("pinned")
			if err == nil {
				t.Fatalf("Identity.%s carrying a forging rune (U+202E) resolved with no "+
					"error — CheckText does not check this leaf", f.Key)
			}
			if !strings.Contains(err.Error(), f.Key) {
				t.Errorf("error does not name %q: %v", f.Key, err)
			}
		})
	}
}

// TestIdentityHasNoReferenceKindedField fails compilation-adjacent drift the
// moment a Ptr, Slice, Map, Interface, Func or Chan field is added anywhere in
// Identity's tree — including inside a future nested block — before that field
// ever reaches CheckText or Resolve.
//
// mustIdentityFields already panics on exactly this at package init (every test
// importing internal/policy runs it), so in one sense this test can never fail
// on the code in this repository; it exists as the second guard beside that
// panic, walking the type independently rather than trusting the one function
// under review to catch its own class of bug, and it names ALL THREE
// consequences a reference-kinded field would have — the ones a panic message
// alone would leave for the next reader to work out:
//
//  1. The identity conflict check (`*p.Identity != id` in Resolve) would degrade
//     to POINTER IDENTITY, since a pointer is comparable but two profiles
//     carrying byte-identical blocks would then compare unequal and refuse each
//     other.
//  2. `id := *prof.Identity` (Resolve) would SHARE the referenced value with the
//     Profile stored in the registry, so the normalisation write-back would
//     mutate the registry itself — a second Resolve call, or the same call with
//     the selection reordered, would then see an already-normalised value and
//     resolution would stop being order-independent.
//  3. FieldByIndex — which identityFields hands to CheckText and to Resolve's
//     expand loop — PANICS the moment it walks through a nil pointer in the
//     index path, turning an absent nested value into a crash instead of a
//     zero string.
func TestIdentityHasNoReferenceKindedField(t *testing.T) {
	var walk func(t reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := path + "." + f.Name
			switch f.Type.Kind() {
			case reflect.String:
				// A leaf. Fine.
			case reflect.Struct:
				walk(f.Type, name)
			case reflect.Ptr, reflect.Slice, reflect.Map, reflect.Interface, reflect.Func, reflect.Chan:
				t.Fatalf("Identity%s is a %s. A reference-kinded field here would: "+
					"(1) degrade the identity conflict check in Resolve to pointer identity, "+
					"refusing two profiles that pin byte-identical blocks; "+
					"(2) let `id := *prof.Identity` share it with the loaded profile, so "+
					"Resolve's normalisation write-back would mutate the registry and make "+
					"resolution order-dependent; and "+
					"(3) make FieldByIndex panic on a nil pointer in the path, which is what "+
					"identityFields hands every caller", name, f.Type.Kind())
			default:
				t.Fatalf("Identity%s is a %s, a kind this walk does not recognise", name, f.Type.Kind())
			}
		}
	}
	walk(reflect.TypeOf(Identity{}), "")
}

// TestIdentityFieldsEnumeratesExactlyTwoPaths pins WHICH leaves carry the
// `path` option identityFields derives from the `snug:"...,path"` struct tag:
// ssh.key and git.signing_key, and no others. Both feed Resolve's
// expand-and-symlink-check loop (resolve.go) — a host file a payload could
// redirect with a planted symlink under the target.
//
// The negative half is the point as much as the positive: git.name is a
// leaf too, and it must NOT be expanded against {home}/{target} or checked
// against a symlink escape, because it is a human's name, not a path.
func TestIdentityFieldsEnumeratesExactlyTwoPaths(t *testing.T) {
	var got []string
	for _, f := range identityFields {
		if f.Path {
			got = append(got, f.Key)
		}
	}
	want := []string{"ssh.key", "git.signing_key"}
	if !slices.Equal(got, want) {
		t.Fatalf("identity leaves carrying `path` = %v, want exactly %v", got, want)
	}

	for _, f := range identityFields {
		if f.Key == "git.name" && f.Path {
			t.Fatalf("git.name is marked as a path; it is a human's name and must not be " +
				"expanded against {home}/{target} or checked against a symlink escape")
		}
	}
}
