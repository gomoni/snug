package policy

import (
	"strings"
	"testing"
)

// directives strips the generated file's comments, leaving only lines git would
// act on.
//
// It exists because every assertion here is about what the file MAKES GIT DO,
// and the file's own comment explains which keys are excluded by naming them —
// `credential.helper`, `alias = !cmd`, `core.pager`. Three tests in this package
// have now been written against the raw text and failed on their own
// documentation. Assert against the directives, not the bytes.
func directives(config string) string {
	var keep []string
	for _, line := range strings.Split(config, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

// A git config VALUE may legally span lines, so
// `user.name = "evil\n[alias]\n\tx = !touch /tmp/PWNED"` closed the
// `name = …` line and opened a real section in the generated file. The red team
// ran the injected alias inside the sandbox. Both identity values work as the
// carrier, which is why this test iterates both: the carrier is the value
// channel, not any particular key.
func TestNoIdentityValueCanAuthorADirective(t *testing.T) {
	evil := "benign\n[alias]\n\tanything = !touch /tmp/PWNED\n[core]\n\tpager = !cmd"
	for _, field := range []string{"name", "email"} {
		t.Run(field, func(t *testing.T) {
			g := IdentityGit{}
			if field == "name" {
				g.Name = evil
			} else {
				g.Email = evil
			}
			out := string(GitConfigFrom(&Identity{SSH: IdentitySSH{Agent: SSHAgentProxy}, Git: g}, "/home/u"))
			for _, forbidden := range []string{"[alias]", "anything", "pager", "!touch", "!cmd"} {
				if strings.Contains(directives(out), forbidden) {
					t.Errorf("a value authored %q in the generated config:\n%s", forbidden, out)
				}
			}
		})
	}
}

// The control. A guard that drops everything would pass the test above and make
// the profile useless — names have spaces, emails have dots and plus signs.
func TestABenignIdentityValueStillSurvives(t *testing.T) {
	out := string(GitConfigFrom(&Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "Some One-Two Jr.", Email: "some.one+tag@example.com"},
	}, "/home/u"))
	for _, want := range []string{"Some One-Two Jr.", "some.one+tag@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("an ordinary value was dropped: %q\n%s", want, out)
		}
	}
}

func TestGitConfigFromNilIdentityRendersNothing(t *testing.T) {
	if out := GitConfigFrom(nil, "/home/u"); out != nil {
		t.Errorf("a policy with no identity got a generated git config:\n%s", out)
	}
}

// A pinned signing_key AUTHORS the three signing directives — user.signingkey
// naming the staged guest path, gpg.format = ssh, commit.gpgsign = true —
// never carries them from the host. See GitConfigFrom for why authoring
// beats carrying here specifically.
func TestGitConfigFromAuthorsSigningDirectivesFromThePin(t *testing.T) {
	id := &Identity{SSH: IdentitySSH{Agent: SSHAgentProxy}, Git: IdentityGit{SigningKey: "~/.ssh/id_ed25519_signing.pub"}}
	out := string(GitConfigFrom(id, "/home/u"))

	want := "/home/u/" + SigningKeyGuest
	if !strings.Contains(out, `signingkey = "`+want+`"`) {
		t.Errorf("generated config has no signingkey directive naming the staged absolute "+
			"guest path %q:\n%s", want, out)
	}
	if !strings.Contains(directives(out), "format = ssh") {
		t.Errorf("generated config does not set gpg.format = ssh:\n%s", out)
	}
	if !strings.Contains(directives(out), "gpgsign = true") {
		t.Errorf("generated config does not set commit.gpgsign = true:\n%s", out)
	}
}

// A pinned signing_key also authors gpg.ssh.allowedSignersFile, pointing at
// the verifier list snug generates from the same pin (#576). Without it
// `git log --show-signature` fails VERIFICATION rather than signing — measured
// on git 2.55.0, it prints "No signature" and exits 0, so a signed commit
// reads as unsigned, successfully.
func TestGitConfigFromAuthorsAllowedSignersFileWhenSigning(t *testing.T) {
	id := &Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy},
		Git: IdentityGit{SigningKey: "~/.ssh/id_ed25519_signing.pub", Email: "u@example.com"},
	}
	out := string(GitConfigFrom(id, "/home/u"))

	want := `allowedSignersFile = "/home/u/` + AllowedSignersGuest + `"`
	if !strings.Contains(directives(out), want) {
		t.Errorf("generated config has no %q directive:\n%s", want, out)
	}
}

// TestGitConfigFromOmitsAllowedSignersFileWhenNotSigning is the half that
// matters: a verifier list authored for a profile that does not sign is a
// grant nobody asked for. Same identity as above, minus signing_key, so
// `signing` in GitConfigFrom is false and the whole [gpg] block — format,
// allowedSignersFile, gpgsign — must not appear.
func TestGitConfigFromOmitsAllowedSignersFileWhenNotSigning(t *testing.T) {
	id := &Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "Some One", Email: "u@example.com"},
	}
	out := string(GitConfigFrom(id, "/home/u"))
	if strings.Contains(out, "allowedSignersFile") {
		t.Errorf("generated config authors an allowedSignersFile with no signing_key pinned:\n%s", out)
	}
}

// TestGitConfigFromAuthorsOpenPGPSigningFromAGPGPin is the gpg arm's parity
// with the ssh one: a sign-scoped identity.gpg turns on commit signing, names
// the FINGERPRINT as user.signingkey (git's openpgp backend hands that string
// to gpg, which matches the key inside the agent by fingerprint — no path is
// involved), and never authors the ssh backend's allowedSignersFile.
func TestGitConfigFromAuthorsOpenPGPSigningFromAGPGPin(t *testing.T) {
	const fp = "6732361300BBFDAE7F22972CD4381E1CE2880244"
	id := &Identity{GPG: IdentityGPG{Fingerprint: fp, Scope: "sign"}, Git: IdentityGit{Email: "u@example.com"}}
	out := string(GitConfigFrom(id, "/home/u"))

	if !strings.Contains(directives(out), `signingkey = "`+fp+`"`) {
		t.Errorf("generated config has no signingkey directive naming the fingerprint %q:\n%s", fp, out)
	}
	if !strings.Contains(directives(out), "format = openpgp") {
		t.Errorf("generated config does not set gpg.format = openpgp:\n%s", out)
	}
	if !strings.Contains(directives(out), "gpgsign = true") {
		t.Errorf("generated config does not set commit.gpgsign = true:\n%s", out)
	}
	if strings.Contains(directives(out), "allowedSignersFile") {
		t.Errorf("the openpgp arm authored an ssh-only allowedSignersFile:\n%s", out)
	}
}

// A DECRYPT-only gpg pin authors NO signing config: turning commit.gpgsign on
// for a pin that never granted "sign" would make a decryption grant a signing
// oracle for the same key.
func TestGitConfigFromDecryptOnlyGPGPinAuthorsNoSigning(t *testing.T) {
	id := &Identity{
		GPG: IdentityGPG{Fingerprint: "6732361300BBFDAE7F22972CD4381E1CE2880244", Scope: "decrypt"},
		Git: IdentityGit{Email: "u@example.com"},
	}
	out := string(GitConfigFrom(id, "/home/u"))
	for _, forbidden := range []string{"signingkey", "gpgsign", "format ="} {
		if strings.Contains(directives(out), forbidden) {
			t.Errorf("a decrypt-only gpg pin authored %q:\n%s", forbidden, out)
		}
	}
}

// TestRefuseTwoSigningKeysRefusesSSHAndGPGBothSigning / its decrypt-only
// control: gpg.format is one value, so two signing keys is a pin that does
// nothing, refused naming both fields.
func TestRefuseTwoSigningKeysRefusesSSHAndGPGBothSigning(t *testing.T) {
	// maximalProfile grants a runnable sandbox, so the CONTROL below reaches a
	// successful resolve rather than the "grants nothing" floor.
	base := func() *Profile {
		p := maximalProfile()
		p.Identity.SSH = IdentitySSH{Host: "gh.example", Key: "/home/u/.ssh/id.pub", Agent: SSHAgentProxy}
		p.Identity.Git = IdentityGit{Name: "Some One", Email: "u@example.com",
			SigningKey: "/home/u/.ssh/id_sign.pub"}
		p.Identity.GPG = IdentityGPG{Fingerprint: "6732361300BBFDAE7F22972CD4381E1CE2880244", Scope: "sign"}
		return p
	}
	resolveWith := func(t *testing.T, p *Profile) error {
		t.Helper()
		reg := testRegistry()
		reg[p.Name] = p
		_, err := Resolve(reg, []ProfileName{p.Name}, testCtx(), newFakeEnv())
		return err
	}

	err := resolveWith(t, base())
	if err == nil {
		t.Fatal("an ssh signing key and a sign-scoped gpg key resolved together; " +
			"git would use one format and silently ignore the other pin")
	}
	for _, want := range []string{"identity.git.signing_key", "identity.gpg"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}

	// The control: the same key scoped DECRYPT-only authors no signing config,
	// so it composes with the ssh signing key.
	p := base()
	p.Identity.GPG.Scope = "decrypt"
	if err := resolveWith(t, p); err != nil {
		t.Errorf("a decrypt-only gpg pin alongside an ssh signing key was refused: %v", err)
	}
}
