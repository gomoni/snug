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
