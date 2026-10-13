package ingest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/hostfacts"
)

const sshConfig = `# comment
Host github.com codeberg.org
    IdentityFile ~/.ssh/github_auth_id_ed25519
    IdentitiesOnly yes

Host ghplainsof
  HostName github.com
  User plainsof
  IdentityFile ~/.ssh/key3_vyskocilme_id_ed25519.pub

Match host evil.example
  IdentityFile ~/.ssh/not_this

Host *
  IdentityFile=~/.ssh/fallback
Host !github.com *.com
  IdentityFile ~/.ssh/dotcom
`

func TestStemsForRanksByHowSpecificTheBlockIs(t *testing.T) {
	h := ParseSSHConfig(strings.NewReader(sshConfig))
	got := StemsFor(h, "github.com")
	want := []string{"github_auth_id_ed25519", "key3_vyskocilme_id_ed25519", "fallback"}
	if !slices.Equal(got, want) {
		t.Errorf("github.com: %v want %v", got, want)
	}
	if got := StemsFor(h, "example.com"); !slices.Equal(got, []string{"fallback", "dotcom"}) {
		t.Errorf("example.com: %v", got)
	}
	if got := StemsFor(h, "evil.example"); slices.Contains(got, "not_this") {
		t.Errorf("a Match block leaked: %v", got)
	}
}

func TestParseKnownHosts(t *testing.T) {
	got := ParseKnownHosts(strings.NewReader("github.com,140.82.1.1 ssh-ed25519 AAAA\n|1|abc|def ssh-ed25519 AAAA\n[git.example.org]:2222 ssh-rsa AAAA\n@cert-authority *.corp ssh-rsa AAAA\n# c\n"))
	if !got["github.com"] || !got["git.example.org"] || len(got) != 3 {
		t.Errorf("%v", got)
	}
}

func TestParseAllowedSigners(t *testing.T) {
	blob := BlobForTest(5)
	fp, _ := hostfacts.FingerprintOf(blob)
	got := ParseAllowedSigners(strings.NewReader("a@x.org,b@x.org namespaces=\"git\" ssh-ed25519 " + blob + " comment\n# c\nbad line\n"))
	if !slices.Equal(got["a@x.org"], []string{fp}) || !slices.Equal(got["b@x.org"], []string{fp}) || len(got) != 2 {
		t.Errorf("%v", got)
	}
}

// TestLoadSSHStaysInsideDotSSH: an Include that climbs out of ~/.ssh, a config
// that is a FIFO's neighbour and a symlink to a file outside read nothing.
func TestLoadSSHStaysInsideDotSSH(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("Host leaked\n  IdentityFile ~/.ssh/leaked\n"), 0o600)
	ssh := filepath.Join(home, ".ssh")
	os.MkdirAll(filepath.Join(ssh, "conf.d"), 0o700)
	os.WriteFile(filepath.Join(ssh, "config"), []byte("Include conf.d/*\nInclude ../../etc/x\nInclude "+outside+"\nHost github.com\n  IdentityFile ~/.ssh/a\n"), 0o600)
	os.WriteFile(filepath.Join(ssh, "conf.d", "one"), []byte("Host gl.example\n  IdentityFile ~/.ssh/b\n"), 0o600)
	os.Symlink(outside, filepath.Join(ssh, "conf.d", "two"))
	f := LoadSSH(home, "")
	if !slices.Equal(StemsFor(f.Hosts, "github.com"), []string{"a"}) || !slices.Equal(StemsFor(f.Hosts, "gl.example"), []string{"b"}) {
		t.Errorf("hosts %+v", f.Hosts)
	}
	if len(StemsFor(f.Hosts, "leaked")) != 0 {
		t.Errorf("read outside ~/.ssh: %+v", f.Hosts)
	}
}
