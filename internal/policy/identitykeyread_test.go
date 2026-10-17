package policy

import (
	"strings"
	"testing"
)

func identityKeyProfile(key, signing string) map[ProfileName]*Profile {
	id := &Identity{
		SSH: IdentitySSH{Host: "ssh.example", Key: key, Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "Some One", Email: "some.one@example.com", SigningKey: signing},
	}
	reg := testRegistry()
	reg["peek"] = &Profile{Name: "peek", Identity: id}
	return reg
}

func identityKeyCtx() Context {
	c := engineStateCtx(testEngineDataRoots, "/tmp/snug-1000-")
	c.RuntimeDirs = []string{"/run/user/1000/snug"}
	return c
}

// TestIdentitySSHKeyUnderEngineStateRefused: identity.ssh.key is read by snug
// and staged into $HOME, and the ro/rw grant scans never see it. A key path
// inside the engine store, a runtime directory or a per-run engine directory
// would hand that state to the sandbox as a file.
func TestIdentitySSHKeyUnderEngineStateRefused(t *testing.T) {
	for _, tc := range []struct{ name, key, want string }{
		{"engine store", "/home/u/.local/share/snug/engines/k.pub", "engine store"},
		{"runtime dir", "/run/user/1000/snug/agent.pub", "runtime directory"},
		{"per-run tmp", "/tmp/snug-1000-x/id.pub", "per-run engine directory"},
	} {
		env := envWith(tc.key, "/home/u/proj/sub")
		_, err := Resolve(identityKeyProfile(tc.key, ""), append(testDefaults, "peek"), identityKeyCtx(), env)
		if err == nil {
			t.Errorf("%s: ACCEPTED identity.ssh.key %s", tc.name, tc.key)
			continue
		}
		for _, w := range []string{"identity.ssh.key", tc.key, tc.want, `"peek"`, "name that path instead"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: refusal lacks %q:\n%v", tc.name, w, err)
			}
		}
	}
}

func TestIdentitySigningKeyUnderEngineStateRefused(t *testing.T) {
	key := "/tmp/snug-1000-x/sign.pub"
	env := envWith(key, "/home/u/.ssh/id.pub", "/home/u/proj/sub")
	_, err := Resolve(identityKeyProfile("/home/u/.ssh/id.pub", key), append(testDefaults, "peek"), identityKeyCtx(), env)
	if err == nil {
		t.Fatalf("ACCEPTED identity.git.signing_key %s", key)
	}
	for _, w := range []string{"identity.git.signing_key", key, "per-run engine directory"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal lacks %q:\n%v", w, err)
		}
	}
}

func TestIdentityKeyViaSymlinkIntoEngineStateRefused(t *testing.T) {
	key := "/opt/link/k.pub"
	env := envWith(key, "/home/u/.local/share/snug/engines", "/home/u/proj/sub")
	env.links["/opt/link"] = "/home/u/.local/share/snug/engines"
	if _, err := Resolve(identityKeyProfile(key, ""), append(testDefaults, "peek"), identityKeyCtx(), env); err == nil {
		t.Fatalf("ACCEPTED identity.ssh.key %s through a link into the engine store", key)
	}
}

func TestIdentityKeyInOrdinaryDirectoryStillWorks(t *testing.T) {
	env := envWith("/home/u/.ssh/id.pub", "/home/u/.ssh/sign.pub", "/home/u/proj/sub")
	if _, err := Resolve(identityKeyProfile("/home/u/.ssh/id.pub", "/home/u/.ssh/sign.pub"),
		append(testDefaults, "peek"), identityKeyCtx(), env); err != nil {
		t.Fatalf("refused keys under an ordinary directory: %v", err)
	}
}

// TestIdentityKeyRelativeRefused would catch a relative key path being read
// against snug's own working directory: the judged string and the string read
// would agree, but nothing in the profile or --dry-run shows where that is.
func TestIdentityKeyRelativeRefused(t *testing.T) {
	for _, tc := range []struct{ name, ssh, signing, field string }{
		{"ssh.key bare", "tmp/k.pub", "", "identity.ssh.key"},
		{"ssh.key dot", "./k.pub", "", "identity.ssh.key"},
		{"signing_key", "{home}/.ssh/id.pub", "k.pub", "identity.git.signing_key"},
	} {
		_, err := Resolve(identityKeyProfile(tc.ssh, tc.signing), append(testDefaults, "peek"), identityKeyCtx(), envWith("/home/u/.ssh/id.pub", "/home/u/proj/sub"))
		if err == nil {
			t.Errorf("%s: ACCEPTED a relative key", tc.name)
			continue
		}
		for _, w := range []string{tc.field, "must be an absolute path", `"peek"`} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: refusal lacks %q:\n%v", tc.name, w, err)
			}
		}
	}
	if _, err := Resolve(identityKeyProfile("{home}/.ssh/k.pub", ""), append(testDefaults, "peek"), identityKeyCtx(), envWith("/home/u/.ssh", "/home/u/proj/sub")); err != nil {
		t.Errorf("control: {home}/.ssh/k.pub refused:\n%v", err)
	}
}
