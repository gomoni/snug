//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPasswdHomeIsHOMEByConstruction is issue #612's end-to-end proof: inside
// the sandbox, getpwuid(getuid())->pw_dir == $HOME, whatever the host's own
// passwd entry says — because the file answering getpwuid is one snug wrote
// for this run, not the host's. Two cases: an ordinary synthetic HOME (the
// divergence every CI job and every `HOME=t.TempDir()` fixture in this suite
// already produces), and a HOME that is itself a host symlink (the
// Silverblue/MicroOS `/home -> /var/home` shape issue #612 names).
func TestPasswdHomeIsHOMEByConstruction(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)

	cases := []struct {
		name string
		home func(t *testing.T) string
	}{
		{"synthetic HOME", func(t *testing.T) string { return t.TempDir() }},
		{"HOME is a symlink", func(t *testing.T) string {
			real := t.TempDir()
			link := filepath.Join(t.TempDir(), "homelink")
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			budget(t)
			home := tc.home(t)
			resolvedHome, err := filepath.EvalSymlinks(home)
			if err != nil {
				t.Fatal(err)
			}

			env := baseEnv("HOME=" + home)
			r := runEnv(t, env, nil, proj,
				`getent passwd "$(id -u)"
echo ---
id -gn
echo ---
getent group "$(id -g)"`).mustRun(t)

			blocks := strings.Split(r.out, "---\n")
			if len(blocks) != 3 {
				t.Fatalf("expected 3 blocks separated by \"---\", got %d:\n%s", len(blocks), r.out)
			}
			pw := strings.Split(strings.TrimSpace(blocks[0]), ":")
			idGn := strings.TrimSpace(blocks[1])
			gr := strings.Split(strings.TrimSpace(blocks[2]), ":")

			if len(pw) != 7 {
				t.Fatalf("getent passwd printed %d fields, want 7: %q", len(pw), blocks[0])
			}
			if pw[5] != resolvedHome {
				t.Errorf("pw_dir = %q, want the resolved $HOME %q", pw[5], resolvedHome)
			}
			if len(gr) != 4 {
				t.Fatalf("getent group printed %d fields, want 4: %q", len(gr), blocks[2])
			}
			if idGn != gr[0] {
				t.Errorf("id -gn = %q, want the generated /etc/group's own name %q", idGn, gr[0])
			}
		})
	}
}

// TestSSHReadsGeneratedConfigUnderSyntheticHOME is the ssh half of the same
// invariant, and the case issue #599's refuseUnreadSSHConfig used to REFUSE
// rather than fix: a pinned identity under a synthetic HOME, with NO `symlink`
// profile making pw_dir land anywhere in particular. ssh takes its per-user
// config from getpwuid()->pw_dir, and that now equals $HOME by construction,
// so the generated ~/.ssh/config is exactly the file ssh opens.
func TestSSHReadsGeneratedConfigUnderSyntheticHOME(t *testing.T) {
	requireSandbox(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	home := t.TempDir()

	pinned := "[profile.pinned]\n" +
		"description = \"one throwaway key\"\n" +
		"[profile.pinned.identity.ssh]\n" +
		"agent = \"proxy\"\n" +
		"key = \"" + pub + "\"\n"
	env := writeProfiles(t, map[string]string{"pinned": pinned}, "HOME="+home, "SSH_AUTH_SOCK="+sock)

	r := runEnv(t, env, []string{"-p", "pinned"}, proj, "ssh -G github.com").mustRun(t)
	for _, want := range []string{"identitiesonly yes", "stricthostkeychecking accept-new"} {
		if !strings.Contains(r.out, "\n"+want+"\n") {
			t.Errorf("ssh inside did not read the generated config under a synthetic HOME, "+
				"with no pwlink profile: no %q:\n%s", want, r.out)
		}
	}
}

// TestGeneratedPasswdIsOneLine pins the shape SANDBOX-POLICY ruled: exactly
// one line each, no root, no nobody, read-only.
func TestGeneratedPasswdIsOneLine(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj, `wc -l < /etc/passwd
wc -l < /etc/group
grep -c '^root:' /etc/passwd || true
grep -c '^nobody:' /etc/passwd || true
echo "x:x:0:0:x:/:/bin/sh" >> /etc/passwd 2>&1 && echo APPEND-OK || echo APPEND-REFUSED`).mustRun(t)

	lines := strings.Split(strings.TrimSpace(r.out), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected at least 5 output lines, got %d:\n%s", len(lines), r.out)
	}
	if lines[0] != "1" {
		t.Errorf("/etc/passwd has %s line(s), want exactly 1:\n%s", lines[0], r.out)
	}
	if lines[1] != "1" {
		t.Errorf("/etc/group has %s line(s), want exactly 1:\n%s", lines[1], r.out)
	}
	if lines[2] != "0" {
		t.Errorf("a root: line is present in the generated /etc/passwd:\n%s", r.out)
	}
	if lines[3] != "0" {
		t.Errorf("a nobody: line is present in the generated /etc/passwd:\n%s", r.out)
	}
	// bash's own "Read-only file system" message lands on the same combined
	// stream between the last `getent`/`grep` line and APPEND-REFUSED, so the
	// last line is asserted rather than a fixed index.
	if lines[len(lines)-1] != "APPEND-REFUSED" {
		t.Errorf("the sandbox could append to /etc/passwd — it must be read-only:\n%s", r.out)
	}
}

// TestNSSServicesStillResolve pins the measurement generatedNsswitchConf's own
// doc comment records: a shorter nsswitch.conf (passwd/group/hosts/networks
// only) broke `getent services http` and `getent protocols tcp` on openSUSE
// with exit 2 rather than falling back to a compiled-in default. The
// `usrfiles` module on those two lines (plus rpc, ethers) is what fixes it.
func TestNSSServicesStillResolve(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj,
		`getent services http >/dev/null 2>&1 && echo SERVICES-OK || echo SERVICES-FAILED
getent protocols tcp >/dev/null 2>&1 && echo PROTOCOLS-OK || echo PROTOCOLS-FAILED`).mustRun(t)

	for _, want := range []string{"SERVICES-OK", "PROTOCOLS-OK"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("want %s in the default sandbox's nsswitch resolution:\n%s", want, r.out)
		}
	}
}

// hostHasLibNSSMyhostname reports whether this host ships the NSS module
// generatedNsswitchConf's `hosts:` line names — under /usr, which @sys's own
// ro bind already carries into the sandbox, so no separate grant is needed to
// exercise it there.
func hostHasLibNSSMyhostname(t *testing.T) bool {
	t.Helper()
	matches, err := filepath.Glob("/usr/lib*/libnss_myhostname.so*")
	if err != nil {
		t.Fatal(err)
	}
	return len(matches) > 0
}

// TestLocalhostResolvesViaMyhostname pins generatedNsswitchConf's `hosts:
// files myhostname dns` line: with no generated /etc/hosts at all, `localhost`
// still resolves, through libnss_myhostname rather than a hosts file.
func TestLocalhostResolvesViaMyhostname(t *testing.T) {
	requireSandbox(t)
	if !hostHasLibNSSMyhostname(t) {
		t.Skip("SKIP: this host has no libnss_myhostname")
	}
	proj, _ := target(t)

	r := run(t, nil, proj, `[ -e /etc/hosts ] && echo HOSTS-FILE-PRESENT || echo HOSTS-FILE-ABSENT
getent hosts localhost`).mustRun(t)

	if !strings.Contains(r.out, "HOSTS-FILE-ABSENT") {
		t.Fatalf("the sandbox has a /etc/hosts, so this run does not test resolving "+
			"localhost with none:\n%s", r.out)
	}
	if r.code != 0 {
		t.Fatalf("getent hosts localhost exited %d:\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "localhost") {
		t.Fatalf("getent hosts localhost produced no entry naming localhost:\n%s", r.out)
	}
}

// TestNoGeneratedAccountsWithoutSys is TestPasswdHomeIsHOMEByConstruction's
// negative control at the profile level: a selection with no `nss` profile at
// all gets no generated /etc/passwd, so a profile that binds the host's own
// copy directly sees it byte-identical, untouched by anything Resolve writes.
func TestNoGeneratedAccountsWithoutSys(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)

	hostPasswd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Skip("SKIP: no host /etc/passwd to compare against")
	}

	runtime := "[profile.runtime]\n" +
		"description = \"OS runtime, no nss\"\n" +
		"ro = [\"/usr\"]\n" +
		"rw = [\"{target}\"]\n" +
		"symlink = [\n" +
		"  { at = \"/bin\", target = \"usr/bin\" },\n" +
		"  { at = \"/sbin\", target = \"usr/sbin\" },\n" +
		"  { at = \"/lib\", target = \"usr/lib\" },\n" +
		"  { at = \"/lib64\", target = \"usr/lib64\" },\n" +
		"]\n"
	etcbind := "[profile.etcbind]\n" +
		"description = \"the host's own /etc/passwd, bound directly, no nss\"\n" +
		"ro = [\"/etc/passwd\"]\n"

	env := writeProfiles(t, map[string]string{"runtime": runtime, "etcbind": etcbind})
	r := runEnv(t, env, []string{"--no-defaults", "-p", "runtime", "-p", "etcbind"}, proj,
		"cat /etc/passwd").mustRun(t)

	if string(hostPasswd) != r.out {
		t.Errorf("the sandbox's /etc/passwd differs from the host's despite an explicit "+
			"bind and no `nss` profile selected — something generated it after all:\n"+
			"--- host\n%s\n--- sandbox\n%s", hostPasswd, r.out)
	}
}
