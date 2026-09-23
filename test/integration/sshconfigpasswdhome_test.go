//go:build integration

package integration

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// hostPasswdHome is pw_dir for this uid, the directory ssh inside the sandbox
// takes its per-user config from. Skips when there is none: every assertion
// below is about the skew between it and $HOME.
func hostPasswdHome(t *testing.T) string {
	t.Helper()
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || !filepath.IsAbs(u.HomeDir) {
		t.Skipf("no passwd entry with an absolute home for uid %d (%v)", os.Getuid(), err)
	}
	return u.HomeDir
}

// passwdHomeLink is the profile refuseUnreadSSHConfig tells a user to add when
// $HOME and pw_dir disagree: pw_dir inside the sandbox resolves to the home the
// generated files are written under. A test pointing HOME at a temp directory
// with an identity pinned needs it, for the same reason a user would.
func passwdHomeLink(t *testing.T, home string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	return "[profile.pwlink]\n" +
		"description = \"pw_dir resolves to the synthetic HOME, so ssh reads the generated config\"\n" +
		"# ABUSE: none beyond @home's — a symlink to a directory the sandbox already has.\n" +
		"symlink = [{ at = \"" + hostPasswdHome(t) + "\", target = \"" + real + "\" }]\n"
}

// Issue #599. Measured on 43ba42d with HOME pointed elsewhere: the generated
// ~/.ssh/config was mounted (247 bytes) and `ssh -G github.com` inside reported
// `identitiesonly no` and `stricthostkeychecking ask`, snug exit 0, because ssh
// opens pw_dir/.ssh/config and never consults $HOME.
func TestAPinnedSSHConfigSSHWouldNotReadIsRefused(t *testing.T) {
	requireSandbox(t)
	pw := hostPasswdHome(t)
	dir, _ := requireHostSystemSSHConfig(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	home := t.TempDir()

	pinned := "[profile.pinned]\n" +
		"description = \"one throwaway key\"\n" +
		"[profile.pinned.identity.ssh]\n" +
		"agent = \"proxy\"\n" +
		"key = \"" + pub + "\"\n"
	profiles := map[string]string{"pinned": pinned, "sshcover": sshCoverageProfile(dir)}

	t.Run("refused, naming both paths", func(t *testing.T) {
		env := writeProfiles(t, profiles, "HOME="+home, "SSH_AUTH_SOCK="+sock)
		out, code := cli(t, env, "-p", "pinned", "-p", "sshcover", proj, "--", "true")
		if code != 77 {
			t.Errorf("exit %d, want 77: a pin ssh will never read ran anyway:\n%s", code, out)
		}
		for _, want := range []string{"would never be read", pw + "/.ssh/config"} {
			if !strings.Contains(out, want) {
				t.Errorf("refusal does not carry %q:\n%s", want, out)
			}
		}
	})

	// The dry-run screen stated the row as live; it must now say REFUSED.
	t.Run("dry run says REFUSED", func(t *testing.T) {
		env := writeProfiles(t, profiles, "HOME="+home, "SSH_AUTH_SOCK="+sock)
		out, _ := cli(t, env, "--dry-run", "-p", "pinned", "-p", "sshcover", proj)
		if !strings.Contains(out, "REFUSED") || !strings.Contains(out, "would never be read") {
			t.Errorf("--dry-run does not show the refusal:\n%s", out)
		}
	})

	// Red-team finding against the first version: a symlink AT pw_dir/.ssh TO
	// the generated file satisfied a lexical walk (the file "covers"
	// .ssh/config/config) while the kernel answers ENOTDIR. Measured: exit 0,
	// `identitiesonly no`, `stricthostkeychecking ask`.
	t.Run("a symlink that only lands lexically is still refused", func(t *testing.T) {
		real, err := filepath.EvalSymlinks(home)
		if err != nil {
			t.Fatal(err)
		}
		lexical := "[profile.pwlink]\n" +
			"description = \"lands on the generated file only lexically\"\n" +
			"symlink = [{ at = \"" + pw + "/.ssh\", target = \"" + real + "/.ssh/config\" }]\n"
		profiles := map[string]string{"pinned": pinned, "sshcover": sshCoverageProfile(dir), "pwlink": lexical}
		env := writeProfiles(t, profiles, "HOME="+home, "SSH_AUTH_SOCK="+sock)
		out, code := cli(t, env, "-p", "pinned", "-p", "sshcover", "-p", "pwlink", proj, "--",
			"sh", "-c", "ssh -G github.com | grep -i ^identitiesonly")
		if code != 77 || !strings.Contains(out, "would never be read") {
			t.Errorf("exit %d, want 77 with the #599 refusal:\n%s", code, out)
		}
	})

	// The positive control, and the proof the message's fix is real: with the
	// symlink it names, ssh inside reads the generated config.
	t.Run("the symlink the refusal offers makes ssh read the pin", func(t *testing.T) {
		profiles := map[string]string{"pinned": pinned, "sshcover": sshCoverageProfile(dir),
			"pwlink": passwdHomeLink(t, home)}
		env := writeProfiles(t, profiles, "HOME="+home, "SSH_AUTH_SOCK="+sock)
		r := runEnv(t, env, []string{"-p", "pinned", "-p", "sshcover", "-p", "pwlink"}, proj,
			"ssh -G github.com").mustRun(t)
		for _, want := range []string{"identitiesonly yes", "stricthostkeychecking accept-new"} {
			if !strings.Contains(r.out, "\n"+want+"\n") {
				t.Errorf("ssh inside did not read the generated config: no %q:\n%s", want, r.out)
			}
		}
	})
}
