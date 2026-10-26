//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// knownHostsSSH is an ssh that reads only the known_hosts lines given,
// instead of the suite's: the PATH entry that puts it first on the host, and
// a profile "khwrap" that makes it the SANDBOX's ssh too (sandboxSSHProfile).
// snug asks the ssh the sandbox's PATH runs for the pin's known_hosts, so a
// wrapper first on the host's PATH alone is not asked, and the real
// ~/.ssh/known_hosts answers instead.
func knownHostsSSH(t *testing.T, lines ...string) (pathEnv, profile string) {
	t.Helper()
	if realSSH == "" {
		t.Skip("ssh is not installed; nothing to measure")
	}
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin, err := sshWrapper(dir, kh)
	if err != nil {
		t.Fatal(err)
	}
	return "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		sandboxSSHProfile("khwrap", bin)
}

// sandboxSSHProfile grants bin read-only at its own path and puts it first
// on the sandbox's PATH, so the ssh in it is the one the sandbox runs and the
// one snug probes. Read-only matters: snug refuses to run an ssh this
// sandbox can write.
func sandboxSSHProfile(name, bin string) string {
	return "[profile." + name + "]\n" +
		"description = \"a test's ssh wrapper, as the sandbox's ssh\"\n" +
		"ro = [\"" + bin + "\"]\n" +
		"[profile." + name + ".environ.merge]\n" +
		"PATH = [\"" + bin + "\"]\n"
}

// githubHostKeys are github.com's published host keys, as `ssh-keygen -F
// github.com` prints them.
var githubHostKeys = []string{
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
	"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
}

func pinnedSSHProfile(pub string) string {
	return "[profile.pinned]\n" +
		"description = \"one throwaway key\"\n" +
		"[profile.pinned.identity.ssh]\n" +
		"agent = \"proxy\"\n" +
		"key = \"" + pub + "\"\n"
}

// TestSandboxSSHNeverLaxerThanHost is #688's property, end to end: for the
// pinned host and for any other one, every algorithm list the sandbox's ssh
// resolves is a subset of the host's, RequiredRSASize is no smaller, and host
// keys are checked strictly — never accept-new, which against a read-only
// known_hosts accepted any key for a pin with no entry, every run.
func TestSandboxSSHNeverLaxerThanHost(t *testing.T) {
	requireSandbox(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	env := writeProfiles(t, map[string]string{"pinned": pinnedSSHProfile(pub)}, "SSH_AUTH_SOCK="+sock)

	for _, tc := range []struct{ name, hostArgs, insideArgs string }{
		{"the pin", "-l git github.com", "github.com"},
		{"another host", "example.org", "example.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostOut, err := exec.Command("sh", "-c", "ssh -G -o BatchMode=yes "+tc.hostArgs).Output()
			if err != nil {
				t.Fatalf("ssh -G on the host: %v", err)
			}
			host := sshGValues(t, string(hostOut))
			r := runEnv(t, env, []string{"-p", "pinned"}, proj, "ssh -G -o BatchMode=yes "+tc.insideArgs).mustRun(t)
			inside := sshGValues(t, r.out)
			if len(host) == 0 || len(inside) == 0 {
				t.Fatalf("ssh -G printed no whitelisted key (host %d, inside %d), so nothing "+
					"below would be compared:\n%s", len(host), len(inside), r.out)
			}
			for k, in := range inside {
				switch k {
				case "requiredrsasize":
					h, _ := strconv.Atoi(host[k])
					i, _ := strconv.Atoi(in)
					if i < h {
						t.Errorf("requiredrsasize inside %d < host %d", i, h)
					}
				case "rekeylimit":
				case "stricthostkeychecking":
					// Redteam on #688: a host's `yes` came back as `ask`
					// inside for an unpinned host, which prompts on a TTY.
					rank := map[string]int{"false": 0, "accept-new": 1, "ask": 2, "true": 3}
					if rank[in] < rank[host[k]] {
						t.Errorf("stricthostkeychecking inside %s is laxer than host %s", in, host[k])
					}
				default:
					allowed := map[string]bool{}
					for _, a := range strings.Split(host[k], ",") {
						allowed[a] = true
					}
					for _, a := range strings.Split(in, ",") {
						if !allowed[a] {
							t.Errorf("%s inside carries %s, which the host's ssh does not allow:\n  host:   %s\n  inside: %s",
								k, a, host[k], in)
						}
					}
				}
			}
			if tc.name == "the pin" && !strings.Contains(r.out, "\nstricthostkeychecking true\n") {
				t.Errorf("the pinned host is not checked with StrictHostKeyChecking yes:\n%s", r.out)
			}
			for _, lax := range []string{"stricthostkeychecking accept-new", "stricthostkeychecking false"} {
				if strings.Contains(r.out, "\n"+lax+"\n") {
					t.Errorf("ssh inside resolves %q:\n%s", lax, r.out)
				}
			}
		})
	}
}

// TestPinnedSSHWithNoKnownHostsEntryRefuses: a pin the host has never
// connected to refuses before anything starts, naming the fix, instead of
// trusting whichever key the first connection is shown.
func TestPinnedSSHWithNoKnownHostsEntryRefuses(t *testing.T) {
	requireSandbox(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	path, khwrap := knownHostsSSH(t, "gitlab.com "+suiteGitHubHostKey)
	env := writeProfilesOnly(t, map[string]string{"pinned": pinnedSSHProfile(pub), "khwrap": khwrap},
		"SSH_AUTH_SOCK="+sock, path)

	r := runEnv(t, env, []string{"-p", "pinned", "-p", "khwrap"}, proj, "true")
	if r.ran || r.code != 77 {
		t.Fatalf("snug exited %d (payload ran: %v), want 77 before anything ran:\n%s", r.code, r.ran, r.out)
	}
	if !strings.Contains(r.out, "no known_hosts entry for github.com") {
		t.Errorf("the refusal does not say what is missing:\n%s", r.out)
	}
}

// TestSandboxSSHRefusesAHostKeyTheHostRevoked is #688 F1's @revoked
// reproduction. The host's known_hosts revokes every key github.com serves
// and holds one @cert-authority line, so the pin has a usable entry and snug
// starts. Before #688 the filter dropped both lines, the generated file was
// empty, accept-new took github.com's key, and ssh went on to publickey auth
// (`Permission denied (publickey)`); now ssh inside refuses the key.
func TestSandboxSSHRefusesAHostKeyTheHostRevoked(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requireInternet(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	lines := []string{"@cert-authority github.com " + suiteGitHubHostKey}
	for _, k := range githubHostKeys {
		lines = append(lines, "@revoked github.com "+k)
	}
	path, khwrap := knownHostsSSH(t, lines...)
	env := writeProfilesOnly(t, map[string]string{"pinned": pinnedSSHProfile(pub), "khwrap": khwrap},
		"SSH_AUTH_SOCK="+sock, path)

	// The real ssh by path, not the wrapper the sandbox's PATH finds: the
	// wrapper's -o UserKnownHostsFile names a host file that is not inside
	// and would replace the generated known_hosts this test is about.
	r := runEnv(t, env, []string{"-p", "pinned", "-p", "khwrap", "-p", "@net"}, proj,
		realSSH+` -o BatchMode=yes -o ConnectTimeout=10 -T git@github.com 2>&1; echo "rc=$?"`).mustRun(t)
	if strings.Contains(r.out, "Permission denied") {
		t.Fatalf("ssh inside got past host-key checking with a key the host revoked:\n%s", r.out)
	}
	if !strings.Contains(r.out, "was revoked") {
		t.Errorf("ssh inside did not refuse the revoked key:\n%s", r.out)
	}
}

// TestTheSuitesSSHIsTheSandboxsAndPlainInside holds the harness every pinned
// test in this suite stands on (pinSuiteKnownHosts). It would catch:
//   - snug's pin probe no longer seeing the suite's known_hosts, so pinned
//     tests pass only where the account's real known_hosts happens to know
//     the pin, and refuse elsewhere;
//   - the suite's wrapper not being the sandbox's ssh, so the probe asks
//     another ssh;
//   - suiteKnownHostsEnv leaking into the sandbox, where the wrapper would
//     then override the generated known_hosts every pinned test measures.
func TestTheSuitesSSHIsTheSandboxsAndPlainInside(t *testing.T) {
	requireSandbox(t)
	if suiteSSHBin == "" {
		skipOrFail(t, "ssh is not installed; there is no suite wrapper")
	}
	if exec.Command("ssh-keygen", "-F", suitePinHost).Run() == nil {
		skipOrFail(t, "this account's own known_hosts knows %s, so the control below cannot refuse", suitePinHost)
	}
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	pinned := "[profile.pinned]\ndescription = \"one throwaway key\"\n" +
		"[profile.pinned.identity.ssh]\nagent = \"proxy\"\nhost = \"" + suitePinHost + "\"\nkey = \"" + pub + "\"\n"
	env := writeProfiles(t, map[string]string{"pinned": pinned}, "SSH_AUTH_SOCK="+sock)

	r := runEnv(t, env, []string{"-p", "pinned"}, proj,
		"command -v ssh\necho \"env=${"+suiteKnownHostsEnv+"-unset}\"\n").mustRun(t)
	if !strings.Contains(r.out, filepath.Join(suiteSSHBin, "ssh")+"\n") {
		t.Errorf("the ssh inside is not the suite's wrapper %s:\n%s", filepath.Join(suiteSSHBin, "ssh"), r.out)
	}
	if !strings.Contains(r.out, "env=unset\n") {
		t.Errorf("%s reached the sandbox:\n%s", suiteKnownHostsEnv, r.out)
	}

	// CONTROL: the same run with the variable empty for snug and its probe.
	// Only the suite's file knows the pin, so this refuses, which is what
	// shows the run above resolved on the suite's file and not on another.
	r = runEnv(t, append(env, suiteKnownHostsEnv+"="), []string{"-p", "pinned"}, proj, "true")
	if r.ran || r.code != 77 || !strings.Contains(r.out, "no known_hosts entry for "+suitePinHost) {
		t.Errorf("with %s empty, snug exited %d (payload ran: %v); want 77 naming the missing entry:\n%s",
			suiteKnownHostsEnv, r.code, r.ran, r.out)
	}
}
