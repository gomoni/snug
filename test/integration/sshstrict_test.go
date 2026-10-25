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

// knownHostsPath is the PATH entry for a snug whose host ssh reads only the
// known_hosts lines given, instead of the suite's.
func knownHostsPath(t *testing.T, lines ...string) string {
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
	return "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")
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
	env := writeProfiles(t, map[string]string{"pinned": pinnedSSHProfile(pub)}, "SSH_AUTH_SOCK="+sock,
		knownHostsPath(t, "gitlab.com "+suiteGitHubHostKey))

	r := runEnv(t, env, []string{"-p", "pinned"}, proj, "true")
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
	// github.com's published host keys, as `ssh-keygen -F github.com` prints them.
	revoked := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
	}
	lines := []string{"@cert-authority github.com " + suiteGitHubHostKey}
	for _, k := range revoked {
		lines = append(lines, "@revoked github.com "+k)
	}
	env := writeProfiles(t, map[string]string{"pinned": pinnedSSHProfile(pub)}, "SSH_AUTH_SOCK="+sock,
		knownHostsPath(t, lines...))

	r := runEnv(t, env, []string{"-p", "pinned", "-p", "@net"}, proj,
		`ssh -o BatchMode=yes -o ConnectTimeout=10 -T git@github.com 2>&1; echo "rc=$?"`).mustRun(t)
	if strings.Contains(r.out, "Permission denied") {
		t.Fatalf("ssh inside got past host-key checking with a key the host revoked:\n%s", r.out)
	}
	if !strings.Contains(r.out, "was revoked") {
		t.Errorf("ssh inside did not refuse the revoked key:\n%s", r.out)
	}
}
