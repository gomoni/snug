//go:build integration

package integration

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unpinnedHostSSH is an ssh configured by the test rather than by the
// machine: a wrapper runs the real ssh with -F on a file named ssh_config
// that names krl as the global RevokedHostKeys, then holds the test's own
// blocks, then Includes this machine's own system-wide ssh_config. The
// wrapper is first on the host's PATH, and with inSandbox it is also the
// sandbox's ssh (sandboxSSHProfile), which is the ssh snug probes. Its -F
// file is then the top-level config snug writes, at its own path, and the
// wrapper inside reads snug's file there.
type unpinnedHostSSH struct {
	env     []string // writeProfiles' environment, wrapper first on the host PATH
	wrapper string   // the wrapper itself, for running it on the host
	conf    string   // the wrapper's -F file
	krl     string   // host path of the RevokedHostKeys file
	sysPath string   // this machine's system-wide ssh_config, as ssh names it
}

// narrowCipher is what the test's blocks set.
const narrowCipher = "aes128-ctr"

// hostXBlock narrows Ciphers for x.invalid alone.
const hostXBlock = "Host x.invalid\n    Ciphers " + narrowCipher + "\n"

func newUnpinnedHostSSH(t *testing.T, krlContent []byte, blocks string, inSandbox bool) unpinnedHostSSH {
	t.Helper()
	if realSSH == "" {
		skipOrFail(t, "ssh is not installed; there is no host ssh to carry from")
	}
	sysPath := hostSystemSSHConfig(t)
	dir := t.TempDir()
	krl := filepath.Join(dir, "host-revoked-keys")
	if err := os.WriteFile(krl, krlContent, 0o644); err != nil {
		t.Fatal(err)
	}
	// Named ssh_config: snug only ever writes a file of that name, and a
	// host.conf would be dropped from the chain rather than written.
	confDir := filepath.Join(dir, "etc")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(confDir, "ssh_config")
	body := "RevokedHostKeys " + krl + "\n" +
		blocks +
		"Match all\n" +
		"Include " + sysPath + "\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := "#!/bin/sh\nexec " + realSSH + " -F " + conf + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	path := "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")
	sshwrap := "[profile.sshwrap]\ndescription = \"the test's ssh wrapper, on the host PATH only\"\n"
	if inSandbox {
		sshwrap = sandboxSSHProfile("sshwrap", bin)
	}
	env := writeProfilesOnly(t, map[string]string{"sshwrap": sshwrap}, path)
	return unpinnedHostSSH{env: env, wrapper: filepath.Join(bin, "ssh"), conf: conf, krl: krl, sysPath: sysPath}
}

// hostSystemSSHConfig is the first system-wide ssh_config the real ssh
// reads, outside $HOME (/usr/etc/ssh/ssh_config on the openSUSE host this
// was written on).
func hostSystemSSHConfig(t *testing.T) string {
	t.Helper()
	cmd := exec.Command(realSSH, "-G", "-v", "-o", "BatchMode=yes", "snug-probe.invalid")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh -G -v on the host: %v\n%s", err, stderr.String())
	}
	home, _ := os.UserHomeDir()
	const marker = "Reading configuration data "
	for _, line := range strings.Split(stderr.String(), "\n") {
		_, p, ok := strings.Cut(line, marker)
		p = strings.TrimSpace(p)
		if ok && filepath.Base(p) == "ssh_config" && (home == "" || !strings.HasPrefix(p, home+"/")) {
			return p
		}
	}
	skipOrFail(t, "this host's ssh reads no system-wide ssh_config, so snug has no "+
		"path to write one at:\n%s", stderr.String())
	return ""
}

// hostSSHG is `ssh -G` through the wrapper, on the host.
func (h unpinnedHostSSH) hostSSHG(t *testing.T, name string) map[string]string {
	t.Helper()
	// By path: exec.Command looks a bare name up on THIS process's PATH,
	// where the suite's own wrapper comes first.
	out, err := exec.Command(h.wrapper, "-G", "-o", "BatchMode=yes", name).Output()
	if err != nil {
		t.Fatalf("ssh -G %s on the host, through the wrapper: %v", name, err)
	}
	return sshGAll(string(out))
}

// realSSHG is `ssh -G` of the real ssh with this machine's own files.
func realSSHG(t *testing.T, name string) map[string]string {
	t.Helper()
	out, err := exec.Command(realSSH, "-G", "-o", "BatchMode=yes", name).Output()
	if err != nil {
		t.Fatalf("%s -G %s on the host: %v", realSSH, name, err)
	}
	return sshGAll(string(out))
}

// sshGAll is every `key value` line of `ssh -G` output.
func sshGAll(out string) map[string]string {
	v := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, val, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			v[k] = val
		}
	}
	return v
}

// payloadSection is the text between `==name==` and the next `==` line of a
// payload that prints several.
func payloadSection(out, name string) (string, bool) {
	_, rest, ok := strings.Cut(out, "=="+name+"==\n")
	if !ok {
		return "", false
	}
	if i := strings.Index(rest, "\n=="); i >= 0 {
		rest = rest[:i+1]
	}
	return rest, true
}

// insideSSHIs fails the test unless the payload's `command -v ssh` printed
// want: every assertion about what the sandbox's ssh reads is otherwise about
// some other binary and its files.
func insideSSHIs(t *testing.T, out, want string) {
	t.Helper()
	which, _ := payloadSection(out, "which")
	if got := strings.TrimSpace(which); got != want {
		t.Fatalf("the ssh inside is %q, want %q:\n%s", got, want, out)
	}
}

// TestUnpinnedSSHReadsTheHostsRevokedHostKeys would catch an unpinned
// sandbox's ssh not checking host keys against its global RevokedHostKeys:
// the file not staged, staged with other bytes, not named by the generated
// ssh_config, or named by the host's path (which does not exist inside, so
// ssh would refuse every host). The host's KRL path must not appear anywhere
// the payload printed. The generated file lands on snug's /tmp tmpfs, at the
// wrapper's -F path, so this is the arm that writes where no grant supplies
// a file, on every host shape.
func TestUnpinnedSSHReadsTheHostsRevokedHostKeys(t *testing.T) {
	requireSandbox(t)
	krl := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcgUwK96NCQlqjPZlPkFyqH6IrvXdrKEmVT0asbOPTC\n")
	h := newUnpinnedHostSSH(t, krl, hostXBlock, true)
	proj, _ := target(t)

	// POSITIVE CONTROL: the ssh snug will probe names the test's KRL
	// globally. Without this an unconfigured fixture would leave nothing to
	// carry and the run below would fail for the wrong reason.
	if got := h.hostSSHG(t, "example.invalid")["revokedhostkeys"]; got != h.krl {
		t.Fatalf("host ssh -G names revokedhostkeys %q, want the fixture's %q", got, h.krl)
	}

	r := runEnv(t, h.env, []string{"-p", "sshwrap"}, proj,
		"echo '==which=='; command -v ssh\n"+
			"echo '==g=='; ssh -G -o BatchMode=yes example.invalid\n"+
			"echo '==krl=='; base64 -w0 /snug/revoked_host_keys; echo\n"+
			"echo '==conf=='; cat "+h.conf+"\n"+
			"echo '==end=='\n").mustRun(t)
	insideSSHIs(t, r.out, h.wrapper)

	g, _ := payloadSection(r.out, "g")
	if got := sshGAll(g)["revokedhostkeys"]; got != "/snug/revoked_host_keys" {
		t.Errorf("ssh -G inside names revokedhostkeys %q, want /snug/revoked_host_keys:\n%s", got, r.out)
	}
	enc, _ := payloadSection(r.out, "krl")
	inside, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil || string(inside) != string(krl) {
		t.Errorf("/snug/revoked_host_keys inside = %q (%v), want the host file's bytes %q", inside, err, krl)
	}
	conf, _ := payloadSection(r.out, "conf")
	if !strings.Contains(conf, "Generated by snug") {
		t.Errorf("%s inside is not snug's generated file:\n%s", h.conf, conf)
	}
	if strings.Contains(r.out, h.krl) {
		t.Errorf("the host's KRL path %s reached the sandbox:\n%s", h.krl, r.out)
	}
}

// TestUnpinnedHostBlockIsNotCarried holds a DISCLOSED RESIDUAL, not a
// property anyone wants: a `Host x.invalid` block narrowing Ciphers does not
// reach the sandbox, and x.invalid negotiates with the global list there.
// The generated file and --dry-run's SSH block both say so. It would catch a
// change that starts carrying per-host blocks for unpinned hosts without
// anyone deciding to, and whoever makes that change on purpose inverts this
// test and rewrites both disclosures in the same commit.
func TestUnpinnedHostBlockIsNotCarried(t *testing.T) {
	requireSandbox(t)
	h := newUnpinnedHostSSH(t, []byte{}, hostXBlock, true)
	proj, _ := target(t)

	// POSITIVE CONTROL: on the host the block is live for x.invalid and for
	// nothing else, so the inside answer below is a statement about carrying.
	hostX, hostOther := h.hostSSHG(t, "x.invalid")["ciphers"], h.hostSSHG(t, "example.invalid")["ciphers"]
	if hostX != narrowCipher || hostOther == narrowCipher {
		t.Fatalf("host ciphers: x.invalid %q, example.invalid %q; want %q and the global list",
			hostX, hostOther, narrowCipher)
	}

	r := runEnv(t, h.env, []string{"-p", "sshwrap"}, proj,
		"echo '==which=='; command -v ssh\n"+
			"echo '==x=='; ssh -G -o BatchMode=yes x.invalid\n"+
			"echo '==other=='; ssh -G -o BatchMode=yes example.invalid\n"+
			"echo '==end=='\n").mustRun(t)
	insideSSHIs(t, r.out, h.wrapper)

	xs, _ := payloadSection(r.out, "x")
	others, _ := payloadSection(r.out, "other")
	x, other := sshGAll(xs), sshGAll(others)
	// The run read snug's generated file: the fixture's KRL is empty but
	// named, so the line is there only if it did.
	if x["revokedhostkeys"] != "/snug/revoked_host_keys" {
		t.Fatalf("ssh inside did not read snug's ssh_config (revokedhostkeys %q):\n%s",
			x["revokedhostkeys"], r.out)
	}
	if x["ciphers"] == narrowCipher || x["ciphers"] != other["ciphers"] {
		t.Errorf("x.invalid inside resolves ciphers %q, example.invalid %q: the Host x.invalid "+
			"block reached the sandbox. If that is now intended, invert this test and rewrite the "+
			"disclosures in SystemSSHConfigFrom and describeSSH", x["ciphers"], other["ciphers"])
	}
	// The global list is what x.invalid gets instead, so it is the probed
	// ssh's global list. A probe that asked about a name some block matches
	// would carry that block to every host and fail here rather than above.
	if other["ciphers"] != hostOther {
		t.Errorf("example.invalid inside resolves ciphers %q, the probed ssh's global list is %q",
			other["ciphers"], hostOther)
	}
}

// TestUnpinnedSSHRefusesAHostKeyTheHostRevoked is the unpinned twin of
// TestSandboxSSHRefusesAHostKeyTheHostRevoked. The global RevokedHostKeys
// lists every key github.com serves; with no identity pinned there is no
// known_hosts inside, so the only thing that can name the revocation is the
// staged file. It would catch a connection from an unpinned sandbox getting
// past the revocation check: without the KRL, ssh fails on the unknown host
// key instead, with no "revoked" in the output.
func TestUnpinnedSSHRefusesAHostKeyTheHostRevoked(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requireInternet(t)
	h := newUnpinnedHostSSH(t, []byte(strings.Join(githubHostKeys, "\n")+"\n"), "", true)
	proj, _ := target(t)

	r := runEnv(t, h.env, []string{"-p", "sshwrap", "-p", "@net"}, proj,
		"echo '==which=='; command -v ssh\n"+
			"echo '==ssh=='; ssh -o BatchMode=yes -o ConnectTimeout=10 -T git@github.com 2>&1; echo \"rc=$?\"\n"+
			"echo '==end=='\n").mustRun(t)
	insideSSHIs(t, r.out, h.wrapper)

	out, _ := payloadSection(r.out, "ssh")
	// The verdict names snug's staged file, so it is a host-key answer from
	// the far end rather than a resolver or connect failure that would also
	// contain no "Permission denied".
	if !strings.Contains(out, "revoked by file /snug/revoked_host_keys") {
		t.Errorf("ssh inside did not refuse github.com's key as revoked by the staged file:\n%s", r.out)
	}
	if strings.Contains(out, "Permission denied") {
		t.Errorf("ssh inside got past host-key checking with a key the host revoked:\n%s", r.out)
	}
}

// TestNegatedHostBlockAppliesToTheExcludedHostInside is the redteam's F1. A
// block `Host * !bank.example` keeps a setting AWAY from bank.example on the
// host; snug asks the ssh about a name no block names, the negated block
// matches that name, so its value is carried into the global section inside
// and applies to bank.example there too. The value is whitelisted (an
// algorithm list, never a program), so this is the disclosed cost and not a
// hole. It would catch the disclosure going false: the run must show the
// carried value reaching bank.example inside, and the generated file and
// --dry-run must both say a negated block does that. If a future probe stops
// carrying negated blocks, the first assertion fails and the disclosures
// change with it.
func TestNegatedHostBlockAppliesToTheExcludedHostInside(t *testing.T) {
	requireSandbox(t)
	h := newUnpinnedHostSSH(t, []byte{}, "Host * !bank.example\n    Ciphers "+narrowCipher+"\n", true)
	proj, _ := target(t)

	// POSITIVE CONTROL: on the host the negated block does what its author
	// meant, so the inside answer below is a difference snug made.
	hostBank, hostOther := h.hostSSHG(t, "bank.example")["ciphers"], h.hostSSHG(t, "example.invalid")["ciphers"]
	if hostBank == narrowCipher || hostOther != narrowCipher {
		t.Fatalf("host ciphers: bank.example %q, example.invalid %q; want the global list and %q",
			hostBank, hostOther, narrowCipher)
	}

	r := runEnv(t, h.env, []string{"-p", "sshwrap"}, proj,
		"echo '==which=='; command -v ssh\n"+
			"echo '==bank=='; ssh -G -o BatchMode=yes bank.example\n"+
			"echo '==conf=='; cat "+h.conf+"\n"+
			"echo '==end=='\n").mustRun(t)
	insideSSHIs(t, r.out, h.wrapper)

	bank, _ := payloadSection(r.out, "bank")
	if got := sshGAll(bank)["ciphers"]; got != narrowCipher {
		t.Errorf("bank.example inside resolves ciphers %q, want the negated block's %q carried to it:\n%s",
			got, narrowCipher, r.out)
	}
	conf, _ := payloadSection(r.out, "conf")
	if !strings.Contains(conf, "Generated by snug") {
		t.Fatalf("%s inside is not snug's generated file:\n%s", h.conf, conf)
	}
	if !strings.Contains(conf, "negated pattern (Host * !x, Match !host x) matches that name") {
		t.Errorf("the generated file does not say a negated block applies to the excluded name:\n%s", conf)
	}
	out, code := cli(t, h.env, "--dry-run", "-p", "sshwrap", proj)
	if code != 0 {
		t.Fatalf("--dry-run exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "pattern (Host * !x, Match !host x) matches that name, so") {
		t.Errorf("--dry-run does not say a negated block applies to the excluded name:\n%s", out)
	}
}

// TestTheSandboxsSSHIsProbedNotTheHostPATHs is the redteam's F5. The ssh first
// on the host's PATH is a wrapper the sandbox does not run; it narrows the
// global Ciphers and names a KRL. The sandbox runs the real ssh, so the
// values written for it must be the real ssh's, with no KRL, and its system
// file must be one it can read: on a host whose ssh_config is under the /usr
// bind (openSUSE), the root-owned original kills ssh inside unless snug
// replaces it, which is also the redteam's F3. It would catch snug carrying
// the host PATH ssh's answers into a sandbox that never runs that ssh.
func TestTheSandboxsSSHIsProbedNotTheHostPATHs(t *testing.T) {
	requireSandbox(t)
	h := newUnpinnedHostSSH(t, []byte{}, "Ciphers "+narrowCipher+"\n", false)
	proj, _ := target(t)

	// POSITIVE CONTROL: the two ssh answer differently, so carrying the
	// wrong one shows below.
	wrapped, real := h.hostSSHG(t, "example.invalid"), realSSHG(t, "example.invalid")
	if wrapped["ciphers"] != narrowCipher || wrapped["revokedhostkeys"] != h.krl ||
		real["ciphers"] == narrowCipher || real["revokedhostkeys"] != "none" {
		t.Fatalf("the fixture's two ssh do not differ as this test needs: wrapper ciphers %q "+
			"revokedhostkeys %q; real ciphers %q revokedhostkeys %q",
			wrapped["ciphers"], wrapped["revokedhostkeys"], real["ciphers"], real["revokedhostkeys"])
	}

	out, code := cli(t, h.env, "--dry-run", "-p", "sshwrap", proj)
	if code != 0 {
		t.Fatalf("--dry-run exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "system-wide ssh_config REPLACED at "+h.sysPath) &&
		!strings.Contains(out, "system-wide ssh_config WRITTEN at "+h.sysPath) {
		t.Errorf("--dry-run writes nothing at %s, the file the sandbox's ssh reads:\n%s", h.sysPath, out)
	}
	r := runEnv(t, h.env, []string{"-p", "sshwrap"}, proj,
		"echo '==which=='; command -v ssh\n"+
			"echo '==g=='; ssh -G -o BatchMode=yes example.invalid 2>&1; echo \"rc=$?\"\n"+
			"echo '==end=='\n").mustRun(t)
	if which, _ := payloadSection(r.out, "which"); strings.TrimSpace(which) == h.wrapper || strings.TrimSpace(which) == "" {
		t.Fatalf("the ssh inside is %q, not the sandbox's own:\n%s", strings.TrimSpace(which), r.out)
	}
	g, _ := payloadSection(r.out, "g")
	if strings.Contains(g, "Bad owner or permissions") || !strings.Contains(g, "\nrc=0\n") {
		t.Fatalf("ssh inside did not run:\n%s", r.out)
	}
	inside := sshGAll(g)
	if inside["ciphers"] != real["ciphers"] {
		t.Errorf("ciphers inside %q, want the sandbox's ssh's own %q (the host PATH wrapper says %q)",
			inside["ciphers"], real["ciphers"], narrowCipher)
	}
	if inside["revokedhostkeys"] != "none" || strings.Contains(r.out, h.krl) {
		t.Errorf("the host PATH wrapper's KRL reached a sandbox that does not run it "+
			"(revokedhostkeys %q):\n%s", inside["revokedhostkeys"], r.out)
	}
}

// TestThePinIsAskedOfTheSandboxsSSH is F5's pinned half: the known_hosts the
// generated ~/.ssh/config trusts for the pin comes from the ssh the sandbox
// runs. Here only a wrapper knows the pinned host. On the host's PATH alone
// it is not the sandbox's ssh and the run refuses; as the sandbox's ssh the
// same selection resolves. It would catch the pin being asked of the host
// PATH ssh again, which writes trust the sandbox's ssh never had.
func TestThePinIsAskedOfTheSandboxsSSH(t *testing.T) {
	requireSandbox(t)
	const host = "snug-pin-697.invalid"
	if exec.Command("ssh-keygen", "-F", host).Run() == nil {
		skipOrFail(t, "this account's own known_hosts knows %s, so the refusal below cannot happen", host)
	}
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	path, khwrap := knownHostsSSH(t, host+" "+suiteGitHubHostKey)
	pinned := "[profile.pinned]\ndescription = \"one throwaway key\"\n" +
		"[profile.pinned.identity.ssh]\nagent = \"proxy\"\nhost = \"" + host + "\"\nkey = \"" + pub + "\"\n"
	env := writeProfilesOnly(t, map[string]string{"pinned": pinned, "khwrap": khwrap}, "SSH_AUTH_SOCK="+sock, path)

	// POSITIVE CONTROL: with the wrapper as the sandbox's ssh the pin
	// resolves, so the refusal below is about which ssh was asked.
	if out, code := cli(t, env, "--dry-run", "-p", "pinned", "-p", "khwrap", proj); code != 0 {
		t.Fatalf("--dry-run with the wrapper as the sandbox's ssh exited %d:\n%s", code, out)
	}
	out, code := cli(t, env, "--dry-run", "-p", "pinned", proj)
	if code != 77 || !strings.Contains(out, "no known_hosts entry for "+host) {
		t.Errorf("with the wrapper on the host's PATH only, --dry-run exited %d; want 77 naming the "+
			"missing entry, because the sandbox's ssh does not know %s:\n%s", code, host, out)
	}
}
