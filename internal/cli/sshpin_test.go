package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The hashed line is `ssh-keygen -H` output for github.com (OpenSSH_10.6p1), and
// `ssh-keygen -F github.com` finds it; the keys are throwaway ones generated for
// this fixture.
const (
	khKeyA   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcgUwK96NCQlqjPZlPkFyqH6IrvXdrKEmVT0asbOPTC"
	khKeyB   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/D7caF+0JCeXDXgao3ZhYGwbY5hasDq6lSZxZKu+ov"
	khHashed = "|1|A+iP4niVBFp02w17nZqw1VCjulQ=|qa3zGFcRjk4n6tqL6noBRbUrxuU= " + khKeyA
)

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestKnownHostsForCarriesHashedRevokedAndBracketed is #688 F1's fixture: the
// filter kept a line only when a comma-separated pattern equalled the host, so
// all four of these came out as the header alone, and the sandbox's ssh accepted
// a key the host's had revoked.
func TestKnownHostsForCarriesHashedRevokedAndBracketed(t *testing.T) {
	f := writeKnownHosts(t,
		khHashed,
		"@revoked github.com "+khKeyB,
		"@cert-authority *.github.com,github.com "+khKeyB,
		"[github.com]:2222 "+khKeyA,
		"gitlab.com "+khKeyB,
		"# github.com "+khKeyB,
	)
	out, usable, err := knownHostsFor("github.com", []string{f})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{khHashed, "@revoked github.com ", "@cert-authority ", "[github.com]:2222 "} {
		if !strings.Contains(got, want) {
			t.Errorf("filtered known_hosts lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "gitlab.com") || strings.Contains(got, "\n# github.com") {
		t.Errorf("filtered known_hosts carries a line for another host or a comment:\n%s", got)
	}
	// The hashed line and the @cert-authority one. Not @revoked, which accepts
	// nothing, and not [github.com]:2222, which ssh consults only on that port.
	if usable != 2 {
		t.Errorf("usable = %d, want 2", usable)
	}
}

func TestKnownHostsLineMatchesLikeSSH(t *testing.T) {
	cases := []struct {
		line, host string
		ok         bool
	}{
		{"github.com " + khKeyA, "github.com", true},
		{"GitHub.COM " + khKeyA, "github.com", true},
		{"a.example,github.com " + khKeyA, "github.com", true},
		{"*.github.com " + khKeyA, "github.com", false},
		{"*.github.com " + khKeyA, "ssh.github.com", true},
		{"git?ub.com " + khKeyA, "github.com", true},
		{"*,!github.com " + khKeyA, "github.com", false},
		{"!github.com,* " + khKeyA, "github.com", false},
		{"github.com.evil " + khKeyA, "github.com", false},
		{"evilgithub.com " + khKeyA, "github.com", false},
		{khHashed, "gitlab.com", false},
		{"@bogus github.com " + khKeyA, "github.com", false},
		{"github.com", "github.com", false},
	}
	for _, tc := range cases {
		if got := knownHostsLineMatches(tc.line, tc.host); got.ok != tc.ok {
			t.Errorf("knownHostsLineMatches(%q, %q) = %v, want %v", tc.line, tc.host, got.ok, tc.ok)
		}
	}
}

// TestKnownHostsForReadsEveryFile: ssh reads the user's files and the global
// ones, and an admin's @revoked line in /etc/ssh/ssh_known_hosts is as binding
// as the user's (#688 F5).
func TestKnownHostsForReadsEveryFile(t *testing.T) {
	user := writeKnownHosts(t, "github.com "+khKeyA)
	global := writeKnownHosts(t, "@revoked github.com "+khKeyB)
	out, usable, err := knownHostsFor("github.com", []string{user, filepath.Join(t.TempDir(), "absent"), global})
	if err != nil {
		t.Fatal(err)
	}
	if usable != 1 || !strings.Contains(string(out), "@revoked github.com") {
		t.Errorf("usable = %d, out:\n%s", usable, out)
	}
}

func TestKnownHostsForRefusesAnUnreadableFile(t *testing.T) {
	dir := t.TempDir() // a directory where a file should be
	if _, _, err := knownHostsFor("github.com", []string{dir}); err == nil {
		t.Fatal("a known_hosts path that cannot be read was treated as empty; it may hold the @revoked line")
	}
}

// TestProbeSSHPinRefusesAPinWithNoEntry: with StrictHostKeyChecking yes the
// sandbox could not connect anyway, and the refusal is where the human learns
// how to fix it.
func TestProbeSSHPinRefusesAPinWithNoEntry(t *testing.T) {
	user := writeKnownHosts(t, "gitlab.com "+khKeyA, "@revoked github.com "+khKeyB)
	sshShim(t, "userknownhostsfile "+user+"\nglobalknownhostsfile none\nrevokedhostkeys none\n")
	_, err := probeSSHPin(t.TempDir(), "github.com")
	if err == nil || !strings.Contains(err.Error(), "no known_hosts entry for github.com") {
		t.Fatalf("err = %v, want the no-entry refusal", err)
	}
	// docs/src/identity.md quotes this refusal, with the file list elided.
	const page = "../../docs/src/identity.md"
	data, rerr := os.ReadFile(page)
	if rerr != nil {
		t.Fatal(rerr)
	}
	got := "snug: " + strings.Replace(err.Error(), "(read "+user+")", "(read …)", 1)
	if !strings.Contains(string(data), "\n"+got+"\n") {
		t.Errorf("%s does not quote the refusal as snug prints it:\n%s", page, got)
	}
}

// TestProbeSSHPinCarriesTheHostBlock is #688 F4: the global probe resolves no
// Host block, so a narrower list under `Host <pin>` never reached the sandbox.
func TestProbeSSHPinCarriesTheHostBlock(t *testing.T) {
	user := writeKnownHosts(t, "github.com "+khKeyA)
	krl := filepath.Join(t.TempDir(), "krl")
	if err := os.WriteFile(krl, []byte(khKeyB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshShim(t, "kexalgorithms mlkem768x25519-sha256\nrequiredrsasize 3072\n"+
		"userknownhostsfile "+user+"\nglobalknownhostsfile none\nrevokedhostkeys "+krl+"\n")
	pin, err := probeSSHPin(t.TempDir(), "github.com")
	if err != nil {
		t.Fatal(err)
	}
	if pin.values["kexalgorithms"] != "mlkem768x25519-sha256" || pin.values["requiredrsasize"] != "3072" {
		t.Errorf("values = %q", pin.values)
	}
	if string(pin.revoked) != khKeyB+"\n" {
		t.Errorf("revoked = %q, want the RevokedHostKeys file verbatim", pin.revoked)
	}
}

func TestProbeSSHPinRefusesAnUnreadableRevokedFile(t *testing.T) {
	user := writeKnownHosts(t, "github.com "+khKeyA)
	sshShim(t, "userknownhostsfile "+user+"\nrevokedhostkeys "+filepath.Join(t.TempDir(), "absent")+"\n")
	if _, err := probeSSHPin(t.TempDir(), "github.com"); err == nil {
		t.Fatal("a RevokedHostKeys file that cannot be read was left behind")
	}
}

// sshShim puts an `ssh` on PATH that prints out for any arguments.
func sshShim(t *testing.T, out string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "out"), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\nexec /bin/cat " + filepath.Join(dir, "out") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

// TestProbeSSHPinRefusesASplitKnownHostsPath is redteam F1 on #688: `ssh -G`
// prints `UserKnownHostsFile "<dir>/sp ace/kh"` unquoted, the fragment after
// the space is relative, and it was opened against the project directory —
// where a repository planted `ace/kh` naming its own key for github.com, and
// the sandbox's ssh then trusted it.
func TestProbeSSHPinRefusesASplitKnownHostsPath(t *testing.T) {
	proj := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proj, "ace"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "ace", "kh"), []byte("github.com "+khKeyB+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(proj)
	user := writeKnownHosts(t, "github.com "+khKeyA)
	sshShim(t, "userknownhostsfile "+filepath.Join(t.TempDir(), "sp")+" ace/kh "+user+"\n")
	pin, err := probeSSHPin(t.TempDir(), "github.com")
	if err == nil {
		t.Fatalf("a known_hosts path split at a space was read, relative fragment and all:\n%s", pin.knownHosts)
	}
	if !strings.Contains(err.Error(), "space") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// TestProbeSSHPinRefusesWhatTheGeneratedBlockDoesNotCarry is redteam F2 and F3
// on #688, measured against github.com: with each of these in the host's
// config the host's ssh refused a revoked key that the sandbox's accepted,
// because the sandbox's ssh looked it up under, or fetched it from, somewhere
// else.
func TestProbeSSHPinRefusesWhatTheGeneratedBlockDoesNotCarry(t *testing.T) {
	user := writeKnownHosts(t, "github.com "+khKeyA)
	for key, line := range map[string]string{
		"KnownHostsCommand": "knownhostscommand /bin/cat /tmp/khc_out",
		"HostKeyAlias":      "hostkeyalias ghalias",
		"HostName":          "hostname ssh.github.com",
		"Port":              "port 443",
	} {
		t.Run(key, func(t *testing.T) {
			sshShim(t, "hostname github.com\nport 22\n"+line+"\nuserknownhostsfile "+user+"\n")
			_, err := probeSSHPin(t.TempDir(), "github.com")
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("probeSSHPin with %q = %v; want a refusal naming %s", line, err, key)
			}
		})
	}
	// CONTROL: the values the generated block does reproduce are not refused.
	sshShim(t, "hostname GitHub.com\nport 22\nknownhostscommand none\nuserknownhostsfile "+user+"\n")
	if _, err := probeSSHPin(t.TempDir(), "github.com"); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// TestProbeSSHPinRefusesAnOptionShapedHost is redteam F5 on #688: the pin
// reached the host's ssh argv before Resolve validated it, and
// `host = "-E<file>"` arrived as ssh's -E option.
func TestProbeSSHPinRefusesAnOptionShapedHost(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "argv")
	body := "#!/bin/sh\necho \"$@\" > " + log + "\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := probeSSHPin(t.TempDir(), "-E/tmp/elog"); err == nil {
		t.Fatal("an option-shaped identity.ssh.host was not refused")
	}
	if _, err := os.Stat(log); err == nil {
		t.Error("the host's ssh ran with an option-shaped identity.ssh.host")
	}
}
