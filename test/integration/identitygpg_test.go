//go:build integration

package integration

// identity.gpg, end to end: a real gpg-agent in a throwaway GNUPGHOME, a real
// sandbox, and the filtering proxy between them. The positive tests prove the
// grant works (a signed commit verifies, a decryption succeeds); the rest are
// the negatives, each paired with a control that the HOST can do the thing the
// sandbox must not: another key, the host's own agent socket, the secret keys.
//
// Every gpg call here uses the throwaway home. ~/.gnupg is never read, and
// the agents started here are killed on cleanup.

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// gpgHost is the throwaway host: one agent, a pinned key (ed25519 primary,
// ed25519 signing subkey, cv25519 encryption subkey) and a second key the
// profiles never pin.
type gpgHost struct {
	home          string
	fpr, otherFpr string
	otherGrips    []string
	agentSocket   string
	env           []string // snug's environment: the throwaway GNUPGHOME and a private runtime dir
	xdgRuntime    string
	t             *testing.T
}

func requireGPG(t *testing.T) {
	t.Helper()
	requireSandbox(t)
	for _, bin := range []string{"gpg", "gpgconf", "gpg-agent", "gpg-connect-agent", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			skipOrFail(t, "%s is not installed; identity.gpg has nothing to run against", bin)
		}
	}
}

func (h *gpgHost) gpg(args ...string) string {
	h.t.Helper()
	out, errs, err := h.gpgRun(nil, args...)
	if err != nil {
		h.t.Fatalf("gpg %v: %v\n%s", args, err, errs)
	}
	return out
}

func (h *gpgHost) gpgRun(stdin []byte, args ...string) (string, string, error) {
	h.t.Helper()
	cmd := exec.Command("gpg", append([]string{"--homedir", h.home, "--batch",
		"--pinentry-mode", "loopback", "--passphrase", ""}, args...)...)
	cmd.Env = append(os.Environ(), "GNUPGHOME="+h.home, "LC_ALL=C")
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func (h *gpgHost) fprOf(uid string) string {
	h.t.Helper()
	for line := range strings.SplitSeq(h.gpg("--with-colons", "--list-keys", "--", uid), "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" && len(f) > 9 {
			return f[9]
		}
	}
	h.t.Fatalf("no fingerprint for %q", uid)
	return ""
}

// gripsOf is every keygrip of a key, primary included, composite split.
func (h *gpgHost) gripsOf(fpr string) []string {
	var out []string
	for line := range strings.SplitSeq(h.gpg("--with-colons", "--with-keygrip", "--list-secret-keys", "--", fpr), "\n") {
		if f := strings.Split(line, ":"); f[0] == "grp" && len(f) > 9 {
			out = append(out, strings.Split(f[9], ",")...)
		}
	}
	if len(out) == 0 {
		h.t.Fatalf("no keygrips for %s", fpr)
	}
	return out
}

func newGPGHost(t *testing.T) *gpgHost {
	t.Helper()
	requireGPG(t)
	// Short, for the agent socket's sun_path and the runtime dir's.
	home, err := os.MkdirTemp("", "gg")
	if err != nil {
		t.Fatal(err)
	}
	xdg, err := os.MkdirTemp("", "gx")
	if err != nil {
		t.Fatal(err)
	}
	h := &gpgHost{home: home, t: t, xdgRuntime: xdg}
	t.Cleanup(func() {
		for _, a := range [][]string{{"--kill", "gpg-agent"}, {"--remove-socketdir"}} {
			c := exec.Command("gpgconf", append([]string{"--homedir", home}, a...)...)
			c.Env = append(os.Environ(), "GNUPGHOME="+home)
			_ = c.Run()
		}
		os.RemoveAll(home)
		os.RemoveAll(xdg)
	})
	h.gpg("--quick-gen-key", "Pinned <pin@example.org>", "ed25519", "cert", "never")
	h.fpr = h.fprOf("pin@example.org")
	h.gpg("--quick-add-key", h.fpr, "ed25519", "sign", "never")
	h.gpg("--quick-add-key", h.fpr, "cv25519", "encr", "never")
	h.gpg("--quick-gen-key", "Other <other@example.org>", "ed25519", "cert", "never")
	h.otherFpr = h.fprOf("other@example.org")
	h.gpg("--quick-add-key", h.otherFpr, "ed25519", "sign", "never")
	h.gpg("--quick-add-key", h.otherFpr, "cv25519", "encr", "never")
	h.otherGrips = h.gripsOf(h.otherFpr)

	cmd := exec.Command("gpgconf", "--homedir", home, "--list-dirs", "agent-socket")
	cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gpgconf --list-dirs agent-socket: %v", err)
	}
	h.agentSocket = strings.TrimSpace(string(out))
	if _, err := os.Stat(h.agentSocket); err != nil {
		t.Fatalf("control: the throwaway agent has no socket at %s: %v", h.agentSocket, err)
	}
	h.env = []string{"GNUPGHOME=" + home, "XDG_RUNTIME_DIR=" + xdg}
	return h
}

// profile writes a profile pinning fpr with the given scope and returns the
// environment to run snug with.
func (h *gpgHost) profile(fpr string, scope ...string) []string {
	h.t.Helper()
	quoted := make([]string, len(scope))
	for i, s := range scope {
		quoted[i] = `"` + s + `"`
	}
	return writeProfile(h.t, "[profile.gpgid]\n"+
		"description = \"one throwaway OpenPGP key\"\n"+
		"[profile.gpgid.identity.gpg]\n"+
		"fingerprint = \""+fpr+"\"\n"+
		"scope = ["+strings.Join(quoted, ", ")+"]\n", h.env...)
}

// profileEnv is profile for the key and both scopes, for callers that start a
// background sandbox.
func (h *gpgHost) profileEnv() []string { return h.profile(h.fpr, "sign", "decrypt") }

const gitIdent = `export GIT_AUTHOR_NAME=a GIT_AUTHOR_EMAIL=a@example.org GIT_COMMITTER_NAME=a GIT_COMMITTER_EMAIL=a@example.org
`

// TestIdentityGPGSignsACommitAsTheSubkey: with scope sign, git inside signs a
// commit through the proxy and the signature verifies against the staged
// public keyring, made by a SUBKEY of the pinned primary. The key's private
// half exists only in the host agent (a positive control that the signing
// worked at all), and the sandbox's GNUPGHOME is a 0700 directory that gpg
// accepts without the "unsafe permissions" warning.
func TestIdentityGPGSignsACommitAsTheSubkey(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	r := runEnv(t, h.profile(h.fpr, "sign"), []string{"-p", "gpgid"}, proj, gitIdent+`
git init -q .
git commit --allow-empty -q -m signed
echo "commit-exit=[$?]"
echo "STATUS-BEGIN"; git log -1 --format='%G?'; echo "STATUS-END"
echo "PRIMARY-BEGIN"; git log -1 --format='%GP'; echo "PRIMARY-END"
echo "SIGNER-BEGIN"; git log -1 --format='%GF'; echo "SIGNER-END"
echo "HOMEMODE=[$(stat -c %a "$GNUPGHOME")]"
gpg --list-keys 2>&1 | grep -c 'unsafe permissions' | sed 's/^/unsafe=/'
`).mustRun(t)
	if !strings.Contains(r.out, "commit-exit=[0]") {
		t.Fatalf("git commit did not sign inside the sandbox:\n%s", r.out)
	}
	status, _ := section(r.out, "STATUS")
	// G is good and trusted, U good with unknown validity: the staged keyring
	// carries no ownertrust, and either way the signature checked out.
	if s := strings.TrimSpace(status); s != "G" && s != "U" {
		t.Errorf("%%G? = %q, want a good signature (G or U):\n%s", s, r.out)
	}
	if primary, _ := section(r.out, "PRIMARY"); strings.TrimSpace(primary) != h.fpr {
		t.Errorf("the signature's primary key is %q, want the pinned %s", strings.TrimSpace(primary), h.fpr)
	}
	if signer, _ := section(r.out, "SIGNER"); strings.TrimSpace(signer) == h.fpr || strings.TrimSpace(signer) == "" {
		t.Errorf("the signing key is %q: it must be a SUBKEY, the primary is never pinned", strings.TrimSpace(signer))
	}
	if !strings.Contains(r.out, "HOMEMODE=[700]") {
		t.Errorf("GNUPGHOME inside is not mode 700:\n%s", r.out)
	}
	if !strings.Contains(r.out, "unsafe=0") {
		t.Errorf("gpg warned about unsafe permissions on its homedir:\n%s", r.out)
	}
}

// TestIdentityGPGDecryptsOnlyWhatIsAddressedToThePin: scope decrypt decrypts a
// file encrypted to the pinned key and fails on one encrypted to a key the
// profile did not pin. The host decrypts BOTH (the controls), so the second
// failure is the proxy's and not a broken message; the plaintext marker in the
// output is what a decryption looks like, so its absence is not an empty run.
func TestIdentityGPGDecryptsOnlyWhatIsAddressedToThePin(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	plain := filepath.Join(proj, "plain.txt")
	if err := os.WriteFile(plain, []byte("the-decrypted-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	toPin, toOther := filepath.Join(proj, "to-pin.gpg"), filepath.Join(proj, "to-other.gpg")
	h.gpg("--trust-model", "always", "-r", h.fpr, "-o", toPin, "-e", plain)
	h.gpg("--trust-model", "always", "-r", h.otherFpr, "-o", toOther, "-e", plain)
	for _, f := range []string{toPin, toOther} {
		if out := h.gpg("-d", f); out != "the-decrypted-secret\n" {
			t.Fatalf("control: the host cannot decrypt %s (got %q)", f, out)
		}
	}
	os.Remove(plain)

	r := runEnv(t, h.profile(h.fpr, "decrypt"), []string{"-p", "gpgid"}, proj, `
echo "PIN-BEGIN"; gpg --batch -d to-pin.gpg 2>&1; echo "exit=[$?]"; echo "PIN-END"
echo "OTHER-BEGIN"; gpg --batch -d to-other.gpg 2>&1; echo "exit=[$?]"; echo "OTHER-END"
echo "SIGN-BEGIN"; echo hi | gpg --batch -u `+h.fpr+` --clearsign 2>&1; echo "exit=[$?]"; echo "SIGN-END"
test -e ~/.gitconfig && echo "gitconfig=present" || echo "gitconfig=absent"
`).mustRun(t)
	pin, _ := section(r.out, "PIN")
	if !strings.Contains(pin, "the-decrypted-secret") {
		t.Errorf("the pinned key's message was not decrypted:\n%s", r.out)
	}
	other, _ := section(r.out, "OTHER")
	if strings.Contains(other, "the-decrypted-secret") || strings.Contains(other, "exit=[0]") {
		t.Errorf("a message addressed to an unpinned key was decrypted:\n%s", other)
	}
	sign, _ := section(r.out, "SIGN")
	if strings.Contains(sign, "BEGIN PGP SIGNED MESSAGE") || strings.Contains(sign, "exit=[0]") {
		t.Errorf("a decrypt-only scope signed:\n%s", sign)
	}
	if !strings.Contains(r.out, "gitconfig=absent") {
		t.Errorf("a decrypt-only pin authored ~/.gitconfig:\n%s", r.out)
	}
}

// TestIdentityGPGSignScopeCannotDecrypt is the mirror: a sign-only profile
// does not become a decryption oracle for the same key.
func TestIdentityGPGSignScopeCannotDecrypt(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	plain := filepath.Join(proj, "plain.txt")
	os.WriteFile(plain, []byte("the-decrypted-secret\n"), 0o600)
	toPin := filepath.Join(proj, "to-pin.gpg")
	h.gpg("--trust-model", "always", "-r", h.fpr, "-o", toPin, "-e", plain)
	if out := h.gpg("-d", toPin); out != "the-decrypted-secret\n" {
		t.Fatalf("control: the host cannot decrypt (got %q)", out)
	}
	os.Remove(plain)
	r := runEnv(t, h.profile(h.fpr, "sign"), []string{"-p", "gpgid"}, proj, `
echo "DEC-BEGIN"; gpg --batch -d to-pin.gpg 2>&1; echo "exit=[$?]"; echo "DEC-END"
echo "SIG-BEGIN"; echo hi | gpg --batch -u `+h.fpr+` --clearsign 2>&1; echo "exit=[$?]"; echo "SIG-END"
`).mustRun(t)
	sig, _ := section(r.out, "SIG")
	if !strings.Contains(sig, "BEGIN PGP SIGNED MESSAGE") {
		t.Fatalf("control: the sign scope did not sign:\n%s", r.out)
	}
	dec, _ := section(r.out, "DEC")
	if strings.Contains(dec, "the-decrypted-secret") || strings.Contains(dec, "exit=[0]") {
		t.Errorf("a sign-only scope decrypted:\n%s", dec)
	}
}

// TestIdentityGPGShowsOnlyThePinnedKey: inside, the agent lists the pinned
// key's grips and no others, gpg lists only the pinned key, the host's own
// agent socket and homedir are not visible, and no private key material is in
// the sandbox's GNUPGHOME. The controls are the host's: its agent does list
// the other key's grips, and its socket path does exist.
func TestIdentityGPGShowsOnlyThePinnedKey(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)

	hostList, _ := exec.Command("gpg-connect-agent", "--homedir", h.home, "KEYINFO --list", "/bye").Output()
	for _, g := range h.otherGrips {
		if !strings.Contains(strings.ToUpper(string(hostList)), strings.ToUpper(g)) {
			t.Fatalf("control: the host agent does not list the other key's grip %s:\n%s", g, hostList)
		}
	}

	r := runEnv(t, h.profile(h.fpr, "sign", "decrypt"), []string{"-p", "gpgid"}, proj, `
echo "KEYINFO-BEGIN"; gpg-connect-agent "KEYINFO --list" /bye 2>&1; echo "KEYINFO-END"
echo "LIST-BEGIN"; gpg --batch --with-colons --list-secret-keys 2>&1; echo "LIST-END"
echo "LS-BEGIN"; ls -A "$GNUPGHOME"; echo "LS-END"
test -S "$GNUPGHOME/S.gpg-agent" && echo "proxy-socket=present"
test -e `+h.agentSocket+` && echo "host-agent-socket=VISIBLE" || echo "host-agent-socket=absent"
test -e `+h.home+` && echo "host-home=VISIBLE" || echo "host-home=absent"
`).mustRun(t)

	keyinfo, _ := section(r.out, "KEYINFO")
	pinned := h.gripsOf(h.fpr)
	if !strings.Contains(strings.ToUpper(keyinfo), strings.ToUpper(pinned[1])) {
		t.Errorf("KEYINFO --list inside omits the pinned subkey grip %s:\n%s", pinned[1], keyinfo)
	}
	for _, g := range append(h.otherGrips, pinned[0]) {
		if strings.Contains(strings.ToUpper(keyinfo), strings.ToUpper(g)) {
			t.Errorf("KEYINFO --list inside shows %s, which is not pinned (the other key, or the primary):\n%s", g, keyinfo)
		}
	}
	list, _ := section(r.out, "LIST")
	if !strings.Contains(list, h.fpr) {
		t.Errorf("gpg inside does not list the pinned key:\n%s", list)
	}
	if strings.Contains(list, h.otherFpr) {
		t.Errorf("gpg inside lists the unpinned key %s:\n%s", h.otherFpr, list)
	}
	ls, _ := section(r.out, "LS")
	for _, bad := range []string{"private-keys-v1.d", "secring", "openpgp-revocs.d"} {
		if strings.Contains(ls, bad) {
			t.Errorf("GNUPGHOME inside holds %s:\n%s", bad, ls)
		}
	}
	for _, want := range []string{"proxy-socket=present", "host-agent-socket=absent", "host-home=absent"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("missing %q:\n%s", want, r.out)
		}
	}
}

// TestIdentityGPGCannotExportOrCertify: the primary key certifies and the
// agent holds the secret keys, so neither may be reachable. Inside,
// --export-secret-keys yields nothing and --quick-add-uid on the pinned key
// fails; afterwards the HOST key has the one user ID it started with. The
// control is the host adding a user ID to the other key, and the signing the
// sandbox does at the end of the run, so the failures are not a gpg that
// cannot reach the agent at all.
func TestIdentityGPGCannotExportOrCertify(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	uids := func(fpr string) int {
		n := 0
		for line := range strings.SplitSeq(h.gpg("--with-colons", "--list-keys", "--", fpr), "\n") {
			if strings.HasPrefix(line, "uid:") {
				n++
			}
		}
		return n
	}
	before := uids(h.fpr)
	h.gpg("--quick-add-uid", h.otherFpr, "Control <control@example.org>")
	if uids(h.otherFpr) != 2 {
		t.Fatal("control: the host could not add a user ID to the other key")
	}
	if out := h.gpg("--export-secret-keys", h.fpr); len(out) == 0 {
		t.Fatal("control: the host exports no secret key either")
	}

	r := runEnv(t, h.profile(h.fpr, "sign", "decrypt"), []string{"-p", "gpgid"}, proj, `
echo "EXPORT-BEGIN"; gpg --batch --export-secret-keys `+h.fpr+` 2>/dev/null | wc -c; echo "EXPORT-END"
echo "ADDUID-BEGIN"; gpg --batch --quick-add-uid `+h.fpr+` 'Evil <evil@attacker.example>' 2>&1; echo "exit=[$?]"; echo "ADDUID-END"
echo "SIGN-BEGIN"; echo hi | gpg --batch -u `+h.fpr+` --clearsign 2>&1 | head -1; echo "SIGN-END"
`).mustRun(t)
	if exp, _ := section(r.out, "EXPORT"); strings.TrimSpace(exp) != "0" {
		t.Errorf("--export-secret-keys inside returned %q bytes:\n%s", strings.TrimSpace(exp), r.out)
	}
	if add, _ := section(r.out, "ADDUID"); strings.Contains(add, "exit=[0]") {
		t.Errorf("--quick-add-uid on the pinned key succeeded inside:\n%s", add)
	}
	if sign, _ := section(r.out, "SIGN"); !strings.Contains(sign, "BEGIN PGP SIGNED MESSAGE") {
		t.Errorf("control: signing inside did not work, so the refusals above prove nothing:\n%s", r.out)
	}
	if got := uids(h.fpr); got != before {
		t.Errorf("the host key's user IDs changed from %d to %d", before, got)
	}
	if strings.Contains(h.gpg("--list-keys", h.fpr), "evil@attacker.example") {
		t.Error("the host key carries the sandbox's user ID")
	}
}

// TestIdentityGPGRefusesAKeyWithNoSigningSubkey: scope sign on a key that has
// only a certifying primary is refused at startup, naming the command that adds
// the subkey. It would catch a fallback to pinning the primary, which signs and
// certifies, and a run that starts and fails every commit with no cause.
func TestIdentityGPGRefusesAKeyWithNoSigningSubkey(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	h.gpg("--quick-gen-key", "Certify only <cert@example.org>", "ed25519", "cert", "never")
	h.gpg("--quick-add-key", h.fprOf("cert@example.org"), "cv25519", "encr", "never")
	certOnly := h.fprOf("cert@example.org")

	r := runEnv(t, h.profile(certOnly, "sign"), []string{"-p", "gpgid"}, proj, "echo started")
	if r.ran {
		t.Fatalf("the payload ran under scope sign on a key with no signing subkey:\n%s", r.out)
	}
	if r.code == 0 {
		t.Errorf("snug exited 0 refusing nothing:\n%s", r.out)
	}
	want := "gpg --quick-add-key " + certOnly + " ed25519 sign"
	if !strings.Contains(r.out, want) {
		t.Errorf("the refusal does not give the fix %q:\n%s", want, r.out)
	}
	// Control: the same key under decrypt starts, so the refusal is about the
	// scope and not about this key being unusable.
	ok := runEnv(t, h.profile(certOnly, "decrypt"), []string{"-p", "gpgid"}, proj, "echo started").mustRun(t)
	if ok.code != 0 {
		t.Errorf("control: decrypt on the same key did not start (exit %d):\n%s", ok.code, ok.out)
	}
}

// TestIdentityGPGRefusesAnUnknownKey: a fingerprint the host has no secret key
// for is refused before the sandbox starts, naming it.
func TestIdentityGPGRefusesAnUnknownKey(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	const unknown = "0000000000000000000000000000000000000001"
	r := runEnv(t, h.profile(unknown, "sign"), []string{"-p", "gpgid"}, proj, "echo started")
	if r.ran || r.code == 0 || !strings.Contains(r.out, unknown) {
		t.Errorf("an unknown fingerprint was not refused by name (ran=%v exit=%d):\n%s", r.ran, r.code, r.out)
	}
}

// TestIdentityGPGProxyDiesWithSnug: the proxy is a goroutine of the snug
// process, so SIGKILL of snug must take the socket with it. The host side
// dials the proxy socket while the sandbox lives (the control that there is
// something to survive), kills snug with SIGKILL, and then the socket refuses
// connections. The host agent, which is not snug's, stays up.
//
// What it does not measure: the socket FILE being removed. A SIGKILLed snug
// cannot clean up; the next run's sweep does (runtime directory tests).
func TestIdentityGPGProxyDiesWithSnug(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	sb := startBgSandbox(t, h.profileEnv(), []string{"-p", "gpgid"}, proj, "sleep 120")
	sb.ready(t)

	socks, _ := filepath.Glob(filepath.Join(h.xdgRuntime, "snug", "run-*", "gpg-agent.sock"))
	if len(socks) != 1 {
		t.Fatalf("expected one proxy socket under %s, found %v\n%s", h.xdgRuntime, socks, sb.log())
	}
	conn, err := net.DialTimeout("unix", socks[0], 2*time.Second)
	if err != nil {
		t.Fatalf("control: the proxy socket does not accept while the sandbox lives: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	conn.Close()
	if !strings.HasPrefix(string(buf[:n]), "OK") {
		t.Fatalf("control: the proxy greeted %q", buf[:n])
	}

	if err := sb.proc.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = sb.proc.wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("unix", socks[0], time.Second)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("the proxy socket still accepts connections after snug was SIGKILLed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(h.agentSocket); err != nil {
		t.Errorf("the host agent's socket is gone: %v", err)
	}
}

// digestAlgo is the `digest algo N` of the first signature packet in a
// `gpg --list-packets` dump, or "" when there is none.
func digestAlgo(packets string) string {
	for line := range strings.SplitSeq(packets, "\n") {
		if _, rest, ok := strings.Cut(line, "digest algo "); ok {
			n, _, _ := strings.Cut(rest, ",")
			return strings.TrimSpace(n)
		}
	}
	return ""
}

// TestIdentityGPGCarriesHostGPGConf: the host's gpg.conf asks for SHA-256
// signatures, and a signature made inside the sandbox uses SHA-256 (OpenPGP
// digest algo 8). The sandbox's generated gpg.conf carries that line and the
// weak-digest one, and leaves behind the lines that name a program, the
// network or a relaxation.
//
// The control is the host itself: the same gpg on the same home signs with
// algo 8 reading the file and with something else under --no-options, which
// skips it — so the assertion inside discriminates, rather than passing on a
// gpg whose default is already SHA-256.
func TestIdentityGPGCarriesHostGPGConf(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	// personal-cipher-prefs is gpg's alias for personal-cipher-preferences:
	// snug must carry it under the long name, not drop it as unknown.
	conf := "personal-digest-preferences SHA256\nweak-digest SHA224\npersonal-cipher-prefs AES128\n" +
		"keyserver hkps://keys.example.invalid\nexec-path /nonexistent\nallow-weak-digest-algos\n"
	if err := os.WriteFile(filepath.Join(h.home, "gpg.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	hostDigest := func(extra ...string) string {
		sig, errs, err := h.gpgRun([]byte("hi"), append(extra, "-u", h.fpr, "--sign")...)
		if err != nil {
			t.Fatalf("control: host gpg could not sign: %v\n%s", err, errs)
		}
		packets, _, _ := h.gpgRun([]byte(sig), "--list-packets")
		return digestAlgo(packets)
	}
	if d := hostDigest(); d != "8" {
		t.Fatalf("control: host gpg reading the file signs with digest algo %q, want 8", d)
	}
	if d := hostDigest("--no-options"); d == "8" || d == "" {
		t.Fatalf("control: host gpg WITHOUT the file signs with digest algo %q; "+
			"the test cannot tell the file was carried", d)
	}
	// The cipher a message was encrypted with, as the host's `gpg -v -d`
	// names it: "AES.OCB encrypted data" for AES128, "AES256.OCB" otherwise.
	cipherOf := func(path string) string {
		_, errs, err := h.gpgRun(nil, "-v", "-d", path)
		if err != nil {
			t.Fatalf("host could not decrypt %s: %v\n%s", path, err, errs)
		}
		for line := range strings.SplitSeq(errs, "\n") {
			if c, ok := strings.CutSuffix(strings.TrimPrefix(line, "gpg: "), " encrypted data"); ok {
				return c
			}
		}
		return ""
	}
	hostEnc := func(out string, extra ...string) {
		if _, errs, err := h.gpgRun([]byte("hi"), append(extra, "--trust-model", "always",
			"-o", out, "-e", "-r", h.fpr)...); err != nil {
			t.Fatalf("control: host gpg could not encrypt: %v\n%s", err, errs)
		}
	}
	ctl := t.TempDir()
	hostEnc(filepath.Join(ctl, "with.gpg"))
	hostEnc(filepath.Join(ctl, "without.gpg"), "--no-options")
	if with, without := cipherOf(filepath.Join(ctl, "with.gpg")), cipherOf(filepath.Join(ctl, "without.gpg")); with != "AES.OCB" || without == with {
		t.Fatalf("control: host encrypts with %q reading the file and %q without; "+
			"want AES.OCB and something else", with, without)
	}

	r := runEnv(t, h.profile(h.fpr, "sign"), []string{"-p", "gpgid"}, proj, `
echo "CONF-BEGIN"; cat "$GNUPGHOME/gpg.conf"; echo "CONF-END"
echo "PKT-BEGIN"; echo hi | gpg --batch -u `+h.fpr+` --sign | gpg --batch --list-packets 2>&1; echo "PKT-END"
echo hi | gpg --batch --trust-model always -o enc.gpg -e -r `+h.fpr+`; echo "enc-exit=[$?]"
`).mustRun(t)
	if c := cipherOf(filepath.Join(proj, "enc.gpg")); c != "AES.OCB" {
		t.Errorf("a message encrypted inside uses %q, want AES.OCB (the host's "+
			"personal-cipher-prefs AES128, carried under its long name):\n%s", c, r.out)
	}
	packets, _ := section(r.out, "PKT")
	if d := digestAlgo(packets); d != "8" {
		t.Errorf("a signature made inside uses digest algo %q, want 8 (the host's "+
			"personal-digest-preferences SHA256):\n%s", d, r.out)
	}
	carried, _ := section(r.out, "CONF")
	lines := strings.Split(carried, "\n")
	for _, want := range []string{"personal-digest-preferences SHA256", "weak-digest SHA224",
		"personal-cipher-preferences AES128"} {
		if !slices.Contains(lines, want) {
			t.Errorf("the sandbox's gpg.conf lacks %q:\n%s", want, carried)
		}
	}
	for _, line := range lines {
		for _, bad := range []string{"keyserver", "exec-path", "allow-weak-digest-algos"} {
			if strings.HasPrefix(line, bad) {
				t.Errorf("the sandbox's gpg.conf carries %q", line)
			}
		}
	}
}

// TestIdentityGPGRefusesAnUncarriableGPGConf: a host gpg.conf line snug cannot
// render faithfully refuses the run, naming the file and line, instead of
// starting the sandbox on gpg's compiled-in default for that option. The value
// is one the host's gpg ACCEPTS (an unterminated quote), so the refusal is
// snug's and not a copy of gpg's own.
func TestIdentityGPGRefusesAnUncarriableGPGConf(t *testing.T) {
	budget(t, 30*time.Second)
	h := newGPGHost(t)
	proj, _ := target(t)
	p := filepath.Join(h.home, "gpg.conf")
	if err := os.WriteFile(p, []byte("# host\npersonal-digest-preferences \"SHA256\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errs, err := h.gpgRun([]byte("hi"), "-u", h.fpr, "--sign"); err != nil {
		t.Fatalf("control: the host's gpg rejects the file itself: %v\n%s", err, errs)
	}
	r := runEnv(t, h.profile(h.fpr, "sign"), []string{"-p", "gpgid"}, proj, "echo started")
	if r.ran || r.code == 0 {
		t.Fatalf("the sandbox started over an uncarriable gpg.conf (ran=%v exit=%d):\n%s", r.ran, r.code, r.out)
	}
	if !strings.Contains(r.out, p+":2") || !strings.Contains(r.out, "personal-digest-preferences") {
		t.Errorf("the refusal does not name %s:2 and the option:\n%s", p, r.out)
	}
}
