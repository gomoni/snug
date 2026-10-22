package gpgproxy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRealAgentSignAndDecrypt drives the proxy with the host's own gpg and
// gpg-agent, so the dialogue under test is the one the installed GnuPG speaks
// rather than the one the fake agent was written from. The two differ by
// version: gpg 2.5 sends `PKDECRYPT --kem=PGP` where 2.4 sends a bare
// PKDECRYPT, and a proxy that dropped the option passed every fake-agent test
// while failing every 2.5 decryption with `Wrong secret key used`.
//
// Two homedirs: `agent` holds the secret keys and runs the real agent, and
// `client` holds only the pinned key's public half and finds the PROXY where
// gpgconf says its agent socket is — the same split snug makes between the
// host and the sandbox.
//
// The pinned set is what internal/cli/gpgidentity.go pins and this file
// replicates, because the packages do not import each other: signing SUBKEYS
// for sign, encryption subkeys for decrypt, and never the primary, which
// certifies. The agent also holds a second key the profile did not pin, and
// the negatives are measured against that key and the primary, each with a
// control that the agent itself would have done the thing.
//
// What this does not cover: a pinentry. The generated keys have no passphrase,
// so the agent never asks one.
func TestRealAgentSignAndDecrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real gpg-agent")
	}
	for _, bin := range []string{"gpg", "gpgconf", "gpg-agent", "gpg-connect-agent"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	ecc := [][]string{
		{"--quick-gen-key", "Pinned <pin@example.org>", "ed25519", "cert", "never"},
		{"--quick-add-key", "{fpr}", "ed25519", "sign", "never"},
		{"--quick-add-key", "{fpr}", "cv25519", "encr", "never"},
	}
	t.Run("ecc sign+decrypt", func(t *testing.T) { realAgentRoundTrip(t, ecc, true, true) })
	t.Run("ecc sign only", func(t *testing.T) { realAgentRoundTrip(t, ecc, true, false) })
	t.Run("ecc decrypt only", func(t *testing.T) { realAgentRoundTrip(t, ecc, false, true) })
	t.Run("pqc decrypt", func(t *testing.T) {
		// gpg 2.5's composite Kyber subkey: two grips on one `grp:` line,
		// `SETKEY --another` for the second, `PKDECRYPT --kem=PQC-PGP`. A pqc
		// key has no signing subkey, so this is decrypt-only. It is skipped
		// only where this gpg does not list Kyber among its algorithms; where
		// it does, a failure to generate is a failure.
		out, _ := exec.Command("gpg", "--version").Output()
		if !strings.Contains(string(out), "Kyber") {
			t.Skip("this gpg lists no Kyber algorithm in `gpg --version`")
		}
		realAgentRoundTrip(t, [][]string{
			{"--quick-gen-key", "Pinned <pin@example.org>", "pqc", "default", "never"},
		}, false, true)
	})
}

// agentRig is the two homedirs and the helpers to drive gpg in either.
type agentRig struct {
	t                  *testing.T
	dir, agent, client string
	nopass             []string
	run                func(home string, stdin []byte, args ...string) (string, string, error)
	must               func(home string, stdin []byte, args ...string) string
}

func newAgentRig(t *testing.T) *agentRig {
	t.Helper()
	// Short: the proxy socket lands in the client homedir's socket dir, and
	// t.TempDir() carries the test and subtest names.
	dir, err := os.MkdirTemp("", "ra")
	if err != nil {
		t.Fatal(err)
	}
	r := &agentRig{t: t, dir: dir, agent: filepath.Join(dir, "a"), client: filepath.Join(dir, "c")}
	for _, d := range []string{r.agent, r.client} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.run = func(home string, stdin []byte, args ...string) (string, string, error) {
		t.Helper()
		cmd := exec.Command(args[0], append([]string{"--homedir", home}, args[1:]...)...)
		cmd.Env = append(os.Environ(), "GNUPGHOME="+home, "LC_ALL=C")
		cmd.Stdin = bytes.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		return out.String(), errb.String(), err
	}
	r.must = func(home string, stdin []byte, args ...string) string {
		t.Helper()
		out, errs, err := r.run(home, stdin, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, errs)
		}
		return out
	}
	t.Cleanup(func() {
		for _, h := range []string{r.agent, r.client} {
			r.run(h, nil, "gpgconf", "--kill", "gpg-agent")
			r.run(h, nil, "gpgconf", "--remove-socketdir")
		}
		os.RemoveAll(dir)
	})
	r.nopass = []string{"--batch", "--pinentry-mode", "loopback", "--passphrase", ""}
	return r
}

// gpgAgent runs gpg in the agent homedir with the batch/no-passphrase flags.
func (r *agentRig) gpgAgent(args ...string) (string, string, error) {
	return r.run(r.agent, nil, append(append([]string{"gpg"}, r.nopass...), args...)...)
}

// generate makes a key from steps (each a gpg argument list, "{fpr}" standing
// for the key made by the first) in the agent homedir and returns its
// fingerprint and the grips snug would pin: the signing subkeys' and the
// encryption subkeys'. The primary's grip is returned separately by primaryGrip.
func (r *agentRig) generate(steps [][]string) (fpr string, signers, encryptors []string) {
	r.t.Helper()
	if _, errs, err := r.gpgAgent(steps[0]...); err != nil {
		r.t.Fatalf("%v: %v\n%s", steps[0], err, errs)
	}
	fpr = r.fprOfUID(steps[0][1])
	for _, step := range steps[1:] {
		args := make([]string, len(step))
		for i, a := range step {
			args[i] = strings.ReplaceAll(a, "{fpr}", fpr)
		}
		if _, errs, err := r.gpgAgent(args...); err != nil {
			r.t.Fatalf("%v: %v\n%s", args, err, errs)
		}
	}
	signers, encryptors = r.subkeyGrips(fpr)
	return fpr, signers, encryptors
}

// fprOfUID is the primary fingerprint of the key whose user ID is uid.
func (r *agentRig) fprOfUID(uid string) string {
	r.t.Helper()
	out := r.must(r.agent, nil, "gpg", "--with-colons", "--fingerprint", "--list-keys", "--", uid)
	for line := range strings.SplitSeq(out, "\n") {
		if f := strings.Split(line, ":"); f[0] == "fpr" && len(f) > 9 {
			return f[9]
		}
	}
	r.t.Fatalf("no fingerprint for %q in:\n%s", uid, out)
	return ""
}

// listing is `gpg --with-colons --with-keygrip -K fpr`.
func (r *agentRig) listing(fpr string) string {
	return r.must(r.agent, nil, "gpg", "--with-colons", "--with-keygrip", "-K", "--", fpr)
}

// primaryGrip is the first grp: of the listing, which belongs to the primary.
func (r *agentRig) primaryGrip(fpr string) string {
	for line := range strings.SplitSeq(r.listing(fpr), "\n") {
		if f := strings.Split(line, ":"); f[0] == "grp" && len(f) > 9 {
			return strings.Split(f[9], ",")[0]
		}
	}
	r.t.Fatal("no primary grip")
	return ""
}

// subkeyGrips is internal/cli's parseKeygrips for a single key: grips of ssb
// records by capability, composite grips split.
func (r *agentRig) subkeyGrips(fpr string) (signers, encryptors []string) {
	caps, inSub := "", false
	for line := range strings.SplitSeq(r.listing(fpr), "\n") {
		f := strings.Split(line, ":")
		switch f[0] {
		case "sec":
			inSub = false
		case "ssb":
			inSub = true
			caps = ""
			if len(f) > 11 {
				caps = f[11]
			}
		case "grp":
			if !inSub || len(f) < 10 {
				continue
			}
			if strings.Contains(caps, "s") {
				signers = append(signers, strings.Split(f[9], ",")...)
			}
			if strings.Contains(caps, "e") {
				encryptors = append(encryptors, strings.Split(f[9], ",")...)
			}
		}
	}
	return signers, encryptors
}

// realAgentRoundTrip generates the pinned key (gen: each step a gpg argument
// list) and a second, unpinned one, pins the first through the proxy with the
// scope sign/decrypt asks for, and drives a client homedir against it.
func realAgentRoundTrip(t *testing.T, gen [][]string, sign, decrypt bool) {
	r := newAgentRig(t)
	dir := r.dir

	fpr, signers, encryptors := r.generate(gen)
	primary := r.primaryGrip(fpr)
	if sign && len(signers) == 0 {
		t.Fatalf("control: the generated key has no signing subkey, so sign scope pins nothing: %s", r.listing(fpr))
	}
	if decrypt && len(encryptors) == 0 {
		t.Fatal("control: the generated key has no encryption subkey")
	}

	// A second key the profile does NOT pin, with both a signing and an
	// encryption subkey, so each negative below has something to be refused.
	otherFpr, otherSigners, otherEncryptors := r.generate([][]string{
		{"--quick-gen-key", "Other <other@example.org>", "ed25519", "cert", "never"},
		{"--quick-add-key", "{fpr}", "ed25519", "sign", "never"},
		{"--quick-add-key", "{fpr}", "cv25519", "encr", "never"},
	})
	otherPrimary := r.primaryGrip(otherFpr)

	var pins []PinnedGrip
	if sign {
		for _, g := range signers {
			pins = append(pins, PinnedGrip{Field: "identity.gpg.fingerprint", Grip: g, Scope: ScopeSign})
		}
	}
	if decrypt {
		for _, g := range encryptors {
			pins = append(pins, PinnedGrip{Field: "identity.gpg.fingerprint", Grip: g, Scope: ScopeDecrypt})
		}
	}

	pub := r.must(r.agent, nil, "gpg", "--batch", "--export", fpr)
	otherPub := r.must(r.agent, nil, "gpg", "--batch", "--export", otherFpr)
	// --no-autostart: an agent started in the client home would hold the
	// socket the proxy is about to bind.
	r.must(r.client, []byte(pub), "gpg", "--batch", "--no-autostart", "--import")
	r.must(r.client, []byte(otherPub), "gpg", "--batch", "--no-autostart", "--import")

	upstream := strings.TrimSpace(r.must(r.agent, nil, "gpgconf", "--list-dirs", "agent-socket"))
	// Without /run/user/UID gpgconf falls back to the homedir and REFUSES
	// --create-socketdir (measured, gpgconf 2.4.4 in ubuntu:24.04): the
	// homedir is then the socket directory and already exists.
	r.run(r.client, nil, "gpgconf", "--create-socketdir")
	sock := strings.TrimSpace(r.must(r.client, nil, "gpgconf", "--list-dirs", "agent-socket"))
	audit := &auditLog{}
	p, err := New(pins, upstream, sock, audit.add)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	client := []string{"gpg", "--batch", "--no-autostart", "--trust-model", "always"}
	crun := func(args ...string) (string, string, error) {
		return r.run(r.client, nil, append(append([]string{}, client...), args...)...)
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	msg := write("msg", "hello through the proxy\n")

	// ── what the pin grants ─────────────────────────────────────────────────
	if sign {
		_, errs, err := crun("-u", fpr, "--detach-sign", msg)
		if err != nil {
			t.Fatalf("sign through the proxy: %v\n%s\naudit: %v", err, errs, audit.lines())
		}
		if strings.Contains(errs, "older than us") {
			t.Errorf("gpg was told a wrong agent version:\n%s", errs)
		}
		if _, errs, err := crun("--verify", msg+".sig", msg); err != nil {
			t.Fatalf("verify: %v\n%s", err, errs)
		}
	} else {
		// Positive control for the refusal: the agent itself signs with this key.
		if _, errs, err := r.gpgAgent("-u", fpr, "--detach-sign", "-o", filepath.Join(dir, "ctl.sig"), msg); err != nil {
			t.Fatalf("control: the agent cannot sign with the key either: %v\n%s", err, errs)
		}
		if _, _, err := crun("-u", fpr, "--detach-sign", "-o", filepath.Join(dir, "no.sig"), msg); err == nil {
			t.Error("decrypt-only scope signed through the proxy")
		}
		if _, err := os.Stat(filepath.Join(dir, "no.sig")); err == nil {
			t.Error("a signature file exists under a decrypt-only scope")
		}
	}

	toPinned := filepath.Join(dir, "to-pinned.gpg")
	r.must(r.agent, nil, "gpg", "--batch", "--trust-model", "always", "-r", fpr, "-o", toPinned, "-e", msg)
	if decrypt {
		out, errs, err := crun("-d", toPinned)
		if err != nil {
			t.Fatalf("decrypt through the proxy: %v\n%s\naudit: %v", err, errs, audit.lines())
		}
		if out != "hello through the proxy\n" {
			t.Fatalf("decrypted %q", out)
		}
	} else {
		if out, _, _ := r.run(r.agent, nil, "gpg", "--batch", "-d", toPinned); out != "hello through the proxy\n" {
			t.Fatalf("control: the agent cannot decrypt the message either (got %q)", out)
		}
		if out, _, err := crun("-d", toPinned); err == nil || out != "" {
			t.Errorf("sign-only scope decrypted through the proxy: err=%v out=%q", err, out)
		}
	}

	// ── what it must not grant ──────────────────────────────────────────────
	// The other key: signing and decrypting both work in the agent home (the
	// controls), and neither works through the proxy.
	if _, errs, err := r.gpgAgent("-u", otherFpr, "--detach-sign", "-o", filepath.Join(dir, "other-ctl.sig"), msg); err != nil {
		t.Fatalf("control: the agent cannot sign with the other key: %v\n%s", err, errs)
	}
	if _, _, err := crun("-u", otherFpr, "--detach-sign", "-o", filepath.Join(dir, "other.sig"), msg); err == nil {
		t.Error("signed with a key the profile did not pin")
	}
	if _, err := os.Stat(filepath.Join(dir, "other.sig")); err == nil {
		t.Error("a signature by the unpinned key exists")
	}
	toOther := filepath.Join(dir, "to-other.gpg")
	r.must(r.agent, nil, "gpg", "--batch", "--trust-model", "always", "-r", otherFpr, "-o", toOther, "-e", msg)
	if out, _, _ := r.run(r.agent, nil, "gpg", "--batch", "-d", toOther); out != "hello through the proxy\n" {
		t.Fatalf("control: the agent cannot decrypt to the other key (got %q)", out)
	}
	if out, _, err := crun("-d", toOther); err == nil || out != "" {
		t.Errorf("decrypted a message addressed to an unpinned key: err=%v out=%q", err, out)
	}

	// The enumeration shows the pin and nothing else.
	list := func(home string) string {
		out, _, _ := r.run(home, nil, "gpg-connect-agent", "--no-autostart", "KEYINFO --list", "/bye")
		return strings.ToUpper(out)
	}
	atAgent := list(r.agent)
	for _, g := range append(append([]string{otherPrimary}, otherSigners...), otherEncryptors...) {
		if !strings.Contains(atAgent, strings.ToUpper(g)) {
			t.Fatalf("control: the agent's own KEYINFO --list does not show %s:\n%s", g, atAgent)
		}
	}
	atProxy := list(r.client)
	for _, g := range pins {
		if !strings.Contains(atProxy, g.Grip) {
			t.Errorf("the proxy's KEYINFO --list omits the pinned grip %s:\n%s", g.Grip, atProxy)
		}
	}
	for _, g := range append(append([]string{otherPrimary, primary}, otherSigners...), otherEncryptors...) {
		if strings.Contains(atProxy, strings.ToUpper(g)) {
			t.Errorf("the proxy's KEYINFO --list shows %s, which is not pinned:\n%s", g, atProxy)
		}
	}

	// The primary certifies, so it is never pinned: adding a user ID to the
	// pinned key needs the primary's signature and must fail. The control is
	// the same call on the unpinned key in the agent home, which succeeds.
	uids := func(f string) int {
		n := 0
		for line := range strings.SplitSeq(r.must(r.agent, nil, "gpg", "--with-colons", "--list-keys", "--", f), "\n") {
			if strings.HasPrefix(line, "uid:") {
				n++
			}
		}
		return n
	}
	before := uids(fpr)
	if _, errs, err := r.gpgAgent("--quick-add-uid", otherFpr, "Control <control@example.org>"); err != nil {
		t.Fatalf("control: the agent cannot add a user ID to the other key: %v\n%s", err, errs)
	}
	if _, _, err := crun("--quick-add-uid", fpr, "Evil <evil@attacker.example>"); err == nil {
		t.Error("a user ID was added to the pinned key through the proxy")
	}
	if after := uids(fpr); after != before {
		t.Errorf("the pinned key's user IDs changed through the proxy: %d -> %d", before, after)
	}
	if strings.Contains(r.must(r.agent, nil, "gpg", "--list-keys", "--", fpr), "evil@attacker.example") {
		t.Error("the host key carries the sandbox's user ID")
	}

	// Still the narrow proxy with a real client on the other side. The
	// control is that the agent exports the secret key when asked directly, so
	// an empty answer through the proxy is the proxy's refusal.
	if ctl := r.must(r.agent, nil, "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys", fpr); ctl == "" {
		t.Fatal("control: the agent exported no secret key when asked directly")
	}
	// No loopback flags here: gpg would send OPTION pinentry-mode, which the
	// proxy refuses first, and the command would fail for that reason without
	// ever reaching EXPORT_KEY. The audit assertion below is what proves it did.
	exp, errs, err := crun("--export-secret-keys", fpr)
	if exp != "" {
		t.Errorf("--export-secret-keys through the proxy returned %d bytes", len(exp))
	}
	if err == nil {
		t.Errorf("--export-secret-keys through the proxy exited 0: %s", errs)
	}
	if !audit.contains("export private key material") {
		t.Errorf("no export refusal in the audit, so the proxy may not have been asked: %v", audit.lines())
	}
}
