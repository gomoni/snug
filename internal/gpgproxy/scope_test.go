package gpgproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pinnedSign and pinnedBoth are the two fixture grip sets the scope tests use.
func pinnedBoth() []PinnedGrip {
	return []PinnedGrip{
		{Field: "identity.gpg.fingerprint", Grip: gripPrimary, Scope: ScopeSign | ScopeDecrypt},
		{Field: "identity.gpg.fingerprint", Grip: gripSubkey, Scope: ScopeDecrypt},
	}
}

func pinnedSignOnly() []PinnedGrip {
	return []PinnedGrip{
		{Field: "identity.gpg.fingerprint", Grip: gripPrimary, Scope: ScopeSign},
	}
}

// pinnedDecryptAsCLI is what internal/cli pins for scope = ["decrypt"]: the
// primary grip carries the profile's scope too, not only the subkey.
func pinnedDecryptAsCLI() []PinnedGrip {
	return []PinnedGrip{
		{Field: "identity.gpg.fingerprint", Grip: gripPrimary, Scope: ScopeDecrypt},
		{Field: "identity.gpg.fingerprint", Grip: gripSubkey, Scope: ScopeDecrypt},
	}
}

func pinnedDecryptOnly() []PinnedGrip {
	return []PinnedGrip{
		{Field: "identity.gpg.fingerprint", Grip: gripSubkey, Scope: ScopeDecrypt},
	}
}

// ── construction ────────────────────────────────────────────────────────────

// TestEmptyPinSetRefuses: a proxy with nothing to pin advertises nothing and
// refuses every signature, which is a sandbox that looks configured and is not.
func TestEmptyPinSetRefuses(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, err := New(nil, a.path, filepath.Join(shortDir(t), "s.sock"), nil)
	if err == nil {
		t.Fatal("New accepted an empty pin set")
	}
	if !strings.Contains(err.Error(), "no keygrip to pin") {
		t.Errorf("refusal does not name the cause: %v", err)
	}
}

// TestZeroScopeRefuses: a grip with an empty scope is a grant that grants
// nothing, and snug refuses that rather than accepting it.
func TestZeroScopeRefuses(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, err := New([]PinnedGrip{{Field: "identity.gpg.fingerprint", Grip: gripPrimary}},
		a.path, filepath.Join(shortDir(t), "s.sock"), nil)
	if err == nil {
		t.Fatal("New accepted a grip with no scope")
	}
	if !strings.Contains(err.Error(), "no scope") {
		t.Errorf("refusal does not name the cause: %v", err)
	}
	if !strings.Contains(err.Error(), "identity.gpg.scope") {
		t.Errorf("refusal does not name the fix: %v", err)
	}
}

// TestBadGripRefuses: a grip that is not 40 hex characters cannot be compared
// against the pin set and must be refused at construction.
func TestBadGripRefuses(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	for _, bad := range []string{"", "xyz", gripPrimary + "00", "zz" + gripPrimary[2:]} {
		_, err := New([]PinnedGrip{{Field: "f", Grip: bad, Scope: ScopeSign}},
			a.path, filepath.Join(shortDir(t), "s.sock"), nil)
		if err == nil {
			t.Errorf("New accepted grip %q", bad)
		}
	}
}

// TestUnheldGripRefusesTheRun: the startup probe asks the agent whether it
// holds the grip, and refuses the run when it does not. This is invariant 5 in
// its literal form.
func TestUnheldGripRefusesTheRun(t *testing.T) {
	a := newFakeAgent(t, gripPrimary) // does NOT hold gripSubkey
	_, err := New(pinnedBoth(), a.path, filepath.Join(shortDir(t), "s.sock"), nil)
	if err == nil {
		t.Fatal("New started with a grip the agent does not hold")
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(gripSubkey)) {
		t.Errorf("refusal does not name the missing grip: %v", err)
	}
	if !strings.Contains(err.Error(), "remove identity.gpg") {
		t.Errorf("refusal does not name the fix: %v", err)
	}
}

// TestUnreachableAgentRefuses: no agent means nothing to proxy.
func TestUnreachableAgentRefuses(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.sock")
	_, err := New([]PinnedGrip{{Field: "f", Grip: gripPrimary, Scope: ScopeSign}},
		missing, filepath.Join(dir, "s.sock"), nil)
	if err == nil {
		t.Fatal("New started against a dead agent")
	}
}

// TestEmptyUpstreamRefuses: an unset upstream is named, not dialled.
func TestEmptyUpstreamRefuses(t *testing.T) {
	_, err := New([]PinnedGrip{{Field: "f", Grip: gripPrimary, Scope: ScopeSign}},
		"", filepath.Join(shortDir(t), "s.sock"), nil)
	if err == nil {
		t.Fatal("New started with no upstream")
	}
	if !strings.Contains(err.Error(), "no gpg-agent") {
		t.Errorf("refusal does not name the cause: %v", err)
	}
}

// TestSignProbeDrivesPKSIGN: a sign-scoped grip is proven signable at startup.
// The probe must actually reach PKSIGN with the pinned grip, not merely HAVEKEY.
func TestSignProbeDrivesPKSIGN(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, _, _ = newTestProxy(t, a, pinnedSignOnly())
	got := a.sawSign()
	if len(got) != 1 || got[0] != gripPrimary {
		t.Fatalf("startup probe signs = %v, want exactly [%s]", got, gripPrimary)
	}
}

// TestDecryptGripIsNotSignProbed: a decrypt-only grip must NOT be sign-probed,
// because the agent would refuse SIGKEY on the encryption subkey and turn a
// working decryption setup into a refusal.
func TestDecryptGripIsNotSignProbed(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, _, _ = newTestProxy(t, a, pinnedDecryptOnly())
	if got := a.sawSign(); len(got) != 0 {
		t.Fatalf("startup probe signed with a decrypt-only grip: %v", got)
	}
}

// TestUnsignableGripRefusesTheRun: a grip the agent LISTS but will not USE must
// refuse the run, because snug authors commit.gpgsign = true inside and a key
// that cannot sign fails every commit with an error naming no cause.
func TestUnsignableGripRefusesTheRun(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	a.setRefuseSign(strings.ToUpper(gripPrimary))
	_, err := New(pinnedSignOnly(), a.path, filepath.Join(shortDir(t), "s.sock"), nil)
	if err == nil {
		t.Fatal("New started with a grip the agent holds but will not sign with")
	}
	if !strings.Contains(err.Error(), "refused to sign") {
		t.Errorf("refusal does not name the cause: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(gripPrimary)) {
		t.Errorf("refusal does not name the grip: %v", err)
	}
}

// ── the local answers ───────────────────────────────────────────────────────

// TestHaveKeyListShowsOnlyPinned is THE leak test: the host agent holds a key
// the profile did not pin, and HAVEKEY --list must not mention it.
func TestHaveKeyListShowsOnlyPinned(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripSubkey, gripOther)
	_, sock, _ := newTestProxy(t, a, pinnedBoth())
	c := dial(t, sock)
	reply := c.send("HAVEKEY --list=1000")
	// The D line carries RAW 20-byte grips, percent-escaped, so unescape first.
	payload := ""
	if p, ok := strings.CutPrefix(reply[0], "D "); ok {
		payload = string(assuanUnescape(p))
	}
	wantPrimary, _ := parseGrip("f", gripPrimary)
	if !strings.Contains(payload, string(wantPrimary[:])) {
		t.Fatalf("HAVEKEY --list omitted the pinned primary grip: %v", reply)
	}
	wantOther, _ := parseGrip("f", gripOther)
	if strings.Contains(payload, string(wantOther[:])) {
		t.Fatalf("HAVEKEY --list leaked an unpinned grip: %v", reply)
	}
}

// TestHaveKeySingleUnpinnedRefused: the single-grip form must read an unpinned
// grip as absent, not forward the question to the agent.
func TestHaveKeySingleUnpinnedRefused(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripOther)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	before := a.contactCount()
	reply := c.send("HAVEKEY " + gripOther)
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("HAVEKEY for an unpinned grip answered %v, want ERR", reply)
	}
	// The agent holds gripOther, so a FORWARDED question would answer OK. The
	// proxy must answer from its own pin set and never ask.
	if a.contactCount() != before {
		t.Errorf("the proxy contacted the agent for a local HAVEKEY answer")
	}
}

// TestHaveKeySinglePinnedAnswersOK.
func TestHaveKeySinglePinnedAnswersOK(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	reply := c.send("HAVEKEY " + gripPrimary)
	if !strings.HasPrefix(terminalOf(reply), "OK") {
		t.Fatalf("HAVEKEY for the pinned grip answered %v, want OK", reply)
	}
}

// TestKeyInfoListShowsOnlyPinned.
func TestKeyInfoListShowsOnlyPinned(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripSubkey, gripOther)
	_, sock, _ := newTestProxy(t, a, pinnedBoth())
	c := dial(t, sock)
	reply := c.send("KEYINFO --list")
	joined := strings.Join(reply, "\n")
	if strings.Contains(joined, gripOther) {
		t.Fatalf("KEYINFO --list leaked an unpinned grip: %v", reply)
	}
}

// TestGetInfoVersionIsTheAgents: gpg picks its protocol from the agent's
// version, so the proxy forwards the question rather than answering a fixed
// string. A fixed 2.4.8 made gpg 2.5 warn "server 'gpg-agent' is older than us"
// on every call.
func TestGetInfoVersionIsTheAgents(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	before := a.contactCount()
	reply := c.send("GETINFO version")
	if !strings.Contains(strings.Join(reply, "\n"), "D 2.4.8") {
		t.Fatalf("GETINFO version answered %v, want the agent's D 2.4.8", reply)
	}
	if a.contactCount() == before {
		t.Errorf("GETINFO version was answered locally, not by the agent")
	}
}

// TestGetInfoHostStateIsForbidden: the GETINFO forms that describe the host
// agent — its pid, its socket paths, its environment — are refused before the
// agent is contacted. Measured on gpg-agent 2.5.24, std_session_env answers
// GPG_TTY, DISPLAY and XAUTHORITY, and getenv answers any variable asked for.
func TestGetInfoHostStateIsForbidden(t *testing.T) {
	for _, what := range []string{"pid", "socket_name", "ssh_socket_name",
		"std_session_env", "std_startup_env", "getenv HOME", "connections", "nonsense"} {
		t.Run(what, func(t *testing.T) {
			a := newFakeAgent(t, gripPrimary)
			_, sock, audit := newTestProxy(t, a, pinnedSignOnly())
			c := dial(t, sock)
			before := a.contactCount()
			reply := c.send("GETINFO " + what)
			if got := terminalOf(reply); got != errForbidden {
				t.Fatalf("GETINFO %s answered %v, want %q", what, reply, errForbidden)
			}
			if a.contactCount() != before {
				t.Errorf("GETINFO %s reached the agent", what)
			}
			if !audit.contains("GETINFO") {
				t.Errorf("GETINFO %s refused without an audit line: %v", what, audit.lines())
			}
		})
	}
}

// TestRefusalIsForbiddenNotErrZero: a refusal carries the agent's own
// GPG_ERR_FORBIDDEN. `ERR 0` is GPG_ERR_NO_ERROR to libgpg-error.
func TestRefusalIsForbiddenNotErrZero(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	for _, cmd := range []string{"EXPORT_KEY " + gripPrimary, "FOOBAR"} {
		if got := terminalOf(c.send(cmd)); got != errForbidden {
			t.Errorf("%s answered %q, want %q", cmd, got, errForbidden)
		}
	}
}

// TestGetInfoSocketNameIsNotForwarded: the host agent's socket path must not
// leak, or a client could try to reach it directly.
func TestGetInfoSocketNameIsNotForwarded(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	reply := c.send("GETINFO socket_name")
	joined := strings.Join(reply, "\n")
	if strings.Contains(joined, a.path) {
		t.Fatalf("GETINFO socket_name leaked the host agent path: %v", reply)
	}
}

// ── the forwarded path ──────────────────────────────────────────────────────

// TestSignRoundTrip: SIGKEY, SETKEYDESC, SETHASH, PKSIGN all reach the agent on
// ONE connection, and the signature comes back.
func TestSignRoundTrip(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	for _, cmd := range []string{
		"RESET",
		"SIGKEY " + gripPrimary,
		"SETKEYDESC snug+test",
		"SETHASH 10 " + strings.Repeat("ab", 64),
	} {
		if got := terminalOf(c.send(cmd)); !strings.HasPrefix(got, "OK") {
			t.Fatalf("%s answered %q, want OK", cmd, got)
		}
	}
	reply := c.send("PKSIGN")
	if !strings.Contains(strings.Join(reply, "\n"), "sig-val") {
		t.Fatalf("PKSIGN reply carries no signature: %v", reply)
	}
	// State survived: the SIGKEY set on this connection is what PKSIGN used.
	//
	// The probe signed too, so the SIGN list holds the probe's call and then
	// this one.
	got := a.sawSign()
	if len(got) != 2 || got[1] != gripPrimary {
		t.Fatalf("signs = %v, want the probe and one client sign with %s", got, gripPrimary)
	}
}

// TestSignUnpinnedGripRefused: SIGKEY for a grip the profile did not pin is
// refused WITHOUT the agent being contacted.
func TestSignUnpinnedGripRefused(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripOther)
	_, sock, log := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	before := a.contactCount()
	reply := c.send("SIGKEY " + gripOther)
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("SIGKEY for an unpinned grip answered %v, want ERR", reply)
	}
	if a.contactCount() != before {
		t.Errorf("the proxy contacted the agent for an unpinned SIGKEY")
	}
	if !log.contains("not in the pinned set") {
		t.Errorf("refusal was not audited: %v", log.lines())
	}
}

// TestSetKeyRefusedWithoutDecryptScope: with only sign granted, SETKEY must be
// refused — a signing grant must not double as a decryption oracle. The grip
// IS pinned (for signing), so the refusal is the scope check and not the
// membership check.
func TestSetKeyRefusedWithoutDecryptScope(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, log := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	before := a.contactCount()
	reply := c.send("SETKEY " + gripPrimary)
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("SETKEY under a sign-only scope answered %v, want ERR", reply)
	}
	if a.contactCount() != before {
		t.Errorf("the proxy forwarded SETKEY under a sign-only scope")
	}
	if !log.contains("without the decrypt scope") {
		t.Errorf("refusal did not name the scope, only audit: %v", log.lines())
	}
}

// TestSignKeyRefusedWithoutSignScope: with only decrypt granted, SIGKEY must be
// refused — a decryption grant must not double as a signing oracle.
func TestSignKeyRefusedWithoutSignScope(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	before := a.contactCount()
	reply := c.send("SIGKEY " + gripSubkey)
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("SIGKEY under a decrypt-only scope answered %v, want ERR", reply)
	}
	if a.contactCount() != before {
		t.Errorf("the proxy forwarded SIGKEY under a decrypt-only scope")
	}
}

// TestDecryptRoundTrip: the full measured decryption dialogue, INCLUDING the
// server-driven INQUIRE. This is the test that would deadlock a naive proxy.
func TestDecryptRoundTrip(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	if got := terminalOf(c.send("RESET")); !strings.HasPrefix(got, "OK") {
		t.Fatalf("RESET: %q", got)
	}
	if got := terminalOf(c.send("SETKEY " + gripSubkey)); !strings.HasPrefix(got, "OK") {
		t.Fatalf("SETKEY: %q", got)
	}
	// PKDECRYPT: the client must answer the INQUIRE. send() alone would only
	// read until OK/ERR and never see the INQUIRE; answerInquire drives it.
	if err := writeLine(c.w, "PKDECRYPT"); err != nil {
		t.Fatal(err)
	}
	if err := c.w.Flush(); err != nil {
		t.Fatal(err)
	}
	reply := c.answerInquire("(7:enc-val(4:ecdh(1:s4:abcd)(1:e4:efgh)))")
	joined := strings.Join(reply, "\n")
	if !strings.Contains(joined, "INQUIRE CIPHERTEXT") {
		t.Fatalf("the INQUIRE was not relayed: %v", reply)
	}
	if !strings.Contains(joined, "value33") {
		t.Fatalf("PKDECRYPT reply carries no plaintext: %v", reply)
	}
	if got := a.sawDecrypt(); len(got) != 1 || got[0] != gripSubkey {
		t.Fatalf("decrypts = %v, want one with %s", got, gripSubkey)
	}
}

// TestPkDecryptKemOptionReachesAgent: gpg 2.5 sends `PKDECRYPT --kem=PGP` and
// expects the agent to finish the ECDH derivation; forwarding a bare PKDECRYPT
// made every 2.5 decryption fail with `Wrong secret key used`. Both the 2.4
// and the 2.5 form must arrive exactly as sent.
func TestPkDecryptKemOptionReachesAgent(t *testing.T) {
	for _, cmd := range []string{"PKDECRYPT", "PKDECRYPT --kem=PGP", "PKDECRYPT --kem=PQC-PGP"} {
		t.Run(cmd, func(t *testing.T) {
			a := newFakeAgent(t, gripSubkey)
			_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
			c := dial(t, sock)
			if got := terminalOf(c.send("SETKEY " + gripSubkey)); !strings.HasPrefix(got, "OK") {
				t.Fatalf("SETKEY: %q", got)
			}
			if err := writeLine(c.w, cmd); err != nil {
				t.Fatal(err)
			}
			if err := c.w.Flush(); err != nil {
				t.Fatal(err)
			}
			reply := c.answerInquire("(7:enc-val(4:ecdh(1:s4:abcd)(1:e4:efgh)))")
			if !strings.Contains(strings.Join(reply, "\n"), "value33") {
				t.Fatalf("%s reply carries no plaintext: %v", cmd, reply)
			}
			if got := a.sawPkdecryptLines(); len(got) != 1 || got[0] != cmd {
				t.Fatalf("agent saw %q, want [%q]", got, cmd)
			}
		})
	}
}

// TestSetKeyAnotherIsGripChecked: a composite (Kyber) subkey's second grip
// arrives as `SETKEY --another <grip>`. A pinned decrypt grip is forwarded with
// the option intact; an unpinned one is refused like a plain SETKEY.
func TestSetKeyAnotherIsGripChecked(t *testing.T) {
	a := newFakeAgent(t, gripSubkey, gripOther)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	if got := terminalOf(c.send("SETKEY " + gripSubkey)); !strings.HasPrefix(got, "OK") {
		t.Fatalf("SETKEY <pinned>: %q", got)
	}
	if got := terminalOf(c.send("SETKEY --another " + gripSubkey)); !strings.HasPrefix(got, "OK") {
		t.Fatalf("SETKEY --another <pinned>: %q", got)
	}
	before := a.contactCount()
	c2 := dial(t, sock)
	if got := terminalOf(c2.send("SETKEY --another " + gripOther)); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("SETKEY --another <unpinned> answered %q, want ERR", got)
	}
	if a.contactCount() != before {
		t.Errorf("SETKEY --another <unpinned> reached the agent")
	}
}

// TestPkDecryptUnknownOptionRefused: gpg-agent 2.5.24 ignores an option it does
// not know, so the proxy forwards only the forms gpg sends and refuses the rest
// before the agent sees them.
func TestPkDecryptUnknownOptionRefused(t *testing.T) {
	for _, cmd := range []string{"PKDECRYPT --bogus", "PKDECRYPT --kem=CMS", "PKDECRYPT --kem"} {
		t.Run(cmd, func(t *testing.T) {
			a := newFakeAgent(t, gripSubkey)
			_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
			c := dial(t, sock)
			if got := terminalOf(c.send("SETKEY " + gripSubkey)); !strings.HasPrefix(got, "OK") {
				t.Fatalf("SETKEY: %q", got)
			}
			if got := terminalOf(c.send(cmd)); got != errForbidden {
				t.Fatalf("%s answered %q, want %q", cmd, got, errForbidden)
			}
			if got := a.sawPkdecryptLines(); len(got) != 0 {
				t.Fatalf("agent saw %q", got)
			}
		})
	}
}

// TestPkDecryptWithoutSetKeyRefused: PKDECRYPT before any SETKEY is the agent's
// own `No secret key`, forwarded rather than invented.
func TestPkDecryptWithoutSetKeyRefused(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	reply := c.send("PKDECRYPT")
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("PKDECRYPT without SETKEY answered %v, want ERR", reply)
	}
}

// TestPkDecryptRefusedWithoutScope: with only sign granted, PKDECRYPT reaches
// the agent but SETKEY was refused, so there is no selected key — the agent
// answers ERR. The proxy must relay that, not invent an OK.
func TestPkDecryptRefusedWithoutScope(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	reply := c.send("PKDECRYPT")
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("PKDECRYPT under a sign-only scope answered %v, want ERR", reply)
	}
	if got := a.sawDecrypt(); len(got) != 0 {
		t.Fatalf("the agent decrypted under a sign-only scope: %v", got)
	}
}

// ── the refusals that are the point ─────────────────────────────────────────

// TestExportKeyRefused is THE test for the verb that transfers private key
// material. It must be refused, and the agent must never see it.
func TestExportKeyRefused(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripSubkey)
	_, sock, log := newTestProxy(t, a, pinnedBoth())
	c := dial(t, sock)
	// `gpg --export-secret-keys` drives exactly this trio.
	c.send("KEYWRAP_KEY --export")
	c.send("KEYINFO " + gripPrimary)
	reply := c.send("EXPORT_KEY  " + gripPrimary) // TWO spaces, as measured
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("EXPORT_KEY answered %v, want ERR", reply)
	}
	if got := a.sawExport(); len(got) != 0 {
		t.Fatalf("the agent was asked to export: %v", got)
	}
	if !log.contains("export private key material") {
		t.Errorf("the export refusal was not audited: %v", log.lines())
	}
}

// TestMutationVerbsRefused: every verb that changes or controls the agent.
func TestMutationVerbsRefused(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripSubkey)
	_, sock, log := newTestProxy(t, a, pinnedBoth())
	c := dial(t, sock)
	for _, cmd := range []string{
		"DELETEKEY " + gripPrimary,
		"IMPORTKEYS",
		"PASSPHRASE abc",
		"PRESET_PASSPHRASE " + gripPrimary,
		"CLEARPASSPHRASE " + gripPrimary,
		"SETEVENTS",
		"SETINFO x y",
		"MKKEY foo",
		"KEYTOOL",
		// SCD is special: SERIALNO is part of gpg's normal path and MUST be
		// forwarded, while every other SCD verb drives the card and is refused.
		// See TestScdSerialnoForwardedButOtherScdRefused.
		"SCD LEARN",
		"SCD APDU 00",
	} {
		reply := c.send(cmd)
		if !strings.HasPrefix(terminalOf(reply), "ERR") {
			t.Errorf("%s answered %v, want ERR", cmd, reply)
		}
	}
	if got := a.sawExport(); len(got) != 0 {
		t.Fatalf("a mutation verb reached the agent: %v", got)
	}
	if len(log.lines()) == 0 {
		t.Errorf("no refusal was audited")
	}
}

// TestScdSerialnoForwardedButOtherScdRefused is the regression test for a live
// bug: refusing SCD wholesale broke EVERY sign and decrypt with
// `problem with fast path key listing: Invalid IPC response - ignored`,
// because gpg sends `SCD SERIALNO` on its normal path. Only the read-only query
// may pass; the verbs that drive the card must not.
func TestScdSerialnoForwardedButOtherScdRefused(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, log := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)

	before := a.contactCount()
	if got := terminalOf(c.send("SCD SERIALNO")); !strings.HasPrefix(got, "ERR") {
		// The fake agent answers ERR for SCD SERIALNO, exactly as a host agent
		// without a smartcard does. What matters is that it REACHED the agent.
		t.Fatalf("SCD SERIALNO answered %q, want the agent's ERR", got)
	}
	if a.contactCount() == before {
		t.Errorf("SCD SERIALNO was answered locally; gpg needs it forwarded")
	}
	if log.contains("smartcard") {
		t.Errorf("SCD SERIALNO was refused: %v", log.lines())
	}

	for _, cmd := range []string{"SCD LEARN", "SCD APDU 00", "SCD SERIALNO extra"} {
		before := a.contactCount()
		if got := terminalOf(c.send(cmd)); !strings.HasPrefix(got, "ERR") {
			t.Errorf("%s answered %q, want ERR", cmd, got)
		}
		if a.contactCount() != before {
			t.Errorf("%s was forwarded to the agent", cmd)
		}
		if !log.contains("smartcard") {
			t.Errorf("%s was not audited as a smartcard refusal: %v", cmd, log.lines())
		}
	}
	// What the agent saw: the one read-only query, and none of the verbs that
	// drive the card.
	saw := a.sawScd()
	if len(saw) == 0 {
		t.Error("control: the agent recorded no SCD at all, so the check below proves nothing")
	}
	for _, got := range saw {
		if strings.TrimSpace(got) != "SCD SERIALNO" {
			t.Errorf("the agent received %q", got)
		}
	}
}

// TestUnknownVerbRefused: an unrecognised command is refused, never guessed at.
func TestUnknownVerbRefused(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, log := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	before := a.contactCount()
	reply := c.send("WOMBAT frobnicate")
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("an unknown verb answered %v, want ERR", reply)
	}
	if a.contactCount() != before {
		t.Errorf("an unknown verb was forwarded to the agent")
	}
	if !log.contains("unknown gpg-agent command") {
		t.Errorf("the unknown-verb refusal was not audited: %v", log.lines())
	}
}

// TestByeClosesConnection: BYE is answered locally.
func TestByeClosesConnection(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)
	reply := c.send("BYE")
	if !strings.HasPrefix(terminalOf(reply), "OK") {
		t.Fatalf("BYE answered %v, want OK", reply)
	}
	// The connection is done; the next read must not hang for a reply.
	c.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := readLine(c.r); err == nil {
		t.Errorf("the proxy kept the connection open after BYE")
	}
}

// ── construction helpers for the fixtures ───────────────────────────────────

func TestGripParsingRoundTrips(t *testing.T) {
	raw, err := parseGrip("f", gripPrimary)
	if err != nil {
		t.Fatal(err)
	}
	if hexString(raw[:]) != strings.ToLower(gripPrimary) {
		t.Fatalf("round trip: %s", hexString(raw[:]))
	}
	if _, err := parseGrip("f", strings.ToUpper(gripPrimary)); err != nil {
		t.Errorf("uppercase grip refused: %v", err)
	}
}

func TestScopeStrings(t *testing.T) {
	cases := map[Scope]string{
		0:                        "nothing",
		ScopeSign:                "sign",
		ScopeDecrypt:             "decrypt",
		ScopeSign | ScopeDecrypt: "sign+decrypt",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Scope(%d).String() = %q, want %q", s, got, want)
		}
	}
}

// TestSocketIsRestricted: anything that can connect can ask for a signature.
func TestSocketIsRestricted(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("proxy socket mode is %o, want 0600", fi.Mode().Perm())
	}
}

// TestUpstreamUnreachableMidSession: a dead agent mid-connection is reported,
// not hung on.
func TestUpstreamUnreachableMidSession(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	p, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	// Kill the agent's listener so the dial fails.
	a.ln.Close()
	p.upstream = filepath.Join(t.TempDir(), "gone.sock")
	c := dial(t, sock)
	reply := c.send("RESET")
	if !strings.HasPrefix(terminalOf(reply), "ERR") {
		t.Fatalf("a dead upstream answered %v, want ERR", reply)
	}
}

// ── scope crossing through the agent's one selected key ─────────────────────

// TestDecryptScopeIsNotASigningOracle: gpg-agent keeps one selected key for
// SIGKEY and SETKEY. Measured on 2.5.24 through the proxy under a decrypt-only
// profile, `SETKEY <primary>`, SETHASH, PKSIGN returned a signature.
func TestDecryptScopeIsNotASigningOracle(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptAsCLI())
	c := dial(t, sock)
	if got := terminalOf(c.send("SETKEY " + gripPrimary)); !strings.HasPrefix(got, "OK") {
		t.Fatalf("SETKEY <primary>: %q", got)
	}
	c.send("SETHASH 10 " + strings.Repeat("ab", 64))
	if got := terminalOf(c.send("PKSIGN")); got != errForbidden {
		t.Fatalf("PKSIGN after SETKEY answered %q, want %q", got, errForbidden)
	}
	if got := a.sawSign(); len(got) != 0 {
		t.Fatalf("the agent signed under a decrypt-only scope: %v", got)
	}
}

// TestSignSelectionIsNotADecryption: the mirror case, and `SETKEY --another`
// after a SIGKEY, which would add a decrypt grip to a sign selection.
func TestSignSelectionIsNotADecryption(t *testing.T) {
	a := newFakeAgent(t, gripPrimary, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedBoth())
	c := dial(t, sock)
	if got := terminalOf(c.send("SIGKEY " + gripPrimary)); !strings.HasPrefix(got, "OK") {
		t.Fatalf("SIGKEY: %q", got)
	}
	if got := terminalOf(c.send("SETKEY --another " + gripSubkey)); !strings.HasPrefix(got, "ERR") {
		t.Fatalf("SETKEY --another after SIGKEY answered %q, want ERR", got)
	}
	if got := terminalOf(c.send("PKDECRYPT")); got != errForbidden {
		t.Fatalf("PKDECRYPT after SIGKEY answered %q, want %q", got, errForbidden)
	}
	if got := a.sawDecrypt(); len(got) != 0 {
		t.Fatalf("the agent decrypted after a SIGKEY: %v", got)
	}
}

// TestRefusedSelectionClearsTheSession: SIGKEY <pinned sign grip> succeeds, a
// later refused SETKEY leaves the AGENT holding the sign grip, and the
// following PKSIGN must not use it — nor may a RESET-cleared one.
func TestRefusedSelectionClearsTheSession(t *testing.T) {
	for _, between := range []string{"SETKEY " + gripOther, "RESET"} {
		t.Run(between, func(t *testing.T) {
			a := newFakeAgent(t, gripPrimary, gripOther)
			_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
			c := dial(t, sock)
			if got := terminalOf(c.send("SIGKEY " + gripPrimary)); !strings.HasPrefix(got, "OK") {
				t.Fatalf("SIGKEY: %q", got)
			}
			c.send(between)
			if got := terminalOf(c.send("PKSIGN")); got != errForbidden {
				t.Fatalf("PKSIGN after %s answered %q, want %q", between, got, errForbidden)
			}
		})
	}
}

// TestGetInfoTrailingArgumentRefused: the zero-argument GETINFO forms are
// forwarded as the bare name, and one carrying a trailing word is refused
// before the agent sees it (red team: `GETINFO version EVIL` was forwarded).
func TestGetInfoTrailingArgumentRefused(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	before := a.contactCount()
	if got := terminalOf(c.send("GETINFO version EVIL")); got != errForbidden {
		t.Fatalf("GETINFO version EVIL answered %q, want %q", got, errForbidden)
	}
	if a.contactCount() != before {
		t.Errorf("GETINFO version EVIL reached the agent")
	}
}
