package gpgproxy

import (
	"strings"
	"testing"
)

// ── the escaping helpers ────────────────────────────────────────────────────
//
// This file exists because of a live-found bug that no amount of reading the
// spec would have caught: the pinned primary grip contains the byte 0x0A, and
// an Assuan D line is newline-terminated. Writing that grip raw truncated the
// payload, and gpg reported `problem with fast path key listing: Invalid IPC
// response - ignored` and then failed to sign at all.

// TestAssuanEscapeIsMinimal: exactly %, LF and CR are escaped, and nothing else.
// Escaping more would still parse but would differ byte-for-byte from what the
// agent writes, and relayed D lines are copied verbatim, so the two must agree.
func TestAssuanEscapeIsMinimal(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"a%0A", "a%250A"},     // a literal %0A becomes %250A
		{"a\nb", "a%0Ab"},      // LF
		{"a\rb", "a%0Db"},      // CR
		{"a\x00b", "a\x00b"},   // NUL is NOT escaped (it does not break framing)
		{"a\x0bb", "a\x0bb"},   // vertical tab is NOT escaped
		{"a\x7fb", "a\x7fb"},   // DEL is NOT escaped
		{"a\r\nb", "a%0D%0Ab"}, // both, in order
		{"100%", "100%25"},     // trailing %
		{"", ""},               // empty
	}
	for _, c := range cases {
		if got := assuanEscape([]byte(c.in)); got != c.want {
			t.Errorf("assuanEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAssuanUnescapeReversesEscape is the round-trip that stops the pair from
// drifting apart. The escape alphabet is chosen so the round trip is exact for
// every byte: %25 comes back as %, %0A as LF, %0D as CR, and any other byte is
// literal and unchanged.
func TestAssuanUnescapeReversesEscape(t *testing.T) {
	// Every byte value, as a payload. The round trip must be the identity.
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if got := assuanUnescape(assuanEscape(all)); string(got) != string(all) {
		t.Fatalf("round trip of all 256 bytes changed the payload:\n got %q\nwant %q", got, all)
	}
	for _, s := range []string{"", "plain", "\n", "\r", "%", "%0A", "%25", "\x00\xff"} {
		if got := assuanUnescape(assuanEscape([]byte(s))); string(got) != s {
			t.Errorf("round trip of %q = %q", s, got)
		}
	}
}

// TestAssuanUnescapeLeavesUnknownEscapesAlone: the payload may be an opaque
// ciphertext, and inventing an error for a sequence the proxy does not recognise
// would refuse something gpg would have accepted.
func TestAssuanUnescapeLeavesUnknownEscapesAlone(t *testing.T) {
	cases := []struct{ in, want string }{
		{"%ZZ", "%ZZ"}, // not hex
		{"%0", "%0"},   // truncated
		{"%", "%"},     // a lone percent
		{"%0A", "\n"},  // known
		{"%0a", "\n"},  // lowercase hex is accepted
		{"a%0Ab", "a\nb"},
		{"100%25", "100%"},
	}
	for _, c := range cases {
		if got := string(assuanUnescape(c.in)); got != c.want {
			t.Errorf("assuanUnescape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestGripWithNewlineByteSurvivesHaveKeyList is THE regression test for the live
// bug. The measurement key's primary grip is 2761D2BF75F0095F0FEA 0A 9216F4114A3B0C20BA
// — the ninth byte is 0x0A. If HAVEKEY --list writes it raw, the D line ends
// early and the client reads a truncated payload. It must come back escaped
// (%0A) and unescape to exactly the two grips.
func TestGripWithNewlineByteSurvivesHaveKeyList(t *testing.T) {
	const withNewline = "2761D2BF75F0095F0FEA0A9216F4114A3B0C20BA"
	raw, err := parseGrip("f", withNewline)
	if err != nil {
		t.Fatal(err)
	}
	if raw[10] != 0x0A {
		t.Fatalf("the fixture grip no longer contains a 0x0A byte at index 10 (got %#x); "+
			"this test would pass vacuously", raw[10])
	}

	a := newFakeAgent(t, withNewline, gripSubkey)
	_, sock, _ := newTestProxy(t, a, []PinnedGrip{
		{Field: "identity.gpg.fingerprint", Grip: withNewline, Scope: ScopeSign},
		{Field: "identity.gpg.fingerprint", Grip: gripSubkey, Scope: ScopeDecrypt},
	})
	c := dial(t, sock)
	reply := c.send("HAVEKEY --list=1000")

	// The reply must be exactly one D line plus OK. A raw 0x0A would have split
	// it into two lines, which is what the client saw as `Invalid IPC response`.
	if len(reply) != 2 {
		t.Fatalf("HAVEKEY --list reply has %d lines, want 2 (one D, one OK): %q", len(reply), reply)
	}
	payload, ok := strings.CutPrefix(reply[0], "D ")
	if !ok {
		t.Fatalf("first reply line is not a D line: %q", reply[0])
	}
	if !strings.Contains(payload, "%0A") {
		t.Errorf("the 0x0A byte in the grip was not escaped to %%0A: %q", payload)
	}
	if strings.ContainsRune(payload, '\n') {
		t.Errorf("the D payload contains a raw newline: %q", payload)
	}

	// And it must decode back to exactly the two grips, in order.
	decoded := assuanUnescape(payload)
	wantPrimary, _ := parseGrip("f", withNewline)
	wantSubkey, _ := parseGrip("f", gripSubkey)
	want := append(append([]byte(nil), wantPrimary[:]...), wantSubkey[:]...)
	if string(decoded) != string(want) {
		t.Fatalf("decoded payload\n got %x\nwant %x", decoded, want)
	}
}

// TestForwardedDLineIsNotReEscaped: the proxy is a byte pipe for relayed lines.
// The measurement that settled it: on a real decrypt the client sent the
// ciphertext with no escapes at all, and the agent accepted it. If the proxy
// re-escaped a relayed D line it would corrupt the payload; if it unescaped one
// the agent sent, it would corrupt the signature or plaintext.
func TestForwardedDLineIsNotReEscaped(t *testing.T) {
	a := newFakeAgent(t, gripPrimary)
	_, sock, _ := newTestProxy(t, a, pinnedSignOnly())
	c := dial(t, sock)

	// The fake agent's signature marker is ASCII; PKSIGN's D line must arrive
	// byte-for-byte as the agent wrote it.
	if got := terminalOf(c.send("RESET")); !strings.HasPrefix(got, "OK") {
		t.Fatalf("RESET: %q", got)
	}
	c.send("SIGKEY " + gripPrimary)
	reply := c.send("PKSIGN")
	joined := strings.Join(reply, "\n")
	if !strings.Contains(joined, "(7:sig-val(5:eddsa") {
		t.Fatalf("the signature D line was not forwarded verbatim: %v", reply)
	}
	if strings.Contains(joined, "%28") || strings.Contains(joined, "%29") {
		t.Errorf("a relayed D line was re-escaped: %v", reply)
	}
}

// TestInquireAnswerIsForwardedVerbatim: the client's ciphertext must reach the
// agent unchanged, escapes and all. gpg escapes only when it must, so a payload
// that arrives with a %0A must leave with it.
func TestInquireAnswerIsForwardedVerbatim(t *testing.T) {
	a := newFakeAgent(t, gripSubkey)
	_, sock, _ := newTestProxy(t, a, pinnedDecryptOnly())
	c := dial(t, sock)
	c.send("RESET")
	c.send("SETKEY " + gripSubkey)

	const ciphertext = "(7:enc-val(4:ecdh(1:s4:%0Aab)(1:e4:efgh)))(7:trailing)"
	if err := writeLine(c.w, "PKDECRYPT"); err != nil {
		t.Fatal(err)
	}
	if err := c.w.Flush(); err != nil {
		t.Fatal(err)
	}
	c.answerInquire(ciphertext)

	got := a.sawDecryptInquire()
	if len(got) != 2 {
		t.Fatalf("the agent saw %d inquire lines, want 2 (a D and an END): %q", len(got), got)
	}
	if got[0] != "D "+ciphertext {
		t.Fatalf("the ciphertext was altered in flight:\n got %q\nwant %q", got[0], "D "+ciphertext)
	}
	if got[1] != "END" {
		t.Fatalf("the terminating line was %q, want END", got[1])
	}
}
