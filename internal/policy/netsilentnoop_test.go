package policy

import (
	"strings"
	"testing"
)

// ── two network grants that used to resolve and deliver something else ─────
//
// Same shape twice, and it is invariant 5's: the profile author wrote a value,
// snug accepted it, and the sandbox got something the author did not ask for
// with nothing on screen saying so. Refusing is the only honest answer in both
// cases, because narrowing an author's value to the nearest thing the helper
// accepts is exactly what an unrecognised value must never be read as.

// `publish` needs pasta, and pasta runs only for an egress policy. Without it
// nothing was forwarded — while `--dry-run --json` reported `"egress": false`
// alongside `"publish": [8090]` in one document, `--dry-run`'s isolated arm
// printed no publish line at all, and `snug show` rendered the capability
// regardless. Reproduced with a user profile before the fix.
func TestPublishWithoutEgressIsRefused(t *testing.T) {
	reg := testRegistry()
	reg["pub"] = &Profile{Name: "pub", Publish: []int{8090}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw", "pub"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("accepted `publish` on a policy with no egress: pasta is what binds a " +
			"published port and it does not run here, so the human asked for a forward and " +
			"got nothing")
	}
	got := err.Error()
	for _, want := range []string{
		"8090",   // WHICH port
		"pub",    // WHICH profile asked
		"@net",   // the fix, by name
		"egress", // why it does not work
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal does not contain %q:\n%s", want, got)
		}
	}
}

// Several profiles publishing is one refusal naming all of them, in fold order
// so the message does not depend on how the selection was written.
func TestPublishWithoutEgressNamesEveryProfileThatAsked(t *testing.T) {
	reg := testRegistry()
	reg["pub-a"] = &Profile{Name: "pub-a", Publish: []int{8090}}
	reg["pub-b"] = &Profile{Name: "pub-b", Publish: []int{9000}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw", "pub-b", "pub-a"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("accepted two profiles publishing with no egress")
	}
	got := err.Error()
	if !strings.Contains(got, "pub-a") || !strings.Contains(got, "pub-b") {
		t.Errorf("the refusal blames only one of the two profiles that asked, so the other "+
			"line stays unedited:\n%s", got)
	}
	if !strings.Contains(got, `"pub-a", "pub-b"`) {
		t.Errorf("the profiles are not named in sorted fold order, so the message depends on "+
			"how the -p flags happened to be written:\n%s", got)
	}
}

// POSITIVE CONTROL: with egress the same profile resolves and keeps the port.
func TestPublishWithEgressStillResolves(t *testing.T) {
	reg := testRegistry()
	reg["pub"] = &Profile{Name: "pub", Network: "egress", Publish: []int{8090}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw", "pub"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("publish alongside egress was refused, which would make the rule above a "+
			"ban on the feature rather than on the silent no-op: %v", err)
	}
	if len(p.Net.Publish) != 1 || p.Net.Publish[0] != 8090 {
		t.Errorf("publish = %v, want [8090]", p.Net.Publish)
	}
}

// pasta PARSES an inline IPv6 prefix and throws it away: there is no
// c->ip6.prefix_len, the address is configured with a literal 64, and the RA's
// Prefix Information option carries a hardcoded 64. Its man page says so under
// `-a`. So `address6 = "fd00::2/112"` used to hand the sandbox a /64 — a WIDER
// on-link set than the profile asked for.
func TestAnIPv6PrefixPastaCannotDeliverIsRefused(t *testing.T) {
	for _, prefix := range []string{"fd00:5e79:1::2/112", "fd00:5e79:1::2/48", "fd00:5e79:1::2/128"} {
		reg := testRegistry()
		reg["pfx"] = &Profile{Name: "pfx", Network: "egress",
			Address: "10.13.13.2/24", Gateway: "10.13.13.1",
			Address6: prefix, Gateway6: "fd00:5e79:1::1"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw", "pfx"}, testCtx(), newFakeEnv())
		if err == nil {
			t.Errorf("accepted address6 %s: pasta configures a /64 regardless, so the sandbox "+
				"treats a wider set of addresses as on-link than the profile asks for", prefix)
			continue
		}
		got := err.Error()
		for _, want := range []string{"address6", "/64", "on-link"} {
			if !strings.Contains(got, want) {
				t.Errorf("the refusal for %s does not contain %q:\n%s", prefix, want, got)
			}
		}
	}
}

// POSITIVE CONTROLS. The rule is v6-only and /64-only, and both halves matter:
// pasta KEEPS the v4 prefix (c->ip4.prefix_len = prefix_len - 96), so applying
// this to the pair would refuse a working configuration — which is the "rule
// written once, applied to one of its two halves" defect this file's subject
// area has already produced twice.
func TestTheIPv6PrefixRuleIsV6AndSlash64Only(t *testing.T) {
	for _, tc := range []struct{ v4, v6, why string }{
		{"10.13.13.2/24", "fd00:5e79:1::2/64", "the shipped @net-anon shape"},
		{"10.13.13.2/16", "fd00:5e79:1::2/64", "a v4 prefix that is not /24 — pasta honours it"},
		{"10.13.13.2/30", "fd00:5e79:1::2/64", "a narrow v4 prefix, still honoured"},
	} {
		reg := testRegistry()
		reg["pfx"] = &Profile{Name: "pfx", Network: "egress",
			Address: tc.v4, Gateway: "10.13.13.1",
			Address6: tc.v6, Gateway6: "fd00:5e79:1::1"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw", "pfx"}, testCtx(), newFakeEnv())
		if err != nil {
			t.Errorf("address %s / address6 %s was refused — %s:\n%v", tc.v4, tc.v6, tc.why, err)
		}
	}
}
