package policy

import (
	"strings"
	"testing"
)

// ── a network grant that resolves and delivers something else ──────────────
//
// Invariant 5's shape: the profile author wrote a value, snug accepted it, and
// the sandbox got something the author did not ask for with nothing on screen
// saying so. Refusing is the only honest answer, because narrowing an author's
// value to the nearest thing the helper accepts is exactly what an unrecognised
// value must never be read as.

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
