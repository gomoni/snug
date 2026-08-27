package cli

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// Issue #62's two named regression tests. Both halves of that finding — the
// unvalidated scalar and the unescaped sink — are closed in the code (netip
// typing plus checkAddressPair's V7 on the source side, visibleArgs on the
// pasta line), and neither had a test carrying the issue's own name.
//
// They are written from opposite ends on purpose, because each covers a
// failure the other does not. TestProfileNetworkScalarRefusesAControlCharacter
// drives the whole PRODUCTION route the reproduction uses — a TOML file in
// $XDG_CONFIG_HOME/snug/profiles.d, profile.Load, policy.Resolve — and asserts
// the value never becomes a policy at all.
// TestDryRunDoesNotRenderAPastaArgOrNetworkScalarVerbatim assumes the source
// half is gone tomorrow and asserts the RENDERER holds anyway, per row.

// forgedNetPayloads are the spellings a value can use to author or erase a row
// on a screen a human reads. The set is the same one policy.IsForgingRune
// answers for, sampled across its four mechanisms: ASCII control, C1 control,
// a line separator category-Zl, and a bidi override category-Cf. Sampling
// rather than enumerating is deliberate — the exhaustive assertion over the
// set belongs to the predicate's own test, and a copy of it here would be a
// second list to keep in step.
var forgedNetPayloads = []struct{ name, payload string }{
	// The reproduction in the issue, verbatim: a CR rewinds the terminal to
	// column 0 and the rest of the value overwrites the pasta line snug
	// printed, so the screen says one thing while the run does another.
	{"CR", "\rpasta --config-net --map-host-loopback none -t none -u none -T none -U none"},
	{"ESC", "\x1b[1A\r         host loopback   REACHABLE"},
	{"CSI (C1, U+009B)", "\u009b1A"},
	{"LINE SEPARATOR (U+2028)", "\u2028  forged"},
	{"RIGHT-TO-LEFT OVERRIDE (U+202E)", "\u202eDEGROF"},
}

// TestProfileNetworkScalarRefusesAControlCharacter is issue #62's source half,
// driven end to end: a real TOML file in a real $XDG_CONFIG_HOME, loaded by
// profile.Load and resolved by policy.Resolve, exactly as `snug --dry-run
// --no-defaults -p evil <dir>` does.
//
// The end-to-end route is the point rather than ceremony. The existing
// TestNetworkAddressAndGatewayRefuseAForgingRune (internal/policy) builds a
// policy.Profile struct in a registry, so it cannot observe the two layers in
// front of it: whether the TOML parser accepts the value at all, and whether
// Load hands it on. It also covers only the v4 pair, while a forged gateway6
// reaches the same pasta line by the same route.
//
// THE PARSER IS NOT THE DEFENCE, and the control below says so out loud. A raw
// control character never gets this far — go-toml refuses one in a basic string
// — but `\u000D` is an ESCAPE, and go-toml decodes it happily. Reading the
// parser's refusal of the raw spelling as coverage is how this class of finding
// survives; the same reasoning is written down in CLAUDE.md for checkEnvValue.
func TestProfileNetworkScalarRefusesAControlCharacter(t *testing.T) {
	for _, key := range []string{"address", "gateway", "address6", "gateway6"} {
		for _, probe := range forgedNetPayloads {
			t.Run(key+"/"+probe.name, func(t *testing.T) {
				reg, ok := loadForgedNetProfile(t, key, probe.payload)
				// CONTROL: the file LOADED. Without this the assertion below
				// is satisfied by a profile that never existed — a typo in
				// the fixture, a directory snug does not read, a TOML syntax
				// error — none of which says anything about the scalar.
				if !ok {
					t.Fatalf("the forged profile did not load at all, so this subtest never "+
						"reached the check it is about (%s = %q)", key, probe.payload)
				}

				_, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
					[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "forged"},
					envGoldenCtx(), newEnvFakeEnv())
				if err == nil {
					t.Fatalf("a profile file whose network %s carries %s was accepted. That "+
						"value reaches the pasta command line on --dry-run, which is the row a "+
						"human reads to decide what the sandbox's network actually is",
						key, probe.name)
				}
				if !strings.Contains(err.Error(), key) {
					t.Errorf("the refusal does not name which key was at fault (%s): %v", key, err)
				}
				// The refusal is itself a screen: it quotes the value back, so
				// it is a sink like any other and must not emit the payload
				// raw. Newline excluded for the same reason every sweep in
				// this package excludes it.
				if i := strings.IndexFunc(err.Error(), func(r rune) bool {
					return r != '\n' && isForgingRune(r)
				}); i >= 0 {
					t.Errorf("the refusal message emits the forged value raw (%q at byte %d) — "+
						"an error is a screen too: %s", []rune(err.Error()[i:])[0], i,
						strings.ReplaceAll(err.Error(), "\x1b", "<ESC>"))
				}
			})
		}
	}

	// POSITIVE CONTROL, and it is load-bearing twice. It proves the fixture's
	// shape is one snug otherwise accepts — so every refusal above is about
	// the payload and not about the profile being malformed — and it proves
	// this test is not passing because Resolve refuses every synthetic
	// address pair, which would be a broken build rather than a guarded one.
	t.Run("control/clean values resolve", func(t *testing.T) {
		reg, ok := loadForgedNetProfile(t, "", "")
		if !ok {
			t.Fatal("the clean profile did not load")
		}
		p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
			[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "forged"},
			envGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			t.Fatalf("the same profile with clean scalars was refused: %v", err)
		}
		if got := p.Net.Gateway.String(); got != "10.9.9.1" {
			t.Fatalf("the clean profile's gateway did not reach the policy (got %q), so the "+
				"subtests above may be refusing a profile that never carried the value", got)
		}
	})
}

// loadForgedNetProfile writes one profile file into a fresh
// $XDG_CONFIG_HOME/snug/profiles.d and loads it the way snug does. key names
// the scalar to forge and payload is appended to that scalar's clean value; an
// empty key writes the profile clean. ok is false when the file did not
// produce a "forged" profile, which is what the callers' control checks.
//
// The payload is written as a TOML \u ESCAPE, not as a raw byte, because a raw
// control character is refused by go-toml before any of snug's own code runs —
// see the test's doc comment. %q on the payload produces exactly that escaping.
func loadForgedNetProfile(t *testing.T, key, payload string) (profile.Registry, bool) {
	t.Helper()

	vals := map[string]string{
		"address":  "10.9.9.9/24",
		"gateway":  "10.9.9.1",
		"address6": "fd00:5e79:1::2/64",
		"gateway6": "fd00:5e79:1::1",
	}
	if key != "" {
		if _, known := vals[key]; !known {
			t.Fatalf("no such network key %q", key)
		}
		vals[key] += payload
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "snug", "profiles.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := fmt.Sprintf(`[profile.forged]
description = "looks fine"
network = "egress"
address = %q
gateway = %q
address6 = %q
gateway6 = %q
`, vals["address"], vals["gateway"], vals["address6"], vals["gateway6"])
	if err := os.WriteFile(filepath.Join(dir, "snug", "profiles.d", "e.toml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	reg, bad, err := profile.Load()
	if err != nil {
		t.Fatalf("profile.Load: %v", err)
	}
	for _, b := range bad {
		// Not a t.Fatal: a file snug could not parse is a legitimate answer
		// for some fixture, and the caller's control turns "no forged
		// profile" into the failure. Logged so a fixture typo is readable
		// rather than silent.
		t.Logf("profile file not loaded: %s: %v", b.Path, b.Err)
	}
	_, ok := reg["forged"]
	return reg, ok
}

// TestDryRunDoesNotRenderAPastaArgOrNetworkScalarVerbatim is issue #62's sink
// half: the pasta line was printed with strings.Join(p.PastaArgs(...), " ") while
// describeBwrap — the same file, the same value class — escaped every element.
// It now goes through visibleArgs, and this pins that per ROW.
//
// It overlaps TestNoSnugScreenEmitsARawControlCharacter deliberately and is not
// redundant with it. That test sweeps the WHOLE screen and answers "does
// anything anywhere emit a raw control character", which is the right question
// and the wrong resolution for this one: it cannot fail if the pasta line stops
// being printed, and it does not say which sink broke. This one names the two
// rows issue #62 is about — the pasta command and the NETWORK address rows —
// asserts each is present, and asserts the payload is escaped IN that row.
//
// The fixture reaches the sink by direct assignment because, with the source
// half closed, no profile can produce one — every route from a TOML file is
// refused by the test above. That is exactly the arrangement this test has to
// survive: `visibleValue` exists because "no screen renders unescaped text it
// did not author" must not depend on a validator upstream staying correct. The
// gateway ZONE is the one spelling that is not hypothetical even today —
// netip.ParseAddr accepts a zone and Addr.String() re-emits it verbatim, so
// only checkAddressPair's V7 stands between it and this line.
func TestDryRunDoesNotRenderAPastaArgOrNetworkScalarVerbatim(t *testing.T) {
	const forged = "FORGED-BY-A-NET-SCALAR"

	for _, probe := range forgedNetPayloads {
		t.Run(probe.name, func(t *testing.T) {
			reg, err := profile.Builtins()
			if err != nil {
				t.Fatal(err)
			}
			sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@net-anon"}
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel,
				envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatal(err)
			}
			if p.Net.Mode != policy.NetEgress {
				t.Fatalf("the fixture selection is not an egress policy (mode %v), so neither "+
					"the pasta line nor the anonymised address rows are printed at all", p.Net.Mode)
			}

			// The zone is where the payload rides: ParsePrefix refuses a
			// forging rune in the PREFIX half outright, so the address rows
			// are exercised through the gateway's rendering of the same pair.
			p.Net.Address = netip.MustParsePrefix("10.9.9.9/24")
			p.Net.Gateway = netip.MustParseAddr("10.9.9.1")
			p.Net.Address6 = netip.MustParsePrefix("fd00:5e79:1::2/64")
			p.Net.Gateway6 = netip.MustParseAddr("fe80::1%" + probe.payload + forged)

			got := dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)

			// CONTROL: the row this test is about is on the screen. A pasta
			// line that stopped being printed would satisfy every "no raw
			// control character" assertion below.
			pasta := linesWithPrefix(got, "pasta ")
			if len(pasta) == 0 {
				t.Fatalf("no pasta command line on the screen, so this test measured nothing:\n%s", got)
			}
			addrRows := linesContaining(got, "address v4", "address v6")
			if len(addrRows) < 2 {
				t.Fatalf("the NETWORK block printed %d address row(s), want both families — "+
					"the other half of issue #62's sinks is not on this screen:\n%s", len(addrRows), got)
			}

			// CONTROL: the payload REACHED the pasta line. Without it a
			// renderer that dropped the gateway entirely would pass.
			joined := strings.Join(pasta, "\n")
			if !strings.Contains(joined, forged) {
				t.Fatalf("the forged gateway never reached the pasta line, so the assertion "+
					"below is about a value that is not there:\n%s", joined)
			}

			for _, row := range append(append([]string{}, pasta...), addrRows...) {
				if i := strings.IndexFunc(row, func(r rune) bool { return isForgingRune(r) }); i >= 0 {
					t.Errorf("a row renders a network scalar verbatim (%q at byte %d): %s",
						[]rune(row[i:])[0], i, strings.ReplaceAll(row, "\x1b", "<ESC>"))
				}
			}
		})
	}
}

func linesWithPrefix(s string, prefix string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			out = append(out, line)
		}
	}
	return out
}

func linesContaining(s string, subs ...string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		for _, sub := range subs {
			if strings.Contains(line, sub) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}
