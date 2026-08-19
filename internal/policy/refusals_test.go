package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── The seven combinations that now error and did not before ───────────────
//
// Every case here is built twice over: once as a focused Test* function that
// asserts the refusal names the right profiles and values, and once as a row
// in TestGoldenRefusals, which pins the EXACT text. The helper below is what
// both share, so the fixture cannot drift between the two.
//
// Before this change every one of these was accepted (see INDEX.md §3.4). Each helper is written so that reverting the corresponding fix in
// resolve.go/validate.go makes ONLY that case's Test* function fail — verified
// by running them against `git stash` (see the report for which method).

// refusalSymlinkConflict: two profiles set the SAME symlink guest to
// DIFFERENT targets. Before: silent — first-by-sorted-name won, and
// provenance printed BOTH names as though they agreed (resolve.go:439's
// `old.Kind == KindBind &&` guard meant Host, which for a symlink IS the link
// target, was never compared). This is the invariant-1 violation: a profile
// displacing another profile's grant.
func refusalSymlinkConflict(t testing.TB) error {
	reg := testRegistry()
	reg["link-a"] = &Profile{Name: "link-a", Symlink: []Symlink{{At: "/custom/tool", Target: "vendor-a"}}}
	reg["link-b"] = &Profile{Name: "link-b", Symlink: []Symlink{{At: "/custom/tool", Target: "vendor-b"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "link-a", "link-b"}, testCtx(), newFakeEnv())
	return err
}

func TestSymlinkConflictAtSamePathIsFatal(t *testing.T) {
	err := refusalSymlinkConflict(t)
	if err == nil {
		t.Fatal("two profiles repointing the same symlink to different targets were silently " +
			"resolved; one of them must have been discarded without a trace")
	}
	for _, want := range []string{"link-a", "link-b", "vendor-a", "vendor-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q; a conflict must name BOTH sides or nobody knows "+
				"which line to delete", err, want)
		}
	}
}

// refusalUserProfileCannotRepointSysBin pins the SPECIFIC case from the
// findings report: a profile named `0shadow` (a digit sorts before `@`) used
// to silently repoint `@sys`'s `/bin -> usr/bin` to `usr/sbin`, and --dry-run
// read `0shadow+@sys` as though the two agreed.
func refusalUserProfileCannotRepointSysBin(t testing.TB) error {
	reg := testRegistry()
	reg["0shadow"] = &Profile{Name: "0shadow", Symlink: []Symlink{{At: "/bin", Target: "usr/sbin"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "0shadow"}, testCtx(), newFakeEnv())
	return err
}

func TestUserProfileCannotRepointSysBin(t *testing.T) {
	err := refusalUserProfileCannotRepointSysBin(t)
	if err == nil {
		t.Fatal("a user profile named 0shadow silently repointed @sys's /bin -> usr/bin; " +
			"a profile displaced another profile's grant")
	}
	for _, want := range []string{"0shadow", "@sys", "usr/bin", "usr/sbin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// refusalJoinDifferentContent: two grants at one guest path with different
// KindData Content. No TOML key can produce this today — Content is only ever
// written by snug itself (Policy.Replace) — so it is exercised directly at the
// `join` level, the same way INDEX §2.2 documents the rule. It matters
// because `join` is the ONE place the whole monotonicity argument lives: if a
// future TOML key ever reaches KindData, this is the test that keeps it honest.
func refusalJoinDifferentContent(t testing.TB) error {
	p := &Policy{Mounts: map[string]Mount{}}
	if err := p.join(Mount{Guest: "/generated", Kind: KindData, Content: []byte("a"), From: []string{"gen-a"}}); err != nil {
		t.Fatalf("control: the first join into an empty map must not fail: %v", err)
	}
	return p.join(Mount{Guest: "/generated", Kind: KindData, Content: []byte("b"), From: []string{"gen-b"}})
}

func TestJoinRefusesDifferingContentAtSamePath(t *testing.T) {
	err := refusalJoinDifferentContent(t)
	if err == nil {
		t.Fatal("two different generated file contents at the same guest path joined silently; " +
			"there is no join between two different file bodies")
	}
	for _, want := range []string{"gen-a", "gen-b", "different generated contents"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// refusalJoinDifferentPerms: same shape as above, for Perms. Also unreachable
// from TOML today.
func refusalJoinDifferentPerms(t testing.TB) error {
	p := &Policy{Mounts: map[string]Mount{}}
	a, b := uint32(0o600), uint32(0o644)
	if err := p.join(Mount{Guest: "/generated", Kind: KindData, Perms: &a, From: []string{"gen-a"}}); err != nil {
		t.Fatalf("control: the first join into an empty map must not fail: %v", err)
	}
	return p.join(Mount{Guest: "/generated", Kind: KindData, Perms: &b, From: []string{"gen-b"}})
}

func TestJoinRefusesDifferingPermsAtSamePath(t *testing.T) {
	err := refusalJoinDifferentPerms(t)
	if err == nil {
		t.Fatal("two different file modes at the same guest path joined silently")
	}
	for _, want := range []string{"gen-a", "gen-b", "0600", "0644"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// refusalGrantAtExactlyProcOrDev: RULE 4. A profile grant at exactly /proc or
// /dev used to silently DISPLACE snug's own mount there — `ro = ["/proc"]`
// handed the sandbox the HOST's procfs instead of one bound to its own pid
// namespace.
func refusalGrantAtExactly(t testing.TB, guest string) error {
	reg := testRegistry()
	reg["claim"] = &Profile{Name: "claim", RW: []string{"/opt:" + guest}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "claim"}, testCtx(), newFakeEnv())
	return err
}

func TestGrantAtExactlyProcIsFatal(t *testing.T) {
	err := refusalGrantAtExactly(t, "/proc")
	if err == nil {
		t.Fatal("a profile grant at exactly /proc was accepted; it displaces snug's OWN procfs, " +
			"bound to the sandbox's pid namespace, with a bind of the host's")
	}
	for _, want := range []string{"claim", "snug's own", "/proc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestGrantAtExactlyDevIsFatal(t *testing.T) {
	err := refusalGrantAtExactly(t, "/dev")
	if err == nil {
		t.Fatal("a profile grant at exactly /dev was accepted; it displaces bwrap's synthetic " +
			"minimal device tree with a bind of the host's (every block and input device)")
	}
	for _, want := range []string{"claim", "snug's own", "/dev"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// POSITIVE CONTROL for both of the above: /tmp is the ONE path that is meant
// to yield to a profile grant — @tmp-shared replacing the private tmpfs with a
// host directory is how it works. If this ever starts failing, RULE 4 was
// applied too broadly and @tmp-shared is broken.
func TestGrantAtExactlyTmpStillYields(t *testing.T) {
	if err := refusalGrantAtExactly(t, "/tmp"); err != nil {
		t.Fatalf("control: a profile grant at exactly /tmp must still be legal — this is how "+
			"@tmp-shared works: %v", err)
	}
}

// refusalGrantCoversStagedBinDir: issue #22. `snugsOwn` used to be keyed on
// the EXACT guest path, so a grant AT StagedBinDir (/run/snug/bin) was
// refused and a grant at an ANCESTOR of it — /run, /run/snug — was accepted.
// Measured before the fix, with @podman-socket added so the directory landed
// on PATH: `tmpfs = ["/run"]` resolved, the payload wrote
// /run/snug/bin/git, and the shadowed git ran. Identical at
// `tmpfs = ["/run/snug"]`, and at both bind spellings — the rw one is worse,
// because it persists the shadowed command to the HOST directory rather than
// to a tmpfs that dies with the sandbox.
func refusalGrantCoversStagedBinDir(t testing.TB, kind, guest string) error {
	reg := testRegistry()
	p := &Profile{Name: "claim"}
	switch kind {
	case "tmpfs":
		p.Tmpfs = []string{guest}
	case "ro":
		p.RO = []string{"/opt:" + guest}
	case "rw":
		p.RW = []string{"/opt:" + guest}
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	reg["claim"] = p
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "claim"}, testCtx(), newFakeEnv())
	return err
}

func TestGrantCoveringStagedBinDirIsFatal(t *testing.T) {
	cases := []struct{ kind, guest string }{
		{"tmpfs", "/run"},
		{"tmpfs", "/run/snug"},
		{"ro", "/run"},
		{"rw", "/run"},
	}
	for _, tc := range cases {
		t.Run(tc.kind+"_"+tc.guest, func(t *testing.T) {
			err := refusalGrantCoversStagedBinDir(t, tc.kind, tc.guest)
			if err == nil {
				t.Fatalf("a profile %s grant at %s was accepted; it CONTAINS %s, snug's own "+
					"staged-bin directory, so a payload staged inside that mount gets a writable "+
					"directory ahead of /usr/bin on PATH", tc.kind, tc.guest, StagedBinDir)
			}
			for _, want := range []string{"claim", tc.guest, StagedBinDir, "CONTAINS"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

// POSITIVE CONTROL: a grant strictly INSIDE StagedBinDir must stay legal —
// this is the whole purpose of the directory, and it is how @claude
// (`ro = ["{home}/.local/bin/claude:/run/snug/bin/claude"]`) and the podman
// dispatcher work. If snugsOwnCovered ever starts refusing this, it has gone
// from "ancestor-aware" to "over-broad", and the directory can no longer be
// used for what it exists for.
func TestGrantInsideStagedBinDirStillLegal(t *testing.T) {
	reg := testRegistry()
	reg["claim"] = &Profile{Name: "claim", RO: []string{"/opt:" + StagedBinDir + "/mytool"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "claim"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: a grant strictly inside %s must stay legal: %v", StagedBinDir, err)
	}
}

// POSITIVE CONTROL: a sibling that merely shares a string PREFIX with
// StagedBinDir must not be refused. `covers` is a path-ancestor test, not
// strings.HasPrefix — /run/snug/binaries is not an ancestor of
// /run/snug/bin, and a prefix-based check would wrongly refuse it.
func TestGrantAtStringPrefixSiblingOfStagedBinDirStillLegal(t *testing.T) {
	reg := testRegistry()
	reg["claim"] = &Profile{Name: "claim", Tmpfs: []string{StagedBinDir + "aries"}} // /run/snug/binaries
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "claim"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: %saries is a string-prefix sibling of %s, not an ancestor, and must "+
			"stay legal: %v", StagedBinDir, StagedBinDir, err)
	}
}

// refusalGrantAtRoot: a redteam finding. Only a BIND at / was refused,
// so `tmpfs = ["/"]` resolved and ran. It was inert — but by ACCIDENT, not by
// the check: nearestCovering stops before / and so can never return it, which
// means the masking rule is structurally blind to anything nested under a root
// grant. What kept it harmless was SortedMounts emitting / first, so every
// sibling landed on top of it. An invariant that holds because of mount
// ordering is one that breaks silently the day the ordering is tuned. All three
// kinds are refused now; the test asserts all three, because refusing only the
// spelling that was reported is how the nested-bind masking bug survived M2.
func refusalGrantAtRoot(t testing.TB, kind string) error {
	reg := testRegistry()
	p := &Profile{Name: "takeroot"}
	switch kind {
	case "tmpfs":
		p.Tmpfs = []string{"/"}
	case "ro":
		p.RO = []string{"/opt:/"}
	case "rw":
		p.RW = []string{"/opt:/"}
	}
	reg["takeroot"] = p
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "takeroot"}, testCtx(), newFakeEnv())
	return err
}

func TestGrantAtRootIsFatalForEveryKind(t *testing.T) {
	for _, kind := range []string{"tmpfs", "ro", "rw"} {
		t.Run(kind, func(t *testing.T) {
			err := refusalGrantAtRoot(t, kind)
			if err == nil {
				t.Fatalf("a profile %s grant at / was accepted; the masking rule cannot see "+
					"inside a root grant (nearestCovering never returns /), so this is only "+
					"ever harmless by mount-ordering accident", kind)
			}
			for _, want := range []string{"takeroot", "root is snug's own"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

// POSITIVE CONTROL: refusing / must not have cost us the ordinary mounts. snug
// authors its own nodes at depth 1 (/proc, /dev, /tmp) and those are Authored,
// so the refusal must not fire on a normal run.
func TestOrdinaryPolicyStillResolvesAfterRootRefusal(t *testing.T) {
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: an ordinary selection must still resolve: %v", err)
	}
	for _, g := range []string{"/proc", "/dev", "/tmp"} {
		if _, ok := p.Mounts[g]; !ok {
			t.Errorf("control: %s missing — snug's own depth-1 mounts must survive the / refusal", g)
		}
	}
}

// refusalGrantStrictlyInside: RULE 2's KindProc/KindDev row. `ro =
// ["/proc/sys"]` and a bind over /dev/null were both accepted and emitted
// before this change — R2 in the findings report.
func refusalGrantStrictlyInside(t testing.TB, guest string) error {
	reg := testRegistry()
	reg["nest"] = &Profile{Name: "nest", RO: []string{"/opt:" + guest}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "nest"}, testCtx(), newFakeEnv())
	return err
}

func TestGrantStrictlyInsideProcIsFatal(t *testing.T) {
	err := refusalGrantStrictlyInside(t, "/proc/sys")
	if err == nil {
		t.Fatal("ro = [\"/proc/sys\"] was accepted; a mount inside /proc substitutes host " +
			"content for kernel content")
	}
	if !strings.Contains(err.Error(), "kernel and bwrap populate") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestGrantStrictlyInsideDevIsFatal(t *testing.T) {
	err := refusalGrantStrictlyInside(t, "/dev/null")
	if err == nil {
		t.Fatal("a bind over /dev/null was accepted; it replaces one of bwrap's synthetic " +
			"device nodes with a regular file")
	}
	if !strings.Contains(err.Error(), "kernel and bwrap populate") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// refusalGrantStrictlyInsideResolvConf: RULE 2's KindData row. A grant
// strictly beneath a generated FILE — /etc/resolv.conf here — is meaningless:
// nothing can be mounted inside a regular file.
func refusalGrantStrictlyInsideResolvConf(t testing.TB) error {
	reg := testRegistry()
	// Deliberately NOT @sys: the fake @sys binds /etc wholesale, and a grant
	// nested under /etc/resolv.conf would then ALSO be caught by the
	// pre-existing "bind not matching the outer tree's subpath" rule — a
	// different rule, firing for a different reason, which would make this
	// case pass even without the KindData-specific fix under test. A minimal
	// runtime profile with no /etc grant keeps this pinned to exactly the rule
	// it names.
	reg["runtime"] = &Profile{Name: "runtime", RO: []string{"/usr"}}
	reg["nest"] = &Profile{Name: "nest", RO: []string{"/opt:/etc/resolv.conf/x"}}
	_, err := Resolve(reg, []ProfileName{"runtime", "@cwd-rw", "nest"}, testCtx(), newFakeEnv())
	return err
}

func TestGrantStrictlyInsideKindDataPathIsFatal(t *testing.T) {
	err := refusalGrantStrictlyInsideResolvConf(t)
	if err == nil {
		t.Fatal("a grant strictly inside /etc/resolv.conf (a generated KindData file) was accepted")
	}
	for _, want := range []string{"generated FILE", "beneath a file is meaningless"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// refusalScalarConflict: two profiles setting different values for a
// last-writer-wins scalar. Before: the alphabetically-later profile won,
// silently — a real answer, just not the one the human who selected the
// FIRST profile expected.
func refusalScalarConflict(t testing.TB, key string) error {
	reg := testRegistry()
	switch key {
	case "address":
		reg["addr-a"] = &Profile{Name: "addr-a", Network: "egress", Address: "10.0.0.2/24"}
		reg["addr-b"] = &Profile{Name: "addr-b", Network: "egress", Address: "10.0.0.3/24"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "addr-a", "addr-b"}, testCtx(), newFakeEnv())
		return err
	case "address-forging":
		// The marker is written backwards: a bidi-rendering terminal shows
		// "FORGED-BY-AN-ADDRESS" after the override. The second value carries
		// the C1 spelling so the golden pins both halves of IsForgingRune.
		reg["addr-a"] = &Profile{Name: "addr-a", Network: "egress",
			Address: "10.0.0.2/24 ‮SSERDDA-NA-YB-DEGROF"}
		reg["addr-b"] = &Profile{Name: "addr-b", Network: "egress",
			Address: "10.0.0.3/24 1AFORGED-BY-A-C1"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "addr-a", "addr-b"}, testCtx(), newFakeEnv())
		return err
	case "gateway":
		reg["gw-a"] = &Profile{Name: "gw-a", Network: "egress", Gateway: "10.0.0.1"}
		reg["gw-b"] = &Profile{Name: "gw-b", Network: "egress", Gateway: "10.0.0.9"}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "gw-a", "gw-b"}, testCtx(), newFakeEnv())
		return err
	case "mtu":
		reg["mtu-a"] = &Profile{Name: "mtu-a", Network: "egress", MTU: 1400}
		reg["mtu-b"] = &Profile{Name: "mtu-b", Network: "egress", MTU: 9000}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "mtu-a", "mtu-b"}, testCtx(), newFakeEnv())
		return err
	default:
		t.Fatalf("unknown scalar key %q", key)
		return nil
	}
}

func TestConflictingAddressesAreFatal(t *testing.T) {
	err := refusalScalarConflict(t, "address")
	if err == nil {
		t.Fatal("two profiles setting different network addresses were silently resolved")
	}
	for _, want := range []string{"addr-a", "addr-b", "10.0.0.2/24", "10.0.0.3/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestConflictingGatewaysAreFatal(t *testing.T) {
	err := refusalScalarConflict(t, "gateway")
	if err == nil {
		t.Fatal("two profiles setting different network gateways were silently resolved")
	}
	for _, want := range []string{"gw-a", "gw-b", "10.0.0.1", "10.0.0.9"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestConflictingMTUsAreFatal(t *testing.T) {
	err := refusalScalarConflict(t, "mtu")
	if err == nil {
		t.Fatal("two profiles setting different MTUs were silently resolved")
	}
	for _, want := range []string{"mtu-a", "mtu-b", "1400", "9000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// refusalNestedGrantUnderLaterReplace: item 7. internal/cli's staging layer
// (claudeFiles, stageGhConfig, BindSocket) adds mounts via Policy.Replace
// AFTER Resolve — and after Resolve's own Validate call already ran. This
// simulates that shape purely within the policy package: a profile grant
// lands INSIDE a path that only becomes a KindData mount later. The first
// Validate cannot see it (nothing occupies that path yet); only a SECOND
// Validate call, run after the Replace, catches it — which is exactly what
// internal/cli/main.go now does after claudeFiles/startIdentity/startContainers.
// See TestPostStagingValidateCatchesNestedGrant in internal/cli for the same
// regression exercised through the real staging code.
func refusalNestedGrantUnderLaterReplace(t testing.TB) error {
	reg := testRegistry()
	reg["hostile"] = &Profile{Name: "hostile", RO: []string{"/opt:{home}/.claude.json/evil"}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw", "hostile"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: Resolve alone must accept this — nothing occupies {home}/.claude.json "+
			"yet, so its own Validate cannot see the nesting: %v", err)
	}
	// Simulates claudeFiles() staging ~/.claude.json as a generated file, after
	// Resolve (and its Validate) already returned.
	p.Replace(Mount{
		Guest: "/home/u/.claude.json", Kind: KindData, Access: AccessRW,
		Content: []byte("{}"), From: []string{"@claude"},
	})
	return p.Validate(newFakeEnv())
}

func TestPostStagingValidateCatchesNestedGrant(t *testing.T) {
	err := refusalNestedGrantUnderLaterReplace(t)
	if err == nil {
		t.Fatal("a profile grant nested inside a mount added AFTER Resolve went unnoticed; " +
			"the staging layer's Replace calls must be re-validated")
	}
	if !strings.Contains(err.Error(), "beneath a file is meaningless") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// refusalForbiddenEnvUnsetOnHost: §4.4. The verdict on a profile does not depend
// on whether the launching host has the variable set. Before, the check sat
// inside the presence guard, so the verdict on a PROFILE depended on the
// environment of whoever ran snug — accepted here, refused there, with nothing
// in either message explaining the difference.
//
// WHAT REFUSES IT HAS CHANGED, and the golden text moves with it. The
// forbidden-name table is an annotation now and refuses nothing; LD_PRELOAD is
// still refused at `inherit` because it is a LIST, and inheriting a list is an
// operation snug will not perform for anybody. So this case keeps measuring the
// host-independence property — the message it pins is simply the type rule's
// rather than the forbidden table's. Read the diff in refusals.txt as exactly
// that: the same refusal, arrived at by the mechanism that was never a denylist.
func refusalForbiddenEnvUnsetOnHost(t testing.TB) error {
	reg := testRegistry()
	reg["bad"] = &Profile{Name: "bad", Environ: EnvGrants{Inherit: []string{"LD_PRELOAD"}}}
	env := newFakeEnv() // deliberately WITHOUT LD_PRELOAD set
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "bad"}, testCtx(), env)
	return err
}

// ── the environment: the parse-time rules ────────────────────────────────────
//
// Every case below is a property of the profile TEXT, so the verdict is the
// same on every host. That is the point of checking here rather than in
// Resolve: §4.4's defect was a refusal that depended on the environment of
// whoever launched snug, and it is adopted as a design in the other direction.

func refusalEnv(g EnvGrants) func(testing.TB) error {
	return func(testing.TB) error { return ValidateEnvGrants(g) }
}

// ── the environment: the resolve-time conflicts ──────────────────────────────
//
// A single-valued slot with two different claims is a symmetric error naming
// EVERY claimant, checked after the fold completes so there is no fold order
// left to keep order-independent.

// refusalTwoPrepends: §2.7 case 1. Only one profile may hold the front of a
// variable, and two wanting it is a genuine disagreement.
func refusalTwoPrepends(t testing.TB) error {
	reg := testRegistry()
	reg["mytools"] = &Profile{Name: "mytools", RO: []string{"/opt/bin"}, Environ: EnvGrants{
		Prepend: map[string][]string{"PATH": {"/opt/bin"}}}}
	reg["othertools"] = &Profile{Name: "othertools", RO: []string{"/srv/bin"}, Environ: EnvGrants{
		Prepend: map[string][]string{"PATH": {"/srv/bin"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "mytools", "othertools"}, testCtx(), newFakeEnv())
	return err
}

// refusalPrependOrder: the same directories, different order. Equality is over
// the whole ordered sequence, because the order is the entire content of the
// claim.
func refusalPrependOrder(t testing.TB) error {
	reg := testRegistry()
	reg["ordera"] = &Profile{Name: "ordera", RO: []string{"/opt/a", "/opt/b"}, Environ: EnvGrants{
		Prepend: map[string][]string{"PATH": {"/opt/a", "/opt/b"}}}}
	reg["orderb"] = &Profile{Name: "orderb", RO: []string{"/opt/a", "/opt/b"}, Environ: EnvGrants{
		Prepend: map[string][]string{"PATH": {"/opt/b", "/opt/a"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "ordera", "orderb"}, testCtx(), newFakeEnv())
	return err
}

// refusalTwoSets: §2.7 case 2. Three profiles, two of which AGREE — the shape
// today's scalar conflicts get wrong, naming the alphabetically-last agreeing
// profile and never mentioning the first.
func refusalTwoSets(t testing.TB) error {
	reg := testRegistry()
	// The fixture keeps an APPLICATION name rather than moving to EDITOR on
	// purpose: what is under test is the disagreement rule, and pinning it to a
	// roster row would make this fixture change meaning the day issue #45
	// withdraws `set` from EDITOR.
	reg["seta"] = &Profile{Name: "seta", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "vim"}}}
	reg["setb"] = &Profile{Name: "setb", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "emacs"}}}
	reg["setc"] = &Profile{Name: "setc", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "vim"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "seta", "setb", "setc"}, testCtx(), newFakeEnv())
	return err
}

// refusalSetVsInherit: CALL 2. `set` and `inherit` on one scalar are one slot.
// "set beats inherit" would be a priority field wearing a verb's clothes.
func refusalSetVsInherit(t testing.TB) error {
	reg := testRegistry()
	reg["emacsy"] = &Profile{Name: "emacsy", Environ: EnvGrants{
		Set: map[string]string{"EDITOR": "emacs"}}}
	// `envy` inherits EDITOR, and the fake host has EDITOR=vim.
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "emacsy", "envy"}, testCtx(), newFakeEnv())
	return err
}

// ── the environment: the grant-coupling rule (§2.5, §2.7 case 4) ─────────────
//
// Resolve-time rather than parse-time, because it needs {target} and {home}
// expanded — but still over profile TEXT, so the verdict is the same on every
// host. Read envcoupling.go before citing any of these as a boundary: they stop
// a profile lying, not a profile reaching.

// refusalUncoupledSet is §2.7 case 4 verbatim: the profile grants .config and
// names .local/share.
func refusalUncoupledSet(t testing.TB) error {
	reg := testRegistry()
	reg["broken"] = &Profile{Name: "broken", Tmpfs: []string{"{home}/.config"}, Environ: EnvGrants{
		Set: map[string]string{"XDG_DATA_HOME": "{home}/.local/share"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "broken"}, testCtx(), newFakeEnv())
	return err
}

// refusalUncoupledMerge: the live bug §4.6(c) records — `/nonexistent/bin` on
// PATH, accepted in silence, measured on main.
func refusalUncoupledMerge(t testing.TB) error {
	reg := testRegistry()
	reg["tpath"] = &Profile{Name: "tpath", Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/nonexistent/bin"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "tpath"}, testCtx(), newFakeEnv())
	return err
}

// refusalUncoupledDespiteAnotherProfile: the verdict is a property of the
// profile's own text plus its include closure, and NOT of what else was
// selected — otherwise adding a profile would change another profile's
// legality. See TestCouplingVerdictDoesNotDependOnTheSelectedSet.
func refusalUncoupledDespiteAnotherProfile(t testing.TB) error {
	reg := testRegistry()
	reg["namer"] = &Profile{Name: "namer", Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/opt/tools/bin"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "namer", "envy"}, testCtx(), newFakeEnv())
	return err
}

// refusalRelativeSet: a relative path in a path-valued scalar. It is refused by
// the coupling check reaching the one function that owns this message, which is
// also the only way a relative `set` is refused at all — checkAbsoluteElement is
// called from the list verbs alone.
func refusalRelativeSet(t testing.TB) error {
	reg := testRegistry()
	reg["rel"] = &Profile{Name: "rel", Environ: EnvGrants{
		Set: map[string]string{"CARGO_HOME": "cargo"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "rel"}, testCtx(), newFakeEnv())
	return err
}

// refusalRelativeStartupFile: the same refusal at a name the coupling rule does
// NOT cover, which is the whole of F3. BASH_ENV, ENV and PYTHONSTARTUP are
// `pathNoGrant`: their value is a path, so it must be absolute, but the profile
// is not required to grant it. Before this row `set BASH_ENV = ".snug-init.sh"`
// resolved clean while `set CARGO_HOME = "cargo"` — the identical shape — was
// refused.
//
// ONE ROW, NOT THREE. The message differs from ENV's and PYTHONSTARTUP's only in
// the variable name, and three copies of one assertion is not three assertions —
// the same reasoning as the single golded bind spelling above. All three names,
// plus the two controls that must stay accepted, are exercised in
// TestARelativeStartupFileIsRefused.
func refusalRelativeStartupFile(t testing.TB) error {
	reg := testRegistry()
	reg["startup"] = &Profile{Name: "startup", Environ: EnvGrants{
		Set: map[string]string{"BASH_ENV": ".snug-init.sh"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "startup"}, testCtx(), newFakeEnv())
	return err
}

// refusalRelativePointer: the same refusal at the fifth POINTER, which had
// neither rule because it has no roster row.
//
// REGRESSION (redteam host round 2, F1). Four of the five writable pointers are
// rostered `path: true`, so `set CARGO_HOME = "cargo"` was refused above and
// three others with it; GIT_CONFIG_SYSTEM is not rostered — deliberately, since a
// row would open the builtin gate — so it was ACCEPTED, resolved against
// `--chdir <target>`, and MEASURED inside a running sandbox to execute both
// `[alias] st = "!cmd"` and `core.sshCommand` out of a file the payload writes.
// The fix reads the fact "snug's own tables call this a pointer at a FILE" from
// the table that already holds it (valueIsAPath -> namesAPointerFile).
//
// ONE ROW, NOT FIVE, for the reason the startup-file row gives: the message
// differs only in the variable name. The sweep over every pointer, with the
// accepted spelling as its control, is TestEveryPointerRefusesARelativeValue.
func refusalRelativePointer(t testing.TB) error {
	reg := testRegistry()
	reg["ptr"] = &Profile{Name: "ptr", Environ: EnvGrants{
		Set: map[string]string{"GIT_CONFIG_SYSTEM": "sys.gitconfig"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "ptr"}, testCtx(), newFakeEnv())
	return err
}

// refusalRelativeAnnotatedPath: the same refusal at a name that is in NEITHER
// table the two rows above read — and which snug's own annotation, printed on
// --dry-run in front of the human, calls a directory of hooks.
//
// REGRESSION (redteam host round 3, F1). The pointer fix closed the pointer set.
// GIT_TEMPLATE_DIR, GIT_EXEC_PATH, GIT_DIR and GIT_COMMON_DIR have no roster row
// (deliberately — a row opens the builtin gate) and are not pointers, so
// valueIsAPath was false and a relative value went through. Two of the four were
// measured executing attacker code out of `--chdir <target>`: the hook in
// <target>/r/tpl fired on the next commit, and `git probecmd` ran
// <target>/gx/git-probecmd. The fix reads the shape off the annotation that was
// already saying it.
//
// ONE ROW, NOT FOUR, for the reason the two rows above give: the message differs
// only in the variable name. The sweep over every path-shaped annotation, with
// the accepted spelling as its control, is TestEveryAnnotatedPathRefusesARelativeValue.
func refusalRelativeAnnotatedPath(t testing.TB) error {
	reg := testRegistry()
	reg["tpl"] = &Profile{Name: "tpl", Environ: EnvGrants{
		Set: map[string]string{"GIT_TEMPLATE_DIR": "tpl"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "tpl"}, testCtx(), newFakeEnv())
	return err
}

// ── the review artifact ──────────────────────────────────────────────────────

// TestGoldenRefusals pins the EXACT text of every refusal above. This change
// is almost entirely refusals and produces no argv diff — refusals.txt is the
// review artifact a human reads to approve it, the same way the .bwrap.txt
// files are for the argv. Regenerate with `go test ./internal/policy -update`,
// then READ the diff before committing it.
func TestGoldenRefusals(t *testing.T) {
	cases := []struct {
		name string
		run  func(testing.TB) error
	}{
		{"symlink_conflict_different_targets", refusalSymlinkConflict},
		{"symlink_cannot_repoint_sys_bin", refusalUserProfileCannotRepointSysBin},
		{"join_conflict_different_content", refusalJoinDifferentContent},
		{"join_conflict_different_perms", refusalJoinDifferentPerms},
		{"grant_at_root_tmpfs", func(t testing.TB) error { return refusalGrantAtRoot(t, "tmpfs") }},
		{"grant_at_root_ro", func(t testing.TB) error { return refusalGrantAtRoot(t, "ro") }},
		{"grant_at_exactly_proc", func(t testing.TB) error { return refusalGrantAtExactly(t, "/proc") }},
		{"grant_at_exactly_dev", func(t testing.TB) error { return refusalGrantAtExactly(t, "/dev") }},
		{"grant_covers_stagedbindir_tmpfs_run", func(t testing.TB) error { return refusalGrantCoversStagedBinDir(t, "tmpfs", "/run") }},
		{"grant_covers_stagedbindir_tmpfs_run_snug", func(t testing.TB) error { return refusalGrantCoversStagedBinDir(t, "tmpfs", "/run/snug") }},
		// Only ONE bind spelling is golded here, not two. describeNode does not
		// render Access, so a `ro` and an `rw` bind at the same guest path produce
		// byte-IDENTICAL refusal text ("profile claim puts a bind of /opt at
		// /run..." names neither "(ro)" nor "(rw)" anywhere) - a review found the
		// pair sitting in this table as two copies of one assertion: a change that
		// only affected `rw` would leave both golden entries unchanged. `ro` stands
		// as the representative of "a BIND, of either access, covering the
		// directory is refused the same way a tmpfs is"; the behavioural assertion
		// for BOTH spellings (does Resolve refuse it at all) still runs, un-golded,
		// in TestGrantCoveringStagedBinDirIsFatal above. That `rw` is the WORSE
		// variant - it would persist the shadowed command to the HOST rather than
		// to a tmpfs that dies with the sandbox - is exercised where that
		// difference is actually observable: test/integration/sandbox_test.go's
		// TestAProfileCannotMountOverTheStagingDirectory, as its own subtest
		// against the real bwrap argv.
		{"grant_covers_stagedbindir_bind_run", func(t testing.TB) error { return refusalGrantCoversStagedBinDir(t, "ro", "/run") }},
		{"grant_strictly_inside_proc", func(t testing.TB) error { return refusalGrantStrictlyInside(t, "/proc/sys") }},
		{"grant_strictly_inside_dev", func(t testing.TB) error { return refusalGrantStrictlyInside(t, "/dev/null") }},
		{"grant_strictly_inside_resolv_conf", refusalGrantStrictlyInsideResolvConf},
		{"scalar_conflict_address", func(t testing.TB) error { return refusalScalarConflict(t, "address") }},
		{"scalar_conflict_gateway", func(t testing.TB) error { return refusalScalarConflict(t, "gateway") }},
		{"scalar_conflict_mtu", func(t testing.TB) error { return refusalScalarConflict(t, "mtu") }},
		// The VALUES in a scalar conflict are profile text snug did not write,
		// and `address` is unvalidated for these runes at parse time (issue
		// #62), so this message is the one place a forging rune reaches a screen
		// through the network keys. The round-3 sweep escaped describeNode and
		// the two join conflicts and did not reach scalarConflict, which issue
		// #64 had named — this case is what makes that visible in a diff rather
		// than in someone's memory.
		{"scalar_conflict_address_forging", func(t testing.TB) error {
			return refusalScalarConflict(t, "address-forging")
		}},
		{"poststaging_nested_grant_under_later_replace", refusalNestedGrantUnderLaterReplace},
		{"forbidden_env_unset_on_host", refusalForbiddenEnvUnsetOnHost},

		// ── issue #55: a graft is a Mount, in its own namespace, with its own
		// checks (graft_test.go). Three representative G1 rows (ancestor at
		// /run, ancestor at /run/snug, exact at StagedBinDir) rather than all
		// six the behavioural TestGraftCoveringStagedBinDirIsRefused covers —
		// the same "one representative, not every spelling" choice this file
		// already makes for grant_covers_stagedbindir above.
		{"graft_covers_stagedbindir_ancestor_run", func(t testing.TB) error {
			return refusalGraftCoversStagedBinDir(t, "/run")
		}},
		{"graft_covers_stagedbindir_ancestor_run_snug", func(t testing.TB) error {
			return refusalGraftCoversStagedBinDir(t, "/run/snug")
		}},
		{"graft_covers_stagedbindir_exact", func(t testing.TB) error {
			return refusalGraftCoversStagedBinDir(t, StagedBinDir)
		}},
		{"graft_destination_does_not_exist_etc_containers", func(t testing.TB) error {
			return refusalGraftDestinationDoesNotExist(t, "/etc/containers")
		}},
		{"graft_destination_does_not_exist_var_tmp", func(t testing.TB) error {
			return refusalGraftDestinationDoesNotExist(t, "/var/tmp")
		}},
		{"graft_source_not_visible_xdg_runtime_dir", refusalGraftSourceNotVisible},
		{"graft_covers_graft", refusalGraftCoversGraft},
		{"graft_optional_forbidden", refusalGraftOptional},
		{"graft_empty_why", refusalGraftEmptyWhy},

		// the name grammar (§2.3): name ::= [A-Za-z_][A-Za-z0-9_]*
		{"env_name_empty", refusalEnv(EnvGrants{Set: map[string]string{"": "x"}})},
		{"env_name_equals", refusalEnv(EnvGrants{Set: map[string]string{"PATH=/evil:": "x"}})},
		{"env_name_nul", refusalEnv(EnvGrants{Set: map[string]string{"EDIT\x00OR": "x"}})},
		{"env_name_newline", refusalEnv(EnvGrants{Set: map[string]string{"EDITOR\nPS1": "x"}})},
		{"env_name_leading_digit", refusalEnv(EnvGrants{Set: map[string]string{"1PATH": "x"}})},
		{"env_name_bad_character", refusalEnv(EnvGrants{Set: map[string]string{"MY-VAR": "x"}})},
		{"env_name_snug_owned", refusalEnv(EnvGrants{Set: map[string]string{"SNUG_PROFILES": "@sys"}})},
		// The VALUE half of the same rule, and the C1 spelling specifically: the
		// byte loop this replaced could not see U+009B (CSI, the single-character
		// form of ESC-[), so it was accepted and reached every screen raw. The
		// golden is worth a row because the message has to NAME the character
		// rather than print it — a refusal that renders the byte it is refusing
		// hands the forgery the screen it was aiming for.
		{"env_value_c1_csi", refusalEnv(EnvGrants{Set: map[string]string{"EDITOR": "vim\u009b1A\u009b1G"}})},
		// The BIDI spelling, and it is here for the same reason the C1 one is: the
		// fix that added C1 asserted "the property rather than a copy of a
		// character list", and the property it asserted was unicode.IsControl —
		// which is the control-character set, while U+202E is category Cf. It was
		// accepted at 8d17f85 and rendered raw in the ENVIRONMENT block, on the
		// --setenv argv line, and in `profile show`. The message must name a
		// DIFFERENT damage than the control characters do: an override adds no row
		// and erases none, it reverses the order the rest of the line reads in.
		{"env_value_bidi_override", refusalEnv(EnvGrants{Set: map[string]string{"EDITOR": "/usr/bin/vim\u202eDEGROF"}})},
		{"env_name_snug_owned_ps1", refusalEnv(EnvGrants{Inherit: []string{"PS1"}})},
		// FIVE ENTRIES USED TO SIT HERE and they are gone rather than moved:
		// GIT_SSH_COMMAND and BASH_FUNC_* and GIT_CONFIG_COUNT at `set`,
		// PIP_INDEX_URL and BASH_ENV at `inherit`. Every one of them is now
		// ACCEPTED and ANNOTATED — snug has only allowlists, and a profile's
		// author is a human on the trusted side of the boundary. Their
		// replacement is not a refusal at all, which is why it could not stay in
		// this file: it is testdata/annotations.txt, the golden of every sentence
		// those names now render, and TestAnnotationSplitsBySetAndInherit, which
		// asserts the acceptance and the sentence together. Deleting a row here
		// without adding one there would have lost the assertion; that is the
		// only reason this comment is longer than the rows it replaces.

		// verb/type agreement (§2.1)
		{"env_set_on_a_list", refusalEnv(EnvGrants{Set: map[string]string{"PATH": "/opt/bin"}})},
		{"env_merge_on_a_scalar", refusalEnv(EnvGrants{Merge: map[string][]string{"EDITOR": {"vim"}}})},
		{"env_merge_on_an_uncomposable_list", refusalEnv(EnvGrants{Merge: map[string][]string{"CDPATH": {"/opt"}}})},
		{"env_inherit_on_a_list", refusalEnv(EnvGrants{Inherit: []string{"PKG_CONFIG_PATH"}})},
		// `env_inherit_on_a_generated_config_path` (inherit XDG_CONFIG_HOME) was
		// here and is gone for the same reason: it was the roster's `noInherit`
		// bit, a permission verdict living inside a table of type facts. It is an
		// annotation now — see annotations.txt, and the pointer loop in
		// TestAnnotationSplitsBySetAndInherit, which asserts BOTH halves of what
		// the bit used to mean: annotated at `inherit`, and silent at `set`,
		// because authoring a pointer is the mechanism snug recommends.
		{"env_sanitise_on_a_scalar", refusalEnv(EnvGrants{Sanitise: []string{"EDITOR"}})},
		{"env_sanitise_on_manpath", refusalEnv(EnvGrants{Sanitise: []string{"MANPATH"}})},
		{"env_sanitise_on_an_unfilterable_list", refusalEnv(EnvGrants{Sanitise: []string{"PYTHONPATH"}})},

		// the roster, and the one verb family it is required to answer (issue #44)
		//
		// A name with no roster row is CARRIED at `set` and `inherit` — a profile
		// with a name, a file and an author writing `set FOO = "x"` is already
		// that author naming the hole, and every row it produces is marked
		// `← unchecked` on both screens. What no profile can do is reach a LIST
		// verb with it: a list verb needs the separator and the meaning of an
		// empty element, and those are facts only a roster row carries. This row
		// is the review artifact for that refusal.
		{"env_unrostered_merge", refusalEnv(EnvGrants{Merge: map[string][]string{"MY_TOOL_PATH": {"/opt/x"}}})},

		// hand-written separators (CALL 1 / §2.7 case 3)
		{"env_separator_in_a_merge_string", refusalEnv(EnvGrants{Merge: map[string][]string{"PATH": {"/usr/bin:/usr/sbin"}}})},
		{"env_separator_in_a_prepend_element", refusalEnv(EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/bin", "/a:/b"}}})},

		// single-valued slots with more than one claim (§2.7 cases 1 and 2,
		// CALL 2)
		// the grant-coupling rule (§2.5 / §2.7 case 4)
		{"env_uncoupled_set", refusalUncoupledSet},
		{"env_uncoupled_merge", refusalUncoupledMerge},
		{"env_uncoupled_despite_another_profile_granting_it", refusalUncoupledDespiteAnotherProfile},
		{"env_relative_set", refusalRelativeSet},
		{"env_relative_set_bash_env", refusalRelativeStartupFile},
		{"env_relative_set_pointer", refusalRelativePointer},
		{"env_relative_set_annotated_path", refusalRelativeAnnotatedPath},

		{"env_two_prepends", refusalTwoPrepends},
		{"env_prepend_order_disagreement", refusalPrependOrder},
		{"env_two_sets_disagree", refusalTwoSets},
		{"env_set_disagrees_with_inherit", refusalSetVsInherit},
	}

	var b strings.Builder
	b.WriteString("# Resolver refusals — a table of (profile selection -> exact refusal text).\n")
	b.WriteString("# Regenerate with: go test ./internal/policy -update\n")
	b.WriteString("# Every case here used to be ACCEPTED; read INDEX.md \u00a73.4 before\n")
	b.WriteString("# changing any line below — a change here is a change to the security boundary.\n\n")
	for _, tc := range cases {
		err := tc.run(t)
		if err == nil {
			t.Fatalf("%s: expected a refusal, got none — a golden of \"no error\" would defeat "+
				"the point of this file", tc.name)
		}
		fmt.Fprintf(&b, "== %s ==\n%s\n\n", tc.name, err.Error())
	}
	got := b.String()

	path := filepath.Join("testdata", "refusals.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/policy -update)", err)
	}
	if got != string(want) {
		t.Errorf("refusal text changed — this is a change to the security boundary.\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// A REFUSAL IS A SCREEN, and this is the sink the two rounds of the
// control-character finding never reached.
//
// Both rounds swept what --dry-run, `snug profile show` and `snug profile list`
// RENDER. Neither read what snug prints when it REFUSES — and a refusal is the
// screen a human reads most carefully, because it is the one that stopped them.
// Measured on this branch, with a host directory whose name carries U+202E:
//
//	FILESYSTEM block   ro /opt/x (from /tmp/host<RLO>OLR)     <- escaped
//	--ro-bind line     /tmp/host<RLO>OLR /opt/x               <- escaped
//	the masking refusal on the same run:
//	  profile hostbidi puts a bind of /tmp/host<RLO>OLR at /opt/x...   <- RAW
//
// The host side cannot be refused for its characters — a file on this machine
// may legally be named that way, and Validate refuses only the GUEST side — so
// rendering is the only guard there is for it, which makes "every sink" include
// the error path.
//
// It is written over the ERROR TEXT rather than over the call sites, for the
// same reason TestNoSnugScreenEmitsARawControlCharacter drives the whole screen:
// a per-site test passes on the site it was written for and says nothing about
// the next one.
func TestARefusalNeverRendersARawForgingRune(t *testing.T) {
	// TWO ASSERTIONS PER MESSAGE, and the second is not redundant. The rune sweep
	// has to exempt '\n', because a refusal is legitimately several lines — which
	// means it structurally CANNOT see the newline probe, the very spelling the
	// original forged-row finding was about. So each message is also checked for
	// the probe string VERBATIM: if the host path went through VisibleText it is
	// there in its escaped form and this substring is absent.
	check := func(t *testing.T, what, message, host string) {
		t.Helper()
		if i := strings.IndexFunc(message, func(r rune) bool { return r != '\n' && IsForgingRune(r) }); i >= 0 {
			t.Errorf("%s rendered a forging rune verbatim: %q", what, message)
		}
		if strings.Contains(message, host) {
			t.Errorf("%s rendered the host path verbatim rather than escaped: %q", what, message)
		}
	}
	// Three spellings, in the one piece of text a profile cannot be refused for: a
	// HOST path. One forges a row, one reverses one, one is the C1 encoding of the
	// first.
	//
	// THE DIRECTORY HAS TO EXIST IN THE FIXTURE, and the first draft of this test
	// did not make it exist: Resolve refused earlier, with "grants %q which does
	// not exist" — a message that escapes through %q — so every assertion below
	// passed against a build with the fix REVERTED. Checked by reverting it. That
	// is the "a test that cannot fail" shape, met while writing the test for a
	// finding about tests that could not fail.
	for _, probe := range []struct{ why, host string }{
		{"a newline, which forges a row", "/srv/a\n  ro     /etc/shadow    @sys"},
		{"a directional override, which reverses one", "/srv/a\u202eOLR-DEGROF"},
		{"a C1 CSI", "/srv/a\u009b1A"},
	} {
		// The masking refusal: six messages are built from describeNode, and this
		// is the one measured rendering raw.
		env := newFakeEnv()
		env.dirs[probe.host] = true
		reg := testRegistry()
		reg["mask"] = &Profile{Name: "mask", RO: []string{probe.host + ":/opt/x"}}
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "mask"}, testCtx(), env)
		if err == nil || !strings.Contains(err.Error(), "which is inside /opt") {
			t.Fatalf("fixture: the MASKING refusal did not fire for %s, so this case measures "+
				"nothing: %v", probe.why, err)
		}
		check(t, "the masking refusal ("+probe.why+")", err.Error(), probe.host)

		// And the join conflict, which renders TWO host paths from two profiles.
		env2 := newFakeEnv()
		env2.dirs[probe.host] = true
		reg2 := testRegistry()
		reg2["a"] = &Profile{Name: "a", RO: []string{"/srv/bin:/srv/x"}}
		reg2["b"] = &Profile{Name: "b", RO: []string{probe.host + ":/srv/x"}}
		_, err = Resolve(reg2, []ProfileName{"@sys", "@cwd-rw", "a", "b"}, testCtx(), env2)
		if err == nil || !strings.Contains(err.Error(), "two host sources") {
			t.Fatalf("fixture: the JOIN CONFLICT did not fire for %s: %v", probe.why, err)
		}
		check(t, "the join-conflict refusal ("+probe.why+")", err.Error(), probe.host)
	}

	// THE POSITIVE CONTROL. An ordinary host path renders unchanged, spaces and
	// accents and all — otherwise a renderer that %q'd every message would pass
	// every assertion above while making each refusal harder to read than the
	// problem it describes.
	env := newFakeEnv()
	env.dirs["/srv/a b/caf\u00e9"] = true
	reg := testRegistry()
	reg["plain"] = &Profile{Name: "plain", RO: []string{"/srv/a b/caf\u00e9:/opt/x"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "plain"}, testCtx(), env)
	if err == nil {
		t.Fatal("fixture: the control did not reach a refusal")
	}
	if !strings.Contains(err.Error(), "/srv/a b/caf\u00e9") {
		t.Errorf("an ordinary host path was escaped in the refusal, which makes every message "+
			"harder to read than the problem it names: %v", err)
	}
}
