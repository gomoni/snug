package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── MVY1: the seven combinations that now error and did not before ─────────
//
// Every case here is built twice over: once as a focused Test* function that
// asserts the refusal names the right profiles and values, and once as a row
// in TestGoldenRefusals, which pins the EXACT text. The helper below is what
// both share, so the fixture cannot drift between the two.
//
// Before this change every one of these was accepted (see the MVY1
// findings). Each helper is written so that reverting the corresponding fix in
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "link-a", "link-b"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "0shadow"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "claim"}, testCtx(), newFakeEnv())
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

// refusalGrantAtRoot: the redteam's MVY1 finding. Only a BIND at / was refused,
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "takeroot"}, testCtx(), newFakeEnv())
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
	p, err := Resolve(testRegistry(), []string{"@sys", "@cwd-rw"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "nest"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"runtime", "@cwd-rw", "nest"}, testCtx(), newFakeEnv())
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
		_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "addr-a", "addr-b"}, testCtx(), newFakeEnv())
		return err
	case "gateway":
		reg["gw-a"] = &Profile{Name: "gw-a", Network: "egress", Gateway: "10.0.0.1"}
		reg["gw-b"] = &Profile{Name: "gw-b", Network: "egress", Gateway: "10.0.0.9"}
		_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "gw-a", "gw-b"}, testCtx(), newFakeEnv())
		return err
	case "mtu":
		reg["mtu-a"] = &Profile{Name: "mtu-a", Network: "egress", MTU: 1400}
		reg["mtu-b"] = &Profile{Name: "mtu-b", Network: "egress", MTU: 9000}
		_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "mtu-a", "mtu-b"}, testCtx(), newFakeEnv())
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

// refusalNestedGrantUnderLaterReplace: item 7. cmd/snug's staging layer
// (claudeFiles, stageGhConfig, BindSocket) adds mounts via Policy.Replace
// AFTER Resolve — and after Resolve's own Validate call already ran. This
// simulates that shape purely within the policy package: a profile grant
// lands INSIDE a path that only becomes a KindData mount later. The first
// Validate cannot see it (nothing occupies that path yet); only a SECOND
// Validate call, run after the Replace, catches it — which is exactly what
// cmd/snug/main.go now does after claudeFiles/startIdentity/startContainers.
// See TestPostStagingValidateCatchesNestedGrant in cmd/snug for the same
// regression exercised through the real staging code.
func refusalNestedGrantUnderLaterReplace(t testing.TB) error {
	reg := testRegistry()
	reg["hostile"] = &Profile{Name: "hostile", RO: []string{"/opt:{home}/.claude.json/evil"}}
	p, err := Resolve(reg, []string{"@sys", "@home", "@cwd-rw", "hostile"}, testCtx(), newFakeEnv())
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

// refusalForbiddenEnvUnsetOnHost: §4.4. A profile naming a code-injection
// variable is refused whether or not the launching host has that variable set.
// Before, the check sat inside the presence guard, so the verdict on a PROFILE
// depended on the environment of whoever ran snug — accepted here, refused
// there, with nothing in either message explaining the difference.
func refusalForbiddenEnvUnsetOnHost(t testing.TB) error {
	reg := testRegistry()
	reg["bad"] = &Profile{Name: "bad", Environ: EnvGrants{Inherit: []string{"LD_PRELOAD"}}}
	env := newFakeEnv() // deliberately WITHOUT LD_PRELOAD set
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "bad"}, testCtx(), env)
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "mytools", "othertools"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "ordera", "orderb"}, testCtx(), newFakeEnv())
	return err
}

// refusalTwoSets: §2.7 case 2. Three profiles, two of which AGREE — the shape
// today's scalar conflicts get wrong, naming the alphabetically-last agreeing
// profile and never mentioning the first.
func refusalTwoSets(t testing.TB) error {
	reg := testRegistry()
	reg["seta"] = &Profile{Name: "seta", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "vim"}}}
	reg["setb"] = &Profile{Name: "setb", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "emacs"}}}
	reg["setc"] = &Profile{Name: "setc", Environ: EnvGrants{Set: map[string]string{"MY_EDITOR": "vim"}}}
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "seta", "setb", "setc"}, testCtx(), newFakeEnv())
	return err
}

// refusalSetVsInherit: CALL 2. `set` and `inherit` on one scalar are one slot.
// "set beats inherit" would be a priority field wearing a verb's clothes.
func refusalSetVsInherit(t testing.TB) error {
	reg := testRegistry()
	reg["emacsy"] = &Profile{Name: "emacsy", Environ: EnvGrants{
		Set: map[string]string{"EDITOR": "emacs"}}}
	// `envy` inherits EDITOR, and the fake host has EDITOR=vim.
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "emacsy", "envy"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "broken"}, testCtx(), newFakeEnv())
	return err
}

// refusalUncoupledMerge: the live bug §4.6(c) records — `/nonexistent/bin` on
// PATH, accepted in silence, measured on main.
func refusalUncoupledMerge(t testing.TB) error {
	reg := testRegistry()
	reg["tpath"] = &Profile{Name: "tpath", Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"/nonexistent/bin"}}}}
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "tpath"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "namer", "envy"}, testCtx(), newFakeEnv())
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
	_, err := Resolve(reg, []string{"@sys", "@cwd-rw", "rel"}, testCtx(), newFakeEnv())
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
		{"grant_strictly_inside_proc", func(t testing.TB) error { return refusalGrantStrictlyInside(t, "/proc/sys") }},
		{"grant_strictly_inside_dev", func(t testing.TB) error { return refusalGrantStrictlyInside(t, "/dev/null") }},
		{"grant_strictly_inside_resolv_conf", refusalGrantStrictlyInsideResolvConf},
		{"scalar_conflict_address", func(t testing.TB) error { return refusalScalarConflict(t, "address") }},
		{"scalar_conflict_gateway", func(t testing.TB) error { return refusalScalarConflict(t, "gateway") }},
		{"scalar_conflict_mtu", func(t testing.TB) error { return refusalScalarConflict(t, "mtu") }},
		{"poststaging_nested_grant_under_later_replace", refusalNestedGrantUnderLaterReplace},
		{"forbidden_env_unset_on_host", refusalForbiddenEnvUnsetOnHost},

		// the name grammar (§2.3): name ::= [A-Za-z_][A-Za-z0-9_]*
		{"env_name_empty", refusalEnv(EnvGrants{Set: map[string]string{"": "x"}})},
		{"env_name_equals", refusalEnv(EnvGrants{Set: map[string]string{"PATH=/evil:": "x"}})},
		{"env_name_nul", refusalEnv(EnvGrants{Set: map[string]string{"EDIT\x00OR": "x"}})},
		{"env_name_newline", refusalEnv(EnvGrants{Set: map[string]string{"EDITOR\nPS1": "x"}})},
		{"env_name_leading_digit", refusalEnv(EnvGrants{Set: map[string]string{"1PATH": "x"}})},
		{"env_name_bad_character", refusalEnv(EnvGrants{Set: map[string]string{"MY-VAR": "x"}})},
		{"env_name_snug_owned", refusalEnv(EnvGrants{Set: map[string]string{"SNUG_PROFILES": "@sys"}})},
		{"env_name_snug_owned_ps1", refusalEnv(EnvGrants{Inherit: []string{"PS1"}})},
		{"env_name_forbidden_both", refusalEnv(EnvGrants{Set: map[string]string{"GIT_SSH_COMMAND": "x"}})},
		{"env_name_forbidden_prefix_both", refusalEnv(EnvGrants{Set: map[string]string{"BASH_FUNC_build": "x"}})},
		{"env_name_forbidden_prefix_git_config", refusalEnv(EnvGrants{Set: map[string]string{"GIT_CONFIG_COUNT": "1"}})},
		{"env_name_forbidden_prefix_inherit_only", refusalEnv(EnvGrants{Inherit: []string{"PIP_INDEX_URL"}})},
		{"env_name_forbidden_inherit_only", refusalEnv(EnvGrants{Inherit: []string{"BASH_ENV"}})},

		// verb/type agreement (§2.1)
		{"env_set_on_a_list", refusalEnv(EnvGrants{Set: map[string]string{"PATH": "/opt/bin"}})},
		{"env_merge_on_a_scalar", refusalEnv(EnvGrants{Merge: map[string][]string{"EDITOR": {"vim"}}})},
		{"env_merge_on_an_uncomposable_list", refusalEnv(EnvGrants{Merge: map[string][]string{"CDPATH": {"/opt"}}})},
		{"env_inherit_on_a_list", refusalEnv(EnvGrants{Inherit: []string{"PKG_CONFIG_PATH"}})},
		{"env_inherit_on_a_generated_config_path", refusalEnv(EnvGrants{Inherit: []string{"XDG_CONFIG_HOME"}})},
		{"env_sanitise_on_a_scalar", refusalEnv(EnvGrants{Sanitise: []string{"EDITOR"}})},
		{"env_sanitise_on_manpath", refusalEnv(EnvGrants{Sanitise: []string{"MANPATH"}})},
		{"env_sanitise_on_an_unfilterable_list", refusalEnv(EnvGrants{Sanitise: []string{"PYTHONPATH"}})},

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

		{"env_two_prepends", refusalTwoPrepends},
		{"env_prepend_order_disagreement", refusalPrependOrder},
		{"env_two_sets_disagree", refusalTwoSets},
		{"env_set_disagrees_with_inherit", refusalSetVsInherit},
	}

	var b strings.Builder
	b.WriteString("# MVY1 refusals — a table of (profile selection -> exact refusal text).\n")
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
