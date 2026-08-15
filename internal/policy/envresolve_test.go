package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// entryValues renders one variable's entries in band order, for assertions
// about ORDER rather than about the joined string.
func entryValues(p *Policy, name string) []string {
	var out []string
	for _, e := range p.Env[name].Entries {
		out = append(out, e.Value)
	}
	return out
}

func entryVerbs(p *Policy, name string) []string {
	var out []string
	for _, e := range p.Env[name].Entries {
		out = append(out, e.Verb.String())
	}
	return out
}

// ── bands ────────────────────────────────────────────────────────────────────

// The bands are structural: nothing a profile writes chooses which one its
// entry lands in. This asserts the whole §2.4 diagram in one policy, in order,
// with every band populated — a band nobody exercises is a band the ordering
// tests cannot see.
func TestListBandsResolveInOrder(t *testing.T) {
	sel := []ProfileName{"@sys", "@cwd-rw", "firsty", "envy", "cwd-ro", "@podman-socket"}
	p, err := Resolve(testRegistry(), sel, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"/opt/first/bin",                         // prepend
		"/home/u/.local/bin",                     // merge, sorted by value
		"/opt/tools/bin",                         // merge
		StagedBinDir,                             // snug's own, generated
		"/usr/bin", "/bin", "/usr/sbin", "/sbin", // snug's own, base
	}
	got := entryValues(p, "PATH")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("PATH bands out of order:\n  got  %v\n  want %v", got, want)
	}

	wantVerbs := []string{"prepend", "merge", "merge", "(snug)", "(snug)", "(snug)", "(snug)", "(snug)"}
	if strings.Join(entryVerbs(p, "PATH"), " ") != strings.Join(wantVerbs, " ") {
		t.Errorf("verbs = %v, want %v", entryVerbs(p, "PATH"), wantVerbs)
	}
}

// The sanitise band sits after merge, because a merge is a declaration by a
// profile the human selected and a sanitise is a filtered copy of ambient host
// state. A declaration must beat ambient state, or the host's environment
// arbitrates between two profiles.
func TestSanitiseBandComesAfterMerge(t *testing.T) {
	reg := testRegistry()
	reg["pkg"] = &Profile{Name: "pkg", RO: []string{"/usr/share/pkgconfig"}, Environ: EnvGrants{
		Merge: map[string][]string{"PKG_CONFIG_PATH": {"/usr/share/pkgconfig"}},
	}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "pkg", "sanity"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/share/pkgconfig", "/usr/lib64/pkgconfig"}
	if got := entryValues(p, "PKG_CONFIG_PATH"); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("PKG_CONFIG_PATH = %v, want %v — the profile's own declaration first", got, want)
	}
}

// ── sanitise ─────────────────────────────────────────────────────────────────

// The filter keeps what policy grants, in the HOST's order, and names what it
// dropped rather than counting it.
func TestSanitiseKeepsGrantedElementsInHostOrder(t *testing.T) {
	env := newFakeEnv()
	// Deliberately NOT sorted, and deliberately interleaved with ungranted
	// entries: if survivors were sorted, /usr/lib64 would come before /usr/share
	// and this would fail.
	env.env["PKG_CONFIG_PATH"] = "/usr/share/pkgconfig:/srv/a:/usr/lib64/pkgconfig:/srv/b"

	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"/usr/share/pkgconfig", "/usr/lib64/pkgconfig"}
	if got := entryValues(p, "PKG_CONFIG_PATH"); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("survivors = %v, want %v in the host's own order — sorting would be a "+
			"second, silent transformation nobody asked for, and §3.3 documents a variable "+
			"where position is semantic", got, want)
	}

	var dropped []string
	for _, d := range p.Env["PKG_CONFIG_PATH"].Dropped {
		dropped = append(dropped, d.Value)
	}
	if strings.Join(dropped, " ") != "/srv/a /srv/b" {
		t.Errorf("dropped = %v, want both ungranted entries NAMED — a filter that silently "+
			"removes two of four elements is the exact shape of failure this model exists "+
			"to avoid, and \"2 of 4 kept\" does not let anyone check it", dropped)
	}
}

// THE §4.3 CASE, and the one place in this whole feature where getting it wrong
// ADDS a hole rather than failing to close one.
//
// When nothing survives the filter, the variable must be UNSET — absent from
// the argv entirely — and never set to the empty string. An empty PATH element
// is the current working directory, which inside snug is the target: the one
// writable thing a hostile payload controls. A feature sold as tightening the
// environment would then let it drop a file named `git` in the project root and
// have it run.
func TestSanitiseToNothingLeavesTheVariableUnset(t *testing.T) {
	env := newFakeEnv()
	env.env["PKG_CONFIG_PATH"] = "/srv/a:/srv/b" // nothing granted

	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := p.EnvValue("PKG_CONFIG_PATH"); ok {
		t.Errorf("PKG_CONFIG_PATH = %q; nothing survived the filter, so it must be UNSET, "+
			"not set to the empty string", v)
	}
	// And it must not reach the argv at all — an empty --setenv would be worse
	// than useless, and snug never emits --unsetenv either.
	args := p.BwrapFlags(1000, 1000, func(string) int { return 10 })
	for i, a := range args {
		if a == "PKG_CONFIG_PATH" {
			t.Errorf("PKG_CONFIG_PATH reached the argv at %d: %v", i, args[i-1:])
		}
		if a == "--unsetenv" {
			t.Error("--unsetenv is in the argv; after --clearenv there is nothing to unset, " +
				"and a subtraction in the argv is a subtraction in the model")
		}
	}

	// POSITIVE CONTROL: with one granted element the variable IS present, so
	// the assertion above cannot pass on a resolver where sanitise never runs.
	env.env["PKG_CONFIG_PATH"] = "/srv/a:/usr/lib64/pkgconfig"
	q, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := q.EnvValue("PKG_CONFIG_PATH"); !ok || v != "/usr/lib64/pkgconfig" {
		t.Errorf("control: PKG_CONFIG_PATH = %q (present=%v), want /usr/lib64/pkgconfig", v, ok)
	}
}

// An empty element in the HOST's value must never be carried through. This is
// the same hazard from the other side: snug does not write empty elements, and
// it does not pass on the ones it is handed either.
func TestSanitiseNeverCarriesAnEmptyElement(t *testing.T) {
	env := newFakeEnv()
	env.env["PKG_CONFIG_PATH"] = ":/usr/lib64/pkgconfig::/srv/a:"

	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := p.EnvValue("PKG_CONFIG_PATH")
	if !ok {
		t.Fatal("control: one element was granted, so the variable must be present")
	}
	if v != "/usr/lib64/pkgconfig" {
		t.Errorf("PKG_CONFIG_PATH = %q, want exactly the one granted element", v)
	}
	for _, part := range strings.Split(v, ":") {
		if part == "" {
			t.Errorf("PKG_CONFIG_PATH = %q contains an empty element, which resolves to the "+
				"current directory — inside snug, the target", v)
		}
	}
}

// Unset and empty both mean absent, FOR LISTS. The inverse — a flag scalar
// where empty is a value — is asserted by TestSetButEmptyHostVariableReaches
// TheSandbox, and the two must not be unified into one helper.
func TestSanitiseTreatsUnsetAndEmptyAlike(t *testing.T) {
	for _, host := range []struct {
		name string
		set  bool
	}{{"unset", false}, {"empty", true}} {
		env := newFakeEnv()
		delete(env.env, "PKG_CONFIG_PATH")
		if host.set {
			env.env["PKG_CONFIG_PATH"] = ""
		}
		p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity"}, testCtx(), env)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.EnvValue("PKG_CONFIG_PATH"); ok {
			t.Errorf("host %s: the variable reached the sandbox anyway", host.name)
		}
	}
}

// sanitise is a TRUTHFULNESS filter, not a capability filter, and the honest
// scope is narrower than the name. `ro` is enough, no mode bits, no stat — so a
// surviving element may name a bind that is empty. Pinning it here stops anyone
// citing sanitise as a guarantee that a surviving PATH entry contains anything.
func TestSanitiseAcceptsAReadOnlyGrant(t *testing.T) {
	env := newFakeEnv()
	env.dirs["/opt/roonly"] = true
	env.env["PKG_CONFIG_PATH"] = "/opt/roonly/lib/pkgconfig"

	reg := testRegistry()
	reg["ro-opt"] = &Profile{Name: "ro-opt", RO: []string{"/opt/roonly"}}

	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "ro-opt", "sanity"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := p.EnvValue("PKG_CONFIG_PATH"); v != "/opt/roonly/lib/pkgconfig" {
		t.Errorf("PKG_CONFIG_PATH = %q; a read-only grant is enough to keep an element", v)
	}
}

// ── sanitise-C: keepHostElement's Kind-switch (the tmpfs-shadow-slot fix) ──
//
// GrantsGuestPath used to answer "is this path granted" for ANY covering
// mount, regardless of Kind — so a host PATH element whose only coverage was
// an empty writable tmpfs (`/tmp`, or `{home}` from @home) survived sanitise
// and reached the argv ahead of `/usr/bin`. keepHostElement narrows the
// SANITISE FILTER's predicate (not GrantsGuestPath itself, which grantMark
// still uses — see TestGrantMarkStillUsesTheWiderPredicate) to "does the
// sandbox have the HOST'S CONTENT here", which a tmpfs answers no to. See
// the design's table in envresolve.go's keepHostElement doc comment.
//
// sanitiseProbeHost exercises every row of that table in one host value:
// a genuine tmpfs shadow slot, the tmpfs mountpoint itself, the writable
// target, a bind nested inside the {home} tmpfs, the SAME directory shadowed
// by the tmpfs above it, and a path nothing grants at all.
const sanitiseProbeHost = "/opt/tools/bin:/tmp/x/bin:/tmp:/home/u/.local/bin:/home/u/.local/bin/tool:/home/u/proj/sub/bin:/srv/nothing"

func sanitiseProbeSelection() []ProfileName {
	return []ProfileName{"@sys", "@home", "@cwd-rw", "envy", "nested-bin", "sanity-path"}
}

func sanitiseProbeEnv() *fakeEnv {
	env := newFakeEnv()
	env.env["PATH"] = sanitiseProbeHost
	return env
}

// pathOperand finds the exact `--setenv PATH <value>` operand bwrap will
// receive. "not in Entries" and "not in the argv" are two separate claims —
// a struct field a payload cannot read is not a security property.
func pathOperand(t *testing.T, p *Policy) string {
	t.Helper()
	args := p.BwrapFlags(1000, 1000, func(string) int { return 10 })
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" && args[i+1] == "PATH" {
			return args[i+2]
		}
	}
	t.Fatal("no --setenv PATH in the argv")
	return ""
}

func hasEntry(entries []string, v string) bool {
	for _, e := range entries {
		if e == v {
			return true
		}
	}
	return false
}

// Test 1 — the named regression for the finding itself: a host PATH element
// whose ONLY covering mount is a tmpfs must not survive sanitise, must be
// recorded as Dropped with DropTmpfsOnly, and — the claim that actually
// matters — must not reach the argv bwrap executes.
func TestSanitiseDropsAShadowSlotOnlyATmpfsCovers(t *testing.T) {
	p, err := Resolve(testRegistry(), sanitiseProbeSelection(), testCtx(), sanitiseProbeEnv())
	if err != nil {
		t.Fatal(err)
	}

	entries := entryValues(p, "PATH")
	for _, shadow := range []string{"/tmp/x/bin", "/tmp"} {
		if hasEntry(entries, shadow) {
			t.Errorf("%s survived sanitise: a writable directory ahead of /usr/bin on the PATH "+
				"snug itself wrote is exactly the shadow-slot abuse this rule exists to close — "+
				"the payload creates it and drops a file named `git` inside", shadow)
		}
	}

	dropped := map[string]EnvDropReason{}
	for _, d := range p.Env["PATH"].Dropped {
		dropped[d.Value] = d.Reason
	}
	for _, shadow := range []string{"/tmp/x/bin", "/tmp"} {
		if r, ok := dropped[shadow]; !ok || r != DropTmpfsOnly {
			t.Errorf("%s: Dropped present=%v reason=%v, want present with DropTmpfsOnly", shadow, ok, r)
		}
	}

	// The claim that actually matters: absence from the argv, not merely from
	// p.Env. A struct field the payload never reads protects nothing.
	operand := pathOperand(t, p)
	for _, part := range strings.Split(operand, ":") {
		if part == "/tmp/x/bin" || part == "/tmp" {
			t.Errorf("--setenv PATH operand %q still names the shadow slot %q", operand, part)
		}
	}
}

// Test 2 — the positive control for test 1, without which it could pass on a
// filter that drops EVERYTHING. Three assertions, each pinning a different
// row of keepHostElement's table.
func TestSanitiseKeepsAnElementARealBindCovers(t *testing.T) {
	p, err := Resolve(testRegistry(), sanitiseProbeSelection(), testCtx(), sanitiseProbeEnv())
	if err != nil {
		t.Fatal(err)
	}
	entries := entryValues(p, "PATH")

	if !hasEntry(entries, "/opt/tools/bin") {
		t.Error("/opt/tools/bin (a real ro bind) did not survive sanitise. If this fails, " +
			"keepHostElement has stopped being a truthfulness filter and become a capability " +
			"filter — see the design's rejection of candidate A")
	}

	// PINS CANDIDATE C OVER CANDIDATE A. A — drop anything whose covering
	// mount is writable — was rejected specifically because it would drop the
	// TARGET's own bind, which is rw. The directory need not exist on the
	// fake host; sanitise never stats.
	if !hasEntry(entries, "/home/u/proj/sub/bin") {
		t.Error("/home/u/proj/sub/bin (a writable bind of the TARGET) did not survive sanitise. " +
			"Candidate A was rejected precisely because dropping every writable-covered element " +
			"would have dropped this one too; keeping it is what makes this candidate C, not A")
	}

	if !hasEntry(entries, "/home/u/.local/bin/tool") {
		t.Error("/home/u/.local/bin/tool (a bind nested inside @home's tmpfs) did not survive " +
			"sanitise — this is @claude's real shape (base.toml: {home}/.local/bin/claude), and " +
			"losing it would break every credential file staged the same way")
	}
}

// Test 3 — both directions of "deepest, not first, covering mount" in one
// test. An implementation that kept an element because SOME mount exists AT
// OR BELOW it (a second, downward walk) would pass the second assertion here
// and fail the first — which is exactly why both live in one test rather
// than two.
func TestSanitiseUsesTheDeepestCoveringMount(t *testing.T) {
	p, err := Resolve(testRegistry(), sanitiseProbeSelection(), testCtx(), sanitiseProbeEnv())
	if err != nil {
		t.Fatal(err)
	}
	entries := entryValues(p, "PATH")

	if hasEntry(entries, "/home/u/.local/bin") {
		t.Error("/home/u/.local/bin survived sanitise. Its deepest covering mount is @home's " +
			"{home} tmpfs — a bind exists only BELOW it, at .../bin/tool — and keeping it means " +
			"an implementation re-admitted 'keep if any mount exists at or below', which the " +
			"design explicitly forbids")
	}
	if !hasEntry(entries, "/home/u/.local/bin/tool") {
		t.Error("/home/u/.local/bin/tool did not survive sanitise. Its deepest covering mount " +
			"is the bind nested-bin installs there, and deepest must win over the tmpfs above it — " +
			"the same 'effective access is the deepest mount' rule CLAUDE.md states for join")
	}
}

// Test 4 — the two drop reasons must never be conflated: "nothing grants
// that path" and "only an empty writable tmpfs is mounted there" are
// materially different facts for a human debugging a vanished PATH entry.
func TestSanitiseDropReasonDistinguishesUngrantedFromTmpfsOnly(t *testing.T) {
	p, err := Resolve(testRegistry(), sanitiseProbeSelection(), testCtx(), sanitiseProbeEnv())
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]EnvDropReason{}
	for _, d := range p.Env["PATH"].Dropped {
		reasons[d.Value] = d.Reason
	}
	if r, ok := reasons["/srv/nothing"]; !ok || r != DropNoGrant {
		t.Errorf("/srv/nothing: reason=%v present=%v, want DropNoGrant — nothing grants this path "+
			"at all, a different fact from a tmpfs granting an empty directory there", r, ok)
	}
	if r, ok := reasons["/tmp/x/bin"]; !ok || r != DropTmpfsOnly {
		t.Errorf("/tmp/x/bin: reason=%v present=%v, want DropTmpfsOnly — conflating the two "+
			"reasons is exactly the ambiguity EnvDropReason exists to remove", r, ok)
	}
}

// Test 6 — pins the clean-to-decide / emit-verbatim split against a
// well-meaning "fix" that writes the cleaned path into Entries. The walk
// that DECIDES an element's fate cleans the path; the VALUE recorded is
// always the raw host string (DROP-NEVER-REWRITE, envresolve.go:284-287).
func TestSanitiseEmitsTheHostElementVerbatimNotCleaned(t *testing.T) {
	env := newFakeEnv()
	env.env["PATH"] = "/tmp/../usr/bin:/tmp/"

	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@home", "@cwd-rw", "sanity-path"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	// Look at the SANITISE band specifically, not the joined PATH: snug's own
	// base band legitimately contributes a genuine "/usr/bin" entry
	// (VerbSnug), so asserting against entryValues(p, "PATH") as a whole would
	// find that one and prove nothing about what sanitise itself wrote.
	var sanitised []string
	for _, e := range p.Env["PATH"].Entries {
		if e.Verb == VerbSanitise {
			sanitised = append(sanitised, e.Value)
		}
	}
	if hasEntry(sanitised, "/usr/bin") {
		t.Errorf("the SANITISE band carries the CLEANED /usr/bin rather than the raw host "+
			"element /tmp/../usr/bin — sanitise must decide on the cleaned path but emit the "+
			"element verbatim, or DROP-NEVER-REWRITE is violated: %v", sanitised)
	}
	if !hasEntry(sanitised, "/tmp/../usr/bin") {
		t.Errorf("/tmp/../usr/bin (cleans to the granted /usr/bin) did not survive verbatim in "+
			"the sanitise band: %v", sanitised)
	}

	dropped := map[string]EnvDropReason{}
	for _, d := range p.Env["PATH"].Dropped {
		dropped[d.Value] = d.Reason
	}
	if r, ok := dropped["/tmp/"]; !ok || r != DropTmpfsOnly {
		t.Errorf(`"/tmp/" (trailing slash, cleans to the tmpfs mountpoint /tmp): dropped=%v `+
			"reason=%v, want present with DropTmpfsOnly, recorded with the trailing slash intact", ok, r)
	}
}

// ── sanitise-D: /proc and /dev magic symlinks (a shadow slot RE-OPENED) ────
//
// REGRESSION (redteam, confirmed 2026-08-10). keepHostElement's Kind-switch
// KEPT KindProc and KindDev, on the argument "kernel- and bwrap-populated, not
// empty" — true of the DIRECTORY, false of what /proc's magic symlinks
// RESOLVE TO. coveringMount is a LEXICAL walk and does not follow them, so it
// stops at /proc (a KindProc mount) while the KERNEL walks
// /proc/self/root/tmp/x/bin all the way to the writable tmpfs, and
// /proc/self/cwd to the target — where the shadow binary also PERSISTS TO THE
// HOST. Reproduced end to end with markers SHADOWED-GIT-RAN-VIA-PROC-ROOT and
// SHADOWED-GIT-VIA-PROC-CWD: a payload that put a file named `git` under the
// (nominally empty, nominally ephemeral) tmpfs shadow slot got it executed
// through /proc/self/root, and a file dropped at /proc/self/cwd/git persisted
// on the host's disk after the sandbox exited.
//
// The fix (env.go, envresolve.go): both kinds now DROP, with a new
// DropPseudoOnly reason distinct from DropTmpfsOnly — the directory really is
// populated, so this is a DIFFERENT untruthfulness than a tmpfs granting an
// empty directory, and a human reading --dry-run should be told which.
//
// STALE AS OF THE #22-ADJACENT ROUTE-A/B FIX: this paragraph used to say "A
// KindSymlink still KEEPs, and the asymmetry is deliberate" — true when
// written, and then the red team found the shadow-slot hole a KindSymlink
// could hide (a PATH entry that is a link to a writable tmpfs), so
// keepHostElement no longer KEEPs a KindSymlink at all: resolveThroughLinks
// now walks THROUGH it and judges the mount it lands on, the same way this
// very fix made /proc and /dev's magic links stop being trusted at face
// value one paragraph up. See TestIsShadowSlotThroughASymlinkToAWritableTmpfs,
// TestIsShadowSlotThroughASymlinkStandingOnWritableGround, and the negative
// control TestIsShadowSlotFalseForASymlinkOnReadOnlyGroundToAReadOnlyTarget,
// below.
//
// The /proc half of the ORIGINAL argument is still right, and is why the two
// cases are not treated alike even now: /proc's magic links are authored by
// the KERNEL and point at whatever the reading process happens to have open,
// which is not a grant at all, so they are refused at the KindProc/KindDev
// arm rather than followed. A KindSymlink IS a grant's own link, pointing
// where that grant says, so resolving it is following the sandbox's own
// topology rather than inventing a second one.
//
// This is the pure table: it builds a Policy by hand (no Resolve, no fake
// host) so it runs everywhere with no privileges, per Layer 1 of the test
// architecture. TestSanitiseResolvesProcSelfCwdOutOfPathAndArgv below is the
// same finding through Resolve and the bwrap argv.
func TestSanitiseDropsProcAndDevMagicSymlinkElements(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/tmp":  {Guest: "/tmp", Kind: KindTmpfs},
		"/proc": {Guest: "/proc", Kind: KindProc},
		"/dev":  {Guest: "/dev", Kind: KindDev},
		"/usr":  {Guest: "/usr", Kind: KindBind, Access: AccessRO},
	}}

	cases := []struct {
		elem       string
		wantKeep   bool
		wantReason EnvDropReason
	}{
		// THE FINDING: /proc's magic symlinks resolve OUT of /proc, to the
		// writable tmpfs and to the target, and a lexical walk cannot see it.
		{"/proc/self/root/tmp/x/bin", false, DropPseudoOnly},
		{"/proc/self/cwd", false, DropPseudoOnly},
		{"/proc/1/root/tmp/x/bin", false, DropPseudoOnly},
		{"/dev/rt/bin", false, DropPseudoOnly},
		// Positive controls. Each pins a DIFFERENT row of the table, so a patch
		// that folds DropPseudoOnly into DropTmpfsOnly (right verdict, wrong
		// reason) or that widens the drop to swallow a real bind is caught here,
		// not just in the shadow-slot test above.
		{"/tmp/x/bin", false, DropTmpfsOnly},
		// filepath.Clean collapses this to /tmp/x/bin before the walk even
		// starts — it was never a second bypass, and the reason must say so:
		// the tmpfs one, not the pseudo-filesystem one.
		{"/usr/../tmp/x/bin", false, DropTmpfsOnly},
		{"/usr/bin", true, DropNoGrant}, // reason is unused when keep is true
	}

	for _, c := range cases {
		keep, reason := p.keepHostElement(c.elem)
		if keep != c.wantKeep {
			t.Errorf("keepHostElement(%q) keep=%v, want %v", c.elem, keep, c.wantKeep)
			continue
		}
		// Assert the REASON, not merely the verdict. "The directory is
		// populated but its magic symlinks leave it" (Pseudo) is a different
		// fact from "the directory is empty" (Tmpfs), and a test that checked
		// only keep would pass on a patch that folded the two together.
		if !keep && reason != c.wantReason {
			t.Errorf("keepHostElement(%q) reason=%v, want %v", c.elem, reason, c.wantReason)
		}
	}
}

// End to end: the same finding, through Resolve and the exact argv bwrap
// executes — not merely the pure predicate above. "not in Entries" and "not in
// the argv" are two separate claims; a struct field the payload never reads
// protects nothing (same discipline as
// TestSanitiseDropsAShadowSlotOnlyATmpfsCovers).
func TestSanitiseResolvesProcSelfCwdOutOfPathAndArgv(t *testing.T) {
	env := newFakeEnv()
	env.env["PATH"] = "/proc/self/cwd:/usr/bin"

	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@cwd-rw", "sanity-path"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	entries := entryValues(p, "PATH")
	if hasEntry(entries, "/proc/self/cwd") {
		t.Errorf("/proc/self/cwd survived sanitise and reached the resolved PATH: it resolves to "+
			"the TARGET, the one writable thing the payload controls, and a file named `git` "+
			"dropped there would run for the next command that uses this PATH entry — entries: %v",
			entries)
	}
	if !hasEntry(entries, "/usr/bin") {
		t.Errorf("/usr/bin (a real bind under @sys) did not survive — the fix must not have "+
			"widened past KindProc/KindDev: entries: %v", entries)
	}

	dropped := map[string]EnvDropReason{}
	for _, d := range p.Env["PATH"].Dropped {
		dropped[d.Value] = d.Reason
	}
	if r, ok := dropped["/proc/self/cwd"]; !ok || r != DropPseudoOnly {
		t.Errorf("/proc/self/cwd: Dropped present=%v reason=%v, want present with DropPseudoOnly", ok, r)
	}

	// THE CLAIM THAT ACTUALLY MATTERS: absence from the --setenv PATH operand
	// bwrap receives, not merely from p.Env.
	operand := pathOperand(t, p)
	for _, part := range strings.Split(operand, ":") {
		if part == "/proc/self/cwd" {
			t.Errorf("--setenv PATH operand %q still names /proc/self/cwd", operand)
		}
	}
	if !strings.Contains(operand, "/usr/bin") {
		t.Errorf("--setenv PATH operand %q lost the granted /usr/bin", operand)
	}
}

// ── sanitise-E: symlinks (Route A/B, the ground-vs-target hole) ─────────────
//
// REGRESSION (redteam, found while fixing issue #22's adjacent sibling).
// IsShadowSlot fell through `default:` on KindSymlink, so a PATH entry that IS
// a symlink to a writable tmpfs carried no `← writable from inside` mark at
// all — Route A. Fixing that by resolving the symlink's TARGET is not enough,
// because a symlink is the one node kind snug emits that is NOT a mountpoint:
// bwrap's --symlink writes a link into whatever filesystem the link's PARENT
// directory is, so if the GROUND under the link is writable the payload can
// `rm` the link and `mkdir` its own directory at that name — Route B, found
// while fixing A, and NOT fixed by resolving the target: the target can be
// read-only and the slot is still live. The fix, resolveThroughLinks, reports
// both: the mount the chain lands on, and whether any hop along the way sits
// on writable ground (`replaceable`).

// buildSymlinkChain constructs n synthetic KindSymlink mounts /link0 ->
// /link1 -> ... -> /link{n-1}, with the last one pointing at /real — a
// KindBind, read-only. It exists for the hop-budget tests, where the only
// thing that varies is the chain LENGTH.
func buildSymlinkChain(n int) *Policy {
	mounts := map[string]Mount{
		"/real": {Guest: "/real", Kind: KindBind, Access: AccessRO},
	}
	target := "/real"
	for i := n - 1; i >= 0; i-- {
		guest := fmt.Sprintf("/link%d", i)
		mounts[guest] = Mount{Guest: guest, Kind: KindSymlink, Host: target}
		target = guest
	}
	return &Policy{Mounts: mounts}
}

// Route A: the PATH entry IS the symlink, its TARGET lands on a writable
// tmpfs, and the GROUND under the link itself is read-only — isolating the
// hole from Route B's. Before the fix, IsShadowSlot's switch had no
// KindSymlink case and fell through `default: return false`, so this carried
// no mark at all.
func TestIsShadowSlotThroughASymlinkToAWritableTmpfs(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/data":      {Guest: "/data", Kind: KindBind, Access: AccessRO}, // ground: read-only
		"/data/bin":  {Guest: "/data/bin", Kind: KindSymlink, Host: "/data/real"},
		"/data/real": {Guest: "/data/real", Kind: KindTmpfs}, // target: writable
	}}
	if !p.IsShadowSlot("/data/bin") {
		t.Fatal("IsShadowSlot(/data/bin) = false; the link resolves to a writable tmpfs " +
			"(/data/real), so a file the payload drops there is exactly the tmpfs shadow-slot " +
			"finding, reached one node later through a link")
	}
}

// Route B: the SAME shape, but with the target and the ground swapped — the
// target is a READ-ONLY bind, and the GROUND under the link is a writable
// tmpfs. Resolving-the-target alone answers false here, because the target
// really is read-only; the discriminator is the ground, not the target.
//
// THIS IS THE ONE THAT FAILS IF SOMEONE "SIMPLIFIES" THE FIX BACK TO
// RESOLVE-THE-TARGET. It was found only because fixing Route A by chasing the
// link to its target and judging THAT mount still left this open: `tmpfs =
// ["/data"]` + `symlink /data/bin -> /usr/bin` measured as WRITE-THROUGH
// refused (EROFS, the target is genuinely read-only) followed by
// REPLACED-THE-LINK-OK (rm /data/bin && mkdir /data/bin) and
// SHADOWED-GIT-RAN-VIA-REPLACED-LINK. If a future change collapses
// resolveThroughLinks back to "return the target mount, done", this test is
// what catches it — TestIsShadowSlotThroughASymlinkToAWritableTmpfs above
// would keep passing.
func TestIsShadowSlotThroughASymlinkStandingOnWritableGround(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/data":     {Guest: "/data", Kind: KindTmpfs}, // ground: writable
		"/data/bin": {Guest: "/data/bin", Kind: KindSymlink, Host: "/usr/bin"},
		"/usr":      {Guest: "/usr", Kind: KindBind, Access: AccessRO}, // target: read-only
	}}
	if !p.IsShadowSlot("/data/bin") {
		t.Fatal("IsShadowSlot(/data/bin) = false; the link stands on a writable tmpfs (/data), " +
			"so the payload can unlink it and create its own directory at that name whatever it " +
			"pointed at — the target being read-only does not save it")
	}
}

// NEGATIVE CONTROL for both of the above, and the one that makes them mean
// something: the identical link, but with NOTHING mounted above it (so it
// sits on the sandbox's own read-only root tmpfs — CLAUDE.md's "the same link
// on the read-only root tmpfs fails rm with EROFS and real git runs") and a
// read-only target. Without this, a predicate that answered true for every
// symlink would pass both tests above.
func TestIsShadowSlotFalseForASymlinkOnReadOnlyGroundToAReadOnlyTarget(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		// No mount at "/", deliberately — nearestCovering stops before / and
		// never returns it (validate.go), which is exactly right here: the
		// sandbox root is snug's own read-only tmpfs, so "no mount found above"
		// and "read-only ground" are the same fact.
		"/databin": {Guest: "/databin", Kind: KindSymlink, Host: "/usr/bin"},
		"/usr":     {Guest: "/usr", Kind: KindBind, Access: AccessRO},
	}}
	if p.IsShadowSlot("/databin") {
		t.Fatal("IsShadowSlot(/databin) = true for a link on read-only ground to a read-only " +
			"target; a predicate that cannot say no here is not discriminating anything")
	}
}

// ── unclean spellings: resolveThroughLinks's INPUT DOMAIN, not an edge case ──
//
// This function is fed host PATH elements verbatim, so a leading "//" or a
// trailing "/" is not a hostile construction — it is an ordinary thing to find
// in $PATH. Before "clean first, every hop" (envresolve.go's
// resolveThroughLinks doc comment), the walk cleaned cur for the coveringMount
// LOOKUP but trimmed the symlink's prefix from the UNCLEANED cur, so the two
// disagreed the moment a spelling was not already canonical.
//
// The measured flip, reproduced here structurally: with a symlink
// `/data/bin -> /t` (a writable tmpfs) and a REAL grant that happens to sit at
// the path the concatenation bug produces, `/t/data/bin` (a read-only bind),
// the clean spelling `/data/bin` resolved to `/t` — correctly DROPPED
// (DropTmpfsOnly) and a live shadow slot. `//data/bin` computed
// TrimPrefix("//data/bin", "/data/bin") = "//data/bin" UNCHANGED (it is not a
// literal prefix of itself once doubled), so the walk built
// filepath.Join("/t", "//data/bin") = "/t/data/bin" — landing on the REAL
// bind instead, an outright verdict flip in the FAIL-OPEN direction: KEPT,
// and shipped as literally "//data/bin" in the --setenv PATH operand bwrap
// received.
func symlinkSpellingFixture() *Policy {
	return &Policy{Mounts: map[string]Mount{
		// The correct target of the symlink: a writable tmpfs, so the clean
		// spelling is both DROPPED (DropTmpfsOnly) and a live shadow slot.
		"/t": {Guest: "/t", Kind: KindTmpfs},
		// The WRONG target the concatenation bug produced for an unclean
		// spelling — a real, granted, read-only bind. If an unclean spelling
		// lands here instead of on /t, it survives sanitise and reads as "not
		// a shadow slot": the fail-open direction.
		"/t/data/bin": {Guest: "/t/data/bin", Kind: KindBind, Access: AccessRO},
		"/data/bin":   {Guest: "/data/bin", Kind: KindSymlink, Host: "/t"},
	}}
}

// TestResolveThroughLinksCleansEveryUncleanSpellingTheSameWay is the pure
// form: three spellings of the SAME path must resolve to the SAME mount, the
// same `keepHostElement` verdict, and the same `IsShadowSlot` answer. The
// clean spelling is included as its own row, not just as a reference value
// computed once — the point being pinned is that all three routes to the
// walk agree, not that two happen to match a value derived from a third.
func TestResolveThroughLinksCleansEveryUncleanSpellingTheSameWay(t *testing.T) {
	cases := []struct {
		name    string
		spelled string
	}{
		{"clean", "/data/bin"},
		{"doubled_leading_slash", "//data/bin"},
		{"trailing_slash", "/data/bin/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := symlinkSpellingFixture()

			final, replaceable, ok := p.resolveThroughLinks(tc.spelled)
			if !ok || final.Guest != "/t" {
				t.Errorf("resolveThroughLinks(%q) landed on %+v (ok=%v), want the tmpfs at /t — "+
					"a value of /t/data/bin here means the walk fell into the concatenation bug",
					tc.spelled, final, ok)
			}
			if replaceable {
				t.Errorf("resolveThroughLinks(%q) replaceable=true; the ground under /data/bin "+
					"(the root tmpfs) has no mount above it, so this must be false", tc.spelled)
			}

			if keep, reason := p.keepHostElement(tc.spelled); keep || reason != DropTmpfsOnly {
				t.Errorf("keepHostElement(%q) = (%v, %v), want (false, DropTmpfsOnly)",
					tc.spelled, keep, reason)
			}
			if !p.IsShadowSlot(tc.spelled) {
				t.Errorf("IsShadowSlot(%q) = false, want true — it resolves to the writable /t "+
					"tmpfs same as the clean spelling does", tc.spelled)
			}
		})
	}
}

// TestSanitiseRecordsTheUncleanSpellingVerbatimNotCleaned is the end-to-end
// form, through Resolve and the exact --setenv PATH operand, and it asserts
// TWO things that must both hold: the unclean spelling is dropped (not just
// that SOME spelling of the path is), and — DROP-NEVER-REWRITE — the
// Dropped.Value recorded is the host's ORIGINAL "//data/bin", never the
// cleaned "/data/bin". Cleaning decides the verdict only; sanitiseHostList's
// own contract is to record and emit the element exactly as the host spelled
// it, and a fix that cleaned the RECORDED value as a side effect would pass
// every other assertion in this file while quietly violating that contract.
func TestSanitiseRecordsTheUncleanSpellingVerbatimNotCleaned(t *testing.T) {
	reg := testRegistry()
	reg["uncleanshadow"] = &Profile{
		Name:    "uncleanshadow",
		Tmpfs:   []string{"/t"},
		RO:      []string{"/opt/tools/bin:/t/data/bin"},
		Symlink: []Symlink{{At: "/data/bin", Target: "/t"}},
		Environ: EnvGrants{Sanitise: []string{"PATH"}},
	}

	env := newFakeEnv()
	env.env["PATH"] = "//data/bin:/opt/tools/bin"

	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "uncleanshadow"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	entries := entryValues(p, "PATH")
	if hasEntry(entries, "//data/bin") || hasEntry(entries, "/data/bin") {
		t.Errorf("a spelling of the shadow slot survived sanitise: entries=%v", entries)
	}
	if !hasEntry(entries, "/opt/tools/bin") {
		t.Errorf("/opt/tools/bin (a real ro bind, the fixture's positive control) did not "+
			"survive: entries=%v", entries)
	}

	found := false
	for _, d := range p.Env["PATH"].Dropped {
		if d.Value == "//data/bin" {
			found = true
			if d.Reason != DropTmpfsOnly {
				t.Errorf("Dropped entry for //data/bin has reason %v, want DropTmpfsOnly", d.Reason)
			}
		}
		if d.Value == "/data/bin" {
			t.Errorf("Dropped entry recorded the CLEANED spelling /data/bin instead of the "+
				"host's original //data/bin — DROP-NEVER-REWRITE says the recorded value is "+
				"always what the host wrote, and cleaning must only ever decide the verdict: %+v", d)
		}
	}
	if !found {
		t.Errorf("no Dropped entry names //data/bin verbatim; Dropped=%v", p.Env["PATH"].Dropped)
	}

	// THE CLAIM THAT ACTUALLY MATTERS: absence from the --setenv PATH operand
	// bwrap receives, in the EXACT unclean spelling the host used — the
	// original finding shipped literally "//data/bin" in the argv.
	operand := pathOperand(t, p)
	if strings.Contains(operand, "//data/bin") {
		t.Errorf("--setenv PATH operand %q still names //data/bin verbatim", operand)
	}
	if !strings.Contains(operand, "/opt/tools/bin") {
		t.Errorf("--setenv PATH operand %q lost the granted /opt/tools/bin", operand)
	}
}

// The hop budget, at its exact boundary. A chain of maxGuestLinkHops symlinks
// followed by a real mount must still resolve; one more must not. This is not
// an off-by-one nicety: a budget that is one hop too SHORT silently turns a
// legitimate (if unusual) profile's PATH entry into DropNoGrant, and one that
// is unbounded is what makes the cycle test below meaningful to have at all.
func TestResolveThroughLinksHopBudgetBoundary(t *testing.T) {
	within := buildSymlinkChain(maxGuestLinkHops)
	m, _, ok := within.resolveThroughLinks("/link0")
	if !ok || m.Guest != "/real" {
		t.Errorf("a chain of exactly maxGuestLinkHops (%d) symlinks did not resolve: "+
			"final=%+v ok=%v", maxGuestLinkHops, m, ok)
	}

	tooLong := buildSymlinkChain(maxGuestLinkHops + 1)
	if _, _, ok := tooLong.resolveThroughLinks("/link0"); ok {
		t.Errorf("a chain of maxGuestLinkHops+1 (%d) symlinks resolved; the budget did not bound it",
			maxGuestLinkHops+1)
	}
}

// A dangling link — nothing mounted at the end of the chain at all — must
// resolve to "not found", the same as a host PATH element nothing grants.
// keepHostElement and IsShadowSlot must not disagree about a path neither can
// see: one drops it, the other must not mark it.
func TestResolveThroughLinksDanglingTarget(t *testing.T) {
	// Dangling AND standing on WRITABLE ground: `replaceable` wins outright, so
	// the recorded reason must be DropReplaceable, not DropNoGrant — the ground
	// is what makes this dangerous, and the target need not even exist for that
	// to be true. (Before the implementer's replaceable-in-keepHostElement fix,
	// this arm read DropNoGrant; the review that produced this test caught the
	// live hole that fix closes, so this case now pins the CORRECTED reason
	// rather than the one keepHostElement used to give.)
	writable := &Policy{Mounts: map[string]Mount{
		"/data": {Guest: "/data", Kind: KindTmpfs},
		"/data/bin": {Guest: "/data/bin", Kind: KindSymlink,
			Host: "/nowhere/at/all"},
	}}
	if _, _, ok := writable.resolveThroughLinks("/data/bin"); ok {
		t.Error("resolveThroughLinks resolved a link to a target nothing grants")
	}
	if keep, reason := writable.keepHostElement("/data/bin"); keep || reason != DropReplaceable {
		t.Errorf("keepHostElement(/data/bin) = (%v, %v), want (false, DropReplaceable) — the link "+
			"stands on writable ground, which must dominate even though the target does not "+
			"resolve to anything", keep, reason)
	}
	// The link still stands on a writable tmpfs, so it is a live shadow slot
	// EVEN THOUGH nothing can be reached through it — the payload does not
	// need the link to resolve anywhere to `rm` and `mkdir` over it.
	if !writable.IsShadowSlot("/data/bin") {
		t.Error("IsShadowSlot(/data/bin) = false for a dangling link standing on writable ground; " +
			"the target need not exist for the ground to matter")
	}

	// NEGATIVE CONTROL, and what isolates DropNoGrant as its own reason: the
	// IDENTICAL dangling link, but on READ-ONLY ground. Without this, the case
	// above cannot tell "replaceable dominates" from "a dangling link is always
	// DropReplaceable regardless of the ground".
	readonly := &Policy{Mounts: map[string]Mount{
		"/data":     {Guest: "/data", Kind: KindBind, Access: AccessRO},
		"/data/bin": {Guest: "/data/bin", Kind: KindSymlink, Host: "/nowhere/at/all"},
	}}
	if keep, reason := readonly.keepHostElement("/data/bin"); keep || reason != DropNoGrant {
		t.Errorf("keepHostElement(/data/bin) = (%v, %v), want (false, DropNoGrant) for a dangling "+
			"link on READ-ONLY ground — with replaceable out of the picture, this is the ordinary "+
			"'nothing grants that path' case", keep, reason)
	}
	if readonly.IsShadowSlot("/data/bin") {
		t.Error("IsShadowSlot(/data/bin) = true for a dangling link on read-only ground")
	}
}

// A CYCLE must terminate — the whole reason the budget is a counter and not a
// visited-set (envresolve.go's comment on maxGuestLinkHops) — and must do so
// within bounded real time, not merely within a bounded number of iterations
// that a future refactor could turn into something else. This is the
// concrete form of "--dry-run does not hang": IsShadowSlot and
// keepHostElement are both called once per rendered PATH entry.
func TestResolveThroughLinksCycleTerminates(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/a": {Guest: "/a", Kind: KindSymlink, Host: "/b"},
		"/b": {Guest: "/b", Kind: KindSymlink, Host: "/a"},
	}}

	done := make(chan struct{})
	var ok bool
	go func() {
		_, _, ok = p.resolveThroughLinks("/a")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("resolveThroughLinks did not return within 2s on a two-node symlink cycle — " +
			"the hop budget is not bounding it")
	}
	if ok {
		t.Error("resolveThroughLinks reported ok=true for a cycle that never lands on a real mount")
	}

	// A cycle is also inert for the shadow-slot question: it never lands
	// anywhere, and neither /a nor /b is a mount with content of its own.
	if p.IsShadowSlot("/a") {
		t.Error("IsShadowSlot(/a) = true for an unresolvable cycle with no writable ground on the way")
	}
}

// The reachability argument the design leans on: a symlink CYCLE combined
// with a PATH merge naming a node in it is refused by the grant-coupling
// check (§2.5, envcoupling.go) before Resolve ever builds a mount the runtime
// walk in resolveThroughLinks would have to chase. Measured through the CLI
// (`snug --dry-run`) as exit 77 in 13ms; pinned here at the Resolve layer so
// the claim "you cannot get a live cycle into a resolved policy's PATH via a
// profile" does not quietly stop holding as the coupling check is refactored.
func TestACyclicSymlinkNamedOnPathIsRefusedByCouplingBeforeItCanResolve(t *testing.T) {
	reg := testRegistry()
	reg["cyclic"] = &Profile{
		Name:    "cyclic",
		Symlink: []Symlink{{At: "/a", Target: "/b"}, {At: "/b", Target: "/a"}},
		Environ: EnvGrants{Merge: map[string][]string{"PATH": {"/a"}}},
	}

	done := make(chan error, 1)
	go func() {
		_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "cyclic"}, testCtx(), newFakeEnv())
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Resolve did not return within 2s on a profile naming a symlink cycle on PATH")
	}
	if err == nil {
		t.Fatal("a profile merging PATH=/a, where /a is one leg of a symlink cycle neither leg " +
			"of which the profile otherwise grants, was accepted")
	}
	if !strings.Contains(err.Error(), "which it does not grant") {
		t.Errorf("refused, but not by the coupling check (wrong message): %v", err)
	}
}

// End to end, through Resolve and the exact --setenv PATH operand: the
// coordinator's reproduction of the LIVE Route-B hole — not the earlier
// version of this test, which named a dangling target and so passed for a
// different reason than it claimed.
//
// THIS TEST'S OWN HISTORY IS THE LESSON. The first version pointed the link
// at `/nonexistent`, so the element was dropped by the DANGLING-TARGET arm
// (nothing mounted at the far end -> DropNoGrant) and the assertion "the
// symlink spelling is dropped" passed without `replaceable` — the fact that
// the link stands on writable ground — ever being consulted. The review found
// that keepHostElement DISCARDS replaceable (`m, _, ok :=
// resolveThroughLinks(guest)`) and switches only on the landing mount's Kind,
// so a link on writable ground to a GRANTED, READ-ONLY target — the shape
// CLAUDE.md's "generate, don't bind" reasoning and IsShadowSlot both already
// treat as a live shadow slot — is KEPT and reaches the argv. That is snug
// handing over the slot pre-installed, which is the serious half of this
// finding: IsShadowSlot(/data/bin) says true, and the sandbox gets it on PATH
// anyway.
//
// So the target here is deliberately NOT dangling: /opt/tools/bin is granted,
// read-only, and real — the dangling arm cannot fire, and the only thing that
// can make /data/bin drop is the ground under it being writable.
func TestSanitiseDropsASymlinkSpellingOfAShadowSlot(t *testing.T) {
	reg := testRegistry()
	reg["symlinkshadow"] = &Profile{
		Name:  "symlinkshadow",
		RO:    []string{"/opt/tools/bin"},
		Tmpfs: []string{"/data"},
		// The link stands on /data (writable), and points at a REAL, GRANTED,
		// READ-ONLY target — so resolveThroughLinks lands on a genuine KindBind
		// and only `replaceable` (the writable ground) can be what drops this.
		Symlink: []Symlink{{At: "/data/bin", Target: "/opt/tools/bin"}},
		Environ: EnvGrants{Sanitise: []string{"PATH"}},
	}

	env := newFakeEnv()
	env.env["PATH"] = "/data/bin:/opt/tools/bin:/nowhere"

	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "symlinkshadow"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	// THE CLAIM THAT ACTUALLY MATTERS: absence from the --setenv PATH operand
	// bwrap receives, not merely from p.Env — a struct field the payload never
	// reads protects nothing.
	operand := pathOperand(t, p)
	for _, part := range strings.Split(operand, ":") {
		if part == "/data/bin" {
			t.Errorf("--setenv PATH operand %q names /data/bin — a symlink standing on the "+
				"writable /data tmpfs, pointing at a real read-only grant. keepHostElement kept it "+
				"because it discards `replaceable` and judges only the mount the link resolves TO; "+
				"the payload can `rm /data/bin && mkdir /data/bin` and own that name on PATH "+
				"regardless of what it used to point at", operand)
		}
	}
	if !strings.Contains(operand, "/opt/tools/bin") {
		t.Errorf("--setenv PATH operand %q lost the granted /opt/tools/bin — the fix must not "+
			"widen past the symlink case and start dropping real grants too", operand)
	}

	entries := entryValues(p, "PATH")
	if hasEntry(entries, "/data/bin") {
		t.Errorf("/data/bin survived sanitise into p.Env, not just the argv: entries=%v", entries)
	}

	// IsShadowSlot must already agree that this is a slot — if this assertion
	// fails, the fixture is not exercising Route B at all, and the operand
	// check above is not exercising `replaceable` either.
	if !p.IsShadowSlot("/data/bin") {
		t.Fatal("control: IsShadowSlot(/data/bin) = false; the fixture is not standing the link " +
			"on writable ground, so a keepHostElement fix that consults `replaceable` would have " +
			"nothing to catch here")
	}
}

// ── dedup ────────────────────────────────────────────────────────────────────

// §4.6(c), measured on main: `path = ["/nonexistent/bin", "/bin"]` resolved to
// /bin:/nonexistent/bin:/usr/bin:/bin:/usr/sbin:/sbin — /bin twice, once from
// the profile and once from the base. A duplicated entry means the rendered
// value depends on how many profiles happened to name a directory, which is a
// fold artifact and not a decision anybody made.
func TestDuplicateEntriesCollapseToTheEarliestBand(t *testing.T) {
	p := mustResolve(t, "@sys", "@cwd-rw", "dupe-path")

	path, _ := p.EnvValue("PATH")
	if n := strings.Count(":"+path+":", ":/usr/bin:"); n != 1 {
		t.Errorf("PATH = %q contains /usr/bin %d times, want exactly 1", path, n)
	}
	// And the survivor is the PROFILE's entry, not the base's: the earliest
	// band wins, which is what makes prepend's guarantee literally true.
	if got := p.Env["PATH"].Entries[0]; got.Value != "/usr/bin" || got.Verb != VerbMerge {
		t.Errorf("first entry = %+v, want /usr/bin from the merge band", got)
	}
	// CONTROL: the rest of the base survives, so the assertion above is not
	// passing because dedup ate everything.
	for _, want := range []string{"/bin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(":"+path+":", ":"+want+":") {
			t.Errorf("PATH = %q lost the base entry %q", path, want)
		}
	}
}

// ── conflicts ────────────────────────────────────────────────────────────────

func TestSecondPrependIsRefused(t *testing.T) {
	err := refusalTwoPrepends(t)
	if err == nil {
		t.Fatal("two profiles both took the front of PATH; only one may hold it")
	}
	for _, want := range []string{"mytools", "othertools", "/opt/bin", "/srv/bin", "environ.merge"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: identical claims AGREE. Two profiles naming the same
	// directory do not disagree about who is first, and the resolved policy is
	// byte-identical either way — refusing that would refuse a non-conflict.
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", RO: []string{"/opt/bin"},
		Environ: EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/bin"}}}}
	reg["b"] = &Profile{Name: "b", RO: []string{"/opt/bin"},
		Environ: EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/bin"}}}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "a", "b"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: two profiles prepending the SAME value must agree: %v", err)
	}
	if got := p.Env["PATH"].Entries[0]; got.Value != "/opt/bin" || strings.Join(got.From, "+") != "a+b" {
		t.Errorf("agreeing prepends = %+v, want one entry credited to both profiles", got)
	}
}

// Equality is over the WHOLE ORDERED SEQUENCE, so two profiles naming the same
// directories in different orders still disagree about order and still fail.
func TestPrependOrderDisagreementIsRefused(t *testing.T) {
	err := refusalPrependOrder(t)
	if err == nil {
		t.Fatal("two profiles prepending the same directories in different orders were " +
			"silently resolved; the whole point of prepend is which one is first")
	}
	for _, want := range []string{"ordera", "orderb"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// Two prepends that differ ONLY in where the element boundaries fall are a
// disagreement, and the key that decides must be able to see the difference.
//
// checkPrependAgreement keyed on `strings.Join(values, " ")`, directly under a
// doc comment saying equality is over the whole ordered sequence. A space-join
// is injective only if no element contains a space, and an absolute path may:
//
//	-p qtools              one element, "/srv/a /srv/b"
//	-p ptools              two elements, "/srv/a" and "/srv/b"
//	-p ptools -p qtools    keys equal -> "they agree" -> qtools' entry deleted,
//	                       exit 0, nothing on the screen
//
// A profile removing what another profile put on PATH is the property this file
// opens by promising. The effect here is a MISSING entry rather than an extra
// one, so it is a tightening rather than an escalation — but a silent deletion
// resting on a coincidence about spaces is not a thing to leave in place.
func TestPrependsDifferingOnlyInElementBoundariesDisagree(t *testing.T) {
	reg := testRegistry()
	// ptools wants two elements; qtools wants ONE element that happens to
	// contain a space — and /opt/a b is a real directory on the fake host, so
	// both profiles grant every path they name and the coupling rule is happy.
	reg["ptools"] = &Profile{Name: "ptools", RO: []string{"/opt/a", "/opt/b"},
		Environ: EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/a", "/opt/b"}}}}
	reg["qtools"] = &Profile{Name: "qtools", RO: []string{"/opt/a b"},
		Environ: EnvGrants{Prepend: map[string][]string{"PATH": {"/opt/a b"}}}}

	_, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "ptools", "qtools"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("two profiles prepending DIFFERENT sequences resolved silently: one wants two " +
			"elements, the other wants one element containing a space. They cannot both be " +
			"first, and one of them just lost an entry without a word")
	}
	// Commutative, like every other refusal here: the verdict may not depend on
	// selection order, or the same pair passes review one way round and fails the
	// other.
	if _, err2 := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "qtools", "ptools"}, testCtx(), newFakeEnv()); err2 == nil {
		t.Error("refused in one selection order and accepted in the other")
	}

	// POSITIVE CONTROL, and it is the whole point of the fix: the two spellings
	// must still be distinguishable, so a profile prepending the one-element
	// version ALONE is perfectly legal. A key that refused everything would pass
	// the assertion above.
	delete(reg, "ptools")
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "qtools"}, testCtx(), newFakeEnv()); err != nil {
		t.Errorf("one profile prepending a single element containing a space was refused: %v", err)
	}
}

func TestConflictingScalarSetsAreRefused(t *testing.T) {
	err := refusalTwoSets(t)
	if err == nil {
		t.Fatal("two profiles set one scalar to different values and one of them was " +
			"silently discarded")
	}
	for _, want := range []string{"seta", "setb", "vim", "emacs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: the same value from two profiles is fine.
	// Independently-authored duplication is plausible and harmless.
	reg := testRegistry()
	// Each profile DECLARES the name it writes: a declaration is a licence for
	// one profile's own use, and it deliberately does not travel — so "both
	// profiles say the same thing" here means both of them, separately, took
	// responsibility for an unrostered name and then agreed about its value.
	reg["a"] = &Profile{Name: "a", Environ: EnvGrants{
		Declare: []string{"MY_MODE"}, Set: map[string]string{"MY_MODE": "fast"}}}
	reg["b"] = &Profile{Name: "b", Environ: EnvGrants{
		Declare: []string{"MY_MODE"}, Set: map[string]string{"MY_MODE": "fast"}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "a", "b"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: two profiles agreeing on a scalar must join, not conflict: %v", err)
	}
}

// CALL 2: `set` and `inherit` on one scalar name are one slot, not two.
// "set beats inherit" would be a priority field wearing a verb's clothes, which
// the model does not have — so they join the rule `set` already follows.
func TestSetAndInheritOnOneScalarMustAgree(t *testing.T) {
	err := refusalSetVsInherit(t)
	if err == nil {
		t.Fatal("a profile's `set` and another's `inherit` disagreed about one scalar and " +
			"snug picked one; there is no priority between verbs")
	}
	for _, want := range []string{"emacsy", "envy", "environ.set", "environ.inherit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: agreeing claims resolve, and BOTH profiles are credited
	// — `setty` sets EDITOR=vim, `envy` inherits the fake host's EDITOR=vim.
	p := mustResolve(t, "@sys", "@cwd-rw", "setty", "envy")
	if v, _ := p.EnvValue("EDITOR"); v != "vim" {
		t.Errorf("EDITOR = %q, want vim", v)
	}
	if got := entryVerbs(p, "EDITOR"); strings.Join(got, " ") != "set inherit" {
		t.Errorf("EDITOR entries = %v, want both claims recorded — a human reading "+
			"--dry-run should see that two profiles asked for this", got)
	}

	// And an inherit of a name the host does not have contributes nothing, so it
	// can never take part in a conflict.
	env := newFakeEnv()
	delete(env.env, "EDITOR")
	reg := testRegistry()
	reg["emacsy"] = &Profile{Name: "emacsy", Environ: EnvGrants{Set: map[string]string{"EDITOR": "emacs"}}}
	q, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "emacsy", "envy"}, testCtx(), env)
	if err != nil {
		t.Fatalf("an inherit of a name the host does not have must contribute nothing, not "+
			"conflict: %v", err)
	}
	if v, _ := q.EnvValue("EDITOR"); v != "emacs" {
		t.Errorf("EDITOR = %q, want emacs", v)
	}
}

// ── monotonicity, both halves ────────────────────────────────────────────────

// The ENTRY SET of a list variable is monotone: adding a profile can only add
// entries. sanitise's predicate is "is this path granted", and grants only ever
// grow, so adding a profile can only make MORE host elements survive.
func TestEnvIsMonotoneAsASet(t *testing.T) {
	base := []ProfileName{"@sys", "@cwd-rw"}
	basePol := mustResolve(t, base...)

	for name := range testRegistry() {
		with, err := Resolve(testRegistry(), append(append([]ProfileName{}, base...), name), testCtx(), newFakeEnv())
		if err != nil {
			continue // a conflict is a symmetric error, not a tightening
		}
		for varName, was := range basePol.Env {
			now, ok := with.Env[varName]
			if !ok {
				t.Errorf("adding %q REMOVED the variable %s entirely", name, varName)
				continue
			}
			have := map[string]bool{}
			for _, e := range now.Entries {
				have[e.Value] = true
			}
			for _, e := range was.Entries {
				// snug's OWN entries are exempt, and the exemption is the same
				// one Mount.Authored carries: SNUG_PROFILES legitimately changes
				// when a profile is added, because reporting the selection is
				// its entire job. What must only ever grow is what PROFILES
				// contributed.
				if e.Verb == VerbSnug {
					continue
				}
				if !have[e.Value] {
					t.Errorf("adding %q REMOVED the %s entry %q — the entry set must only grow",
						name, varName, e.Value)
				}
			}
		}
	}
}

// ...and the ORDER is not monotone, which is the half the test above must not
// be read as covering.
//
// A prepend pushes another profile's merged entry one place later. That is a
// tightening of precedence rather than an escalation — the same shape CLAUDE.md
// already carves out for mount depth — but it has to be said out loud, and this
// test is where it is said.
func TestPrependReordersWithoutRemoving(t *testing.T) {
	without := mustResolve(t, "@sys", "@cwd-rw", "envy")
	with := mustResolve(t, "@sys", "@cwd-rw", "envy", "firsty")

	if entryValues(without, "PATH")[0] != "/opt/tools/bin" {
		t.Fatalf("control: without the prepend, envy's merged entry is first: %v",
			entryValues(without, "PATH"))
	}
	got := entryValues(with, "PATH")
	if got[0] != "/opt/first/bin" {
		t.Errorf("PATH = %v, want the prepended entry first", got)
	}
	// The demoted entry is still THERE — that is the monotone half.
	found := false
	for _, v := range got {
		if v == "/opt/tools/bin" {
			found = true
		}
	}
	if !found {
		t.Error("adding a prepend removed another profile's entry; only its POSITION may move")
	}
}
