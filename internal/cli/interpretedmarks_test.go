package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── the review artifact for the disclosure marks (issues #169/#170) ─────────
//
// --dry-run's FILESYSTEM block and `snug profile show` now say something
// about a grant that names a command table or a credential — see
// internal/policy/interpretedpaths.go for the catalogue and
// internal/policy/testdata/interpreted-paths.txt for every mark shape a row
// can render. These tests pin the same marks reaching the two SCREENS a human
// actually reads, driven through the real commands (dryRun, profileCmd), not
// a re-implementation of their rendering.

// interpretedMarksFixtureDirs are the extra fake host paths the "marks"
// fixture profile below needs to exist for its RO grants to resolve. Added on
// top of newEnvFakeEnv's own dirs (envgolden_test.go), which already carries
// the fixture home/target and @sys's non-optional /etc entries — irrelevant
// here since this fixture selects no builtin, but harmless to inherit.
func interpretedMarksFixtureDirs() []string {
	return []string{
		"/host/etc-ancestor",
		"/host/gitconfig-src",
		"/host/managed-settings-src",
		"/host/usr-src",
		"/host/usr-share-src",
		"/home/u/.npmrc",
		"/home/u/.netrc",
		"/home/u/.ssh",
	}
}

// interpretedMarksFixtureProfile is the one synthetic profile exercising
// every mark shape issues #169/#170 define, in a single resolved policy:
//
//   - /etc/gitconfig, /etc/claude-code/managed-settings.json: guest-exact
//     hits on two DIFFERENT system rows (template A, one with a long Reads
//     clause, one without empty Reads).
//   - {home}/.npmrc: guest-exact hit on a home row (template A, Reads empty).
//   - {home}/.netrc: guest-exact hit on a home row (template B, credential).
//   - {home}/.ssh:/opt/keys: the GUEST side (/opt/keys) matches nothing, so
//     only the HOST side (~/.ssh) fires — template C.
//   - /etc, as its own ancestor grant of the same 17 system rows two of the
//     bullets above also grant exactly: this deliberately does NOT trigger
//     replacement suppression (nothing here is a KindData mount), so the
//     collapsed ancestor line (template D) appears ALONGSIDE the two exact
//     hits above rather than instead of them — both are real, independent
//     mounts, and PolicyInterpretedMarks computes marks per mount.
//   - /usr, /usr/share: both broad grants that must render NO mark — /usr
//     because BroadHostTrees suppresses the ancestor direction there, /usr/share
//     because nothing is catalogued underneath it at all. Different reasons,
//     same silence, which is the point of carrying both.
//   - a symlink at {home}/.bashrc (a home row) rather than at a system row:
//     the spec's example symlinks a system row (/etc/gitconfig), but that
//     guest path already carries a BIND above, and a symlink and a bind
//     cannot share one guest path (Policy.join refuses the kind conflict).
//     A home row demonstrates the exact same thing (KindSymlink -> guest-side
//     classification only, template A) without colliding with the bind demo.
//
// The profile grants neither the target nor a target-covering path, so
// Resolve returns a REFUSED policy (Validate's "target is not visible"
// check) — irrelevant here: Resolve returns the policy anyway (its own
// documented contract), dryRun renders a refused policy exactly like a
// runnable one, and every helper below extracts only the FILESYSTEM block.
func interpretedMarksFixtureProfile() *policy.Profile {
	return &policy.Profile{
		Name: "marks",
		RO: []string{
			"/host/etc-ancestor:/etc",
			"/host/gitconfig-src:/etc/gitconfig",
			"/host/managed-settings-src:/etc/claude-code/managed-settings.json",
			"{home}/.npmrc",
			"{home}/.netrc",
			"{home}/.ssh:/opt/keys",
			"/host/usr-src:/usr",
			"/host/usr-share-src:/usr/share",
		},
		Symlink: []policy.Symlink{
			{At: "{home}/.bashrc", Target: "/wherever"},
		},
	}
}

// interpretedMarksFixture resolves interpretedMarksFixtureProfile against the
// deterministic fake host envgolden_test.go already defines, at the same
// fixed Home/Target envGoldenCtx() uses, so this golden — like env.*.txt — is
// stable across machines and does not depend on the real filesystem.
func interpretedMarksFixture(t *testing.T) *policy.Policy {
	t.Helper()
	env := newEnvFakeEnv()
	for _, d := range interpretedMarksFixtureDirs() {
		env.dirs[d] = true
	}
	reg := map[policy.ProfileName]*policy.Profile{
		"marks": interpretedMarksFixtureProfile(),
	}
	p, err := policy.Resolve(reg, []policy.ProfileName{"marks"}, envGoldenCtx(), env)
	if p == nil {
		t.Fatalf("Resolve returned no policy at all: %v", err)
	}
	return p
}

// filesystemBlock extracts --dry-run's FILESYSTEM block (header through the
// "ro-/" summary line) out of a full dryRun capture, so these goldens pin
// only the section the marks land in rather than the whole screen — TARGET,
// HOME, PROFILES and everything below ENVIRONMENT are somebody else's golden
// (env.*.txt, show.*.txt) and would just be noise here.
func filesystemBlock(t *testing.T, got string) string {
	t.Helper()
	start := strings.Index(got, "FILESYSTEM")
	if start < 0 {
		t.Fatalf("no FILESYSTEM block in dry-run output:\n%s", got)
	}
	rest := got[start:]
	end := strings.Index(rest, "\n\n  NOT GRANTED")
	if end < 0 {
		t.Fatalf("no NOT GRANTED block follows FILESYSTEM, so the slice boundary is wrong:\n%s", got)
	}
	return rest[:end]
}

// flattenWrapped undoes wrapMark's word-wrapping for the purpose of a
// substring search: it trims every line and joins them with a single space,
// which reconstructs the original sentence exactly because wrapMark only
// ever breaks BETWEEN words, never inside one. Used only for "does this
// phrase appear" assertions — the golden itself is written from the
// UNFLATTENED block, since the exact wrapping is part of what a human
// reviews.
func flattenWrapped(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.Join(lines, " ")
}

func writeGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
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
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s changed — a diff here is a change to what a human is told about the sandbox "+
			"before they trust it.\n--- got\n%s\n--- want\n%s", name, got, string(want))
	}
}

// TestFilesystemBlockMarksAnInterpretedGrant is §9 test 13: the FILESYSTEM
// block must render every mark shape the fixture above sets up, each with
// its own positive control naming the shape it proves.
func TestFilesystemBlockMarksAnInterpretedGrant(t *testing.T) {
	p := interpretedMarksFixture(t)
	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, fmt.Errorf("fixture is refused on purpose")) })
	block := filesystemBlock(t, got)
	flat := flattenWrapped(block)

	for _, tc := range []struct{ shape, want string }{
		{"A, system row, Reads populated (git)", "COMMAND TABLE: git reads this as its system config"},
		{"A, system row, Reads populated (claude managed settings)", "COMMAND TABLE: claude reads this as managed (enterprise) settings"},
		{"A, home row, Reads empty (npm)", "COMMAND TABLE: npm reads this. Read-only SUPPLIES registry auth tokens"},
		{"B, home row, Reads empty (netrc)", "CREDENTIAL PATH: curl (and anything else honouring .netrc) reads this; whatever is here"},
		{"C, host-side (ssh)", "the host's ~/.ssh is exposed inside - CREDENTIAL: private keys"},
		{"D, ancestor collapse (/etc, 17 rows)", "17 paths SUPPLIED (17 command tables, 0 credentials)"},
		{"A, via KindSymlink (bashrc)", "COMMAND TABLE: bash reads this. Read-only SUPPLIES runs on every shell"},
	} {
		// Compared against the FLATTENED block: wrapMark breaks a long mark
		// across several physical lines (each indented, per markIndent), so a
		// literal strings.Contains against the raw block would fail on a
		// phrase that happens to straddle a wrap — flattenWrapped rejoins
		// exactly that, and only that, since wrapMark never splits a word.
		if !strings.Contains(flat, tc.want) {
			t.Errorf("shape %s: expected %q in the FILESYSTEM block, found nothing:\n%s",
				tc.shape, tc.want, block)
		}
	}

	// The two NEGATIVE directions, and they are negative for DIFFERENT
	// reasons — see the fixture's own doc comment. Asserted by TOTAL mark
	// count rather than by string absence, so a stray substring match cannot
	// hide a real mark that fired for the wrong path.
	if n := strings.Count(block, "←"); n != 7 {
		t.Errorf("the FILESYSTEM block carries %d marks, want exactly 7 (2 system A + 1 home A + "+
			"1 home B + 1 host C + 1 ancestor D + 1 symlink A) — /usr and /usr/share must both "+
			"stay silent:\n%s", n, block)
	}

	// POSITIVE CONTROL for the count above: the block actually rendered the
	// two silent grants, so their absence from the mark count is not because
	// they never reached the screen at all.
	for _, want := range []string{"/usr", "/usr/share"} {
		if !strings.Contains(block, want) {
			t.Fatalf("control: the %s grant itself never reached the FILESYSTEM block, so its "+
				"silence proves nothing:\n%s", want, block)
		}
	}

	writeGolden(t, "filesystem.marks.txt", block)
}

// TestFilesystemBlockIsQuietOnTheDefaultSelection is §9 test 14, and the
// quiet control CLAUDE.md's own working agreement asks for: with the shipped
// defaults (no user profile involved at all), the FILESYSTEM block must
// render ZERO interpreted marks. The design's own claim — "no builtin
// matches the table" — is BECAUSE /usr and /opt sit in BroadHostTrees and
// /etc/containers is a named exclusion; this is the golden that would show a
// regression of that claim as a diff.
func TestFilesystemBlockIsQuietOnTheDefaultSelection(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", profile.BuiltinDefaults(), err)
	}

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })
	block := filesystemBlock(t, got)

	// POSITIVE CONTROL: the block actually rendered real content, so the
	// absence of a mark is not because nothing rendered at all.
	if !strings.Contains(block, "ro     /usr") {
		t.Fatalf("control: the default FILESYSTEM block does not even mention /usr; this fixture "+
			"is not resolving what it thinks it is:\n%s", block)
	}
	if strings.Contains(block, "←") {
		t.Errorf("the default selection's FILESYSTEM block carries an interpreted mark, which "+
			"contradicts the design's own claim that no builtin matches the catalogue:\n%s", block)
	}

	writeGolden(t, "filesystem.defaults.txt", block)
}

// TestProfileShowMarksAnInterpretedGrant is §9 test 15: the SAME shapes,
// rendered by `snug profile show` from UNRESOLVED grant text rather than
// from resolved mounts (GrantInterpretedMarks, not PolicyInterpretedMarks) —
// the screen a human reads BEFORE selecting an unfamiliar profile, upstream
// of every --dry-run.
func TestProfileShowMarksAnInterpretedGrant(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/snug/profiles.d", 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[profile.marks]\n" +
		"description = \"fixture for issues #169/#170\"\n" +
		"ro = [\n" +
		"  \"/host/etc-ancestor:/etc\",\n" +
		"  \"/host/gitconfig-src:/etc/gitconfig\",\n" +
		"  \"/host/managed-settings-src:/etc/claude-code/managed-settings.json\",\n" +
		"  \"{home}/.npmrc\",\n" +
		"  \"{home}/.netrc\",\n" +
		"  \"{home}/.ssh:/opt/keys\",\n" +
		"  \"/host/usr-src:/usr\",\n" +
		"  \"/host/usr-share-src:/usr/share\",\n" +
		"]\n" +
		"symlink = [{ at = \"{home}/.bashrc\", target = \"/wherever\" }]\n"
	if err := os.WriteFile(dir+"/snug/profiles.d/marks.toml", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", "/home/u")

	var code int
	got := captureStdout(t, func() { code = profileCmd([]string{"show", "marks"}) })
	if code != 0 {
		t.Fatalf("`profile show marks` exited %d:\n%s", code, got)
	}
	if got == "" {
		t.Fatal("`profile show marks` printed nothing")
	}

	flat := flattenWrapped(got)
	for _, tc := range []struct{ shape, want string }{
		{"A, system row, Reads populated (git)", "COMMAND TABLE: git reads this as its system config"},
		{"A, system row, Reads populated (claude managed settings)", "COMMAND TABLE: claude reads this as managed (enterprise) settings"},
		{"A, home row, Reads empty (npm)", "COMMAND TABLE: npm reads this. Read-only SUPPLIES registry auth tokens"},
		{"B, home row, Reads empty (netrc)", "CREDENTIAL PATH: curl (and anything else honouring .netrc) reads this"},
		{"C, host-side (ssh)", "the host's ~/.ssh is exposed inside - CREDENTIAL: private keys"},
		{"D, ancestor collapse (/etc, 17 rows)", "17 paths SUPPLIED"},
		{"A, via symlink (bashrc)", "COMMAND TABLE: bash reads this. Read-only SUPPLIES runs on every shell"},
	} {
		if !strings.Contains(flat, tc.want) {
			t.Errorf("shape %s: expected %q in `profile show`, found nothing:\n%s", tc.shape, tc.want, got)
		}
	}
	// /usr and /usr/share stay quiet here too, same reasons as the --dry-run
	// case — asserted by control + count, mirroring
	// TestFilesystemBlockMarksAnInterpretedGrant.
	for _, want := range []string{"/usr", "/usr/share"} {
		if !strings.Contains(got, want) {
			t.Fatalf("control: the %s grant itself never reached `profile show`:\n%s", want, got)
		}
	}
	// Same grants, same shapes as TestFilesystemBlockMarksAnInterpretedGrant's
	// fixture, so the same count: 2 system A + 1 home A + 1 home B + 1 host C
	// + 1 ancestor D + 1 symlink A.
	if n := strings.Count(got, "←"); n != 7 {
		t.Errorf("`profile show marks` carries %d marks, want exactly 7:\n%s",
			n, got)
	}

	// The "defined in" line names the REAL path profiles.d was loaded from,
	// which here is t.TempDir() — a different directory on every run. Redact
	// it to a fixed placeholder before writing the golden, or the file would
	// never stop "changing".
	writeGolden(t, "show.interpreted.txt", redactProfileSource(got))
}

// redactProfileSource replaces `profile show`'s "defined in  <path>" line
// with a fixed placeholder. Every other golden of this screen
// (show.sys.txt, show.claude.txt, show.podman-socket.txt) golds a BUILTIN
// profile instead, whose Source is the stable literal "builtin:base.toml" —
// this fixture is loaded from profiles.d specifically to exercise
// GrantInterpretedMarks's un-resolved-grant-text path, so its Source is a
// real, unstable temp-directory path and has to be redacted by hand.
func redactProfileSource(got string) string {
	lines := strings.Split(got, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "defined in  ") {
			lines[i] = "defined in  <profiles.d>/marks.toml"
		}
	}
	return strings.Join(lines, "\n")
}

// TestMarkDoesNotFireOnASnugReplacedPath is §9 test 16: a row covered by an
// ancestor grant must NOT be marked when snug itself already replaced that
// exact guest path with generated content (a KindData mount) — the measured
// case is `data /usr/etc/ssh/ssh_config (snug)+replaces:@sys`. Both the FULL
// case (the only catalogued row under the ancestor is the one replaced, so
// the mark disappears entirely) and the PARTIAL case (a broader ancestor
// covering 17 rows, only one of which is replaced, so the count drops from 17
// to 16 rather than to 0) are covered — the corrections record names the
// partial case "the better test of the two". (17, not the original 8: the
// shell-startup and claude-code-root rows issue #170/upstream PR #181 added
// are all under /etc too.)
func TestMarkDoesNotFireOnASnugReplacedPath(t *testing.T) {
	const home = "/home/u"

	t.Run("full", func(t *testing.T) {
		p := &policy.Policy{
			Home: home,
			Mounts: map[string]policy.Mount{
				"/etc/ssh": {
					Guest: "/etc/ssh", Host: "/host/ssh-src", Kind: policy.KindBind,
					Access: policy.AccessRO, From: []string{"fixture"},
				},
			},
		}
		// POSITIVE CONTROL: without the replacement, the ancestor grant does
		// mark — /etc/ssh/ssh_config is the only catalogued row underneath it.
		if got := policy.PolicyInterpretedMarks(p, p.Mounts["/etc/ssh"]); len(got) == 0 {
			t.Fatal("control: /etc/ssh with nothing replaced produced no mark; this test measures nothing")
		}

		p.Mounts["/etc/ssh/ssh_config"] = policy.Mount{
			Guest: "/etc/ssh/ssh_config", Kind: policy.KindData, Access: policy.AccessRO,
			Authored: true, From: []string{"(snug)", "replaces:fixture"},
		}
		if got := policy.PolicyInterpretedMarks(p, p.Mounts["/etc/ssh"]); len(got) != 0 {
			t.Errorf("/etc/ssh still marked after its only catalogued row was replaced by a "+
				"KindData mount: %v", got)
		}
	})

	t.Run("partial", func(t *testing.T) {
		p := &policy.Policy{
			Home: home,
			Mounts: map[string]policy.Mount{
				"/etc": {
					Guest: "/etc", Host: "/host/etc-src", Kind: policy.KindBind,
					Access: policy.AccessRO, From: []string{"fixture"},
				},
			},
		}
		before := policy.PolicyInterpretedMarks(p, p.Mounts["/etc"])
		if len(before) != 1 {
			t.Fatalf("control: expected exactly one collapsed ancestor mark before any "+
				"replacement, got %d: %v", len(before), before)
		}
		if !strings.Contains(before[0], "17 paths") {
			t.Fatalf("control: expected /etc to cover exactly 17 rows before any replacement: %q", before[0])
		}

		p.Mounts["/etc/ssh/ssh_config"] = policy.Mount{
			Guest: "/etc/ssh/ssh_config", Kind: policy.KindData, Access: policy.AccessRO,
			Authored: true, From: []string{"(snug)", "replaces:fixture"},
		}
		after := policy.PolicyInterpretedMarks(p, p.Mounts["/etc"])
		if len(after) != 1 {
			t.Fatalf("expected exactly one collapsed ancestor mark after one row was replaced, "+
				"got %d: %v", len(after), after)
		}
		if !strings.Contains(after[0], "16 paths") {
			t.Errorf("replacing ssh_config alone did not drop the /etc ancestor's count from 17 "+
				"to 16 (not to 0 — the other 16 rows were never replaced): %q", after[0])
		}
	})
}

// TestNoFilesystemLineCanBeMistakenForAMark is §9 test 17: no ordinary
// FILESYSTEM or NOT-GRANTED data line may reach markIndent (21) — the
// structural property that makes "a line indented 20 or more is snug's own
// mark" hold at all. Driven against a REAL, rich builtin selection
// (@sys+@home+@claude, via loadTestRegistry/testTree from dryrun_test.go)
// rather than the synthetic fixture above, specifically because it is the
// selection most likely to produce long lines — @sys's 14 /etc entries, a
// staged binary path, `from` provenance joining several profile names — and
// it carries NO interpreted mark at all (TestNoBuiltinGrantsACredentialOrCommandTablePath,
// internal/profile, is what keeps that true), so every line in the two
// blocks below is exactly the ordinary case this test needs.
func TestNoFilesystemLineCanBeMistakenForAMark(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })

	start := strings.Index(got, "FILESYSTEM")
	if start < 0 {
		t.Fatalf("no FILESYSTEM block:\n%s", got)
	}
	rest := got[start:]
	end := strings.Index(rest, "\n\nENVIRONMENT")
	if end < 0 {
		t.Fatalf("no ENVIRONMENT block follows FILESYSTEM/NOT GRANTED, so the slice boundary is wrong:\n%s", got)
	}
	block := rest[:end]

	// POSITIVE CONTROL: this really is a rich, multi-line block, or the
	// absence of a wide indent below proves nothing.
	if lines := strings.Count(block, "\n"); lines < 20 {
		t.Fatalf("control: only %d lines in FILESYSTEM+NOT GRANTED; this selection is not "+
			"exercising enough real data for the assertion below to mean anything", lines)
	}
	if strings.Contains(block, "←") {
		t.Fatalf("control: this selection unexpectedly carries an interpreted mark, which means "+
			"every line below markIndent in this block is no longer guaranteed ordinary:\n%s", block)
	}

	for _, line := range strings.Split(block, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent >= markIndent {
			t.Errorf("a FILESYSTEM/NOT GRANTED line is indented %d spaces (>= markIndent %d) with "+
				"no interpreted mark on this selection, so it could be mistaken for one: %q",
				indent, markIndent, line)
		}
	}
}

// TestTheInterpretedMarkIsOrderIndependent is §9 test 18: rendering an
// already-resolved policy must not even LOOK order-dependent.
// PolicyInterpretedMarks is computed per mount from p.Mounts (a map) over
// SortedMounts(), and must not read Mount.From, so resolve([a,b]) and
// resolve([b,a]) must produce byte-identical FILESYSTEM blocks.
func TestTheInterpretedMarkIsOrderIndependent(t *testing.T) {
	env := newEnvFakeEnv()
	for _, d := range interpretedMarksFixtureDirs() {
		env.dirs[d] = true
	}
	reg := map[policy.ProfileName]*policy.Profile{
		"a": {
			Name: "a",
			RO: []string{
				"/host/gitconfig-src:/etc/gitconfig",
				"/host/usr-src:/usr",
			},
		},
		"b": {
			Name: "b",
			RO:   []string{"{home}/.npmrc"},
		},
	}

	render := func(sel []policy.ProfileName) string {
		p, err := policy.Resolve(reg, sel, envGoldenCtx(), env)
		if p == nil {
			t.Fatalf("Resolve(%v) returned no policy: %v", sel, err)
		}
		got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, err) })
		return filesystemBlock(t, got)
	}

	ab := render([]policy.ProfileName{"a", "b"})
	ba := render([]policy.ProfileName{"b", "a"})

	// POSITIVE CONTROL: marks actually fired, so a byte-identical comparison
	// of two EMPTY blocks would not be the thing proving order-independence.
	if !strings.Contains(ab, "←") {
		t.Fatalf("control: no interpreted mark fired at all; order-independence is unverifiable:\n%s", ab)
	}

	if ab != ba {
		t.Errorf("the FILESYSTEM block differs by selection order alone:\n--- [a,b]\n%s\n--- [b,a]\n%s", ab, ba)
	}
}
