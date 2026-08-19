package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// ── the review artifact for the whole catalogue (issues #169/#170) ──────────
//
// TestInterpretedPathsGolden pins every row's data AND every mark shape that
// row can render — the guest-side mark (template A or B, whichever the row's
// Class picks), the host-side mark (template C), and the string the row
// contributes to a collapsed ancestor line (template D). A human reviewing a
// new row reads this file, not the Go literal, the same way
// testdata/annotations.txt is the review artifact for the environment notes
// rather than envNotes itself.
//
// Regenerate with `go test ./internal/policy -update`, then READ the diff —
// a change here is a change to what a human is told about a sandbox before
// they trust it.
func TestInterpretedPathsGolden(t *testing.T) {
	var b strings.Builder
	b.WriteString("# The interpreted-path catalogue (issues #169/#170) — every row\n")
	b.WriteString("# policy.InterpretedPaths carries, and every mark shape it can render.\n")
	b.WriteString("# Regenerate with:\n")
	b.WriteString("#   go test ./internal/policy -update\n")
	b.WriteString("#\n")
	b.WriteString("# NONE OF THESE IS A REFUSAL. Every row below is a DISCLOSURE: a profile\n")
	b.WriteString("# granting one of these paths is fully permitted, on every screen, before and\n")
	b.WriteString("# after this table existed (issue #44). What changes is that a human reading\n")
	b.WriteString("# --dry-run or `snug profile show` is now TOLD what the tool does with the file.\n")
	b.WriteString("#\n")
	b.WriteString("# class:    COMMAND TABLE (a key names a program the tool runs) or CREDENTIAL\n")
	b.WriteString("#           (the file IS the secret). The worse of the two when both apply.\n")
	b.WriteString("# reads:    the clause completing \"the tool reads this as ___\"; (none) means the\n")
	b.WriteString("#           mark drops the clause rather than inventing an unmeasured claim.\n")
	b.WriteString("# guest:    the mark rendered when a grant's GUEST path matches this row exactly\n")
	b.WriteString("#           (template A for a command table, B for a credential).\n")
	b.WriteString("# host:     the mark rendered when only the grant's HOST path matches this row\n")
	b.WriteString("#           (template C) — the guest path is something else, but the host file\n")
	b.WriteString("#           this row names is exposed inside anyway.\n")
	b.WriteString("# ancestor: how this row's path reads inside a collapsed template-D line, when\n")
	b.WriteString("#           a grant is an ancestor of several rows at once.\n\n")

	for i, row := range InterpretedPaths {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "path:     %s\n", row.Path)
		fmt.Fprintf(&b, "class:    %s\n", row.Class)
		fmt.Fprintf(&b, "tool:     %s\n", row.Tool)
		reads := row.Reads
		if reads == "" {
			reads = "(none — the mark drops this clause)"
		}
		fmt.Fprintf(&b, "reads:    %s\n", reads)
		fmt.Fprintf(&b, "keys:     %s\n", row.Keys)
		fmt.Fprintf(&b, "evidence: %s\n", row.Evidence)
		guestMark := strings.TrimSpace(renderInterpretedHit(InterpretedHit{Row: row, Side: SideGuest, Match: MatchExact}))
		hostMark := strings.TrimSpace(renderInterpretedHit(InterpretedHit{Row: row, Side: SideHost, Match: MatchExact}))
		fmt.Fprintf(&b, "guest:    %s\n", guestMark)
		fmt.Fprintf(&b, "host:     %s\n", hostMark)
		fmt.Fprintf(&b, "ancestor: %s\n", displayInterpretedPath(row))
	}

	got := b.String()
	path := filepath.Join("testdata", "interpreted-paths.txt")
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
		t.Errorf("the interpreted-path catalogue changed — this is a change to what a human is "+
			"told about the sandbox they are about to trust.\n--- got\n%s\n--- want\n%s", got, string(want))
	}
}

// TestEveryInterpretedRowIsWellFormed checks the shape every row must have,
// independent of its content: Tool/Keys/Evidence non-empty, Reads required
// for a system (absolute) row, Path either absolute or a bare home tail (no
// leading "/", "{" or "~" — Scope is derived from this, so a row whose Path
// disagrees with itself would silently misclassify), no duplicate Path.
func TestEveryInterpretedRowIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i, row := range InterpretedPaths {
		if row.Tool == "" {
			t.Errorf("row %d (%q): empty Tool", i, row.Path)
		}
		if row.Keys == "" {
			t.Errorf("row %d (%q): empty Keys", i, row.Path)
		}
		if n := utf8.RuneCountInString(row.Keys); n > 60 {
			t.Errorf("row %d (%q): Keys is %d runes, over the 60-char budget wrapMark's 3-line "+
				"limit needs — move the extra detail into Evidence instead: %q", i, row.Path, n, row.Keys)
		}
		if row.Evidence == "" {
			t.Errorf("row %d (%q): empty Evidence — a measured claim with no measurement recorded "+
				"is the thing this catalogue's doc comment forbids", i, row.Path)
		}
		absolute := strings.HasPrefix(row.Path, "/")
		if absolute && row.Reads == "" {
			t.Errorf("row %d (%q): a system (absolute) row must carry Reads — it is required for "+
				"exactly this class of row", i, row.Path)
		}
		if strings.HasPrefix(row.Path, "{") || strings.HasPrefix(row.Path, "~") {
			t.Errorf("row %d: Path %q must not start with \"{\" or \"~\" — a home row is a bare "+
				"tail, expanded at match time, never spelled with the token itself", i, row.Path)
		}
		if seen[row.Path] {
			t.Errorf("row %d: duplicate Path %q", i, row.Path)
		}
		seen[row.Path] = true
	}
}

// TestInterpretedMarksNeverInterpolateProfileText is the regression for
// spec §4's correction: the templates interpolate NO profile-supplied text at
// all, only policy.InterpretedPaths' own literals and integers. Poison is
// planted on the side of a "host:guest" grant that is NOT the side which
// matches a catalogued row — the host side for a guest-exact hit, the guest
// side for a host-only hit — because a forging rune INSIDE the matched text
// would simply stop that text matching the row at all, and the positive
// control ("the same grant still produces a mark") would then be vacuous for
// the wrong reason.
func TestInterpretedMarksNeverInterpolateProfileText(t *testing.T) {
	const marker = "FORGED-BY-A-GRANT"
	const home = "/home/u"

	poisons := []struct {
		name  string
		rune_ string
	}{
		{"RLO (directional override)", "\u202e"},
		{"line separator", "\u2028"},
		{"ESC", "\x1b"},
		{"NEL (C1)", "\u0085"},
	}

	var cases []struct{ name, grant string }
	for _, p := range poisons {
		cases = append(cases,
			struct{ name, grant string }{
				"host position, " + p.name,
				"/host" + p.rune_ + marker + ":/etc/gitconfig",
			},
			struct{ name, grant string }{
				"guest position, " + p.name,
				"{home}/.ssh:/opt" + p.rune_ + marker,
			},
		)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marks := GrantInterpretedMarks(tc.grant, home)
			// POSITIVE CONTROL: without this, the assertions below could be
			// passing because the poisoned grant matched nothing at all.
			if len(marks) == 0 {
				t.Fatalf("grant %q produced no mark; this case tests nothing", tc.grant)
			}
			joined := strings.Join(marks, "\n")
			if strings.Contains(joined, marker) {
				t.Errorf("the mark for %q contains the profile's own marker text: %q", tc.grant, joined)
			}
			if i := strings.IndexFunc(joined, IsForgingRune); i >= 0 {
				t.Errorf("the mark for %q carries a forging rune %q at byte %d — an interpreted "+
					"mark must interpolate nothing a profile wrote: %q",
					tc.grant, []rune(joined[i:])[0], i, joined)
			}
		})
	}
}

// TestBroadHostTreesIsExactly pins the suppression set by name: "/", "/usr"
// and "/opt", and explicitly NOT "/etc" — @sys enumerates fourteen /etc
// entries instead of binding all of it (invariant 2), so a profile that DOES
// grant the whole of /etc really does supply /etc/gitconfig and must still be
// marked.
func TestBroadHostTreesIsExactly(t *testing.T) {
	want := []string{"/", "/opt", "/usr"}
	got := append([]string{}, BroadHostTrees...)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("BroadHostTrees = %v, want exactly %v — this set is what keeps a profile granting "+
			"the whole of /usr or /opt from earning a COMMAND TABLE mark on every default run; "+
			"changing it changes which broad grants go quiet", got, want)
	}
	if slices.Contains(BroadHostTrees, "/etc") {
		t.Error("/etc must not be in BroadHostTrees: @sys enumerates fourteen /etc entries instead " +
			"of binding all of it (invariant 2), and a profile that DOES grant the whole of /etc " +
			"really does supply /etc/gitconfig — that grant must still be marked")
	}
}

// TestAncestorMatchCollapsesToOneMark: a grant of /etc is an ancestor of
// every system row that sits under it (17, after issue #170/PR #181's shell
// startup and claude-code-root rows joined the ten this test used to count),
// and they must render as ONE line naming the count and at most three paths,
// never as seventeen — "eight marks x3 lines is the noise failure"
// (interpretedpaths.go's own comment on renderInterpretedAncestors, written
// when the count was smaller; the shape of the complaint is unchanged). /usr
// is the negative: BroadHostTrees suppresses the ancestor direction there
// entirely, so it must render zero marks despite two catalogued rows (npmrc,
// ssh_config) sitting under /usr/etc.
func TestAncestorMatchCollapsesToOneMark(t *testing.T) {
	const home = "/home/u"

	etcMarks := InterpretedMarks(ClassifyInterpretedPath("/etc", home))
	if len(etcMarks) != 1 {
		t.Fatalf("ro /etc produced %d marks, want exactly one collapsed line: %v", len(etcMarks), etcMarks)
	}
	if !strings.Contains(etcMarks[0], "17 paths") {
		t.Errorf("the collapsed mark does not name the 17 rows under /etc: %q", etcMarks[0])
	}
	if !strings.Contains(etcMarks[0], "+14 more") {
		t.Errorf("the collapsed mark should name 3 paths and fold the remaining 14 into '+14 more': %q",
			etcMarks[0])
	}

	usrMarks := InterpretedMarks(ClassifyInterpretedPath("/usr", home))
	if len(usrMarks) != 0 {
		t.Errorf("ro /usr produced %d marks, want zero — BroadHostTrees suppresses the ancestor "+
			"direction there even though /usr/etc/npmrc and /usr/etc/ssh/ssh_config are both "+
			"catalogued underneath it: %v", len(usrMarks), usrMarks)
	}
}

// TestDeepestInterpretedRowWinsOnASharedCandidate is the regression for the
// rule the new rows forced: with /etc/claude-code catalogued alongside
// /etc/claude-code/managed-settings.json, a grant of the child matches BOTH
// (the specific row exactly, the root row as MatchInside) — without
// deepestInterpretedHits collapsing that down, the FILESYSTEM line for one
// grant would carry two marks.
func TestDeepestInterpretedRowWinsOnASharedCandidate(t *testing.T) {
	const home = "/home/u"

	hits := ClassifyInterpretedPath("/etc/claude-code/managed-settings.json", home)
	direct := 0
	for _, h := range hits {
		if h.Match != MatchAncestor {
			direct++
		}
	}
	if direct != 1 {
		t.Fatalf("granting /etc/claude-code/managed-settings.json produced %d non-ancestor hit(s), "+
			"want exactly 1 (the deepest row) — every extra one is an extra mark on the same "+
			"FILESYSTEM line: %v", direct, hits)
	}
	marks := InterpretedMarks(hits)
	if len(marks) != 1 {
		t.Fatalf("granting /etc/claude-code/managed-settings.json rendered %d mark(s), want 1: %v",
			len(marks), marks)
	}
	if !strings.Contains(marks[0], "managed (enterprise) settings") {
		t.Errorf("the rendered mark is not the managed-settings.json row's own text (the "+
			"deepest/most specific row), it is the shallower /etc/claude-code root's: %q", marks[0])
	}
	if strings.Contains(marks[0], "everything written below") {
		t.Errorf("the rendered mark carries the /etc/claude-code ROOT row's Keys text — the "+
			"shallower row won when the deeper one should have: %q", marks[0])
	}

	// NEGATIVE CONTROL: granting the root directory ITSELF has no deeper row to
	// lose to (nothing else is an Exact/Inside match for that exact candidate,
	// only Ancestor hits on the rows beneath it, which is a different collapse
	// entirely) — so the root's OWN row must render, unchanged by dedupe.
	rootHits := ClassifyInterpretedPath("/etc/claude-code", home)
	rootDirect := 0
	for _, h := range rootHits {
		if h.Match != MatchAncestor {
			rootDirect++
		}
	}
	if rootDirect != 1 {
		t.Fatalf("granting /etc/claude-code itself produced %d non-ancestor hit(s), want exactly "+
			"1 (its own row): %v", rootDirect, rootHits)
	}
	rootMarks := InterpretedMarks(rootHits)
	found := false
	for _, m := range rootMarks {
		if strings.Contains(m, "the managed-scope root") {
			found = true
		}
	}
	if !found {
		t.Errorf("granting /etc/claude-code itself did not render the root row's own mark: %v", rootMarks)
	}
}

// TestEverySystemSSHConfigPathIsInterpreted is the drift guard §7 asks for:
// the two lists (SystemSSHConfigPaths, the sshConfigRows() this file derives
// from it) must never name different files.
func TestEverySystemSSHConfigPathIsInterpreted(t *testing.T) {
	if len(SystemSSHConfigPaths) < 2 {
		t.Fatalf("only %d SystemSSHConfigPaths; this drift guard is checking almost nothing",
			len(SystemSSHConfigPaths))
	}
	for _, want := range SystemSSHConfigPaths {
		found := false
		for _, row := range InterpretedPaths {
			if row.Path != want {
				continue
			}
			found = true
			if row.Class != ClassCommandTable {
				t.Errorf("row %q is %v, want ClassCommandTable — ssh's system config names "+
					"ProxyCommand/LocalCommand/Match exec/IdentityAgent", want, row.Class)
			}
			break
		}
		if !found {
			t.Errorf("SystemSSHConfigPaths entry %q has no InterpretedPaths row — the two lists "+
				"must never name different files", want)
		}
	}
}

// interpretedIdentifier matches any exported identifier this package defines
// for the interpreted-path catalogue. A word-boundary regexp rather than a
// hand-enumerated list, so a symbol added to interpretedpaths.go later is
// swept for free — and Go regexp, never shell grep, per CLAUDE.md's
// `grep -rn 'a|b'` trap: without -E that matches a literal pipe and finds
// nothing, which looks exactly like proof of absence.
var interpretedIdentifier = regexp.MustCompile(`\bInterpreted[A-Za-z]*\b`)

// TestInterpretedPathsIsNeverConsultedByARefusal is the regression for the
// catalogue's own doc comment: "IT IS NOT A FILTER AND MUST NEVER BECOME
// ONE." No refusal path may read it — not Validate, not Resolve, not
// rejectMasking, nothing in internal/sandbox or internal/stage — because the
// catalogue's own completeness is not guaranteed the way a refusal's input
// must be (a missing row is a missing SENTENCE for the two disclosure sinks,
// but would be a missing REFUSAL if anything ever consulted it for one).
//
// This sweeps SOURCE, not behaviour, deliberately: the property being
// guarded is "nobody imports this idea into a refusal", which shows up as a
// reference in the wrong file before it shows up as a bug.
func TestInterpretedPathsIsNeverConsultedByARefusal(t *testing.T) {
	type hit struct{ file, line string }
	var stray []hit
	sawInOwnFile := false

	roots := []string{".", "../sandbox", "../stage"}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			base := filepath.Base(path)
			for _, line := range strings.Split(string(data), "\n") {
				if !interpretedIdentifier.MatchString(line) {
					continue
				}
				if base == "interpretedpaths.go" {
					sawInOwnFile = true
					continue
				}
				stray = append(stray, hit{path, strings.TrimSpace(line)})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, h := range stray {
		t.Errorf("%s references an Interpreted* identifier outside interpretedpaths.go: %s\n"+
			"      the catalogue must never be consulted by a refusal path (Validate, Resolve, "+
			"rejectMasking, the sanitise filter, the container proxy's bind filter) — it is a "+
			"disclosure table, and this is exactly the kind of file a refusal lives in", h.file, h.line)
	}

	// Named explicitly, per spec, even though the general sweep above already
	// covers them: these three are where the finding that motivated this test
	// would actually have landed.
	for _, f := range []string{"validate.go", "resolve.go", "envresolve.go"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("could not read %s to check it: %v", f, err)
		}
		if interpretedIdentifier.MatchString(string(data)) {
			t.Errorf("%s references an Interpreted* identifier; a refusal-computing file must "+
				"carry none", f)
		}
	}

	// POSITIVE CONTROL: the sweep actually found the identifier where it is
	// supposed to live. Without this, a pattern matching nothing (a typo, a
	// wrong root) would pass this test on a package it never read.
	if !sawInOwnFile {
		t.Fatal("the sweep found no Interpreted* identifier even in interpretedpaths.go itself, " +
			"so it is not reading the files it thinks it is")
	}
}

// TestTheInterpretedCatalogueActuallyMatches is the positive control for the
// matcher itself: a catalogue that silently stopped matching would leave
// every mark-rendering test passing on a policy that hands over ~/.ssh, or
// /etc/gitconfig, with nothing said about it.
//
// The home-relative spellings are exactly TestTheCredentialCatalogueActuallyMatches's
// list (internal/profile/credentialsurface_test.go, before this rewrite),
// carried over verbatim so no spelling the old catalogue covered stops being
// covered by the new one — plus the absolute spellings issue #170 exists for.
func TestTheInterpretedCatalogueActuallyMatches(t *testing.T) {
	const home = "/home/u"

	matches := []string{
		// Home-relative, inherited from the old catalogue's positive control.
		"{home}/.ssh", "~/.ssh", "{home}/.ssh/id_ed25519", "{home}/.gitconfig",
		"{home}/.config/gh", "{home}/.aws/credentials", "{home}/.local/share/keyrings",
		"{home}/.claude/settings.json",
		"{home}//.ssh", "{home}/./.ssh", "{home}/.config/../.ssh", "{home}/.ssh/",
		"{home}", "{home}/", "{home}/.config", "{home}/.cargo",
		// Absolute — issue #170's whole point.
		"/etc/gitconfig",
		"/etc/claude-code/managed-settings.json",
		"/etc/claude-code/managed-settings.d/10-x.json", // inside a catalogued directory
		"/usr/etc/ssh/ssh_config",
		"/usr/etc/npmrc",
		"/etc/npmrc",
		"/etc", // ancestor of seventeen rows
	}
	for _, spelling := range matches {
		if hits := ClassifyInterpretedPath(spelling, home); len(hits) == 0 {
			t.Errorf("the catalogue does not recognise %q; every mark-rendering test would pass "+
				"on this spelling for the wrong reason", spelling)
		}
	}

	zero := []string{
		"/usr", "/opt", "/", "/usr/share", "/etc/passwd", "/etc/containers",
		"{home}/.claude/skills", "{home}/.claude/plugins", "{home}/.local/bin/claude", "{target}",
	}
	for _, ordinary := range zero {
		if hits := ClassifyInterpretedPath(ordinary, home); len(hits) != 0 {
			t.Errorf("the catalogue fires on %q, which is an ordinary grant: %v", ordinary, hits)
		}
	}

	// /usr and / must be quiet BECAUSE OF BroadHostTrees, not because nothing
	// is catalogued underneath them — proved by emptying the suppression list
	// and watching the same candidates immediately produce hits.
	orig := append([]string{}, BroadHostTrees...)
	BroadHostTrees = nil
	for _, p := range []string{"/usr", "/"} {
		if hits := ClassifyInterpretedPath(p, home); len(hits) == 0 {
			t.Errorf("control: with BroadHostTrees emptied, %q still produces no hits — the "+
				"zero-hit assertion above would pass whether or not suppression does anything", p)
		}
	}
	BroadHostTrees = orig

	// And /etc must not be in that set: it produces real ancestor hits with
	// BroadHostTrees exactly as shipped, because @sys enumerates its /etc
	// entries rather than granting all of /etc, so a profile that DOES grant
	// all of /etc is a deliberate, wide grant that must still be marked.
	if slices.Contains(BroadHostTrees, "/etc") {
		t.Fatal("/etc has been added to BroadHostTrees; see TestBroadHostTreesIsExactly")
	}
	if hits := ClassifyInterpretedPath("/etc", home); len(hits) == 0 {
		t.Error("/etc produced no hits even though it is not in BroadHostTrees and 17 catalogued " +
			"rows sit under it")
	}
}

// TestInterpretedTableIsNonEmptyAndCarriesTheKnownHazards pins the table's
// size and a sample of the reclassifications issue #169 requires — a filed
// row silently dropping back to its old (wrong) class would pass every other
// test here, since none of them check a SPECIFIC row's class against what it
// used to be.
func TestInterpretedTableIsNonEmptyAndCarriesTheKnownHazards(t *testing.T) {
	if len(InterpretedPaths) != 52 {
		t.Errorf("len(InterpretedPaths) = %d, want 52 (19 system + 33 home) — if this changed on "+
			"purpose, testdata/interpreted-paths.txt needs `-update` and the diff needs reading",
			len(InterpretedPaths))
	}
	system, home := 0, 0
	for _, row := range InterpretedPaths {
		if strings.HasPrefix(row.Path, "/") {
			system++
		} else {
			home++
		}
	}
	if system != 19 {
		t.Errorf("%d absolute (system) rows, want 19 (10 pre-existing + the /etc/claude-code root, "+
			"/etc/claude-code/.claude and seven shell startup files ported from upstream PR #181, "+
			"refs #170)", system)
	}
	if home != 33 {
		t.Errorf("%d home rows, want 33", home)
	}

	want := map[string]InterpretedClass{
		"/etc/gitconfig":                         ClassCommandTable,
		"/etc/claude-code/managed-settings.json": ClassCommandTable,
		"/etc/claude-code":                       ClassCommandTable,
		"/etc/claude-code/.claude":               ClassCommandTable,
		"/etc/profile":                           ClassCommandTable,
		"/etc/zshenv":                            ClassCommandTable,
		".ssh":                                   ClassCredential,
		".gitconfig":                             ClassCommandTable,
		".docker":                                ClassCommandTable, // reclassified from CREDENTIAL, issue #169
		".config/gh":                             ClassCommandTable, // reclassified from CREDENTIAL, issue #169
		".claude.json":                           ClassCommandTable, // reclassified from CREDENTIAL, issue #169
	}
	have := map[string]InterpretedClass{}
	for _, row := range InterpretedPaths {
		have[row.Path] = row.Class
	}
	for path, class := range want {
		got, ok := have[path]
		if !ok {
			t.Errorf("no row for %q", path)
			continue
		}
		if got != class {
			t.Errorf("%q is %v, want %v", path, got, class)
		}
	}
}
