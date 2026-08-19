package profile

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// NO BUILTIN PROFILE MAY GRANT A PATH THAT CARRIES CREDENTIALS OR NAMES PROGRAMS
// TO RUN. There is no allowlist, no declared-exception table and no flag: a
// builtin that trips this test is wrong, and the fix is to generate the file
// instead of binding it.
//
// Written because `@git-ro` shipped for a milestone binding `~/.gitconfig`
// read-only, and no review caught it. The abuse comment on that profile was
// present and honest as far as it went — "any secrets you unwisely put in
// ~/.gitconfig" — and it still missed the point twice over:
//
//   - the file is a COMMAND TABLE, not a data file with secrets in it.
//     credential.helper, alias.x = !cmd, core.pager, core.sshCommand,
//     diff.*.textconv and filter.*.clean/smudge all name programs for git to
//     run. A read-only bind does not stop that; it supplies it.
//   - "unwisely put in" reads as the user's mistake. It is not: those keys are
//     what the file is FOR.
//
// The process failure is the reusable part. The abuse sentence was written once,
// at authoring time, and nothing re-read it as identity, GIT_CONFIG_GLOBAL and
// credential staging grew around it. A comment cannot fail; this test can.
//
// It governs BUILTINS ONLY, and that boundary is the design rather than a
// weakening. A human writing `ro = ["{home}/.gitconfig"]` in their own
// profiles.d is making a declaration about their own machine — invariant 3 puts
// that decision outside the sandboxed material, which is exactly where it
// belongs. What must never happen is snug SHIPPING that decision on everyone's
// behalf.
//
// REWRITTEN onto policy.ClassifyInterpretedPath (issues #169/#170). The
// catalogue used to be duplicated here as sensitiveHostPath, and that
// duplicate was HOME-ROOTED ONLY — every entry was normalised to a path
// relative to $HOME, so there was no way to express an absolute path like
// /etc/gitconfig or /etc/claude-code/managed-settings.json at all. A builtin
// granting either would have PASSED this test despite being exactly the kind
// of command table it exists to catch (#170, confirmed: no live leak, because
// no builtin actually grants either path today — but the check could not have
// caught one that did). The catalogue now lives in policy.InterpretedPaths,
// shared with the --dry-run and `profile show` disclosure marks (#169) — this
// test keeps its own iteration and its own verdict (a GATE that refuses a
// builtin outright, never a disclosure), sharing only the DATA and the
// matcher, per the design's "unify the data, not the assertion."
func TestNoBuiltinGrantsACredentialOrCommandTablePath(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	home := realHomeForSweep(t)

	found := false
	for name, p := range reg {
		for _, h := range builtinInterpretedHazards(p, home) {
			found = true
			t.Errorf("builtin profile %q grants a path matching %s (%s: %s).\n"+
				"There is no exception list for this. Generate the file from the resolved "+
				"policy and point the tool at it with its own env var (GIT_CONFIG_GLOBAL, "+
				"GH_CONFIG_DIR, NPM_CONFIG_USERCONFIG, …), the way @git-ro and the identity "+
				"band do — a bind carries every unrelated thing in the file, and for a "+
				"command table it supplies the commands rather than stopping them.",
				name, displayHazardPath(h.Row), h.Row.Class, h.Row.Keys)
		}
	}
	if found {
		t.Log("if the grant is genuinely needed and genuinely safe, the catalogue in " +
			"policy.InterpretedPaths is what to argue with — in a diff, with the reason written down.")
	}
}

// builtinInterpretedHazards is the SWEEP both TestNoBuiltinGrantsACredentialOrCommandTablePath
// and TestTheBuiltinSweepActuallyFires drive: a profile's RO, RW and
// Symlink.At entries (never Symlink.Target — that is a link TARGET, not a
// host path, the same Kind gating policy.ClassifyInterpretedPath's other
// callers give KindSymlink), classified against the shared catalogue.
//
// Kept in the test file rather than promoted into production code: this is a
// GATE with its own iteration and its own verdict, and the design's whole
// argument for sharing only data and matcher is that this sweep's input
// (snug's own reviewed profiles) is a different trust class from the
// disclosure sinks' input (a resolved policy touching the host and the
// payload) — folding the iteration together would blur that boundary for no
// benefit.
func builtinInterpretedHazards(p *policy.Profile, home string) []policy.InterpretedHit {
	var hits []policy.InterpretedHit
	check := func(spec string) {
		// A grant may be `host:guest`; the host side is what a tool on the
		// HOST machine would read if the same spec were, say, a bind mount —
		// but here we are sweeping unresolved TOML, so this mirrors the old
		// sensitiveHostPath's own rule: the host half is what is read.
		host := spec
		if i := strings.Index(spec, ":"); i > 0 {
			host = spec[:i]
		}
		hits = append(hits, policy.ClassifyInterpretedPath(host, home)...)
	}
	for _, g := range p.RO {
		check(g)
	}
	for _, g := range p.RW {
		check(g)
	}
	for _, s := range p.Symlink {
		check(s.At)
	}
	return hits
}

// realHomeForSweep mirrors the old sensitiveHostPath's own guard: a home of
// "" or "/" cannot usefully be trimmed from a path, so normalizeInterpretedPath
// is handed "" in that case and falls back to matching the literal "{home}"
// and "~" tokens a builtin profile actually writes (base.toml never spells a
// real host path).
func realHomeForSweep(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		return ""
	}
	return home
}

// displayHazardPath is this test's own rendering of a hit's row path, kept
// separate from policy.displayInterpretedPath (unexported, and this package
// is not policy) — a home row reads with its "~/" back, a system row is
// already absolute.
func displayHazardPath(row policy.InterpretedPath) string {
	if strings.HasPrefix(row.Path, "/") {
		return row.Path
	}
	return "~/" + row.Path
}

// TestTheBuiltinSweepActuallyFires is the gap unifying the catalogue would
// otherwise inherit silently: TestTheCredentialCatalogueActuallyMatches (the
// predecessor of this test, before the rewrite onto policy.ClassifyInterpretedPath)
// exercised the MATCHING PREDICATE directly, never the SWEEP that walks a
// registry and calls it — so a refactor that made
// TestNoBuiltinGrantsACredentialOrCommandTablePath iterate an EMPTY registry,
// or skip Symlink.At, would have passed forever with nobody noticing the loop
// body never ran.
//
// Feeds a synthetic registry with the SAME hazardous path planted TWICE —
// once as a `ro` bind, once as a `symlink` — through builtinInterpretedHazards,
// the exact helper the real gate calls, and asserts it reports BOTH.
func TestTheBuiltinSweepActuallyFires(t *testing.T) {
	reg := Registry{
		"fixture": &policy.Profile{
			Name: "fixture",
			RO:   []string{"/etc/gitconfig"},
			Symlink: []policy.Symlink{
				{At: "/etc/gitconfig", Target: "/somewhere/else"},
			},
		},
	}

	var hits []policy.InterpretedHit
	for _, p := range reg {
		hits = append(hits, builtinInterpretedHazards(p, "")...)
	}

	if len(hits) < 2 {
		t.Fatalf("the sweep found %d hazard(s) in a profile that plants the same command table "+
			"TWICE — once as a `ro` bind, once as a `symlink` — want at least 2, one per grant "+
			"kind, or the sweep is not actually walking both fields: %v", len(hits), hits)
	}
	for _, h := range hits {
		if h.Row.Path != "/etc/gitconfig" {
			t.Errorf("hit named row %q, want /etc/gitconfig — the fixture only ever plants that "+
				"one path, so anything else means the matcher, not the sweep, is what fired", h.Row.Path)
		}
		if h.Row.Class != policy.ClassCommandTable {
			t.Errorf("/etc/gitconfig hit classified as %v, want ClassCommandTable", h.Row.Class)
		}
	}

	// NEGATIVE CONTROL: an ordinary profile, granting nothing catalogued,
	// must report zero — otherwise this test could pass because the helper
	// reports something for every input regardless of content.
	ordinary := &policy.Profile{Name: "ordinary", RO: []string{"/usr"}}
	if got := builtinInterpretedHazards(ordinary, ""); len(got) != 0 {
		t.Errorf("an ordinary grant of /usr reported %d hazard(s), want 0: %v", len(got), got)
	}
}
