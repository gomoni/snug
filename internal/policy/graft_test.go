package policy

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ── §7 item 1 (the model half) ───────────────────────────────────────────────
//
// TestNoProfileCanAuthorAGraft here is the STRUCTURAL half: Profile, the parsed
// form of a [profile.NAME] table, has no field whose type can express a Graft
// — no field named Graft, no []Graft, no map[...]Graft — so there is no
// assignment ANYWHERE Resolve could reach that writes one. The parse-time half
// (DisallowUnknownFields refusing an unrelated unknown key) already exists and
// is not what this checks; this is the type-system guard that stands behind
// it. internal/policy cannot import internal/profile (resolve_test.go's own
// testRegistry doc comment says why), so the RUNTIME half — resolving every
// REAL builtin and checking p.Grafts is empty — lives in internal/cli under
// the same test name.
func TestNoProfileCanAuthorAGraft(t *testing.T) {
	rt := reflect.TypeOf(Profile{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if typeMentionsGraft(f.Type) {
			t.Errorf("Profile.%s has type %s, which can express a Graft — a TOML key could then "+
				"author one, and no profile may ever author a graft (issue #55)", f.Name, f.Type)
		}
	}

	// The runtime half, over the widest combination THIS package's fake
	// registry can resolve — the default selection. If Resolve ever grew a
	// path from a Profile field into p.Grafts, this is the fold that would
	// have to carry it. The structural check above is what actually prevents
	// it; this is the fact a reader can see MOVE if it broke.
	p := mustResolveDefaults(t)
	if len(p.Grafts) != 0 {
		t.Errorf("a default Resolve produced %d grafts; nothing in Resolve authors one", len(p.Grafts))
	}
}

// typeMentionsGraft reports whether t is Graft, or a pointer/slice/array/map
// that could eventually hold one.
func typeMentionsGraft(t reflect.Type) bool {
	if t.Name() == "Graft" {
		return true
	}
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return typeMentionsGraft(t.Elem())
	case reflect.Map:
		return typeMentionsGraft(t.Key()) || typeMentionsGraft(t.Elem())
	}
	return false
}

// ── §7 item 2 ─────────────────────────────────────────────────────────────────
//
// The property, over the syntax tree rather than over source text (issue
// #354): Policy.Graft (graft.go) is meant to be the ONLY place that ever
// mutates a field named Grafts, module-wide, not just within internal/policy —
// p.Grafts is an exported field, and a future Tier C (#125) writer could just
// as easily land in internal/cli or internal/stage. This is
// TestMountCollectionsHaveThreeWriters's shape (norestriction_test.go, P2 of
// the no-restriction sweep) restated for a different field: a single-writer
// invariant is checkable by finding every mutation and asking where it lives,
// not by trusting the comment that claims it, and not by cataloguing the
// spellings a demote might take. It reuses that file's walk (sweepModule,
// moduleRoot), its detector plumbing (forEachFunc, fieldSelector, unparen,
// writeSite, detectInSource, requireWalked) and its shape for a mutation
// (index assignment, whole-field assignment, alias assignment, address taken,
// delete, clear, maps.Copy/Insert/DeleteFunc as destination) — all defined in
// norestriction_test.go and reused here verbatim, same package, because the
// property is identical to P2's and only the field name changes.
//
// It replaces three regexps that answered "which spellings write p.Grafts" by
// listing them: graftWriteRE for `X.Grafts[k] = v` and `X.Grafts = ...`,
// graftMapsCopyRE for maps.Copy with Grafts as the destination, graftAliasRE
// for `x := (something).Grafts`. Each was itself a response to a redteam
// evasion the previous, narrower pattern missed (issue #55, finding F3b), and
// the shape recurred: a fourth evasion answered by a fourth pattern is the
// catalogue invariant 2's corollary rejects. graftAliasRE is also the worked
// example of the failure mode this ticket names — it required `:=` immediately
// before the aliased expression, so `req.EngineGrafts = spec.Grafts`
// (internal/stage/stage.go, a plain `=`, not `:=`) is an alias of `.Grafts`
// that regexp could never see. The AST detector below does not care which
// assignment token was used, and this exact statement is
// TestGraftsMutationDetectorCatchesEverySpelling's "the spelling a `:=`-only
// regexp misses" fixture, and TestOnlyGraftWritesGrafts's one documented,
// non-filtered collision below.

// graftsField is the field name the sweep keys on, the same device
// accessField and mountsField are in norestriction_test.go.
const graftsField = "Grafts"

// graftMutations is mountsMutations's twin for a different field name. It
// cannot simply call mountsMutations, which is hardcoded to mountsField, so
// this restates the same four AssignStmt/UnaryExpr/CallExpr shapes against
// graftsField instead.
func graftMutations(file string, f *ast.File, fset *token.FileSet) []writeSite {
	var sites []writeSite
	forEachFunc(f, func(name string, root ast.Node) {
		add := func(pos token.Pos, how string) {
			sites = append(sites, writeSite{file: file, fn: name, how: how, line: fset.Position(pos).Line})
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					switch l := unparen(lhs).(type) {
					case *ast.IndexExpr:
						if fieldSelector(l.X, graftsField) {
							add(l.Pos(), "index assignment")
						}
					case *ast.SelectorExpr:
						if l.Sel != nil && l.Sel.Name == graftsField {
							add(l.Pos(), "whole-field assignment")
						}
					}
				}
				// `m := p.Grafts` aliases the map: the later `m[k] = v` is
				// invisible to every shape above, so what is flagged is the
				// alias itself, and a human looks at it. `for _, g := range
				// p.Grafts` (a RangeStmt, not an AssignStmt) and `gr :=
				// p.Grafts[guest]` (an IndexExpr, a one-entry copy) are
				// ordinary reads and are not alias assignments. Unlike the
				// regexp this replaces, the alias's own token (`=` or `:=`)
				// is not part of the shape — both are AssignStmt.
				for _, rhs := range v.Rhs {
					if fieldSelector(rhs, graftsField) {
						add(rhs.Pos(), "alias assignment")
					}
				}
			case *ast.UnaryExpr:
				if v.Op == token.AND && fieldSelector(v.X, graftsField) {
					add(v.Pos(), "address taken")
				}
			case *ast.CallExpr:
				graftCallMutation(v, add)
			}
			return true
		})
	})
	return sites
}

// graftCallMutation names the builtin and stdlib spellings that mutate a map
// in place, reporting through add so that a call matching none of them adds
// nothing. Grafts must be the FIRST argument (the destination); as maps.Copy's
// second argument it is the source, a read.
func graftCallMutation(c *ast.CallExpr, add func(token.Pos, string)) {
	if len(c.Args) == 0 || !fieldSelector(c.Args[0], graftsField) {
		return
	}
	switch fn := unparen(c.Fun).(type) {
	case *ast.Ident:
		switch fn.Name {
		case "delete":
			add(c.Pos(), "delete")
		case "clear":
			add(c.Pos(), "clear")
		}
	case *ast.SelectorExpr:
		if fn.Sel != nil && (fn.Sel.Name == "Copy" || fn.Sel.Name == "Insert" || fn.Sel.Name == "DeleteFunc") {
			add(c.Pos(), "maps."+fn.Sel.Name)
		}
	}
}

// TestOnlyGraftWritesGrafts sweeps the whole module for every mutation of a
// field named Grafts and asserts that Policy.Graft — and only Policy.Graft —
// performs one. It is the same device TestMountCollectionsHaveThreeWriters
// (norestriction_test.go) is for p.Mounts and deriveTopology's discipline is
// for p.Topology: an invariant with a single writer, checked by finding every
// mutation module-wide rather than trusted from a doc comment.
func TestOnlyGraftWritesGrafts(t *testing.T) {
	sites, dirs := sweepModule(t, graftMutations)
	requireWalked(t, dirs)

	var fromGraftGo, others []writeSite
	for _, s := range sites {
		if s.file == "internal/policy/graft.go" {
			fromGraftGo = append(fromGraftGo, s)
		} else {
			others = append(others, s)
		}
	}

	// POSITIVE CONTROL on the walk: Policy.Graft writes p.Grafts TWICE — the
	// nil-init whole-field assignment (`p.Grafts = map[string]Graft{}`) and
	// the bracketed write (`p.Grafts[g.Guest] = g`) two lines below it — and
	// both rows are kept rather than collapsed, so a third write landing in
	// Policy.Graft is a failure rather than a no-op. A detector that matched
	// nothing at all would report zero rows here and read as proof that
	// nobody writes p.Grafts, which is not a claim this sweep can make.
	if len(fromGraftGo) != 2 {
		t.Fatalf("the sweep found %d write(s) to a field named Grafts in policy/graft.go, want\n"+
			"exactly 2 — the nil-init whole-field assignment and the bracketed index assignment\n"+
			"inside Policy.Graft. Policy.Graft is the whole of the single-writer argument in code;\n"+
			"if this sweep cannot see both of its writes, it cannot see a third writer either:\n  %s",
			len(fromGraftGo), strings.Join(sitesLines(fromGraftGo), "\n  "))
	}
	for _, s := range fromGraftGo {
		if s.fn != "(*Policy).Graft" {
			t.Errorf("policy/graft.go writes a field named Grafts outside (*Policy).Graft, at %s — "+
				"Policy.Graft is meant to be the only writer, and that is where it must live", s)
		}
	}

	// internal/stage's EngineSpec.Grafts ([]EngineGraft, the engine's own
	// flattened list — internal/engine's engineGrafts builds it FROM p.Grafts
	// and it is never held alongside p.Mounts) shares the field name and is a
	// KNOWN COLLISION, listed rather than filtered: a sweep that hid its own
	// name collisions would be hiding exactly what a reader has to check
	// (norestriction_test.go's two (*lossyEncoder).document rows for Mounts
	// are the same call). `req.EngineGrafts = spec.Grafts` is read as an
	// alias of spec.Grafts — this is the plain-`=` spelling graftAliasRE's
	// `:=`-only pattern could never see, which is this ticket's own argument
	// for the change, sitting in the tree already. If you touch StartSandbox,
	// add or drop this row; anything else here is a genuine fourth writer.
	want := "internal/stage/stage.go (*Stage).StartSandbox (alias assignment)"
	if len(others) != 1 || others[0].key() != want {
		t.Fatalf("the sweep found writes to a field named Grafts outside policy/graft.go:\n  %s\n"+
			"want exactly one, the documented collision:\n  %s\n\n"+
			"Policy.Graft is meant to be the only writer of p.Grafts. A hit here that is not the\n"+
			"stage.EngineSpec.Grafts alias above is a fourth writer, and p.Grafts must move to\n"+
			"where it lives or this sweep's expectation must change with a stated reason.",
			strings.Join(sitesLines(others), "\n  "), want)
	}
}

// TestGraftsMutationDetectorCatchesEverySpelling is the mandatory positive
// control on graftMutations, in TestMountsMutationDetectorCatchesEveryDeriveSpelling's
// style (norestriction_test.go): fixtures the OLD three regexps could not see
// at all, plus the two they could, each asserted reported AND classified.
func TestGraftsMutationDetectorCatchesEverySpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"the bracketed write graftWriteRE always saw", `package p
func evil(p *Policy) { p.Grafts["x"] = Graft{} }`, "index assignment"},

		{"the whole-map form, graft.go's own nil-init shape", `package p
func evil(p *Policy) { p.Grafts = map[string]Graft{"/run": g} }`, "whole-field assignment"},

		{"maps.Copy with Grafts as the destination", `package p
func evil(p *Policy) { maps.Copy(p.Grafts, other) }`, "maps.Copy"},

		{"the `:=` alias graftAliasRE saw", `package p
func evil(p *Policy) { m := p.Grafts; m["/run"] = g }`, "alias assignment"},

		// The spelling graftAliasRE COULD NOT see: an alias through a plain
		// `=`, not `:=` — issue #354's own example, and the exact shape at
		// internal/stage/stage.go:423 (`req.EngineGrafts = spec.Grafts`) that
		// TestOnlyGraftWritesGrafts above must list as a collision rather
		// than miss entirely.
		{"an alias through a plain `=`, not `:=`", `package p
func evil(req *Request, spec *EngineSpec) { req.EngineGrafts = spec.Grafts }`, "alias assignment"},

		// Three spellings none of the three regexps covered at all — no
		// pattern in graft_test.go's previous form ever looked for them.
		{"un-granting by delete", `package p
func evil(p *Policy, k string) { delete(p.Grafts, k) }`, "delete"},

		{"un-granting everything", `package p
func evil(p *Policy) { clear(p.Grafts) }`, "clear"},

		{"address of the map handed to a callee", `package p
func evil(p *Policy) { rebuild(&p.Grafts) }`, "address taken"},

		{"overwriting through maps.Insert", `package p
func evil(p *Policy, other iter.Seq2[string, Graft]) { maps.Insert(p.Grafts, other) }`, "maps.Insert"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectInSource(t, graftMutations, tc.src)
			if len(got) == 0 {
				t.Fatalf("the detector reports nothing for this spelling, so a fourth writer of "+
					"p.Grafts written this way ships green:\n%s", tc.src)
			}
			var hows []string
			for _, s := range got {
				hows = append(hows, s.how)
			}
			if !strings.Contains(strings.Join(hows, ","), tc.want) {
				t.Errorf("reported %v, want one containing %q", hows, tc.want)
			}
		})
	}

	// NEGATIVE controls: the ordinary reads this module is full of, each a
	// real shape from internal/policy, internal/cli or internal/engine, and
	// each what a naive pattern confuses with a write.
	clean := `package p
func f(p *Policy, guest string) int {
	for g := range p.Grafts { _ = g }
	for _, g := range p.Grafts { _ = g }
	gr := p.Grafts[guest]
	_ = gr
	if _, ok := p.Grafts[guest]; ok { return 1 }
	if p.Grafts == nil { return 0 }
	maps.Copy(dst, p.Grafts)
	ok := a == p.Grafts["z"]
	_ = ok
	return len(p.Grafts)
}`
	if got := detectInSource(t, graftMutations, clean); len(got) != 0 {
		t.Errorf("the detector reports one of these ordinary reads as a mutation: %v", got)
	}
}

// ── shared fixtures for the G1-G5 tests below ────────────────────────────────

// rawGraft returns a structurally-valid Graft at an arbitrary absolute guest,
// with no attempt to satisfy G3 or G4 — usable only where the rule under test
// fires BEFORE those two are ever reached (checkGraft's order is G5's
// structural checks, then path hygiene, then G1, G2, G3, G4 in that order), so
// G1's own table and G3's own negative cases can name any guest they like
// without first building a policy that would make it exist.
func rawGraft(guest string) Graft {
	return Graft{
		Mount: Mount{
			Guest: guest, Host: "/opt", Kind: KindGraft, Access: AccessRO,
			From: []string{"(snug)"},
		},
		Why: "test abuse sentence: a hostile process inside the sandbox can use this to test",
	}
}

// resolveDefaults resolves the default profile selection against this
// package's fake registry — the same fixture mustResolveDefaults(*testing.T)
// uses, spelled to take testing.TB so the refusal helpers below (which are
// shared between a focused Test* function and TestGoldenRefusals's table, and
// so are typed testing.TB like every other helper in refusals_test.go) can
// call it too.
func resolveDefaults(t testing.TB) *Policy {
	t.Helper()
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("fixture: the default profile selection failed to resolve: %v", err)
	}
	return p
}

// validGraft returns a Graft the default profile selection ACCEPTS: Guest and
// Host both strictly inside the writable target, so it passes G1 (nowhere
// near snug's own paths), G3 (inside the target's AccessRW grant — the third,
// approximating disjunct of existsInSandbox) and G4 (the target's own Host
// tree is visible, since the sandbox's own grant of it is AccessRW).
//
// Every refusal test below starts here and changes exactly ONE field, so a
// refusal it produces is attributable to the ONE rule under test rather than
// to an unrelated fixture mistake. See TestValidGraftFixtureIsAccepted, the
// shared positive control every one of those tests depends on meaning
// something.
func validGraft(p *Policy, suffix string) Graft {
	target := p.Mounts[p.Target]
	return Graft{
		Mount: Mount{
			Guest: p.Target + "/" + suffix,
			Host:  target.Host + "/" + suffix,
			Kind:  KindGraft, Access: AccessRO,
			From: []string{"(snug)"},
		},
		Why: "a hostile process inside the sandbox can use this to reach the host's project tree " +
			"outside the exact target it was given",
	}
}

// TestValidGraftFixtureIsAccepted is the shared positive control named above.
func TestValidGraftFixtureIsAccepted(t *testing.T) {
	p := mustResolveDefaults(t)
	if err := p.Graft(newFakeEnv(), validGraft(p, "control")); err != nil {
		t.Fatalf("control: the shared valid-graft fixture was refused, so every refusal test built "+
			"from it by changing one field cannot be trusted to be refusing for the reason it "+
			"claims: %v", err)
	}
}

// ── §7 item 3 ─────────────────────────────────────────────────────────────────

// refusalGraftCoversStagedBinDir is G1: a graft may not cover one of snug's
// own paths, in EITHER namespace — the same rule Validate's mount-level check
// applies, asked of a graft's Guest with the trap named in graft.go's own doc
// comment: validate.go's mount-level version reads `ours && !m.Authored`, and
// every graft is Authored by construction, so copying that clause here makes
// this check a PERMANENT NO-OP. Nothing legitimately covers StagedBinDir in
// ANY namespace, so unlike the mount-level check there is no analogous
// exemption to carry over — checkGraft's G1 deliberately does not have one.
func refusalGraftCoversStagedBinDir(t testing.TB, guest string) error {
	p := resolveDefaults(t)
	return p.Graft(newFakeEnv(), rawGraft(guest))
}

// graftInsideSnugDir builds the shape that was ACCEPTED before G1b existed: a
// writable graft, with a source G4's second disjunct admits (a host path snug
// created for the run), aimed at a path inside snug's own namespace.
//
// @podman-socket is selected and the proxy socket is bound, because that is
// what made the hole reachable: G3 asks whether the destination exists in the
// sandbox, and the socket IS a mount, so nothing downstream refused it.
func graftInsideSnugDir(t testing.TB, guest string) error {
	t.Helper()
	sel := append(append([]ProfileName{}, testDefaults...), "@podman-socket")
	p, err := Resolve(testRegistry(), sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	p.BindSocket("/host/podman.sock", ContainerSocketGuest, "(containers)")
	if err := p.OwnEngineHostPath(newFakeEnv(), "/opt"); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	g := rawGraft(guest)
	g.Access = AccessRW
	return p.Graft(newFakeEnv(), g)
}

// TestGraftInsideSnugDirIsRefusedExceptUnderTheEngineSubtree is G1b, and it is
// a regression test for a hole an independent review found in the change that
// introduced the namespace.
//
// Rule 4b (validate.go) made SnugDir total for the PAYLOAD's mounts. G1 covers
// grafts through snugsOwn, which is a LIST, and that list held SnugDir and
// StagedBinDir but not the two proxy socket paths — so the namespace was total
// on one side and partial on the other, which is CLAUDE.md's "a rule written
// once and applied to one of its two halves", committed in the change that
// quotes it.
//
// MEASURED before the fix: a writable graft at ContainerSocketGuest was
// ACCEPTED, putting an arbitrary host tree where the engine expects the
// container proxy's socket.
func TestGraftInsideSnugDirIsRefusedExceptUnderTheEngineSubtree(t *testing.T) {
	for _, guest := range []string{
		ContainerSocketGuest,
		AgentSocketGuest,
		SnugDir + "/engine",   // the engine directory ITSELF, not a leaf inside it
		SnugDir + "/whatever", // a path snug has not placed anything at yet
	} {
		t.Run(guest, func(t *testing.T) {
			err := graftInsideSnugDir(t, guest)
			if err == nil {
				t.Fatalf("a writable graft at %s was accepted; it is inside %s, so it replaces "+
					"whatever snug put there with this graft's source in the ENGINE's view",
					guest, SnugDir)
			}
			// The refusal must name the namespace AND the one subtree that is
			// allowed, or it is a dead end rather than a correction.
			for _, want := range []string{SnugDir, EngineDir} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not name %s: %v", want, err)
				}
			}
		})
	}
}

// TestGraftUnderTheEngineSubtreeIsNotRefusedByTheNamespaceRule is G1b's
// POSITIVE CONTROL, and without it the rule above passes on an implementation
// that refuses every graft inside SnugDir — which would make Tier C
// unimplementable while looking correct.
//
// It asserts what G1b does NOT do rather than that the graft succeeds: the
// destination does not exist in the sandbox yet, so G3 refuses it, and that is
// the honest state of the tree today. What must not appear is G1b's own
// message.
func TestGraftUnderTheEngineSubtreeIsNotRefusedByTheNamespaceRule(t *testing.T) {
	err := graftInsideSnugDir(t, EngineDir+"/store")
	if err == nil {
		return // Tier C has landed and created the directory; nothing to check.
	}
	if strings.Contains(err.Error(), "the only part of it a graft may land in") {
		t.Fatalf("G1b refused the engine's own subtree, which is the one place inside %s a graft "+
			"is FOR — Tier C cannot place its destinations anywhere else: %v", SnugDir, err)
	}
}

// TestGraftAtTheLegacySnugDirIsRefused is G1c: the pre-#206 tombstone applies
// to grafts as well as to profile grants. A tombstone honoured on one side only
// is the same half-applied shape G1b exists to close.
func TestGraftAtTheLegacySnugDirIsRefused(t *testing.T) {
	for _, guest := range []string{legacySnugDir, legacySnugDir + "/bin", legacySnugDir + "/bin/tool"} {
		t.Run(guest, func(t *testing.T) {
			err := graftInsideSnugDir(t, guest)
			if err == nil {
				t.Fatalf("a graft at the pre-#206 path %s was accepted", guest)
			}
			if !strings.Contains(err.Error(), EngineDir) {
				t.Errorf("the refusal does not name where the engine's destinations now live: %v", err)
			}
		})
	}
}

// TestGraftCoveringStagedBinDirIsRefused is the test the trap above exists
// for. If `&& !g.Authored` (or any spelling of it) is ever added to G1 in
// graft.go, every one of these subtests goes from refusing to accepting,
// because Policy.Graft sets Authored unconditionally three lines before
// checkGraft ever runs. Mutation-checked: reverting this file's comment is not
// enough on its own — see the report for how this was verified by actually
// adding the clause and watching this fail.
func TestGraftCoveringStagedBinDirIsRefused(t *testing.T) {
	for _, guest := range []string{"/", SnugDir, StagedBinDir, "/proc", "/dev"} {
		t.Run(guest, func(t *testing.T) {
			err := refusalGraftCoversStagedBinDir(t, guest)
			if err == nil {
				t.Fatalf("a graft at %s was accepted; it covers one of snug's own paths, in a "+
					"namespace this check must refuse it in exactly as it would in the sandbox's",
					guest)
			}
			at, _, ours := snugsOwnCovered(guest)
			if !ours {
				t.Fatalf("fixture bug: %s does not cover any of snug's own paths at all — this "+
					"case is not testing G1", guest)
			}
			// "is snug's" is G1's OWN wording (both of its branches — one
			// reads "%s is snug's own:", the other wraps across a line as
			// "...is snug's\n       own:", so "is snug's" is the longest
			// substring common to both) and G3's message does not contain it
			// at all (G3 refuses with "nothing in this policy creates that
			// directory" instead). Required specifically so this assertion
			// cannot be satisfied by a DIFFERENT rule firing for a different
			// reason. Without it, the StagedBinDir-exact subtest still
			// "passes" if `&& !g.Authored` is reintroduced into G1: G1 stops
			// firing, but G3 then refuses the same guest anyway (nothing
			// creates /snug/bin either), producing a non-nil error that
			// also names the guest — a false pass, caught only by requiring
			// G1's own wording. Measured by reverting this exact clause into
			// graft.go and re-running this test: every subtest but one failed
			// outright, and the sixth (StagedBinDir exact) passed for the
			// wrong reason until this line was added.
			for _, want := range []string{guest, at, "cannot graft", "is snug's"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

// ── §7 item 4 ─────────────────────────────────────────────────────────────────

// TestGraftInsideStagedBinDirIsRefusedByTheNamespaceRule replaces a test whose
// PREMISE expired, and the change of subject is the point rather than a
// mechanical fixup.
//
// It used to assert that a graft strictly INSIDE StagedBinDir stays legal, on
// the stated grounds that this is "the shape a Tier C graft onto a writable
// grant would actually take". That was written while Tier C's destinations were
// still an open question; they were then settled as EngineDir/*, so no graft
// lands in the staging directory any more and the old assertion was protecting
// a shape nothing produces.
//
// What it asserted underneath — that G1's snugsOwnCovered is an ANCESTOR test
// and not a prefix test — is still true and still checked, by
// TestGraftUnderTheEngineSubtreeIsNotRefusedByTheNamespaceRule (a path strictly
// inside SnugDir that G1b does allow) and by covers()'s own unit tests. What
// changed is only that StagedBinDir is no longer the place to observe it, since
// G1b now refuses everything inside SnugDir outside the engine's subtree.
//
// Keeping the old test would have meant keeping a hole open to satisfy a
// control: a graft at StagedBinDir/mytool replaces a staged executable in the
// ENGINE's view with an arbitrary source, and while the engine's own PATH does
// not include that directory (issue #125's C2-path pinned it to /usr/bin and
// friends), "it is not reachable through the one path we thought of" is the
// argument this project's red-team table is a list of.
func TestGraftInsideStagedBinDirIsRefusedByTheNamespaceRule(t *testing.T) {
	base := mustResolveDefaults(t)
	p := *base
	p.Mounts = make(map[string]Mount, len(base.Mounts)+1)
	for k, v := range base.Mounts {
		p.Mounts[k] = v
	}
	// The existing staged bind this graft would land onto — so G3 is satisfied
	// and the refusal below can only be G1b's.
	p.Mounts[StagedBinDir+"/mytool"] = Mount{
		Guest: StagedBinDir + "/mytool", Host: "/opt/mytool", Kind: KindBind, Access: AccessRO,
	}

	g := Graft{
		Mount: Mount{
			Guest: StagedBinDir + "/mytool", Host: "/opt/mytool",
			Kind: KindGraft, Access: AccessRO, From: []string{"(snug)"},
		},
		Why: "test abuse sentence",
	}
	err := p.Graft(newFakeEnv(), g)
	if err == nil {
		t.Fatalf("a graft at %s/mytool was accepted; it replaces a staged executable in the "+
			"ENGINE's view with this graft's source", StagedBinDir)
	}
	// It must be G1b that refuses, naming the namespace and the one subtree a
	// graft may use. If some other rule happens to refuse it today, this test
	// would pass while G1b was broken.
	for _, want := range []string{SnugDir, EngineDir} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s, so it is not the namespace rule that "+
				"refused: %v", want, err)
		}
	}
}

// ── §7 item 5 — the control the issue exists for ─────────────────────────────

// TestEngineViewIsShadowSlotSeesAGraft is the positive control issue #55
// demands (spec §4, §7 item 5). It hand-builds a Policy — bypassing
// Policy.Graft entirely, so the SUBJECT here is IsShadowSlot/EngineView, not
// the refusal machinery — installs an AccessRW graft at /run, and asserts
// EngineView().IsShadowSlot(StagedBinDir) is true.
//
// THE SECOND HALF IS NOT DECORATION. Written in the style
// internal/cli/shadowslot_test.go's own TestShadowSlotPredicateFiresOnAWritableHomeDirectory
// used for exactly this reason: a predicate that answered true for every guest
// path would pass the first half and mean nothing. So this also asks the
// IDENTICAL View — same Mounts, no graft applied — and requires false: the
// verdict has to hinge on the graft's presence, not on StagedBinDir being
// asked about at all. And it asks the SANDBOX's own view of the very same
// Policy and requires false there too, which is the fact issue #55 is
// actually about: a graft is invisible to the payload's own namespace by
// construction, and only EngineView can ever see it.
func TestEngineViewIsShadowSlotSeesAGraft(t *testing.T) {
	mounts := map[string]Mount{
		"/usr": {Guest: "/usr", Kind: KindBind, Access: AccessRO},
	}
	p := &Policy{Mounts: mounts}

	// WITHOUT the graft: neither view may say StagedBinDir is a shadow slot.
	if (View{Mounts: mounts}).IsShadowSlot(StagedBinDir) {
		t.Fatal("control: IsShadowSlot(StagedBinDir) = true with NO graft installed at all — the " +
			"predicate below would then be unfalsifiable, exactly the defect " +
			"shadowslot_test.go documents about its own earlier version")
	}
	if p.SandboxView().IsShadowSlot(StagedBinDir) {
		t.Fatal("control: the SANDBOX's own view must never see a graft")
	}

	p.Grafts = map[string]Graft{
		SnugDir: {
			Mount: Mount{Guest: SnugDir, Kind: KindGraft, Access: AccessRW, From: []string{"(snug)"}},
			Why:   "test",
		},
	}

	// THE CLAIM. SnugDir is not itself StagedBinDir, but it is StagedBinDir's
	// ancestor, and the graft's writability makes the whole subtree it covers
	// writable in the ENGINE's derived view — the graft-covers-the-staging-
	// directory shape issue #55 is named for. (It was written against /run,
	// which stopped being an ancestor when issue #206 moved snug's paths to
	// their own namespace; the shape is the same one directory up.)
	ev, ok := p.EngineView()
	if !ok {
		t.Fatal("EngineView() ok=false with a graft present")
	}
	if !ev.IsShadowSlot(StagedBinDir) {
		t.Fatal("EngineView().IsShadowSlot(StagedBinDir) = false with an AccessRW graft at " + SnugDir + " — " +
			"a graft is a Mount like any other once it is in the engine's view, and this is the " +
			"exact hole issue #55 reports: neither Validate nor IsShadowSlot could see one")
	}

	// The payload's OWN view is still blind to it, even now that the graft
	// exists — this is the fact that makes "the engine's view is derived from
	// the sandbox's, never the other way, and never the same map" true rather
	// than aspirational.
	if p.SandboxView().IsShadowSlot(StagedBinDir) {
		t.Fatal("the SANDBOX's own view answered true once a graft existed — a graft must never " +
			"reach the payload's mount namespace, in the model or at runtime")
	}
}

// ── issue #55, finding F1 (redteam round against the graft model) ───────────

// TestEngineViewGraftShadowsDeeperMounts is the regression test for finding
// F1. EngineView's overlay USED TO BE per-key, on the premise (its own former
// comment, quoted in the fix) that "a graft's Guest can only ever coincide
// with an existing sandbox mount's Guest, never with another graft's, so
// overlaying is a plain per-key replacement with no ordering to get wrong".
// That premise is FALSE: G3's own second disjunct explicitly accepts a graft
// whose Guest is a strict ANCESTOR of an existing mount (an auto-created
// directory), and move_mount(2) onto that directory takes everything mounted
// beneath it WITH it — the kernel does not leave a deeper mount poking
// through. A per-key overlay left every mount BENEATH a graft fully visible
// in EngineView, which defeats the exact sweep #125 is specified to run: "for
// every element of the engine's PATH, EngineView().IsShadowSlot(elem) must be
// false".
//
// Two shapes, both measured by the red team against the pre-fix code:
//   - a graft-rw at /etc must shadow snug's own generated /etc/resolv.conf
//     (KindData) sitting beneath it.
//   - a graft-rw at /opt, over an existing read-only PATH element at
//     /opt/tools/bin, must shadow it too — the #125 PATH sweep's own
//     acceptance criterion, and the shape the old per-key overlay could not
//     see at all: IsShadowSlot("/opt/tools/bin") would answer false ON A PATH
//     ELEMENT THE ENGINE COULD ACTUALLY WRITE.
//
// Every subtest carries its own positive control: the identical query on a
// View with NO graft installed must be false, and the SANDBOX's own view of
// the same Policy must stay false even once the graft exists — a graft must
// never reach the payload's own mount namespace.
func TestEngineViewGraftShadowsDeeperMounts(t *testing.T) {
	t.Run("etc_resolv_conf", func(t *testing.T) {
		p := mustResolveDefaults(t)
		if _, ok := p.Mounts["/etc/resolv.conf"]; !ok {
			t.Fatal("fixture: the default policy has no /etc/resolv.conf mount — nothing is keyed " +
				"deeper than /etc, so this case could not observe a shadow at all")
		}
		// POSITIVE CONTROL, before any graft exists.
		if p.SandboxView().IsShadowSlot("/etc/resolv.conf") {
			t.Fatal("control: the payload's own view must not call /etc/resolv.conf a shadow slot " +
				"before any graft exists")
		}
		if ev, ok := (&Policy{Mounts: p.Mounts}).EngineView(); ok {
			_ = ev
			t.Fatal("control: EngineView() ok=true with NO graft installed at all")
		}

		target := p.Mounts[p.Target]
		g := Graft{
			Mount: Mount{Guest: "/etc", Host: target.Host, Kind: KindGraft, Access: AccessRW,
				From: []string{"(snug)"}},
			Why: "a hostile process inside the engine can use a writable /etc to replace snug's " +
				"generated resolv.conf, or anything else under /etc, with its own content",
		}
		if err := p.Graft(newFakeEnv(), g); err != nil {
			t.Fatalf("fixture: graft-rw at /etc (G3's FIRST disjunct: /etc is itself an existing "+
				"mountpoint, @sys's own ro bind) was refused: %v", err)
		}

		ev, ok := p.EngineView()
		if !ok {
			t.Fatal("EngineView() ok=false with a graft installed")
		}
		if !ev.IsShadowSlot("/etc/resolv.conf") {
			t.Fatal("EngineView().IsShadowSlot(/etc/resolv.conf) = false with a graft-rw at /etc — " +
				"a per-key overlay leaves the deeper KindData mount visible THROUGH the graft " +
				"(issue #55, finding F1); move_mount(2) onto /etc takes everything beneath it with it")
		}
		// POSITIVE CONTROL: the SANDBOX's own view of the identical Policy must
		// still say no.
		if p.SandboxView().IsShadowSlot("/etc/resolv.conf") {
			t.Fatal("the SANDBOX's own view answered true once the graft existed — a graft must " +
				"never reach the payload's namespace")
		}
	})

	t.Run("opt_tools_bin_the_path_shape", func(t *testing.T) {
		// Hand-built, mirroring TestEngineViewIsShadowSlotSeesAGraft's own
		// style and the red team's exact reproduction: this is #125's PATH
		// sweep's own acceptance criterion, so it is written against that
		// literal shape rather than against whatever Policy.Graft's G3/G4
		// happen to accept for /opt today.
		mounts := map[string]Mount{
			"/opt/tools/bin": {Guest: "/opt/tools/bin", Kind: KindBind, Access: AccessRO,
				From: []string{"toolprof"}},
		}
		p := &Policy{Mounts: mounts}

		// POSITIVE CONTROL, before any graft exists.
		if (View{Mounts: mounts}).IsShadowSlot("/opt/tools/bin") {
			t.Fatal("control: a read-only PATH element must not be a shadow slot before any graft exists")
		}
		if p.SandboxView().IsShadowSlot("/opt/tools/bin") {
			t.Fatal("control: the sandbox's own view must not see a shadow slot either, before any graft exists")
		}

		p.Grafts = map[string]Graft{
			"/opt": {
				Mount: Mount{Guest: "/opt", Kind: KindGraft, Access: AccessRW, From: []string{"(snug)"}},
				Why:   "test abuse sentence: a hostile process inside the engine can write anywhere " + "under /opt, including ahead of a read-only PATH element the sandbox itself granted",
			},
		}

		ev, ok := p.EngineView()
		if !ok {
			t.Fatal("EngineView() ok=false with a graft present")
		}
		if !ev.IsShadowSlot("/opt") {
			t.Fatal("EngineView().IsShadowSlot(/opt) = false with an AccessRW graft installed exactly there")
		}
		if !ev.IsShadowSlot("/opt/tools/bin") {
			t.Fatal("EngineView().IsShadowSlot(/opt/tools/bin) = false with a graft-rw at /opt, its " +
				"ancestor — this is #125's own PATH-sweep acceptance criterion (\"for every element " +
				"of the engine's PATH, IsShadowSlot(elem) must be false\"), and the exact case a " +
				"per-key overlay could not see (issue #55, finding F1): the sweep would otherwise " +
				"pass on a PATH element the engine can actually write")
		}
		// POSITIVE CONTROL: the SANDBOX's own view of the identical Policy must
		// still say no — a graft never reaches the payload's namespace.
		if p.SandboxView().IsShadowSlot("/opt/tools/bin") {
			t.Fatal("the SANDBOX's own view answered true once the graft existed")
		}
	})
}

// ── §7 item 6 ─────────────────────────────────────────────────────────────────

// TestGraftSourceMustBeVisibleToTheSandbox is G4. Negative: a graft whose Host
// is $XDG_RUNTIME_DIR's real path — the ssh-agent, D-Bus, Wayland and the
// host's rootless podman socket reach ENGINE-NETNS.md §5.1 measured through a
// /run graft — is refused, because no grant in the default profile selection
// exposes it. Positive control: a graft whose Host sits inside an AccessRW
// grant (the target) is accepted.
// refusalGraftSourceNotVisible is also used as a TestGoldenRefusals row.
func refusalGraftSourceNotVisible(t testing.TB) error {
	p := resolveDefaults(t)
	bad := validGraft(p, "xdg")
	bad.Host = "/run/user/1000"
	return p.Graft(newFakeEnv(), bad)
}

func TestGraftSourceMustBeVisibleToTheSandbox(t *testing.T) {
	p := mustResolveDefaults(t)

	err := refusalGraftSourceNotVisible(t)
	if err == nil {
		t.Fatal("a graft whose Host is /run/user/1000 (ssh-agent, D-Bus, Wayland, the host's " +
			"rootless podman socket — ENGINE-NETNS.md §5.1) was accepted; no grant in this " +
			"policy exposes it, so no graft may reach it either")
	}
	for _, want := range []string{"/run/user/1000", "does not expose this host path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL, same Policy: TestValidGraftFixtureIsAccepted already
	// proves this shape is accepted; repeated here as g4's own control so this
	// file's G4 test does not depend on reading another one to mean anything.
	if err := p.Graft(newFakeEnv(), validGraft(p, "inside-target")); err != nil {
		t.Fatalf("control: a graft whose Host sits inside an AccessRW grant must be accepted: %v", err)
	}
}

// ── §7 item 7 ─────────────────────────────────────────────────────────────────

// refusalGraftDestinationDoesNotExist is G3, checked against the two negative
// rows ENGINE-NETNS.md §5.1 measured: /etc/containers and /var/tmp both fail
// move_mount's implicit mkdir with EROFS on the read-only sandbox root,
// because nothing in the default profile selection creates either directory
// inside the sandbox (the real @sys binds fourteen individual /etc entries and
// never /etc itself).
func refusalGraftDestinationDoesNotExist(t testing.TB, guest string) error {
	p := resolveDefaults(t)
	return p.Graft(newFakeEnv(), rawGraft(guest))
}

func TestGraftDestinationMustExist(t *testing.T) {
	for _, guest := range []string{"/etc/containers", "/var/tmp"} {
		t.Run(guest, func(t *testing.T) {
			err := refusalGraftDestinationDoesNotExist(t, guest)
			if err == nil {
				t.Fatalf("a graft at %s was accepted; nothing in the default selection creates that "+
					"directory inside the sandbox, and move_mount's implicit mkdir fails EROFS on "+
					"the read-only sandbox root (measured, ENGINE-NETNS.md §5.1)", guest)
			}
			for _, want := range []string{guest, "EROFS"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}

	// POSITIVE CONTROL: a destination inside a writable grant passes G3.
	p := mustResolveDefaults(t)
	if err := p.Graft(newFakeEnv(), validGraft(p, "inside")); err != nil {
		t.Fatalf("control: a graft destination inside a writable grant must pass G3: %v", err)
	}
}

// ── §7 item 9 ─────────────────────────────────────────────────────────────────

// TestGraftNeverReachesBwrapArgs is the mechanical form of the claim §9 and
// §10 both make: a graft is unreachable from the bwrap argv, so a moved
// .bwrap.txt golden means a graft reached the payload's namespace. Three
// parts: the argv itself never names a graft's Guest or Host; a KindGraft
// hand-placed into p.Mounts (never through Policy.Graft, which cannot produce
// one there) is refused by Validate; and — bypassing Validate on purpose,
// because what is under test here IS what happens if that refusal is ever
// removed or skipped — BwrapFlags panics rather than silently omitting or
// emitting the mount, closing the exact "--seccomp after bwrap's --" shape
// CLAUDE.md warns about.
func TestGraftNeverReachesBwrapArgs(t *testing.T) {
	base := mustResolveDefaults(t)
	p := *base
	p.Mounts = make(map[string]Mount, len(base.Mounts))
	for k, v := range base.Mounts {
		p.Mounts[k] = v
	}

	g := validGraft(&p, "argv-probe")
	if err := p.Graft(newFakeEnv(), g); err != nil {
		t.Fatalf("fixture: a valid graft was rejected: %v", err)
	}

	args := p.BwrapFlags(1000, 1000, func(string) int { return 9 })
	for _, a := range args {
		if a == g.Guest {
			t.Errorf("bwrap argv contains the graft's Guest (%s) — a graft must never reach the "+
				"payload's mount namespace", g.Guest)
		}
		if a == g.Host {
			t.Errorf("bwrap argv contains the graft's Host (%s)", g.Host)
		}
	}

	// A hand-placed KindGraft in p.Mounts — Validate must refuse it.
	leaking := *base
	leaking.Mounts = make(map[string]Mount, len(base.Mounts)+1)
	for k, v := range base.Mounts {
		leaking.Mounts[k] = v
	}
	leaking.Mounts["/mnt/leak"] = Mount{
		Guest: "/mnt/leak", Host: "/host/leak", Kind: KindGraft, Access: AccessRW,
		From: []string{"(snug)"},
	}
	err := leaking.Validate(newFakeEnv())
	if err == nil {
		t.Fatal("a KindGraft mount hand-placed in p.Mounts was accepted by Validate")
	}
	if !strings.Contains(err.Error(), "KindGraft in p.Mounts") {
		t.Errorf("unexpected message: %v", err)
	}

	// The default arm, exercised DIRECTLY against BwrapFlags — skipping
	// Validate on purpose, since this is the one place in this file allowed to:
	// the claim under test is what happens if Validate's refusal above is ever
	// bypassed, and the answer must be "fails loudly", never "silently omitted
	// or emitted as a real bind".
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("BwrapFlags over a policy with a KindGraft in p.Mounts did not panic — a " +
					"future Kind reaching this switch with no case would be silently OMITTED from " +
					"the argv instead, the exact shape CLAUDE.md warns about")
			}
			if !strings.Contains(fmt.Sprint(r), "unhandled Kind") {
				t.Errorf("panic message %v does not say \"unhandled Kind\"", r)
			}
		}()
		leaking.BwrapFlags(1000, 1000, func(string) int { return 9 })
	}()
}

// ── §7 item 10 ────────────────────────────────────────────────────────────────

// TestGraftCarriesAnAbuseSentence is G5's Why check, plus a sweep of every
// CALL to Policy.Graft in the shipped (non-test) source tree, asserting each
// one constructs its Graft literal with a non-empty Why. Today the sweep finds
// nothing to complain about, because nothing in the shipped code path calls
// Policy.Graft at all — Tier C (#125) has not landed, the same fact
// TestOnlyGraftWritesGrafts confirms a different way. Written now so the day a
// graft IS authored, this sweep is already watching rather than being bolted
// on after the fact.
// refusalGraftEmptyWhy is also used as a TestGoldenRefusals row
// (refusals_test.go), which is why it is split out rather than inlined below.
func refusalGraftEmptyWhy(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "why-probe")
	g.Why = ""
	return p.Graft(newFakeEnv(), g)
}

func TestGraftCarriesAnAbuseSentence(t *testing.T) {
	err := refusalGraftEmptyWhy(t)
	if err == nil {
		t.Fatal("a graft with an empty Why was accepted; every graft is the abuse sentence's only " +
			"home, since no profile authors one for a TOML comment to sit beside it")
	} else if !strings.Contains(err.Error(), "Why is empty") {
		t.Errorf("error %q does not name the empty Why", err)
	}

	// POSITIVE CONTROL for the refusal above — TestValidGraftFixtureIsAccepted
	// already proves validGraft's own Why is accepted; nothing further needed
	// here beyond that shared control.

	sites, dirs := graftCallSitesWithoutWhy(t)
	requireWalked(t, dirs)
	for _, s := range sites {
		t.Errorf("%s", s)
	}
	if len(sites) == 0 {
		t.Log("no policy.Graft call sites found under the module root with a missing or empty Why " +
			"(expected: Tier C, issue #125, has not landed — see the positive control below, " +
			"which proves this walk can actually see a violation)")
	}

	// POSITIVE CONTROL for the sweep: fed an in-memory fixture with a call
	// that omits Why, it must flag it — otherwise the zero found above proves
	// nothing about the real tree either.
	bad := "func evil(p *policy.Policy) error {\n" +
		"\treturn p.Graft(policy.Graft{Mount: policy.Mount{Guest: \"/x\"}})\n" +
		"}\n"
	if got := graftLiteralsWithoutWhy("control.go", bad); len(got) != 1 {
		t.Fatalf("control: the sweep's own checker did not flag a Graft{} call whose literal omits "+
			"Why — it would pass on any real omission too: %v", got)
	}
	good := "func fine(p *policy.Policy) error {\n" +
		"\treturn p.Graft(policy.Graft{Mount: policy.Mount{Guest: \"/x\"}, Why: \"because\"})\n" +
		"}\n"
	if got := graftLiteralsWithoutWhy("control.go", good); len(got) != 0 {
		t.Fatalf("control: the sweep flagged a Graft{} call whose literal DOES set a non-empty "+
			"Why: %v", got)
	}
}

// graftWhyCallRE finds a call to (something).Graft( — the method, not the
// type. Deliberately loose (it does not require the receiver to be a
// *Policy): the point of this sweep is "can I see a Why beside this call",
// and a stricter match would need full type information this package-local
// text scan does not have.
var graftWhyCallRE = regexp.MustCompile(`\.Graft\(`)

// graftWhyRE looks for a non-empty Why field inside the TEXT of one call's
// argument list.
var graftWhyRE = regexp.MustCompile(`Why:\s*"[^"]+"`)

// graftLiteralsWithoutWhy scans src for every `.Graft(...)` call and returns
// one line per call whose argument text does not contain a non-empty `Why:
// "..."`. Matching on the TEXT between the call's own parens, via bracket
// counting, rather than on an AST: this file's other sweeps use go/ast where
// the shape under test is a table (envnotesource_test.go); a single-method
// call site is simple enough that a text scan is the more readable choice,
// and the positive control above is what keeps that choice honest.
func graftLiteralsWithoutWhy(filename, src string) []string {
	var bad []string
	for _, loc := range graftWhyCallRE.FindAllStringIndex(src, -1) {
		depth := 1
		i := loc[1]
		for ; i < len(src) && depth > 0; i++ {
			switch src[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		call := src[loc[0]:i]
		if !graftWhyRE.MatchString(call) {
			line := 1 + strings.Count(src[:loc[0]], "\n")
			bad = append(bad, fmt.Sprintf("%s:%d: call to .Graft(...) has no literal, non-empty "+
				"Why field visible in its argument text: %s", filename, line, strings.TrimSpace(call)))
		}
	}
	return bad
}

// graftCallSitesWithoutWhy runs graftLiteralsWithoutWhy over every non-test
// .go file under the module root (moduleRoot, authoredwriters_test.go) —
// not just internal/, so a call site in cmd/snug is in scope too (issue
// #353). It also returns the directories it visited: requireWalked
// (norestriction_test.go) is the walk's own positive control, shared with
// P1/P2's sweep, so a future narrowing of the root fails loudly instead of
// shipping green.
func graftCallSitesWithoutWhy(t *testing.T) ([]string, map[string]bool) {
	t.Helper()
	root := moduleRoot(t)
	var bad []string
	dirs := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		// A source sweep walks a tree other packages' tests are writing in. An entry
		// that vanished between its parent's ReadDir and this call is not a source
		// file and is not this sweep's business: skipping it keeps a failure in
		// THIS package from being caused by another one (issue #350).
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Dotted directories (.claude/worktrees/ holds full copies of
			// this tree on other branches, in the primary checkout) and
			// vendor/ are skipped for the same reason sweepModule skips
			// them.
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		dirs[filepath.ToSlash(filepath.Dir(rel))] = true
		src, rerr := os.ReadFile(path)
		// The file can vanish between the walk naming it and this read, for
		// the reason above.
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		bad = append(bad, graftLiteralsWithoutWhy(rel, string(src))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad, dirs
}

// ── §7 item 11 ────────────────────────────────────────────────────────────────

func TestGraftAccessIsROorRW(t *testing.T) {
	p := mustResolveDefaults(t)
	g := validGraft(p, "access-probe")
	g.Access = AccessNone
	err := p.Graft(newFakeEnv(), g)
	if err == nil {
		t.Fatal("a graft with Access=none (neither ro nor rw) was accepted; Access is a " +
			"REQUIREMENT enforced by mount_setattr before move_mount, and \"none\" describes " +
			"nothing the stage can build")
	}
	if !strings.Contains(err.Error(), "must be ro or rw") {
		t.Errorf("error %q does not say Access must be ro or rw", err)
	}
}

// refusalGraftOptional is also used as a TestGoldenRefusals row.
func refusalGraftOptional(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "optional-probe")
	g.Optional = true
	return p.Graft(newFakeEnv(), g)
}

func TestGraftMayNotBeOptional(t *testing.T) {
	err := refusalGraftOptional(t)
	if err == nil {
		t.Fatal("a graft with Optional=true was accepted; -try semantics mean \"silently do " +
			"less\", and under Tier C the derived view IS the enforcement boundary — a graft " +
			"that silently did not happen is a different confinement from the one --dry-run " +
			"described")
	}
	if !strings.Contains(err.Error(), "Optional is not permitted") {
		t.Errorf("error %q does not say Optional is not permitted", err)
	}
}

// ── issue #55, finding F7 ─────────────────────────────────────────────────────
//
// checkGraft runs checkPathHygiene on a graft's Guest AND Host, the same two
// checks a mount's own Guest already gets — refusing a control character or a
// directional-override rune, because the ENGINE VIEW block renders one row
// per line in fixed columns and such a rune can forge a second row that looks
// like it came from somewhere else. Both calls were unasserted: deleting
// EITHER one left the whole suite green.

// refusalGraftGuestControlCharacter is also used as a TestGoldenRefusals row.
func refusalGraftGuestControlCharacter(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "guest-forge-probe")
	g.Guest += "\u202eDEGROF" // a directional override in the DESTINATION path
	return p.Graft(newFakeEnv(), g)
}

// TestGraftGuestRefusesAForgingRune is the regression test for the FIRST of
// F7's two unasserted checkPathHygiene calls: deleting the one on g.Guest in
// graft.go leaves the entire suite green without this test.
func TestGraftGuestRefusesAForgingRune(t *testing.T) {
	err := refusalGraftGuestControlCharacter(t)
	if err == nil {
		t.Fatal("a graft whose Guest contains a directional-override rune (U+202E) was accepted; " +
			"the ENGINE VIEW block renders one row per line, and such a rune can forge a row that " +
			"looks like it came from somewhere else")
	}
	if !strings.Contains(err.Error(), "graft destination") {
		t.Errorf("error %q does not say this is about the graft DESTINATION (Guest)", err)
	}
}

// refusalGraftSourceControlCharacter is also used as a TestGoldenRefusals row.
func refusalGraftSourceControlCharacter(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "source-forge-probe")
	g.Host += "\u202eDEGROF" // a directional override in the SOURCE path
	return p.Graft(newFakeEnv(), g)
}

// TestGraftSourceRefusesAForgingRune is the regression test for the SECOND of
// F7's two unasserted checkPathHygiene calls: deleting the one on g.Host in
// graft.go leaves the entire suite green without this test.
func TestGraftSourceRefusesAForgingRune(t *testing.T) {
	err := refusalGraftSourceControlCharacter(t)
	if err == nil {
		t.Fatal("a graft whose Host contains a directional-override rune (U+202E) was accepted; " +
			"the ENGINE VIEW block renders one row per line, and such a rune can forge a row that " +
			"looks like it came from somewhere else")
	}
	if !strings.Contains(err.Error(), "graft source") {
		t.Errorf("error %q does not say this is about the graft SOURCE (Host)", err)
	}

	// POSITIVE CONTROL, shared by both subtests above: the identical shape
	// with no forging rune is accepted.
	p := mustResolveDefaults(t)
	if err := p.Graft(newFakeEnv(), validGraft(p, "forge-control")); err != nil {
		t.Fatalf("control: a graft with no forging rune anywhere must be accepted: %v", err)
	}
}

func TestGraftFromNamesNoProfile(t *testing.T) {
	p := mustResolveDefaults(t)
	g := validGraft(p, "from-probe")
	g.From = []string{"@sys"}
	err := p.Graft(newFakeEnv(), g)
	if err == nil {
		t.Fatal("a graft whose From names @sys (a resolved profile) was accepted; no profile may " +
			"ever author a graft, and a From naming one means the caller copied provenance from a " +
			"Mount instead of writing the graft's own")
	}
	for _, want := range []string{"@sys", "No profile may author a graft"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// TestGraftMayNotCoverAnotherGraft is G2. Not itemised by number in the
// spec's §7 list, but required by §9's golden table ("graft-covers-graft"):
// checkGraft's own doc comment explains why the EXACT-same-Guest case is
// checked by Policy.Graft's map lookup rather than here, so this test is
// deliberately about two DIFFERENT guests in an ancestor relationship, which
// only checkGraft's G2 loop can see.
// refusalGraftCoversGraft is also used as a TestGoldenRefusals row: it installs
// the inner graft for real, then attempts an outer one covering it.
func refusalGraftCoversGraft(t testing.TB) error {
	p := resolveDefaults(t)
	inner := validGraft(p, "nest/child")
	if err := p.Graft(newFakeEnv(), inner); err != nil {
		t.Fatalf("fixture: the inner graft was refused: %v", err)
	}
	return p.Graft(newFakeEnv(), validGraft(p, "nest"))
}

func TestGraftMayNotCoverAnotherGraft(t *testing.T) {
	p := mustResolveDefaults(t)
	inner := validGraft(p, "nest/child")
	outer := validGraft(p, "nest")

	if err := p.Graft(newFakeEnv(), inner); err != nil {
		t.Fatalf("fixture: the inner graft was refused: %v", err)
	}
	err := p.Graft(newFakeEnv(), outer)
	if err == nil {
		t.Fatal("a graft at an ancestor of an existing graft was accepted; it would take the " +
			"descendant's destination with it in the engine's mount namespace")
	}
	for _, want := range []string{outer.Guest, inner.Guest, "CONTAIN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// The reverse order: outer first, then inner — the OTHER branch of G2's
	// loop.
	q := mustResolveDefaults(t)
	if err := q.Graft(newFakeEnv(), validGraft(q, "nest2")); err != nil {
		t.Fatalf("fixture: the outer graft was refused: %v", err)
	}
	err = q.Graft(newFakeEnv(), validGraft(q, "nest2/child"))
	if err == nil {
		t.Fatal("a graft at a descendant of an existing graft was accepted")
	}
	if !strings.Contains(err.Error(), "CONTAINS") {
		t.Errorf("error %q does not say CONTAINS", err)
	}
}

// ── issue #55, finding F2 ─────────────────────────────────────────────────────

// engineOwnedWriteRE matches an assignment into p.EngineOwnedHostPaths, in
// both its shapes — OwnEngineHostPath contains one of EACH, two lines apart
// (`p.EngineOwnedHostPaths = map[string]bool{}` when nil, then
// `p.EngineOwnedHostPaths[path] = true`) — the same reason graftWriteRE
// widened past the bracket-only form for p.Grafts (F3b): a second WHOLE-MAP
// write anywhere else in the tree would not stand out in review next to the
// legitimate one already there, and a bracket-only regex could not see it.
var engineOwnedWriteRE = regexp.MustCompile(`\.EngineOwnedHostPaths\s*(\[[^]]*\])?\s*=[^=]`)

// TestOnlyOneWriterOfEngineOwnedHostPaths is TestOnlyGraftWritesGrafts's twin
// for the OTHER half of G4. Before OwnEngineHostPath existed,
// EngineOwnedHostPaths had a doc comment and a reader (checkGraft's second
// disjunct) but NO writer, no hygiene check and no sweep: any string placed
// in the map — by a hand-built Policy, or a future Tier C caller reaching for
// the field directly — passed G4 unconditionally, with nothing bounding it to
// a grant the sandbox's own policy made (issue #55, finding F2). This is what
// makes OwnEngineHostPath's writer discipline checkable rather than merely
// documented.
func TestOnlyOneWriterOfEngineOwnedHostPaths(t *testing.T) {
	// The walk root is the module root (moduleRoot, authoredwriters_test.go),
	// not internal/ — a write in cmd/snug is in scope (issue #353). dirs is
	// the walk's own positive control (requireWalked,
	// norestriction_test.go): without it a future narrowing of root ships
	// green again.
	root := moduleRoot(t)
	var hits []string
	dirs := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		// A source sweep walks a tree other packages' tests are writing in. An entry
		// that vanished between its parent's ReadDir and this call is not a source
		// file and is not this sweep's business: skipping it keeps a failure in
		// THIS package from being caused by another one (issue #350).
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		dirs[filepath.ToSlash(filepath.Dir(rel))] = true
		src, rerr := os.ReadFile(path)
		// The file can vanish between the walk naming it and this read, for
		// the reason above.
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		text := string(src)
		for _, loc := range engineOwnedWriteRE.FindAllStringIndex(text, -1) {
			line := 1 + strings.Count(text[:loc[0]], "\n")
			hits = append(hits, fmt.Sprintf("%s:%d", rel, line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	requireWalked(t, dirs)

	// Two hits are EXPECTED from the one legitimate writer — the nil-init
	// whole-map assignment and the bracketed one, both inside
	// OwnEngineHostPath — so the assertion is "every hit traces to
	// internal/policy/graft.go", not "exactly one", which the widened
	// pattern can no longer promise even for the correct code.
	if len(hits) == 0 {
		t.Fatal("found ZERO assignments into a .EngineOwnedHostPaths map under the module root — " +
			"OwnEngineHostPath itself must trip this sweep, or it is not testing anything")
	}
	for _, h := range hits {
		if !strings.HasPrefix(h, "internal/policy/graft.go:") {
			t.Errorf("found an assignment into p.EngineOwnedHostPaths outside "+
				"internal/policy/graft.go, at %s — OwnEngineHostPath is meant to be the only "+
				"writer", h)
		}
	}

	// POSITIVE CONTROL: the pattern can tell a write from a read and from a
	// comparison.
	fixture := "func evil(p *Policy) { p.EngineOwnedHostPaths[\"x\"] = true }\n" +
		"// a read: _ = p.EngineOwnedHostPaths[\"y\"]\n" +
		"// a comparison: ok := a == p.EngineOwnedHostPaths[\"z\"]\n" +
		"for k := range p.EngineOwnedHostPaths { _ = k }\n"
	if got := engineOwnedWriteRE.FindAllString(fixture, -1); len(got) != 1 {
		t.Fatalf("control: the pattern found %d writes in a fixture with exactly one real "+
			"assignment, one read, one comparison and one range: %v", len(got), got)
	}
	// SECOND POSITIVE CONTROL: the WHOLE-MAP form, which the pre-F3b spelling
	// of graftWriteRE could not see for p.Grafts and which this field carries
	// too (OwnEngineHostPath's own nil-init line).
	if got := engineOwnedWriteRE.FindAllString(
		"p.EngineOwnedHostPaths = map[string]bool{}\n", -1); len(got) != 1 {
		t.Fatalf("control: the pattern does not see the WHOLE-MAP assignment shape: %v", got)
	}
}

// TestOwnEngineHostPathIsTheOnlyWayIn is the behavioural half of F2: a graft
// whose Host the sandbox's own grants do NOT expose is refused unless
// OwnEngineHostPath declared it first — asserted directly, rather than only
// inferred from the sweep above finding one writer.
func TestOwnEngineHostPathIsTheOnlyWayIn(t *testing.T) {
	p := mustResolveDefaults(t)
	env := newFakeEnv()

	unowned := validGraft(p, "unowned")
	unowned.Host = "/home/u/secrets" // resolvable, but no grant in the default selection exposes it
	if err := p.Graft(env, unowned); err == nil {
		t.Fatal("a graft sourced from an UNOWNED, ungranted host path was accepted")
	}

	if err := p.OwnEngineHostPath(env, "/home/u/secrets"); err != nil {
		t.Fatalf("fixture: OwnEngineHostPath refused a hygienic absolute path: %v", err)
	}
	owned := validGraft(p, "owned")
	owned.Host = "/home/u/secrets"
	if err := p.Graft(env, owned); err != nil {
		t.Fatalf("a graft sourced from a path OwnEngineHostPath declared its own was refused: %v", err)
	}
}

// ── issue #55, finding F3a ────────────────────────────────────────────────────

// TestValidateRefusesAHandBuiltGraft is the regression test for F3a. Deleting
// Validate's graft re-check loop (validate.go) leaves the ENTIRE test suite
// green, because nothing installs an unchecked graft through any path this
// suite exercised — Policy.Graft is the only SHIPPED writer, and it runs
// checkGraft itself. This test writes DIRECTLY into p.Grafts, bypassing
// Policy.Graft (and every one of G1-G5) entirely, the same shape a hand-built
// Policy or a future careless Tier C writer could produce, and requires
// Validate to catch each one on its own.
func TestValidateRefusesAHandBuiltGraft(t *testing.T) {
	env := newFakeEnv()
	cases := []struct {
		name   string
		mutate func(g *Graft)
	}{
		// G1: a graft covering one of snug's own paths.
		{"covers_run", func(g *Graft) { g.Guest = "/run" }},
		// G5: the abuse sentence, the one thing a Graft literal is required to
		// carry since no profile can write one.
		{"empty_why", func(g *Graft) { g.Why = "" }},
		// G4: a source no grant exposes and snug never declared its own —
		// the host's ssh-agent, session D-Bus, Wayland, rootless podman socket.
		{"run_user_source", func(g *Graft) { g.Host = "/run/user/1000" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolveDefaults(t)
			g := validGraft(p, "handbuilt-"+tc.name)
			tc.mutate(&g)
			g.Authored = true
			p.Grafts = map[string]Graft{g.Guest: g} // RAW assignment — Policy.Graft never runs
			if err := p.Validate(env); err == nil {
				t.Fatalf("Validate accepted a hand-built graft that bypassed Policy.Graft and every "+
					"one of G1-G5 (%s) — the re-check loop is the only thing standing between a "+
					"careless writer and an unchecked graft reaching bwrap.go/--dry-run (issue #55, "+
					"finding F3a)", tc.name)
			}
		})
	}

	// POSITIVE CONTROL: a hand-built graft that IS otherwise valid must still
	// be accepted — proving Validate is re-running G1-G5, not refusing every
	// hand-built graft unconditionally regardless of content.
	p := mustResolveDefaults(t)
	g := validGraft(p, "handbuilt-valid")
	g.Authored = true
	p.Grafts = map[string]Graft{g.Guest: g}
	if err := p.Validate(env); err != nil {
		t.Fatalf("control: a hand-built but otherwise VALID graft must still be accepted: %v", err)
	}
}

// ── issue #55, finding F6 (redteam round 2) ──────────────────────────────────
//
// G4 used to be purely lexical: checkGraft asked HostPathVisible about the
// literal string in g.Host, but open_tree(2) FOLLOWS a final symlink
// (measured) and the sandbox's writable target is attacker-controlled, so
// `ln -s ~/.ssh $TARGET/link` produced a Host that passed G4 on the NAME
// while the kernel would have opened whatever the link pointed at — the
// identical hole a previous redteam round found and fixed in the container
// proxy's own bind filter. The fix resolves BEFORE any rule looks at Host,
// inside Policy.Graft, and stores the RESOLVED path; checkGraft additionally
// requires an installed graft's Host to already be a fixed point of that same
// resolution, closing F3a's door for exactly this field.

// refusalGraftSourceSymlinkEscapesTheSandbox is also used as a
// TestGoldenRefusals row (graft_source_symlink_escapes_the_sandbox, the F6
// decision's §6 golden row): the existing G4 message with the appended
// "named as …, which is a SYMLINK on the host" sentence.
func refusalGraftSourceSymlinkEscapesTheSandbox(t testing.TB) error {
	p := resolveDefaults(t)
	target := p.Target
	env := newFakeEnv()
	env.links[target+"/link"] = "/home/u/secrets" // planted by the payload; no grant exposes this
	g := validGraft(p, "resolve-probe")
	g.Host = target + "/link"
	return p.Graft(env, g)
}

// TestGraftSourceIsResolvedBeforeItIsJudged: a graft whose Host is a symlink
// the payload planted (inside the writable target) resolving to a host path
// no grant exposes is refused, and the refusal NAMES the resolved
// destination — not the literal string that was asked about, which is the
// one a human could otherwise mistake for something harmless.
func TestGraftSourceIsResolvedBeforeItIsJudged(t *testing.T) {
	err := refusalGraftSourceSymlinkEscapesTheSandbox(t)
	if err == nil {
		t.Fatal("a graft whose Host is a SYMLINK the payload can plant, resolving to " +
			"/home/u/secrets (a path no grant exposes), was accepted — open_tree(2) follows a " +
			"final symlink (measured, issue #55, finding F6), so the literal string judged is not " +
			"the tree the kernel would open")
	}
	if !strings.Contains(err.Error(), "/home/u/secrets") {
		t.Errorf("error %q does not name the RESOLVED destination /home/u/secrets — it must judge "+
			"(and report) what the link resolves to, not the name that was asked about", err)
	}
	// The refusal must be G4's ORDINARY visibility disjunct, with the
	// symlink sentence appended — not checkGraft's separate "source is not a
	// fixed point" refusal, which fires only for a graft that bypassed
	// Policy.Graft's own resolution (F3a's family, TestValidateRefusesAGraftWhoseSourceIsUnresolved).
	// A Policy.Graft call that skipped normalising Host would still trip
	// THAT check from inside checkGraft and so still produce a non-nil
	// error naming /home/u/secrets — asserting the SPECIFIC message this
	// caller is meant to reach is what keeps this test pinned to
	// Policy.Graft's own normalisation step rather than passing for a
	// different reason.
	for _, want := range []string{"does not expose this host path", "which is a SYMLINK on the host"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q — this must be G4's ordinary visibility "+
				"refusal (with the symlink sentence appended), not some other rule firing instead", err, want)
		}
	}

	// POSITIVE CONTROL: the identical shape of graft, with a Host that is NOT
	// a symlink at all (still strictly inside the writable target), is
	// accepted — the refusal above is about what the link resolves TO, not
	// about grafting out of the target in general.
	p2 := mustResolveDefaults(t)
	if err := p2.Graft(newFakeEnv(), validGraft(p2, "resolve-control")); err != nil {
		t.Fatalf("control: a graft whose Host is not a symlink must be accepted: %v", err)
	}
}

// TestGraftSourceIsStoredResolved: a graft whose Host resolves to a VISIBLE
// host path is accepted, and — this is the field this fix exists to set
// correctly — the value STORED in p.Grafts is the RESOLVED path, not the
// literal one, with HostAsked carrying what was actually named. Storing the
// literal would leave the stage calling open_tree(2) on the attacker's link
// even though checkGraft judged the safe destination — validating without
// normalising is unsound here no matter where the validation sits (F6
// decision §0).
func TestGraftSourceIsStoredResolved(t *testing.T) {
	p := mustResolveDefaults(t)
	target := p.Target

	env := newFakeEnv()
	env.links[target+"/link"] = "/usr/share" // visible: @sys grants ro /usr

	g := validGraft(p, "stored-probe")
	g.Host = target + "/link"
	if err := p.Graft(env, g); err != nil {
		t.Fatalf("fixture: a graft whose source resolves to a VISIBLE host path (/usr/share, "+
			"under @sys's ro /usr) was refused: %v", err)
	}
	stored := p.Grafts[g.Guest]
	if stored.Host != "/usr/share" {
		t.Errorf("p.Grafts[%s].Host = %q, want the RESOLVED path /usr/share — a graft installed "+
			"with an unresolved source is the exact hole issue #55 F6 is about: open_tree(2) opens "+
			"whatever the link points at, not the string checkGraft judged", g.Guest, stored.Host)
	}
	if stored.HostAsked != target+"/link" {
		t.Errorf("p.Grafts[%s].HostAsked = %q, want %q — the path snug's own code named, kept only "+
			"so --dry-run can show it differs from the path it will open", g.Guest, stored.HostAsked, target+"/link")
	}

	// POSITIVE CONTROL: a non-symlink source is stored UNCHANGED, and
	// HostAsked stays empty — catches "validated but not selectively
	// rewritten", i.e. a fix that stamps HostAsked (or mutates Host) on every
	// graft regardless of whether resolution actually changed anything.
	p2 := mustResolveDefaults(t)
	g2 := validGraft(p2, "stored-control")
	if err := p2.Graft(env, g2); err != nil {
		t.Fatalf("control: %v", err)
	}
	stored2 := p2.Grafts[g2.Guest]
	if stored2.Host != g2.Host {
		t.Errorf("control: a non-symlink source's Host changed from %q to %q", g2.Host, stored2.Host)
	}
	if stored2.HostAsked != "" {
		t.Errorf("control: HostAsked = %q for a non-symlink source, want empty", stored2.HostAsked)
	}
}

// TestValidateRefusesAGraftWhoseSourceIsUnresolved is F3a's family, specific
// to F6's own fixed-point clause: a hand-built Policy that writes an
// UNRESOLVED symlink literal straight into p.Grafts — bypassing
// Policy.Graft's own resolution entirely — must be refused by Validate's
// re-check. Without this, "Policy.Graft always resolves" is a fact about one
// function, not about every graft that can reach bwrap.go or --dry-run.
func TestValidateRefusesAGraftWhoseSourceIsUnresolved(t *testing.T) {
	p := mustResolveDefaults(t)
	target := p.Target

	env := newFakeEnv()
	env.links[target+"/link"] = "/usr/share"

	g := validGraft(p, "unresolved-probe")
	g.Host = target + "/link" // UNRESOLVED — the literal, not what it resolves to
	g.Authored = true
	p.Grafts = map[string]Graft{g.Guest: g}
	if err := p.Validate(env); err == nil {
		t.Fatal("Validate accepted a hand-built graft whose stored Host is an UNRESOLVED symlink — " +
			"the fixed-point check exists exactly to close this door (issue #55, finding F6)")
	}

	// POSITIVE CONTROL: the same graft, with Host already the RESOLVED path,
	// is accepted — this is the only thing that makes the fixed-point clause
	// falsifiable, rather than a check that refuses every hand-built graft
	// regardless of content.
	p2 := mustResolveDefaults(t)
	g2 := validGraft(p2, "unresolved-control")
	g2.Host = "/usr/share"
	g2.Authored = true
	p2.Grafts = map[string]Graft{g2.Guest: g2}
	if err := p2.Validate(env); err != nil {
		t.Fatalf("control: a hand-built graft whose Host is ALREADY resolved must be accepted: %v", err)
	}
}

// TestGraftSourceThatCannotBeResolvedIsJudgedLexically: a Host that
// ResolveExistingHostPath cannot resolve at all (nothing on the fake host
// exists anywhere along its ancestry) must still produce G4's ordinary
// visibility refusal, never a resolution error of its own — "a resolution
// FAILURE is not a refusal and must not become one" (F6 decision §2c),
// because making existence a policy input would let a payload flip which
// refusal a human sees by creating or deleting a directory.
func TestGraftSourceThatCannotBeResolvedIsJudgedLexically(t *testing.T) {
	p := mustResolveDefaults(t)
	env := newFakeEnv() // "/run/user/1000" is absent from fakeEnv entirely, all the way up to "/"

	unresolved := validGraft(p, "cannot-resolve")
	unresolved.Host = "/run/user/1000"
	err := p.Graft(env, unresolved)
	if err == nil {
		t.Fatal("a graft sourced from /run/user/1000 (unresolvable on the fake host, and no grant " +
			"exposes it) was accepted")
	}
	if !strings.Contains(err.Error(), "does not expose this host path") {
		t.Errorf("error %q is not G4's ordinary visibility refusal — an unresolvable source must "+
			"fall back to the LEXICAL form and let G4 speak, not surface a resolution failure of "+
			"its own", err)
	}

	// POSITIVE CONTROL: a RESOLVABLE but equally invisible source (a real
	// directory on the fake host, granted to nobody) must produce the
	// IDENTICAL class of refusal — the two arms (resolution succeeds and
	// finds nothing granted; resolution fails outright) must not print
	// different messages for the same underlying fact.
	p2 := mustResolveDefaults(t)
	resolvable := validGraft(p2, "resolvable-invisible")
	resolvable.Host = "/home/u/secrets" // exists in fakeEnv.dirs, granted to no profile
	err2 := p2.Graft(env, resolvable)
	if err2 == nil {
		t.Fatal("control: a graft sourced from /home/u/secrets (resolvable, granted to nobody) was accepted")
	}
	if !strings.Contains(err2.Error(), "does not expose this host path") {
		t.Errorf("control: error %q is not G4's visibility refusal either", err2)
	}
}

// ── issue #55, finding F8 ─────────────────────────────────────────────────────

// refusalGraftFromWearsTheSigil is also used as a TestGoldenRefusals row.
// @podman-socket is a real, sigil-marked builtin name in this package's
// registry, and — the point — it is NOT in testDefaults, so a
// From-against-p.Profiles check alone would have let this straight through,
// exactly as F8 measured.
func refusalGraftFromWearsTheSigil(t testing.TB) error {
	p := resolveDefaults(t)
	if slices.Contains(p.Profiles, ProfileName("@podman-socket")) {
		t.Fatal("fixture: @podman-socket is in THIS run's resolved profiles — the point of this " +
			"case is a sigil name that was never selected at all")
	}
	g := validGraft(p, "sigil-probe")
	g.From = []string{"@podman-socket"}
	return p.Graft(newFakeEnv(), g)
}

// TestGraftFromMayNotWearTheSigil is the regression test for F8: checkGraft
// used to compare From only against p.Profiles, THIS RUN's resolved
// selection — so From: []string{"@podman-socket"} passed on any selection
// that did not happen to include @podman-socket, forging the one guarantee
// the @ sigil on --dry-run exists to make ("a name marked @ came from snug's
// own resolved profile set"). The fix requires From to be EXACTLY
// []string{"(snug)"}, which refuses a sigil-marked name whether or not it was
// selected — this test's whole point is the UNSELECTED case, since the
// selected one (TestGraftFromNamesNoProfile) could pass on a narrower,
// selection-only check that F8 already defeated once.
func TestGraftFromMayNotWearTheSigil(t *testing.T) {
	err := refusalGraftFromWearsTheSigil(t)
	if err == nil {
		t.Fatal("a graft whose From is [\"@podman-socket\"] — a real @-marked builtin name, not even " +
			"selected by this run — was accepted; the @ sigil on --dry-run is supposed to be a " +
			"guarantee that a name came from snug's own resolved profile set, and here it would be " +
			"settable by a Graft literal (issue #55, finding F8)")
	}
	for _, want := range []string{"@podman-socket", "From is"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: the only From this ever accepts.
	p2 := mustResolveDefaults(t)
	if err := p2.Graft(newFakeEnv(), validGraft(p2, "sigil-control")); err != nil {
		t.Fatalf("control: From=[\"(snug)\"] must be accepted: %v", err)
	}
}
