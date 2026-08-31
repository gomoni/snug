package policy

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── Half A: CheckEngineBinary (internal/policy/engineexec.go) ───────────────
//
// CheckEngineBinary judges a FILE, so there is no tree arm for it — only the
// ancestor arm HostPathVisible already answers. Six rows: four ACCEPT and two
// REFUSE, matching issue #405's §5 matrix. The four ACCEPT rows are the ones
// an over-broad predicate destroys, so each one is paired with a fixture
// control proving the path really WOULD be refused if the predicate were
// "visible at all" rather than "writable, at or above".
func TestCheckEngineBinary(t *testing.T) {
	// A1: a READ-ONLY ancestor. /home/u/proj is granted ro by @parent-ro, which
	// this row SELECTS (issue #550 took it out of the defaults), and
	// /home/u/proj/other/podman sits under it but nowhere near @cwd-rw's rw
	// grant at /home/u/proj/sub — so the only mount that covers it at all is
	// read-only, and CheckEngineBinary must not refuse on visibility alone.
	t.Run("A1: read-only ancestor is accepted", func(t *testing.T) {
		p := mustResolve(t, withParentRo()...)
		const path = "/home/u/proj/other/podman"
		if !p.HostPathVisible(path, false) {
			t.Fatalf("fixture: %s is not visible at all, so this row asserts nothing about a "+
				"read-only ancestor specifically", path)
		}
		if p.HostPathVisible(path, true) {
			t.Fatalf("fixture: %s is WRITE-visible, so this is not the read-only case this row "+
				"means to exercise", path)
		}
		if err := p.CheckEngineBinary(path); err != nil {
			t.Errorf("a read-only ancestor refused the engine binary: %v — CheckEngineBinary must "+
				"ask about WRITE visibility, not mere visibility", err)
		}
	})

	// A2: the real OS binary, granted ro by @sys. The predicate this ticket
	// adds must not turn "the sandbox can see podman" into a reason to refuse
	// it — only "the sandbox can WRITE it" is the question.
	t.Run("A2: /usr/bin/podman via @sys is accepted", func(t *testing.T) {
		p := resolveDefaults(t)
		const path = "/usr/bin/podman"
		if !p.HostPathVisible(path, false) {
			t.Fatalf("fixture: %s is not visible under @sys's /usr grant — the fixture no longer "+
				"matches @sys's shape", path)
		}
		if err := p.CheckEngineBinary(path); err != nil {
			t.Errorf("the real system podman, read-only under @sys, was refused: %v", err)
		}
	})

	// A3: entirely ungranted. A predicate that reads "must be visible" (the
	// wrong direction) would refuse this, breaking every $SNUG_PODMAN pointed
	// outside the sandbox entirely — which is the common, legitimate case of
	// running a distro podman this profile selection never named.
	t.Run("A3: an entirely ungranted path is accepted", func(t *testing.T) {
		p := resolveDefaults(t)
		const path = "/srv/other/podman"
		if p.HostPathVisible(path, false) {
			t.Fatalf("fixture: %s is visible to SOME grant — this row means to exercise a path no "+
				"grant of the default selection names at all", path)
		}
		if err := p.CheckEngineBinary(path); err != nil {
			t.Errorf("an entirely ungranted path was refused: %v", err)
		}
	})

	// A4: the strings.HasPrefix sibling off-by-one. /home/u/proj/sub is
	// @cwd-rw's rw grant; /home/u/proj/sub-other/podman merely shares a
	// string prefix with it and is a completely different, ungranted
	// directory. A bare strings.HasPrefix(path, grant) would match this; the
	// slash-boundary check HostPathVisible actually uses must not.
	t.Run("A4: a sibling sharing a string prefix is accepted", func(t *testing.T) {
		p := resolveDefaults(t)
		const path = "/home/u/proj/sub-other/podman"
		if p.HostPathVisible(path, true) {
			t.Fatalf("fixture bug (or the off-by-one this row exists to catch): %s reads as "+
				"write-visible against the rw grant at /home/u/proj/sub, but it is a SIBLING, "+
				"not a descendant", path)
		}
		if err := p.CheckEngineBinary(path); err != nil {
			t.Errorf("a sibling sharing only a string prefix with the rw grant at /home/u/proj/sub "+
				"was refused: %v — this is the classic strings.HasPrefix off-by-one", err)
		}
	})

	// A5: strictly INSIDE the target's own rw grant — the finding itself,
	// and the golden row (engine_binary_inside_a_writable_grant).
	t.Run("A5: strictly inside a writable grant is refused", func(t *testing.T) {
		p := resolveDefaults(t)
		const path = "/home/u/proj/sub/bin/podman"
		if !p.HostPathVisible(path, true) {
			t.Fatalf("fixture: %s is not write-visible, so this row would be asserting nothing", path)
		}
		err := p.CheckEngineBinary(path)
		if err == nil {
			t.Fatal("a binary strictly inside @cwd-rw's rw grant was accepted")
		}
		for _, want := range []string{path, "WRITABLE", "uid 0", "CAP_SYS_ADMIN"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not contain %q", err, want)
			}
		}
	})

	// A6: EXACTLY the rw grant's own Host — the boundary of the ancestor
	// arm's "host == m.Host" branch, distinct from A5's "strictly below"
	// branch.
	t.Run("A6: exactly the rw grant's Host is refused", func(t *testing.T) {
		p := resolveDefaults(t)
		const path = "/home/u/proj/sub"
		if !p.HostPathVisible(path, true) {
			t.Fatalf("fixture: %s is not write-visible", path)
		}
		if err := p.CheckEngineBinary(path); err == nil {
			t.Fatal("a path EQUAL to the rw grant's own Host was accepted")
		}
	})
}

// ── Half B: CheckEngineToolchainTree (internal/policy/engineexec.go) ────────
//
// viaEngineToolchain and viaGraft are the two entry points issue #405 names —
// B1 asks EngineToolchain, before any graft exists at all; B2 keeps G4b's own
// call inside checkGraft, reached from an already-recorded root. Both must
// refuse the same two cases (issue #390's ancestor arm, issue #405's tree
// arm), because either could regress independently of the other.
func viaEngineToolchain(t testing.TB, root string) error {
	t.Helper()
	p := resolveDefaults(t)
	return p.EngineToolchain(newFakeEnv(), root)
}

// viaGraft exercises G4b directly: p.EngineToolchainRoot is set BYPASSING
// EngineToolchain's own writer (legal only in _test.go —
// TestOnlyOneWriterOfEngineToolchainRoot's source sweep excludes it), exactly
// as refusalGraftToolchainRootWritable does, so this reaches checkGraft's
// delegation to CheckEngineToolchainTree even though EngineToolchain itself
// would have refused first.
func viaGraft(t testing.TB, root string) error {
	t.Helper()
	p := resolveDefaults(t)
	p.EngineToolchainRoot = root
	g := validGraft(p, "toolchain")
	g.Host = root
	g.Access = AccessRO
	return p.Graft(newFakeEnv(), g)
}

func TestCheckEngineToolchainTree(t *testing.T) {
	// B1: the ANCESTOR arm — root itself is the target, which @cwd-rw grants
	// rw. Exercised through BOTH entry points.
	t.Run("B1: root itself writable is refused via EngineToolchain", func(t *testing.T) {
		const root = "/home/u/proj/sub"
		p := resolveDefaults(t)
		if !p.HostPathVisible(root, true) {
			t.Fatalf("fixture: %s is not write-visible", root)
		}
		err := viaEngineToolchain(t, root)
		if err == nil {
			t.Fatal("a toolchain root equal to the rw target was accepted")
		}
		if strings.Contains(err.Error(), "TREE") {
			t.Errorf("the ANCESTOR arm's refusal mentions TREE, which is the tree arm's wording: %v", err)
		}
		if !strings.Contains(err.Error(), "WRITABLE") {
			t.Errorf("refusal %q does not say WRITABLE", err)
		}
	})
	t.Run("B1: root itself writable is refused via Graft (G4b)", func(t *testing.T) {
		const root = "/home/u/proj/sub"
		err := viaGraft(t, root)
		if err == nil {
			t.Fatal("a graft of a writable toolchain root was accepted")
		}
		if !strings.Contains(err.Error(), "cannot graft") {
			t.Errorf("refusal %q does not carry checkGraft's own prefix", err)
		}
		if !strings.Contains(err.Error(), "WRITABLE") {
			t.Errorf("refusal %q does not say WRITABLE", err)
		}
	})

	// B2: the TREE arm — the finding. Root is /home/u/proj, granted RO by
	// @parent-ro; /home/u/proj/sub sits strictly below it and IS granted rw
	// by @cwd-rw. The ancestor arm must NOT fire here — asserted explicitly,
	// per the instruction that without this assertion the row can pass on
	// unfixed code by silently falling through the OLD ancestor-only check.
	t.Run("B2: a writable grant inside the tree is refused via EngineToolchain", func(t *testing.T) {
		const root = "/home/u/proj"
		const inside = "/home/u/proj/sub"
		p := resolveDefaults(t)
		if p.HostPathVisible(root, true) {
			t.Fatalf("fixture: %s is itself write-visible — this row means to exercise the TREE "+
				"arm, not the ancestor arm; a root that trips the ancestor arm proves nothing "+
				"about the tree arm existing at all", root)
		}
		if len(p.writableGrantsBelow(root)) == 0 {
			t.Fatalf("fixture: nothing below %s reads as writable, so this row would be asserting "+
				"nothing", root)
		}
		err := viaEngineToolchain(t, root)
		if err == nil {
			t.Fatal("a toolchain root containing a writable grant below it was accepted")
		}
		if !strings.Contains(err.Error(), "TREE") {
			t.Errorf("refusal %q does not say TREE", err)
		}
		if !strings.Contains(err.Error(), inside) {
			t.Errorf("refusal %q does not name the offending path %s", err, inside)
		}
	})
	t.Run("B2: a writable grant inside the tree is refused via Graft (G4b)", func(t *testing.T) {
		const root = "/home/u/proj"
		const inside = "/home/u/proj/sub"
		p := resolveDefaults(t)
		if p.HostPathVisible(root, true) {
			t.Fatalf("fixture: %s is itself write-visible", root)
		}
		if len(p.writableGrantsBelow(root)) == 0 {
			t.Fatalf("fixture: nothing below %s reads as writable", root)
		}
		err := viaGraft(t, root)
		if err == nil {
			t.Fatal("a graft recording a tree-writable toolchain root was accepted")
		}
		if !strings.Contains(err.Error(), "TREE") {
			t.Errorf("refusal %q does not say TREE", err)
		}
		if !strings.Contains(err.Error(), inside) {
			t.Errorf("refusal %q does not name %s", err, inside)
		}
	})

	// B3: ACCEPT — a read-only ancestor with NO writable descendant. /usr is
	// ro via @sys, and nothing rw is nested inside it in the default
	// selection.
	t.Run("B3: read-only root with no writable descendant is accepted", func(t *testing.T) {
		const root = "/usr"
		p := resolveDefaults(t)
		if p.HostPathVisible(root, true) {
			t.Fatalf("fixture: %s is write-visible, which is not the case this row means to test", root)
		}
		if got := p.writableGrantsBelow(root); len(got) != 0 {
			t.Fatalf("fixture: %s has writable descendants (%v) in the default selection — this row "+
				"means to test the clean read-only case", root, got)
		}
		if err := viaEngineToolchain(t, root); err != nil {
			t.Errorf("a read-only tree with nothing writable inside it was refused: %v", err)
		}
	})

	// B4: ACCEPT — an entirely ungranted root: no ancestor match, nothing
	// writable below it either.
	t.Run("B4: an entirely ungranted root is accepted", func(t *testing.T) {
		const root = "/srv/bin"
		p := resolveDefaults(t)
		if p.HostPathVisible(root, true) || p.HostPathVisible(root, false) {
			t.Fatalf("fixture: %s is visible to some grant of the default selection", root)
		}
		if got := p.writableGrantsBelow(root); len(got) != 0 {
			t.Fatalf("fixture: %s unexpectedly has writable descendants: %v", root, got)
		}
		if err := viaEngineToolchain(t, root); err != nil {
			t.Errorf("an entirely ungranted root was refused: %v", err)
		}
	})

	// B5: ACCEPT — the tree arm's OWN sibling off-by-one. "/home/u/proj/su"
	// is a bare string prefix of the rw grant "/home/u/proj/sub", not an
	// ancestor of it; a hand-rolled strings.HasPrefix in writableGrantsBelow
	// would wrongly include /home/u/proj/sub as "below" this root.
	// CheckEngineToolchainTree is asked directly (bypassing EngineToolchain's
	// own resolution, which requires an existing path) because this row is
	// about the LEXICAL predicate, not about resolving a fixture directory
	// that need not exist on the fake host.
	t.Run("B5: a tree-level sibling sharing a string prefix is accepted", func(t *testing.T) {
		p := resolveDefaults(t)
		const root = "/home/u/proj/su"
		if got := p.writableGrantsBelow(root); len(got) != 0 {
			t.Fatalf("fixture bug (or the off-by-one this row exists to catch): writableGrantsBelow(%q) "+
				"= %v, but /home/u/proj/sub is a SIBLING of %q, not a descendant", root, got, root)
		}
		if err := p.CheckEngineToolchainTree(root); err != nil {
			t.Errorf("a sibling sharing only a string prefix with the rw grant was refused: %v", err)
		}
	})

	// B6: REFUSE — depth independence. /home/u is granted only as a TMPFS by
	// @home (no KindBind, so the ancestor arm cannot see it at all), and
	// /home/u/proj/sub — three levels down — is @cwd-rw's rw grant. The tree
	// arm must catch a writable grant at ANY depth below root, not just an
	// immediate child.
	t.Run("B6: a writable grant several levels below root is refused", func(t *testing.T) {
		const root = "/home/u"
		const inside = "/home/u/proj/sub"
		p := resolveDefaults(t)
		if p.HostPathVisible(root, true) {
			t.Fatalf("fixture: %s is itself write-visible — this row means to test the tree arm "+
				"alone, at depth, not the ancestor arm", root)
		}
		if got := p.writableGrantsBelow(root); len(got) == 0 {
			t.Fatalf("fixture: nothing below %s reads as writable", root)
		}
		err := viaEngineToolchain(t, root)
		if err == nil {
			t.Fatal("a root whose tree contains a writable grant three levels down was accepted")
		}
		if !strings.Contains(err.Error(), inside) {
			t.Errorf("refusal %q does not name %s", err, inside)
		}
	})
}

// ── The partition property ───────────────────────────────────────────────────
//
// For any root, at most one of HostPathVisible(root, true) (the ancestor arm)
// and len(writableGrantsBelow(root)) > 0 (the tree arm) may hold. Issue #405's
// second half exists precisely because nothing asked the SECOND arm at all —
// this test is the one that would have caught its absence, since it fails if
// either arm starts overlapping the other (which "deleting" either one, in
// the sense of merging their questions back into one, produces) or if the
// tree arm's STRICT exclusion of the equal case is dropped.
func TestEngineToolchainTreePartitionsWithHostPathVisible(t *testing.T) {
	p := resolveDefaults(t)

	var roots []string
	for _, m := range p.Mounts {
		if m.Kind != KindBind || m.Host == "" {
			continue
		}
		h := m.Host
		roots = append(roots,
			h,                                // the grant itself
			parentOf(h),                      // its parent
			h+"/x",                           // a synthetic child
			"/",                              // the top of the lattice
			parentOf(h)+"/"+baseOf(h)+"-sib", // a sibling sharing a string prefix
		)
	}
	if len(roots) == 0 {
		t.Fatal("fixture: the default policy has no KindBind mounts at all — this test would be " +
			"asserting nothing")
	}

	overlaps, gaps := 0, 0
	for _, root := range dedupStrings(roots) {
		ancestor := p.HostPathVisible(root, true)
		tree := len(p.writableGrantsBelow(root)) > 0
		if ancestor && tree {
			overlaps++
			t.Errorf("root %q: BOTH the ancestor arm and the tree arm hold — the pair no longer "+
				"partitions the question, so composing them (CheckEngineToolchainTree's own "+
				"\"ask both\") is no longer provably total", root)
		}

		// THE OTHER HALF OF "PARTITION", and this test asserted only the first
		// until it was read against its own name: no OVERLAP is what makes the
		// composition order-independent, and no GAP is what makes it TOTAL.
		// Without this loop a predicate that matched nothing at all — a broken
		// covers(), an arm returning early — would satisfy "not both" for every
		// root and the test would still pass under its current name.
		//
		// Totality, stated in the model's own terms: some writable bind is in an
		// ancestor-or-equal-or-descendant relation with the root if and only if
		// one of the two arms holds. covers() includes equality, so asking it
		// both ways round is exactly that relation.
		related := false
		for _, m := range p.Mounts {
			if m.Kind != KindBind || m.Host == "" || m.Access != AccessRW {
				continue
			}
			h := filepath.Clean(m.Host)
			if covers(h, root) || covers(root, h) {
				related = true
				break
			}
		}
		if related != (ancestor || tree) {
			gaps++
			t.Errorf("root %q: a writable grant is in an ancestor/equal/descendant relation "+
				"with it = %v, but the two arms together say %v. The pair is meant to be TOTAL "+
				"over that relation, so a disagreement is a root no arm judges (or one judged "+
				"without any grant relating to it)", root, related, ancestor || tree)
		}
	}
	if overlaps > 0 || gaps > 0 {
		t.Fatalf("%d root(s) violated the no-overlap half and %d the no-gap half", overlaps, gaps)
	}
}

func parentOf(p string) string {
	i := strings.LastIndex(strings.TrimSuffix(p, "/"), "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func baseOf(p string) string {
	i := strings.LastIndex(strings.TrimSuffix(p, "/"), "/")
	return p[i+1:]
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ── writableGrantsBelow edge semantics ───────────────────────────────────────

func TestWritableGrantsBelowEdgeSemantics(t *testing.T) {
	t.Run("equality is excluded — that is HostPathVisible's arm", func(t *testing.T) {
		p := &Policy{Mounts: map[string]Mount{
			"/g/exact": {Guest: "/g/exact", Host: "/root/exact", Kind: KindBind, Access: AccessRW},
		}}
		if got := p.writableGrantsBelow("/root/exact"); len(got) != 0 {
			t.Errorf("writableGrantsBelow(root) included root itself: %v — that is the ancestor "+
				"arm's job, and including it here breaks the partition", got)
		}
	})

	t.Run("root is Cleaned before comparison", func(t *testing.T) {
		p := &Policy{Mounts: map[string]Mount{
			"/g/child": {Guest: "/g/child", Host: "/root/a/b/c", Kind: KindBind, Access: AccessRW},
		}}
		want := []string{"/root/a/b/c"}
		for _, root := range []string{"/root/a/b/", "/root/a/../a/b", "/root/a/b"} {
			if got := p.writableGrantsBelow(root); !equalStrings(got, want) {
				t.Errorf("writableGrantsBelow(%q) = %v, want %v — root must be filepath.Clean'd "+
					"before comparison", root, got, want)
			}
		}
	})

	t.Run("root == / covers every writable bind", func(t *testing.T) {
		p := &Policy{Mounts: map[string]Mount{
			"/g/a": {Guest: "/g/a", Host: "/a", Kind: KindBind, Access: AccessRW},
			"/g/b": {Guest: "/g/b", Host: "/b/c", Kind: KindBind, Access: AccessRW},
		}}
		got := p.writableGrantsBelow("/")
		want := []string{"/a", "/b/c"}
		if !equalStrings(got, want) {
			t.Errorf("writableGrantsBelow(\"/\") = %v, want %v", got, want)
		}
	})

	t.Run("a read-only grant inside root is not returned", func(t *testing.T) {
		p := &Policy{Mounts: map[string]Mount{
			"/g/ro": {Guest: "/g/ro", Host: "/root/ro", Kind: KindBind, Access: AccessRO},
		}}
		if got := p.writableGrantsBelow("/root"); len(got) != 0 {
			t.Errorf("a read-only bind inside root was returned as writable: %v", got)
		}
	})

	t.Run("tmpfs, KindData and KindProc inside root are never returned, even carrying a Host", func(t *testing.T) {
		// Host is set on each of these despite none of these Kinds normally
		// carrying one in production, precisely so this proves the Kind
		// filter is doing real work rather than passing by accident because
		// m.Host happens to be empty for these Kinds in practice.
		p := &Policy{Mounts: map[string]Mount{
			"/g/tmpfs": {Guest: "/g/tmpfs", Host: "/root/tmpfs", Kind: KindTmpfs, Access: AccessRW},
			"/g/data":  {Guest: "/g/data", Host: "/root/data", Kind: KindData, Access: AccessRW},
			"/g/proc":  {Guest: "/g/proc", Host: "/root/proc", Kind: KindProc, Access: AccessRW},
		}}
		if got := p.writableGrantsBelow("/root"); len(got) != 0 {
			t.Errorf("a non-KindBind mount was returned as a writable grant below root: %v", got)
		}
	})

	t.Run("judged on Host, never Guest — a divergent bind", func(t *testing.T) {
		// Guest is under root but Host is elsewhere: must NOT be returned —
		// the payload writes the HOST inode, and this one is outside root.
		// Guest is elsewhere but Host is under root: MUST be returned — the
		// payload's write lands under root regardless of where the sandbox
		// displays it.
		p := &Policy{Mounts: map[string]Mount{
			"/root/decoy":      {Guest: "/root/decoy", Host: "/elsewhere/real", Kind: KindBind, Access: AccessRW},
			"/elsewhere/guest": {Guest: "/elsewhere/guest", Host: "/root/actual", Kind: KindBind, Access: AccessRW},
		}}
		got := p.writableGrantsBelow("/root")
		want := []string{"/root/actual"}
		if !equalStrings(got, want) {
			t.Errorf("writableGrantsBelow(\"/root\") = %v, want %v — it must judge Host, not Guest", got, want)
		}
	})

	t.Run("sorted and deduplicated", func(t *testing.T) {
		p := &Policy{Mounts: map[string]Mount{
			"/g/one":      {Guest: "/g/one", Host: "/root/z", Kind: KindBind, Access: AccessRW},
			"/g/two":      {Guest: "/g/two", Host: "/root/a", Kind: KindBind, Access: AccessRW},
			"/g/dup-a":    {Guest: "/g/dup-a", Host: "/root/a", Kind: KindBind, Access: AccessRW},
			"/g/dup-a-rw": {Guest: "/g/dup-a-rw", Host: "/root/a", Kind: KindBind, Access: AccessRW},
		}}
		got := p.writableGrantsBelow("/root")
		want := []string{"/root/a", "/root/z"}
		if !equalStrings(got, want) {
			t.Errorf("writableGrantsBelow(\"/root\") = %v, want %v (sorted, deduplicated)", got, want)
		}
	})
}

// ── issue #369: ResolveEngineBinary and writableNameOnChain ─────────────────
//
// The measured defect: a payload-writable symlink $TARGET/podman ->
// /usr/bin/true was ACCEPTED and exec'd as the engine, because
// CheckEngineBinary only ever saw the RESOLVED bytes (clean) and never the
// symlink NAME a payload had written inside its own rw grant. Every test
// below is phrased on the symlink or the spelling, never on the resolved
// target — asserting the resolved target is the shape that let the defect
// through in the first place.

// TestResolveEngineBinaryJudgesTheNameNotOnlyTheTarget is the measured shape
// itself: $TARGET/podman -> /usr/bin/podman, a clean system binary. The
// refusal must be ABOUT THE SYMLINK — the name the payload actually
// controls — not about the binary it happens to point at.
func TestResolveEngineBinaryJudgesTheNameNotOnlyTheTarget(t *testing.T) {
	env := newFakeEnv()
	env.links["/home/u/proj/sub/podman"] = "/usr/bin/podman"
	env.files["/usr/bin/podman"] = true
	p := resolveDefaults(t)

	const symlink = "/home/u/proj/sub/podman"
	_, err := p.ResolveEngineBinary(env, symlink)
	if err == nil {
		t.Fatal("a payload-writable symlink pointing at a clean system binary was accepted as " +
			"this run's container engine")
	}
	// The refusal must open by naming the SYMLINK as the refused object, not
	// the clean binary it resolves to — that is the whole content of "judges
	// the name, not only the target".
	wantPrefix := symlink + " cannot be this run's container engine"
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Errorf("refusal %q does not open by naming the SYMLINK as the refused object; a "+
			"refusal opening with /usr/bin/podman instead would be describing the clean "+
			"target as the problem, which is the defect itself", err)
	}

	// POSITIVE CONTROL, same test: without it, a function that refuses every
	// absolute path would pass the assertions above for the wrong reason.
	resolved, err := p.ResolveEngineBinary(env, "/usr/bin/podman")
	if err != nil {
		t.Fatalf("control: an ungranted system binary, named directly with no symlink involved, "+
			"was refused: %v", err)
	}
	if resolved != "/usr/bin/podman" {
		t.Errorf("control: resolved = %q, want /usr/bin/podman", resolved)
	}
}

// TestResolveEngineBinaryArmsPartition asserts CheckEngineBinary's arm (the
// BYTES) and writableNameOnChain's arm (the NAME) never absorb each other's
// case: a target-writable REGULAR FILE, with no symlink anywhere in its
// spelling, must produce a refusal BYTE-IDENTICAL to calling CheckEngineBinary
// directly — proving refusals.txt's engine_binary_inside_a_writable_grant
// section is untouched by this fix — while a symlink into the same grant must
// produce the SELECTION wording instead.
func TestResolveEngineBinaryArmsPartition(t *testing.T) {
	t.Run("a writable regular file keeps CheckEngineBinary's own wording, byte-identical", func(t *testing.T) {
		env := newFakeEnv()
		p := resolveDefaults(t)
		const path = "/home/u/proj/sub/bin/podman"

		_, err := p.ResolveEngineBinary(env, path)
		if err == nil {
			t.Fatal("a binary strictly inside the writable target was accepted")
		}
		direct := p.CheckEngineBinary(path)
		if direct == nil {
			t.Fatal("fixture: CheckEngineBinary itself does not refuse this path, so the " +
				"byte-identical comparison below would prove nothing")
		}
		if err.Error() != direct.Error() {
			t.Errorf("ResolveEngineBinary's refusal is not byte-identical to CheckEngineBinary's "+
				"own — the endpoint arm's wording was re-authored (or absorbed by the "+
				"selection arm):\nResolveEngineBinary: %s\nCheckEngineBinary:   %s", err, direct)
		}
	})

	t.Run("a symlink to a clean binary gets the SELECTION wording, not the endpoint's", func(t *testing.T) {
		env := newFakeEnv()
		env.links["/home/u/proj/sub/podman"] = "/usr/bin/podman"
		env.files["/usr/bin/podman"] = true
		p := resolveDefaults(t)

		_, err := p.ResolveEngineBinary(env, "/home/u/proj/sub/podman")
		if err == nil {
			t.Fatal("a symlink into a writable grant, pointing at a clean binary, was accepted")
		}
		if !strings.Contains(err.Error(), "CHOOSING") {
			t.Errorf("refusal %q does not carry the selection arm's wording", err)
		}
		if strings.Contains(err.Error(), "snug execs this file") {
			t.Errorf("refusal %q carries CheckEngineBinary's OWN wording (\"snug execs this "+
				"file\"), so the endpoint arm absorbed a case that belongs to the "+
				"selection arm", err)
		}
	})
}

// TestResolveEngineBinaryCatchesAPathEntrySymlinkedIntoTheTarget is
// writableNameOnChain's CANONICAL arm: a $PATH entry (/opt/tools) is itself
// symlinked into the sandboxed tree's writable bin directory, so naming
// "podman" through it is the payload choosing the engine exactly as the
// measured defect did, just one hop further from the leaf.
//
// MEASURED AGAINST THIS TREE, NOT AS FIRST DRAFTED: a fixture with nothing
// between /opt/tools and the leaf (asGiven = "/opt/tools/podman", no
// intervening directory) does NOT reach this arm through
// ResolveEngineBinary at all — ResolveExistingHostPath walks the WHOLE
// asGiven string in one call and lands on the exact writable bytes
// CheckEngineBinary already judges, so the endpoint arm fires first and this
// test would be indistinguishable from TestResolveEngineBinaryArmsPartition's
// regular-file case. Interposing a real, non-symlinked directory
// ("/opt/tools/bin", already present in this package's fixture host for
// unrelated tests) makes the OUTER full-path resolution stop one level too
// early to ever see /opt/tools's own symlink — while writableNameOnChain's
// own prefix walk, which visits every ancestor rather than only the two
// endpoints, still finds it. That gap is exactly what this arm exists to
// close, and TestWritableNameOnChainAddsNothingOnACanonicalPath's control
// carries the simpler (one-hop) shape of this same fixture directly against
// the predicate.
func TestResolveEngineBinaryCatchesAPathEntrySymlinkedIntoTheTarget(t *testing.T) {
	env := newFakeEnv()
	env.links["/opt/tools"] = "/home/u/proj/sub/bin"
	env.dirs["/opt/tools/bin"] = true
	p := resolveDefaults(t)

	const asGiven = "/opt/tools/bin/podman"
	resolved, err := p.ResolveEngineBinary(env, asGiven)
	if err == nil {
		t.Fatal("a $PATH entry symlinked into the target's writable bin directory was accepted " +
			"as this run's container engine")
	}
	if resolved != "" {
		t.Errorf("a refusal also returned a path: %q", resolved)
	}
	for _, want := range []string{"/home/u/proj/sub/bin", "/opt/tools"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q — a caller cannot tell WHICH name to fix "+
				"without both the link and where it points", err, want)
		}
	}
	if !strings.Contains(err.Error(), "CHOOSING") {
		t.Errorf("refusal %q is not the selection arm's wording", err)
	}
}

// TestResolveEngineBinaryRefusesARelativePath: a relative $SNUG_PODMAN makes
// every lexical check in this file vacuous rather than wrong-answered
// (HostPathVisible compares against canonical, absolute grant Hosts, so a
// relative string matches none of them and would be silently accepted).
func TestResolveEngineBinaryRefusesARelativePath(t *testing.T) {
	env := newFakeEnv()
	p := resolveDefaults(t)

	if _, err := p.ResolveEngineBinary(env, "bin/podman"); err == nil {
		t.Fatal("a relative container engine path was accepted")
	}

	// CONTROL: the absolute equivalent — ungranted, clean — is accepted.
	if _, err := p.ResolveEngineBinary(env, "/srv/bin/podman"); err != nil {
		t.Errorf("control: the absolute equivalent was refused: %v", err)
	}
}

// TestResolveEngineBinaryEndpointArmOutranksTheSelectionArm is the mirror of
// TestEngineToolchainEndpointArmOutranksTheSelectionArm (enginetoolchain_test.go)
// for ResolveEngineBinary: a PLAIN, non-symlinked writable regular file must
// be refused with CheckEngineBinary's own wording, never the selection arm's.
// THE NEGATIVE HALF IS THE ASSERTION — without it this test passes under
// either arm ordering, and getting the ordering backwards is exactly what
// EngineToolchain's first draft did (issue #369's commit message).
func TestResolveEngineBinaryEndpointArmOutranksTheSelectionArm(t *testing.T) {
	env := newFakeEnv()
	p := resolveDefaults(t)
	const path = "/home/u/proj/sub/bin/podman" // no symlink anywhere in this spelling

	_, err := p.ResolveEngineBinary(env, path)
	if err == nil {
		t.Fatal("a binary strictly inside the writable target was accepted")
	}
	if !strings.Contains(err.Error(), "WRITABLE") {
		t.Errorf("refusal %q does not carry CheckEngineBinary's own wording", err)
	}
	if strings.Contains(err.Error(), "CHOOSING") {
		t.Errorf("refusal %q carries the selection arm's wording for a case with no chain at "+
			"all — the endpoint arm must run first", err)
	}
}

// TestWritableNameOnChainAddsNothingOnACanonicalPath is the theorem that
// licenses checkGraft's G4b having no equivalent door (engine.go's own doc
// comment on writableNameOnChain), made checkable: on a CANONICAL path (one
// this fixture host has no symlink for), writableNameOnChain must agree with
// HostPathVisible exactly, over every shape HostPathVisible itself
// distinguishes.
//
// IF THIS TEST EVER FAILS, the G4b asymmetry argument has expired — say so
// rather than tuning the assertion, because the argument is what justifies
// checkGraft never calling this predicate itself.
func TestWritableNameOnChainAddsNothingOnACanonicalPath(t *testing.T) {
	env := newFakeEnv()
	p := resolveDefaults(t)

	cases := []struct {
		name string
		path string
	}{
		{"inside a writable (rw) grant", "/home/u/proj/sub/somefile"},
		{"inside a read-only (ro) grant", "/usr/bin/somefile"},
		{"under no grant at all", "/srv/other/thing"},
		{"exactly a grant's own Host", "/home/u/proj/sub"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, found := p.writableNameOnChain(env, tc.path)
			want := p.HostPathVisible(tc.path, true)
			if found != want {
				t.Errorf("writableNameOnChain(%q).found = %v, HostPathVisible(true) = %v — "+
					"on a canonical path the two predicates must agree", tc.path, found, want)
			}
		})
	}

	// POSITIVE CONTROL: a NON-canonical path where the two DISAGREE, so the
	// agreement above is not vacuously true for every input this package can
	// construct. This is the same $PATH-entry-symlinked-into-the-target shape
	// TestResolveEngineBinaryCatchesAPathEntrySymlinkedIntoTheTarget exercises
	// through the full call, asked of the predicate directly.
	t.Run("control: a non-canonical path where the two disagree", func(t *testing.T) {
		env := newFakeEnv()
		env.links["/opt/tools"] = "/home/u/proj/sub/bin"
		const q = "/opt/tools/podman"

		visible := p.HostPathVisible(q, true)
		if visible {
			t.Fatalf("fixture: %q is visible on its own literal spelling, so this is not the "+
				"non-canonical case this control means to exercise", q)
		}
		_, _, found := p.writableNameOnChain(env, q)
		if !found {
			t.Fatal("fixture: writableNameOnChain did not find the writable path entry " +
				"symlinked into the target, so the disagreement this control depends on " +
				"does not exist")
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
