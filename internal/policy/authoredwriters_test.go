package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// authoredWriteRE finds every assignment to Mount.Authored / Graft.Authored.
// Comparisons are excluded by requiring a `=` that is not `==`, the gap the
// EngineToolchainRoot guard has and which cost a contorted `len(...) == 0` at
// one read site.
var authoredWriteRE = regexp.MustCompile(`\.Authored\s*=[^=]`)

// TestAuthoredWritersAreTheThreeTheCommentsName makes the "a profile cannot
// borrow the exemption" argument CHECKABLE instead of prose.
//
// Two rules rest on Mount.Authored: rejectMasking's RULE 3 (snug may replace
// what a profile exposed) and rejectEndpointSource (#219 — snug's own proxy
// sockets are sockets, deliberately). Both carried the same sentence — "set
// only by Policy.Replace, which nothing a profile can write reaches" — and it
// was false in both: there are THREE writers. The exemption survives, for a
// reason that has to be given per writer:
//
//	Policy.Replace   snug's own post-resolve writes; a profile cannot express one
//	Policy.Graft     writes p.Grafts, a different map neither rule reads
//	Policy.yieldTo   installs base mounts ONLY at an unclaimed guest, so a
//	                 profile's grant is left UNauthored and RULE 4 can name it
//
// The same false sentence in two places is this project's most-repeated shape
// — a rule written once and applied to one of its halves — and prose cannot
// notice a fourth writer arriving. This test can: if one does, it fails here,
// pointing at the two comments whose argument would then be incomplete rather
// than merely out of date.
func TestAuthoredWritersAreTheThreeTheCommentsName(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		text := string(src)
		for _, loc := range authoredWriteRE.FindAllStringIndex(text, -1) {
			line := 1 + strings.Count(text[:loc[0]], "\n")
			rel, _ := filepath.Rel(root, path)
			hits = append(hits, fmt.Sprintf("%s:%d", filepath.ToSlash(rel), line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hits)

	// The FILES rather than the line numbers: a line moves whenever anything
	// above it is edited, and a test that fails on an unrelated edit is a test
	// people learn to update without reading.
	var files []string
	for _, h := range hits {
		files = append(files, h[:strings.LastIndex(h, ":")])
	}
	want := []string{"policy/graft.go", "policy/resolve.go", "policy/types.go"}
	if len(files) != len(want) {
		t.Fatalf("Mount.Authored is assigned in %v (%d sites), want exactly %v.\n"+
			"Two security rules — rejectMasking's RULE 3 and rejectEndpointSource — exempt an\n"+
			"Authored mount, and both justify it by naming who can set the field. A new writer\n"+
			"is a new way for a mount to become exempt, so it belongs in that argument or it\n"+
			"belongs nowhere.", hits, len(hits), want)
	}
	for i := range files {
		if files[i] != want[i] {
			t.Errorf("Authored is written in %s; the three writers the comments name are %v",
				files[i], want)
		}
	}
}

// TestAuthoredIsNotSettableFromProfileText is the other half, and it is the
// one a reader actually cares about: whatever the writers are, no profile can
// reach them.
//
// Profile is the whole of what a TOML file can say. If none of its fields is
// named Authored — and no path from ParseProfile to a Mount copies one — then
// the exemption cannot be requested, only granted by snug's own code. This is
// asserted structurally rather than by reading the parser, because the parser
// is the thing that would change.
func TestAuthoredIsNotSettableFromProfileText(t *testing.T) {
	// A profile that tries every spelling a TOML author might reach for is
	// beside the point: the type has no such field, so this is a compile-time
	// property. What CAN drift is a future Mount built FROM profile text
	// carrying Authored through, so the check is on the resolved policy.
	reg := testRegistry()
	reg["binder"] = &Profile{Name: "binder", RO: []string{"/opt:/home/u/mounted"}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binder"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts["/home/u/mounted"]
	if !ok {
		t.Fatal("the fixture profile's grant is not in the policy, so this test measured nothing")
	}
	if m.Authored {
		t.Error("a mount that came from PROFILE TEXT is Authored — it would be exempt from " +
			"rejectMasking's RULE 3 and from rejectEndpointSource, which is exactly the " +
			"loophole both comments claim is impossible")
	}
}
