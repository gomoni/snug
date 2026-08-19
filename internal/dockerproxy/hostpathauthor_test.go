package dockerproxy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestHostPathVisibleHasOneAuthor is §7 item 13 of issue #55's specification:
// invariant 6 says one author of "can the sandbox see this host path", not two
// implementations that eventually disagree — the same argument that moved this
// package's OWN walk into policy.HostPathVisible in the first place, so a
// graft's G4 check and the container bind filter cannot drift apart. This test
// is what keeps that true after the move rather than only at the moment of it.
//
// Two parts. First: (*Proxy).hostPathVisible's body is nothing but a call to
// policy.HostPathVisible — no loop of its own. Second: nowhere ELSE in this
// package walks p.pol.Mounts for KindBind the way the old implementation did,
// which is the shape a "helpful" future patch could reintroduce without
// touching hostPathVisible at all (a second predicate living beside the first,
// never called by it, and asked instead of it from some new call site).
func TestHostPathVisibleHasOneAuthor(t *testing.T) {
	src, err := os.ReadFile("create.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	// Part 1: the function body.
	fn := funcBody(t, text, "func (p *Proxy) hostPathVisible(host string, needWrite bool) bool {")
	if !strings.Contains(fn, "p.pol.HostPathVisible(") {
		t.Errorf("hostPathVisible's body does not call p.pol.HostPathVisible — it has grown a "+
			"second implementation of \"can the sandbox see this host path\": %q", fn)
	}
	// POSITIVE CONTROL: the extraction actually found the real function and not
	// an empty string a typo in the signature above would also produce.
	if !strings.Contains(fn, "return") {
		t.Fatalf("control: funcBody extracted an empty-looking body (%q) — the signature this test "+
			"greps for has drifted from create.go's own", fn)
	}

	// Part 2: no OTHER walk of p.pol.Mounts for KindBind exists in this
	// package's shipped (non-test) source. hostPathVisible's own call site is
	// excluded by construction — mountWalkRE matches a RANGE over
	// p.pol.Mounts, and hostPathVisible no longer contains one (part 1 already
	// proved its body is one line).
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for range mountWalkRE.FindAllString(string(b), -1) {
			hits = append(hits, f.Name())
		}
	}
	if len(hits) != 0 {
		t.Errorf("found %d walk(s) of p.pol.Mounts outside policy.HostPathVisible, in: %v — "+
			"this package must have exactly one implementation of \"can the sandbox see this host "+
			"path\", and it must be policy's", len(hits), hits)
	}

	// POSITIVE CONTROL for Part 2's pattern: it must actually be ABLE to match
	// the shape the pre-issue-#55 implementation had.
	oldShape := "for _, m := range p.pol.Mounts {\n\tif m.Kind != policy.KindBind {\n"
	if !mountWalkRE.MatchString(oldShape) {
		t.Fatalf("control: mountWalkRE does not match the pre-#55 shape of hostPathVisible's own " +
			"walk — it would not catch a reintroduced copy either")
	}
}

// mountWalkRE matches a `range` over `p.pol.Mounts` — the shape a second,
// hand-rolled implementation of "what can the sandbox see" would need in order
// to walk the same data hostPathVisible now delegates on.
var mountWalkRE = regexp.MustCompile(`range\s+p\.pol\.Mounts`)

// funcBody extracts the text between a function's opening `{` (found via sig,
// which must include it) and its matching closing `}`, by brace counting. Used
// instead of go/ast here because the property under test is "what literal call
// appears in this one function's source", which a brace-counted substring
// answers as directly as a parsed FuncDecl would.
func funcBody(t *testing.T, src, sig string) string {
	t.Helper()
	i := strings.Index(src, sig)
	if i < 0 {
		t.Fatalf("signature %q not found in create.go — it was renamed or reshaped, and this test "+
			"needs to be updated to match", sig)
	}
	start := i + len(sig)
	depth := 1
	j := start
	for ; j < len(src) && depth > 0; j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return src[start:j]
}
