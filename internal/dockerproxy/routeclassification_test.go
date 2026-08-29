package dockerproxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// routerSegments parses proxy.go and returns every first path segment that
// allowed()'s own switch names.
//
// Derived from the source rather than typed into the test on purpose. Issue
// #340's predecessor, TestLibpodNativeBodyIsRefusedRatherThanForwardedUnexamined,
// enumerates six routes and touches neither of the two segments that were
// broken — a test that enumerates routes proves things about the routes it
// enumerates and nothing about the ones it does not. Reading the switch means a
// route added to the router shows up here whether or not anybody remembered
// this file.
func routerSegments(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "proxy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if g, ok := d.(*ast.FuncDecl); ok && g.Name.Name == "allowed" && g.Recv == nil {
			fn = g
		}
	}
	if fn == nil {
		t.Fatal("allowed() not found in proxy.go — the router was renamed and this " +
			"sweep now proves nothing; point it at the new function rather than deleting it")
	}
	var segs []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		// Only the switch over segs[0]. allowed() has a second one, over
		// segs[2], whose cases are sub-paths and not routes in their own right.
		ix, ok := sw.Tag.(*ast.IndexExpr)
		if !ok {
			return true
		}
		lit, ok := ix.Index.(*ast.BasicLit)
		if !ok || lit.Value != "0" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, e := range cc.List {
				bl, ok := e.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(bl.Value)
				if err != nil {
					t.Fatalf("unquoting a case in allowed(): %v", err)
				}
				segs = append(segs, s)
			}
		}
		return false
	})
	if len(segs) < 5 {
		t.Fatalf("found only %d segments in allowed()'s switch (%v) — the parse stopped "+
			"matching the code's shape, and every assertion below would then be vacuous",
			len(segs), segs)
	}
	sort.Strings(segs)
	return segs
}

// classified is the human acknowledgement half. The LEFT side of the comparison
// below comes from the code; this is the right side, and its only job is to make
// a route added to allowed() FAIL until somebody has decided whether a
// libpod-shaped request on it can be judged.
//
// The value is the decision, not a description: true means "snug's filter READS
// this route, so a state-changing libpod request to it may be forwarded", and it
// must agree with libpodExamined, which is what the proxy actually consults.
// Only `build` is true, and the four GET-only routes are false rather than
// exempt — they are reachable without being read, and safeMethod is what keeps
// them usable. Recording them as false is the honest entry: if podman ever
// serves a POST under /libpod/info, nothing here quietly permits it.
//
// Examination is a property of the whole PATH, not of the first segment. That
// future arrived with issue #459: `images/pull` is examined and the rest of
// `images` is not, so this map records the SEGMENT verdict (false for images —
// a libpod POST to images/anything-else is refused) and classifiedPaths below
// carries the path column it predicted.
var classified = map[string]bool{
	"_ping":      false,
	"version":    false,
	"info":       false,
	"events":     false,
	"build":      true,
	"system":     false,
	"images":     false,
	"networks":   false,
	"volumes":    false,
	"containers": false,
	"exec":       false,
}

// classifiedPaths is the path column, and it exists because examination is now
// finer than a segment: handleImagePull READS POST /libpod/images/pull, while
// every other POST under `images` stays refused by the segment verdict above.
//
// Same rule as classified: the value is the DECISION, and it must agree with
// libpodExamined, which is what the proxy consults. An entry whose first
// segment is examined at segment level would be redundant and is refused
// below, so this map cannot drift into a second, weaker copy of the other one.
var classifiedPaths = map[string]bool{
	"images/pull":   true,
	"images/create": false,
	"images/load":   false,
	"images/import": false,
	// The compat spelling of the same import, on the libpod path. Recorded
	// false rather than omitted: it is the parameter handleImagePull's
	// default-deny refuses by name in imagepull_test.go.
	"containers/create": false,
	"volumes/create":    false,
}

func TestEveryExaminedLibpodPathIsClassified(t *testing.T) {
	for path, want := range classifiedPaths {
		segs := strings.Split(path, "/")
		if got := libpodExamined(segs); got != want {
			t.Errorf("path %q: classifiedPaths says examined=%v, libpodExamined says %v — "+
				"the acknowledgement and the code the proxy consults disagree", path, want, got)
		}
		if classified[segs[0]] {
			t.Errorf("path %q is acknowledged per-path while its segment %q is already "+
				"examined as a whole — the entry says nothing and would go stale silently",
				path, segs[0])
		}
	}

	// The half that keeps the map from being a list of trues: at least one
	// examined path and one refused path under the SAME segment, which is the
	// configuration issue #459 introduced and the reason this column exists.
	var examinedUnderImages, refusedUnderImages bool
	for path, want := range classifiedPaths {
		if !strings.HasPrefix(path, "images/") {
			continue
		}
		if want {
			examinedUnderImages = true
		} else {
			refusedUnderImages = true
		}
	}
	if !examinedUnderImages || !refusedUnderImages {
		t.Error("no segment has both an examined and a refused path, so this test is not " +
			"measuring what it was added for (issue #459: images/pull is read, the rest " +
			"of images is not)")
	}
}

func TestEveryRouteTheRouterCanReachIsClassifiedForLibpod(t *testing.T) {
	segs := routerSegments(t)

	for _, s := range segs {
		want, ok := classified[s]
		if !ok {
			t.Errorf("allowed() can reach the route %q and nothing here classifies it. "+
				"Decide whether a libpod-shaped POST to /libpod/%s can be judged by this "+
				"filter: if it can, add it to libpodExamined WITH THE REASON and to "+
				"classified as true; if it cannot, add it to classified as false and it "+
				"stays refused. This is the check that stops a new route arriving "+
				"unexamined the way networks and system did (issue #340).", s, s)
			continue
		}
		if examined := libpodExamined([]string{s}); examined != want {
			t.Errorf("route %q: classified says examined=%v, libpodExamined says %v — "+
				"the acknowledgement and the code the proxy consults disagree", s, want, examined)
		}
	}

	// The inverse, so an entry here cannot outlive the route it acknowledges and
	// be read as though it still applied.
	for s := range classified {
		found := false
		for _, r := range segs {
			if r == s {
				found = true
			}
		}
		if !found {
			t.Errorf("classified names %q, which allowed() cannot reach — an acknowledgement "+
				"for a route that no longer exists", s)
		}
	}

	// The gate is an ALLOWLIST, and this is the half that says so rather than
	// enumerating: a segment nobody has heard of is NOT examined. Without it the
	// assertions above are satisfied by any function whose default is true.
	for _, seg := range []string{"segment-podman-adds-in-2027", "", "networks", "system"} {
		if libpodExamined([]string{seg}) {
			t.Errorf("libpodExamined(%q) = true — the gate has a permissive default, which "+
				"is the denylist shape issue #340 was", seg)
		}
	}
}

// TestNoUnexaminedLibpodBodyReachesTheEngine is the behavioural half, and it is
// the one that measures rather than acknowledges: every route the router can
// reach is driven with a real libpod-spelled POST carrying the escape body.
//
// Issue #340, measured before the fix: POST /v5.0.0/libpod/networks/create and
// POST /v5.0.0/libpod/system/prune both reached the engine with the body
// forwarded unexamined, while the 403 text for the routes that WERE refused
// claims forwarding it unexamined "would bypass every check".
func TestNoUnexaminedLibpodBodyReachesTheEngine(t *testing.T) {
	// The libpod SpecGenerator escape, in libpod spelling: lowercase top-level
	// keys that the docker-compat filter cannot read.
	const escape = `{"image":"alpine","privileged":true,"netns":{"nsmode":"host"},
	                "cap_add":["SYS_ADMIN"],
	                "mounts":[{"type":"bind","source":"/","destination":"/host"}]}`

	sock, eng, _ := startProxyMode(t, policy.PodmanBuild)

	for _, seg := range routerSegments(t) {
		if libpodExamined([]string{seg}) {
			continue
		}
		for _, m := range []struct{ method, path string }{
			{http.MethodPost, "/v5.0.0/libpod/" + seg + "/create"},
			{http.MethodPost, "/libpod/" + seg + "/prune"},
			// DELETE was the half the old gate never covered: bodyBearing
			// tested for POST or PUT, so every libpod removal route reached the
			// engine over a schema this filter does not read.
			{http.MethodDelete, "/v5.0.0/libpod/" + seg + "/abc"},
		} {
			t.Run(m.method+" "+m.path, func(t *testing.T) {
				before := eng.reached.Load()
				code, resp := do(t, sock, m.method, m.path, escape)
				if code != http.StatusForbidden {
					t.Errorf("status %d, want 403 — a libpod body on an unclassified route "+
						"was not refused: %s", code, resp)
				}
				if eng.reached.Load() != before {
					t.Errorf("the request reached the engine unexamined on %s %s", m.method, m.path)
				}
			})
		}
	}

	// POSITIVE CONTROL, and it is what keeps the sweep from being satisfied by a
	// proxy that refuses everything: the one allowlisted route with a body still
	// reaches the engine. /libpod/build's body is the context tar, forwarded
	// unread by design, and every policy-relevant option is a query parameter
	// handleBuild filters on its own.
	t.Run("control: an examined libpod route still reaches the engine", func(t *testing.T) {
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL(""), "")
		if code != 200 {
			t.Fatalf("status %d on an allowlisted libpod route, want 200: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Error("the allowlisted route did not reach the engine, so the refusals above " +
				"prove nothing about classification — they would pass on a proxy that " +
				"refuses every libpod request")
		}
	})

	// POSITIVE CONTROL: a GET on a refused segment is untouched. bodyBearing is
	// about bodies, and a read-only libpod route carries none to misread.
	t.Run("control: a read-only libpod route is not caught by the body rule", func(t *testing.T) {
		segs, _, libpod, ok := normaliseFull("/v5.0.0/libpod/containers/json")
		if !ok || !libpod {
			t.Fatalf("normaliseFull did not recognise the libpod prefix: %v %v %v", segs, libpod, ok)
		}
		if !safeMethod(http.MethodGet) {
			t.Error("a GET carries no body to misread and must not be refused as libpod")
		}
		if !allowed(segs, http.MethodGet) {
			t.Error("listing containers over libpod should still be allowed")
		}
	})
}

// do is post() with the method as a parameter. The gate is stated in terms of
// methods, so a sweep that can only POST would leave the DELETE half of it —
// the half that was open — untested.
func do(t *testing.T, sock, method, path, body string) (int, string) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest(method, "http://d"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(buf)
}
