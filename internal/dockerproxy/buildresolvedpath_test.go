package dockerproxy

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REGRESSION, issue #304 (sev:high, found by a redteam sweep of the container
// proxy). handleCreate has always substituted the RESOLVED bind source into the
// body it forwards, for the reason checkOne's own comment gives: the symlink can
// be swapped between snug's check and the engine's own resolution, so the engine
// must be asked for the thing that was actually approved.
//
// The BUILD path did not. checkBuildVolume and checkAdditionalContexts called
// `_, err := p.checkOne(...)` — resolving the path, judging the resolved path,
// and DISCARDING it — while handleBuild ended in p.forward on the ORIGINAL URI.
// checkSeccompProfile computed `real` and forwarded the raw value. So three
// checks (hostPathVisible, the #251/#255 dangling-symlink refusal, and the
// guest==host reasoning built on them) all judged a string the engine never
// resolves.
//
// The measured consequence, with `ln -sfT /snug/engine/store <target>/link`
// re-pointed in a loop so buildah resolves the link during RUN:
//
//	build -v <link>:/x:ro       reads the whole cross-run engine image store
//	--build-context x=<link>    the same, by another name
//	seccomp=<link>              swapped to {"defaultAction":"SCMP_ACT_ALLOW"},
//	                            running the build container UNCONFINED
//
// The assertion is on the FORWARDED URI, not on the status code. A 200 proves
// only that the build was allowed; what this issue was about is WHICH STRING
// went upstream, and nothing in the suite looked at that before — which is why
// the fake engine now records it.
func TestBuildForwardsTheResolvedPathNotTheClientsSymlink(t *testing.T) {
	cases := []struct {
		name string
		// query builds the parameter under test from the link's path.
		query func(link string) string
		// wantRaw is the substring the RESOLVED forward must NOT contain, and
		// wantResolved the one it must.
		wantResolved string
	}{
		{
			name:         "build -v",
			query:        func(link string) string { return "volume=" + url.QueryEscape(link+":/x:ro") },
			wantResolved: "/usr:/x:ro",
		},
		{
			name: "--build-context",
			query: func(link string) string {
				return "additionalbuildcontexts=" + url.QueryEscape(
					`{"extra":{"IsURL":false,"IsImage":false,"Value":"`+link+`"}}`)
			},
			wantResolved: `"Value":"/usr"`,
		},
		{
			name:         "--security-opt seccomp=",
			query:        func(link string) string { return "seccomp=" + url.QueryEscape(link) },
			wantResolved: "seccomp=%2Fusr",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, target := startBuildProxy(t)

			// The link lives in the sandbox's own target, which is the one
			// writable tree an agent controls — the same place the measured
			// attack puts it. It points at /usr, which the test policy grants
			// READ-ONLY, so every check the build path applies passes on the
			// resolved path and the request is genuinely allowed. That matters:
			// a case that ends in a refusal would prove nothing about what gets
			// forwarded.
			link := filepath.Join(target, "link")
			if err := os.Symlink("/usr", link); err != nil {
				t.Fatal(err)
			}

			before := eng.reached.Load()
			code, resp := post(t, sock, buildURL(tc.query(link)), "")
			if code != 200 {
				t.Fatalf("the build was refused (status %d), so this test measures nothing "+
					"about what is forwarded: %s", code, resp)
			}
			if eng.reached.Load() == before {
				t.Fatal("the build never reached the engine, so there is no forwarded URI to judge")
			}

			uri, _ := eng.lastURI.Load().(string)
			if uri == "" {
				t.Fatal("the fake engine recorded no request URI, so this test measures nothing")
			}
			decoded, err := url.QueryUnescape(uri)
			if err != nil {
				t.Fatalf("the forwarded URI does not decode: %v", err)
			}

			// THE ASSERTION. The client's own string must be gone.
			if strings.Contains(decoded, link) {
				t.Errorf("the forwarded URI still carries the CLIENT's path %s, so the engine "+
					"resolves a string snug did not judge — the symlink can be re-pointed "+
					"between the check and buildah's own resolution (issue #304):\n%s", link, decoded)
			}
			if !strings.Contains(uri, tc.wantResolved) && !strings.Contains(decoded, tc.wantResolved) {
				t.Errorf("the forwarded URI does not carry the RESOLVED path %q. Removing the "+
					"client's string is only half of the fix; the engine still has to be asked "+
					"for what was approved:\n%s", tc.wantResolved, decoded)
			}
		})
	}
}

// POSITIVE CONTROL for the sweep above, and it is the one that keeps it honest:
// a build that names NO host path must be forwarded byte for byte. Without
// this, "the client's string is not in the forwarded URI" would also be
// satisfied by a fix that mangled or dropped parameters wholesale, and by an
// unconditional url.Values.Encode() that re-orders and re-escapes every build's
// query — a diff in the forwarded bytes for every request, which is how the one
// case that matters gets lost in noise nobody reads.
func TestBuildWithNoHostPathIsForwardedUnchanged(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)

	want := buildURL("")
	if code, resp := post(t, sock, want, ""); code != 200 {
		t.Fatalf("the CLI's own default build was refused (status %d): %s", code, resp)
	}
	got, _ := eng.lastURI.Load().(string)
	if got != want {
		t.Errorf("a build naming no host path was rewritten on the way upstream.\n"+
			"  sent:      %s\n  forwarded: %s\n"+
			"Only a value snug RESOLVED may differ; everything else is the client's own "+
			"request and rewriting it is snug authoring something nobody asked for.", want, got)
	}
}

// The other half of the two-namespace divergence, asserted on the BUILD path
// because that is where it was never checked in a way that reached the engine.
// A symlink that dangles in snug's own namespace can point at one of snug's
// /snug/engine grafts inside the engine's derived view (issue #251), so a
// source snug cannot follow is one it must not forward.
//
// This half was already enforced — checkOne runs resolveForwardable — but it
// was enforced over a string that was then discarded, so nothing downstream
// depended on the answer. Pinned here so the build path keeps its own named
// regression rather than inheriting the create path's.
func TestBuildRefusesADanglingSymlinkSource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query func(link string) string
	}{
		{"build -v", func(link string) string { return "volume=" + url.QueryEscape(link+":/x:ro") }},
		{"--build-context", func(link string) string {
			return "additionalbuildcontexts=" + url.QueryEscape(
				`{"extra":{"IsURL":false,"IsImage":false,"Value":"`+link+`"}}`)
		}},
		{"--security-opt seccomp=", func(link string) string { return "seccomp=" + url.QueryEscape(link) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, target := startBuildProxy(t)
			link := filepath.Join(target, "dangling")
			// The target names one of snug's own engine grafts, which is the
			// case #251 is about: absent in snug's namespace, present in the
			// engine's.
			if err := os.Symlink("/snug/engine/store", link); err != nil {
				t.Fatal(err)
			}
			refuse(t, sock, eng, buildURL(tc.query(link)), "", "does not exist in this sandbox")
		})
	}
}

// A build parameter carrying a path the sandbox genuinely cannot see must still
// be REFUSED rather than resolved-and-forwarded. Issue #304 is about forwarding
// what was judged; it is not a licence to forward more.
func TestBuildStillRefusesAnUngrantedPathThroughASymlink(t *testing.T) {
	sock, eng, target := startBuildProxy(t)
	link := filepath.Join(target, "etclink")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	refuse(t, sock, eng, buildURL("volume="+url.QueryEscape(link+":/x:ro")), "",
		"cannot see /etc")
}
