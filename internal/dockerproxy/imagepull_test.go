package dockerproxy

import (
	"net/http"
	"strings"
	"testing"
)

// ── POST /libpod/images/pull, the route `podman run` needs (issue #459) ──────
//
// Every URL below is one the podman 6.0.2 CLI was MEASURED sending, against a
// unix socket that logged the request and answered it. That is why the
// parameter set is spelled out in full rather than reduced to the parameter
// under test: a filter tested only with the parameter it judges is a filter
// nobody has run against a real client.
const pullDefaults = "alltags=false&arch=&authfile=&os=&policy=always&quiet=false&variant="

// pullURL is `podman pull <ref>` on the wire, byte for byte.
func pullURL(ref string) string {
	return "/v6.0.2/libpod/images/pull?" + pullDefaults + "&reference=" + urlEscape(ref)
}

func urlEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '/' || r == ':' || r == '@' || r == '%':
			b.WriteString(map[rune]string{'/': "%2F", ':': "%3A", '@': "%40", '%': "%25"}[r])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// TestThePodmanCLIsOwnPullReachesTheEngine is the ergonomics half and the
// reason #459 exists: `podman run` posts this route BEFORE containers/create,
// with policy=missing, even when the image is already in the store — so
// refusing it refused `podman run` outright and `--pull=never` was not a
// workaround.
func TestThePodmanCLIsOwnPullReachesTheEngine(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, url string }{
		{"`podman pull alpine:3.20`", pullURL("alpine:3.20")},
		{"`podman run` pulls with policy=missing first",
			"/v6.0.2/libpod/images/pull?alltags=false&arch=&authfile=&os=&policy=missing&quiet=false&variant=&reference=alpine%3A3.20"},
		{"a bare repository name", pullURL("alpine")},
		{"a digest reference", pullURL("alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000")},
		{"a registry with a PORT, which has a colon and is not a transport",
			pullURL("localhost:5000/team/app:v1")},
		{"the explicit registry transport", pullURL("docker://alpine:3.20")},
		{"`--all-tags --quiet --arch arm64 --os linux`",
			"/v6.0.2/libpod/images/pull?alltags=true&arch=arm64&authfile=&os=linux&policy=always&quiet=true&variant=&reference=alpine"},
		{"`--tls-verify=false --retry 2 --retry-delay 1s`",
			"/v6.0.2/libpod/images/pull?" + pullDefaults + "&reference=alpine&tlsVerify=false&retry=2&retrydelay=1s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.reached.Load()
			code, resp := post(t, sock, tc.url, "")
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if eng.reached.Load() == before {
				t.Error("the pull did not reach the engine, so this test proves nothing " +
					"about the route being usable")
			}
		})
	}
}

// TestPullRefusesAnImportWearingAPullsSpelling is the security half, and the
// abuse it closes was MEASURED on the wire: the podman CLI forwards a
// containers/image TRANSPORT inside `reference` verbatim, so an unfiltered
// pull route is an import route — the engine reads a tarball or a directory
// from a path snug never resolved, in the engine's mount namespace.
//
// The docker-compat path refuses the same thing by name (`fromSrc`), which is
// what makes this a screen/run agreement rather than a new rule.
func TestPullRefusesAnImportWearingAPullsSpelling(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ ref, wantMsg string }{
		{"docker-archive:/tmp/x.tar", "`docker-archive:` names a tarball written by `docker save`"},
		{"oci-archive:/tmp/x.tar", "`oci-archive:` names an OCI layout tarball"},
		{"dir:/etc", "`dir:` names a directory of blobs"},
		{"oci:/tmp/layout", "`oci:` names an OCI layout directory"},
		// No slash after the colon, so the SHAPE rule does not fire and the
		// transport list is what refuses it. Both arms matter: the shape rule
		// alone would forward this one.
		{"containers-storage:alpine", "`containers-storage:` names another local image store"},
		{"docker-daemon:alpine:latest", "`docker-daemon:` names a docker daemon's own store"},
		// A transport snug has never heard of, spelled as a path. The shape rule
		// is what catches it, which is the property that keeps the list from
		// being the defence.
		{"transport-podman-adds-in-2027:/tmp/x", "names something other than a registry"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			refuse(t, sock, eng, pullURL(tc.ref), "", tc.wantMsg)
		})
	}
}

// TestPullRefusesAnAuthfileTheEngineWouldOpen pins the measurement that makes
// authfile a JUDGED parameter rather than metadata: `podman pull --authfile
// /etc/passwd` sends `authfile=%2Fetc%2Fpasswd` to the SERVER.
func TestPullRefusesAnAuthfileTheEngineWouldOpen(t *testing.T) {
	sock, eng, _ := startProxy(t)
	refuse(t, sock, eng,
		"/v6.0.2/libpod/images/pull?alltags=false&arch=&authfile=%2Fetc%2Fpasswd&os=&policy=always&quiet=false&variant=&reference=alpine",
		"", "REGISTRY_AUTH_FILE")
}

// TestPullRefusesAParameterItHasNotRead is the default-deny half. A newer
// podman sending a parameter this filter has not read refuses LOUDLY rather
// than forwarding it unexamined — invariant 5, and the same trade issue #478's
// ruling makes for the engine version itself.
func TestPullRefusesAParameterItHasNotRead(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, param string }{
		{"a parameter from a podman that does not exist yet", "unpackfrom=/host/root"},
		{"the compat spelling of a source, on the libpod route", "fromSrc=-"},
		{"a plausible credential parameter", "credentials=user%3Apass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, pullURL("alpine")+"&"+tc.param, "",
				"is one snug's filter has not read")
		})
	}

	t.Run("a body, which the CLI never sends and snug has not read", func(t *testing.T) {
		refuse(t, sock, eng, pullURL("alpine"),
			`{"reference":"docker-archive:/tmp/x.tar"}`, "with a request body is not permitted")
	})

	t.Run("a pull naming no image", func(t *testing.T) {
		refuse(t, sock, eng, "/v6.0.2/libpod/images/pull?"+pullDefaults, "",
			"names no image to pull")
	})
}

// TestEveryPullParameterIsEitherJudgedOrMetadata keeps the two maps from
// overlapping, because an overlap is how a judged parameter becomes a waved-
// through one: handleImagePull checks pullMetadata FIRST, so a name in both is
// silently unjudged.
func TestEveryPullParameterIsEitherJudgedOrMetadata(t *testing.T) {
	for name := range pullJudged {
		if reason, ok := pullMetadata[name]; ok {
			t.Errorf("the pull parameter %q is in BOTH pullJudged and pullMetadata (%q) — "+
				"handleImagePull consults pullMetadata first, so its check never runs",
				name, reason)
		}
	}
	if len(pullJudged) == 0 || len(pullMetadata) == 0 {
		t.Fatal("one of the two parameter maps is empty, which would make every " +
			"assertion in this file vacuous")
	}
	// The refusal names the whole set it read, so a parameter added to either map
	// without a description cannot hide.
	for _, n := range pullParameterNames() {
		if n == "" {
			t.Error("an empty parameter name is in one of the maps")
		}
	}
}
