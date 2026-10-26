//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildKitEntryPointsAreRefusedAtTheProxy is issue #690's regression end
// to end: snug writes DOCKER_BUILDKIT=0, a payload may write 1, and the
// requests a BuildKit client then sends must stop at snug's proxy rather than
// reach the engine. The paths and headers are the ones a recorder saw from
// docker 29.7.2-ce / buildx 0.36.1 (internal/dockerproxy's
// TestBuildKitEntryPointsNeverReachTheEngine has the recording), sent here
// through the real socket a sandbox selecting @podman-build is handed.
//
// The control is a `GET /_ping` on the same socket answering 200 — without
// it, three 403s would equally describe a proxy that refuses everything.
func TestBuildKitEntryPointsAreRefusedAtTheProxy(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)
	requireEngine(t)
	requirePython(t)
	requireRealEngine(t, baseEnv())

	proj, _ := target(t)
	script := pyPreamble + `
up = {"Connection": "Upgrade", "Upgrade": "h2c"}
status, _ = req("GET", "/_ping")
print("PING: %d" % status, flush=True)
for name, method, path, hdr in [
    ("grpc", "POST", "/grpc", up),
    ("session", "POST", "/v1.44/session", up),
    ("build2", "POST", "/v1.44/build?version=2", {"Content-Type": "application/x-tar"}),
]:
    status, body = req(method, path, b"", hdr)
    msg = json.loads(body).get("message", "") if body.startswith(b"{") else body.decode(errors="replace")
    print("%s: %d %s" % (name, status, msg.replace("\n", " ")), flush=True)
print("PROBE-COMPLETE", flush=True)
`
	if err := os.WriteFile(filepath.Join(proj, "buildkit690.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@podman-build"}, proj, `python3 buildkit690.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, "PING: 200") {
		t.Fatalf("CONTROL: /_ping through the proxy did not answer 200, so the refusals "+
			"below would prove nothing:\n%s", r.out)
	}
	for _, tc := range []struct{ name, want string }{
		{"grpc", "endpoint POST /grpc is not permitted"},
		{"session", "endpoint POST /session is not permitted"},
		{"build2", "BuildKit"},
	} {
		line := ""
		for _, l := range strings.Split(r.out, "\n") {
			if strings.HasPrefix(l, tc.name+": ") {
				line = l
				break
			}
		}
		if !strings.HasPrefix(line, tc.name+": 403 snug refused this request") {
			t.Errorf("%s was not refused by snug's proxy: %q\n%s", tc.name, line, r.out)
			continue
		}
		if !strings.Contains(line, tc.want) {
			t.Errorf("%s was refused, but not for the reason this case holds (want %q): %q",
				tc.name, tc.want, line)
		}
	}
}
