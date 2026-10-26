package dockerproxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// REGRESSION (issue #690): a payload that sets DOCKER_BUILDKIT=1 over snug's
// DOCKER_BUILDKIT=0 must not reach BuildKit through the proxy. The requests
// are VERBATIM from a recorder listening as DOCKER_HOST, docker 29.7.2-ce with
// buildx 0.36.1, the recorder answering /_ping with `Builder-Version: 2`:
// both `DOCKER_BUILDKIT=1 docker build .` and `docker buildx build --builder
// default .` open with
//
//	POST /grpc   Connection: Upgrade   Upgrade: h2c
//
// (the engine's built-in BuildKit), and only when that fails fall back to
// the docker-container driver, whose first request is
// GET /v1.44/containers/buildx_buildkit_default/json — the ownership gate's
// to answer, not this test's. `/session` and `/build?version=2` are the
// remaining BuildKit entry points into an engine, and are refused here by
// name so that a future allowlist entry cannot open one quietly. With such an
// entry added to allowed(), podman 6.1.2 itself answered 404 to /grpc and
// /session: the engine snug runs serves no BuildKit today, so the refusal
// here is what still holds if one ever does.
//
// What the docker-container driver reaches when it does get a builder is the
// builder CONTAINER's view: it is created through the create filter like any
// other container, and buildx then speaks to it over exec/{id}/start, the
// hijack every `docker exec` takes. Measured inside a sandbox with
// `@podman-build @net`: a pre-created moby/buildkit:buildx-stable-1 booted,
// buildx connected, and the build failed reading its own Dockerfile with
// "failed to mount /tmp/buildkit-mount…: … operation not permitted", the
// builder holding no CAP_SYS_ADMIN. That is test/integration's
// TestBuildKitEntryPointsAreRefusedAtTheProxy's to hold end to end.
func TestBuildKitEntryPointsNeverReachTheEngine(t *testing.T) {
	upgrade := map[string]string{"Connection": "Upgrade", "Upgrade": "h2c"}
	for _, mode := range []policy.PodmanMode{policy.PodmanSocket, policy.PodmanBuild} {
		for _, tc := range []struct {
			name, path string
			hdr        map[string]string
			want       string
		}{
			{"grpc, as recorded", "/grpc", upgrade, "is not permitted"},
			{"grpc, versioned", "/v1.44/grpc", upgrade, "is not permitted"},
			{"session", "/v1.44/session", upgrade, "is not permitted"},
			{"session, no upgrade", "/session", nil, "is not permitted"},
		} {
			t.Run(mode.String()+"/"+tc.name, func(t *testing.T) {
				sock, eng, _ := startProxyMode(t, mode)
				before := eng.reached.Load()
				code, resp := postHdr(t, sock, tc.path, "", tc.hdr)
				if eng.reached.Load() != before {
					t.Fatalf("%s reached the engine: a BuildKit session is a channel "+
						"snug does not filter", tc.path)
				}
				if code != http.StatusForbidden {
					t.Errorf("status %d, want 403: %s", code, resp)
				}
				if msg := denyMessage(resp); !strings.Contains(msg, tc.want) {
					t.Errorf("refused, but not by the route allowlist: %s", msg)
				}
			})
		}
	}

	// The compat /build with BuildKit selected. In build mode it is the build
	// filter's `version` check that refuses it; TestBuildVersionSelectorAllowsClassicOnly
	// holds the libpod spelling.
	sock, eng, _ := startBuildProxy(t)
	refuse(t, sock, eng, "/v1.44/build?version=2", "", "BuildKit")
}
