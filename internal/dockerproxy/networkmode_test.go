package dockerproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCreateRefusesTheNetworkFlagAndAcceptsItsAbsence drives the REAL recorded
// `docker run` body with only HostConfig.NetworkMode varied, so the difference
// between the arms is exactly the one field and nothing else.
//
// Built from testdata/docker-run-create-body.json rather than from a
// hand-typed `{"HostConfig":{"NetworkMode":"host"}}`, and that is what makes it
// evidence about a client: a two-key body exercises the namespace loop but says
// nothing about whether the surrounding 62 fields would have been refused first
// for some unrelated reason. TestNamespaceModeRefusalsAreExhaustive covers the
// minimal shapes; this covers the wire.
//
// MEASURED against docker 29.4.0-ce (API v1.54), by pointing DOCKER_HOST at a
// recording unix socket — every --network spelling maps 1:1 onto the field:
//
//	no flag                 -> NetworkMode "default"   (and the ONLY case that
//	                           populates NetworkingConfig.EndpointsConfig)
//	--network=host          -> NetworkMode "host"
//	--network=none          -> NetworkMode "none"
//	--network=bridge        -> NetworkMode "bridge"
//	--network=container:abc -> NetworkMode "container:abc"
//	--network=default       -> NetworkMode "default"
//
// So refusing "host" refuses `--network=host` and nothing else, and "default"
// is the no-flag value that must keep working. THE `default` ARM IS WHY THIS
// TEST IS SHIPPABLE AT ALL: without it, the refusal above is indistinguishable
// from a ban on `docker run`.
//
// ONE SPELLING, unlike the build path. A build sends its network request twice
// (the networkmode query parameter and an nsoptions entry — see checkNetworkMode
// and checkNSOptions), so both have to be judged. On create, an explicit
// --network leaves NetworkingConfig.EndpointsConfig EMPTY, measured above:
// HostConfig.NetworkMode is the only door.
func TestCreateRefusesTheNetworkFlagAndAcceptsItsAbsence(t *testing.T) {
	// withNetworkMode re-encodes the recorded body with NetworkMode set to v,
	// or with the key deleted entirely when v is nil.
	withNetworkMode := func(t *testing.T, v *string) string {
		t.Helper()
		rec := loadRecordedCreateBody(t)
		hc := recordedHostConfig(t, rec)
		if v == nil {
			delete(hc, "NetworkMode")
		} else {
			raw, err := json.Marshal(*v)
			if err != nil {
				t.Fatal(err)
			}
			hc["NetworkMode"] = raw
		}
		hcRaw, err := json.Marshal(hc)
		if err != nil {
			t.Fatal(err)
		}
		rec.Body["HostConfig"] = hcRaw
		body, err := json.Marshal(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	str := func(s string) *string { return &s }

	t.Run("--network=host is refused", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		code, resp := post(t, sock, "/v1.41/containers/create", withNetworkMode(t, str("host")))
		if code == 200 {
			t.Fatalf("`docker run --network=host` reached the engine")
		}
		msg := denyMessage(resp)
		if !strings.Contains(msg, "HostConfig.NetworkMode") {
			t.Errorf("the refusal does not name the field to change:\n%s", msg)
		}
		// It must name a fix, and the fix must not be a spelling that is
		// itself refused — the build path shipped exactly that bug, ending its
		// networkmode=1 refusal with "or use --network=host".
		if !strings.Contains(msg, "drop the --network flag") {
			t.Errorf("the refusal does not name the fix:\n%s", msg)
		}
		for _, forbidden := range []string{"--network=host", "use --network="} {
			if strings.Contains(msg, forbidden) {
				t.Errorf("the refusal offers %q, a spelling it refuses:\n%s", forbidden, msg)
			}
		}
		if eng.reached.Load() != 0 {
			t.Error("the engine was reached by a refused create")
		}
	})

	// THE CONTROLS, and they are the point of the test rather than symmetry:
	// a filter that refused every value would pass the arm above.
	for _, tc := range []struct {
		name string
		mode *string
	}{
		{"no --network flag at all (NetworkMode \"default\")", str("default")},
		{"NetworkMode absent from the body", nil},
		{"NetworkMode empty", str("")},
	} {
		t.Run("control: "+tc.name, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			before := eng.reached.Load()
			code, resp := post(t, sock, "/v1.41/containers/create", withNetworkMode(t, tc.mode))
			if code != 200 {
				t.Fatalf("a body naming no network was refused (status %d). That is a ban on "+
					"`docker run`, not a filter: %s", code, denyMessage(resp))
			}
			if eng.reached.Load() == before {
				t.Fatal("the create never reached the engine, so this control proves nothing")
			}
		})
	}
}
