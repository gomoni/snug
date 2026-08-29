package dockerproxy

import (
	"net/http"
	"testing"
)

// ── POST /libpod/containers/{id}/{start,wait} (issue #459) ──────────────────
//
// Every URL below is one the podman 6.0.2 CLI was MEASURED sending against a
// unix socket that logged the request and answered it, the same method
// imagepull_test.go's URLs come from. A filter tested only with the parameter
// under test is a filter nobody has run against a real client.

// TestThePodmanCLIsOwnStartReachesTheEngine is the ergonomics half: with
// containers/create landed, `podman run -d` died at this route because the
// libpod schema gate had never heard of it.
func TestThePodmanCLIsOwnStartReachesTheEngine(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, url string }{
		{"`podman run -d` starts with recursive=true, which the CLI always sends",
			"/v6.0.2/libpod/containers/mine/start?recursive=true"},
		{"a start with no parameters at all",
			"/v6.0.2/libpod/containers/mine/start"},
		{"`podman wait` polls with an interval",
			"/v6.0.2/libpod/containers/mine/wait?interval=250ms"},
		{"`podman wait --condition exited`",
			"/v6.0.2/libpod/containers/mine/wait?condition=exited&interval=250ms"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.reached.Load()
			code, resp := post(t, sock, tc.url, "")
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if eng.reached.Load() == before {
				t.Error("the request did not reach the engine, so this test proves nothing " +
					"about the route being usable")
			}
		})
	}
}

// TestLifecycleRefusesAParameterItHasNotRead is the default-deny half. The
// parameter set is measured, so a podman that grows a new one refuses loudly
// rather than forwarding it unread — invariant 5, and the same trade
// handleImagePull makes.
func TestLifecycleRefusesAParameterItHasNotRead(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, url string }{
		{"a parameter from a podman that does not exist yet",
			"/v6.0.2/libpod/containers/mine/start?recursive=true&mountfrom=%2Fhost"},
		{"a plausible detach-keys parameter, which start does not carry",
			"/v6.0.2/libpod/containers/mine/start?detachKeys=ctrl-p"},
		{"wait, with start's parameter",
			"/v6.0.2/libpod/containers/mine/wait?recursive=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, tc.url, "", "is one snug's filter has not read")
		})
	}

	t.Run("a body, which the CLI never sends and snug has not read", func(t *testing.T) {
		refuse(t, sock, eng, "/v6.0.2/libpod/containers/mine/start",
			`{"privileged":true}`, "with a request body is not permitted")
	})
}

// TestForegroundPodmanRunStillStopsAtAttach pins the deliberate exclusion, and
// it is the test that stops "body-less" being read as the whole rule.
//
// MEASURED: `podman run --rm alpine:3.20 true` — no -d — posts create, then a
// GET inspect, then attach, and never reaches start at all. attach carries no
// body either; it is refused because it is a HIJACK, and admitting it is a
// decision about the libpod attach stream (issues #465/#508) rather than about
// an empty body.
//
// If this test starts failing because attach was admitted, that is a security
// decision and must read as one: the refusal below is what a reviewer diffs.
func TestForegroundPodmanRunStillStopsAtAttach(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, url string }{
		{"attach, the route foreground `podman run` posts before start",
			"/v6.0.2/libpod/containers/mine/attach?detachKeys=ctrl-p%2Cctrl-q&stderr=true&stdout=true&stream=true"},
		{"stop, whose query surface was never measured",
			"/v6.0.2/libpod/containers/mine/stop?t=10"},
		{"kill, likewise",
			"/v6.0.2/libpod/containers/mine/kill?signal=KILL"},
		{"resize, likewise",
			"/v6.0.2/libpod/containers/mine/resize?h=24&w=80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, tc.url, "", "snug does not filter the libpod-native API")
		})
	}
}

// TestTheCompatSpellingIsUnchangedByTheLibpodReader is invariant 6's half: this
// file reads the LIBPOD wire, and the docker-compat spelling of the same
// segments keeps going through allowed() exactly as before. A compat client
// sending a parameter the libpod table does not name must not start being
// refused by a change made for podman.
func TestTheCompatSpellingIsUnchangedByTheLibpodReader(t *testing.T) {
	sock, eng, _ := startProxy(t)

	// The cases have to DISCRIMINATE, and the first version of this test did
	// not: a compat start with no parameters passes the libpod reader too, so
	// the test went green with the libpod condition deleted. Each case below is
	// a compat request carrying a parameter the libpod table does NOT name, on
	// a route the table DOES hold — the only shape where the two paths differ.
	for _, tc := range []struct{ name, url string }{
		{"docker's start with detachKeys, which the libpod table does not name",
			"/v1.41/containers/mine/start?detachKeys=ctrl-p%2Cctrl-q"},
		{"docker's wait with a condition spelling of its own",
			"/v1.41/containers/mine/wait?condition=next-exit&foo=bar"},
		{"docker's stop, a route the libpod table does not hold at all",
			"/v1.41/containers/mine/stop?t=10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.reached.Load()
			code, resp := post(t, sock, tc.url, "")
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if eng.reached.Load() == before {
				t.Error("the compat request did not reach the engine — the libpod reader " +
					"has changed the other wire, which is the thing it must not do")
			}
		})
	}
}

// TestEveryAdmittedLifecycleVerbNamesItsParameters keeps the table honest: a
// route admitted with an empty parameter map would pass every test above by
// refusing everything, which reads as strictness and is actually a route
// nobody can use.
func TestEveryAdmittedLifecycleVerbNamesItsParameters(t *testing.T) {
	for verb, route := range libpodLifecycleRoutes {
		if route.verb != verb {
			t.Errorf("the table keys %q onto a route whose verb is %q — the key is what "+
				"isLibpodLifecycle matches and the verb is what the refusal prints, so a "+
				"mismatch makes the message name the wrong route", verb, route.verb)
		}
		if len(route.metadata) == 0 {
			t.Errorf("route %q names no parameters, so every real request to it refuses; "+
				"admit it with its measured parameter set or do not admit it", verb)
		}
		for name, reason := range route.metadata {
			if reason == "" {
				t.Errorf("route %q's parameter %q carries no reason. The reason is what a "+
					"later reader checks the admission against", verb, name)
			}
		}
	}
}
