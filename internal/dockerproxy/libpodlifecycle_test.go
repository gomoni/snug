package dockerproxy

import (
	"net/http"
	"testing"
)

// ── POST /libpod/containers/{id}/{start,stop,kill,restart,pause,unpause,wait}
//    (issue #459) ────────────────────────────────────────────────────────────
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
		{"`podman start` on an existing container, which always sends detachkeys",
			"/v6.0.2/libpod/containers/mine/start?detachkeys=ctrl-p%2Cctrl-q"},
		{"`podman wait` polls with an interval",
			"/v6.0.2/libpod/containers/mine/wait?interval=250ms"},
		{"`podman wait --condition exited`",
			"/v6.0.2/libpod/containers/mine/wait?condition=exited&interval=250ms"},
		{"`podman stop -t 1`",
			"/v6.0.2/libpod/containers/mine/stop?ignore=false&timeout=1"},
		{"`podman stop --ignore -t 3`",
			"/v6.0.2/libpod/containers/mine/stop?ignore=true&timeout=3"},
		{"`podman stop` with no -t, which sends no timeout at all",
			"/v6.0.2/libpod/containers/mine/stop?ignore=false"},
		{"`podman kill`, which always names a signal",
			"/v6.0.2/libpod/containers/mine/kill?signal=KILL"},
		{"`podman kill -s SIGTERM`",
			"/v6.0.2/libpod/containers/mine/kill?signal=SIGTERM"},
		{"`podman stop`'s own kill, which spells the signal without the SIG prefix",
			"/v6.0.2/libpod/containers/mine/kill?signal=TERM"},
		{"`podman restart -t 1`",
			"/v6.0.2/libpod/containers/mine/restart?timeout=1"},
		{"`podman pause`, measured carrying no query at all",
			"/v6.0.2/libpod/containers/mine/pause"},
		{"`podman unpause`, likewise",
			"/v6.0.2/libpod/containers/mine/unpause"},
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
		// The CAMEL spelling. `podman start` sends the LOWERCASE
		// `detachkeys` and that one is admitted; `attach` sends both,
		// and `start` never sends this one. url.Values is
		// case-sensitive, so the two are different parameters and only
		// the measured one is in the table.
		{"start's detachKeys in the camel spelling no measured client sends",
			"/v6.0.2/libpod/containers/mine/start?detachKeys=ctrl-p"},
		{"wait, with start's parameter",
			"/v6.0.2/libpod/containers/mine/wait?recursive=true"},
		{"stop, with docker's spelling of the timeout rather than podman's",
			"/v6.0.2/libpod/containers/mine/stop?t=10"},
		{"kill, with a parameter selecting WHICH processes are signalled",
			"/v6.0.2/libpod/containers/mine/kill?signal=KILL&all=true"},
		{"pause, which was measured carrying no query at all",
			"/v6.0.2/libpod/containers/mine/pause?recursive=true"},
		{"restart, with a checkpoint path — the shape that must never be metadata",
			"/v6.0.2/libpod/containers/mine/restart?timeout=1&import=%2Fhost%2Fckpt"},
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

// TestARepeatedLifecycleParameterIsRefused is a MEASUREMENT, not a tidiness
// rule, and the measurement is the whole reason it exists.
//
// MEASURED, podman 6.0.2, isolated store:
//
//	DELETE /v6.0.2/libpod/containers/v2?depend=false&depend=true&force=true
//	  -> 200, the container AND its dependent destroyed
//
// The engine reads the LAST value of a repeated query parameter; Go's
// url.Values.Get reads the FIRST. So any rule here written with q.Get() would
// pass a request the engine then reads the other way. Refused outright so that
// no rule in this package depends on two parsers agreeing.
func TestARepeatedLifecycleParameterIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, url string }{
		{"a repeated parameter that is otherwise admitted",
			"/v6.0.2/libpod/containers/mine/stop?timeout=1&timeout=9999"},
		{"start's own recursive, twice",
			"/v6.0.2/libpod/containers/mine/start?recursive=false&recursive=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, tc.url, "", "appears more than once")
		})
	}
}

// TestForegroundPodmanRunStillStopsAtAttach pins the deliberate exclusions, and
// it is the test that stops "body-less" being read as the whole rule. attach is
// the maintainer's ruling (YAGNI, revisit if a foreground `podman run` is ever
// needed); checkpoint and restore are the sharpest of the rest, because a query
// parameter carrying a PATH is not metadata however body-less the route is.
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
		{"resize, which frames a stream this proxy does not frame",
			"/v6.0.2/libpod/containers/mine/resize?h=24&w=80"},
		{"checkpoint, whose export= names a HOST PATH resolved in the engine's view",
			"/v6.0.2/libpod/containers/mine/checkpoint?export=%2Fhome%2Fu%2F.ssh%2Fckpt"},
		{"restore, checkpoint's twin",
			"/v6.0.2/libpod/containers/mine/restore?import=%2Ftmp%2Fckpt"},
		{"commit, which turns a container into an image snug never inspected",
			"/v6.0.2/libpod/containers/mine/commit?repo=x"},
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
		// A route with an EMPTY map is admitted, and pause/unpause are why: they
		// were MEASURED carrying no query string at all, so the empty set IS
		// their whole surface and every real request to them passes. The check
		// this replaces — "an empty map means nothing can use the route" — was
		// true only for routes that do carry parameters, and it would have
		// forced two invented ones onto these.
		if len(route.metadata) == 0 && !parameterlessVerbs[verb] {
			t.Errorf("route %q names no parameters, so every real request to it refuses; "+
				"admit it with its measured parameter set, or add it to parameterlessVerbs "+
				"with the capture showing it carries no query string", verb)
		}
		for name, reason := range route.metadata {
			if reason == "" {
				t.Errorf("route %q's parameter %q carries no reason. The reason is what a "+
					"later reader checks the admission against", verb, name)
			}
		}
	}
}

// parameterlessVerbs is the routes MEASURED to carry no query string at all,
// podman 6.0.2:
//
//	POST /v6.0.2/libpod/containers/<id>/pause
//	POST /v6.0.2/libpod/containers/<id>/unpause
//
// Named here rather than inferred from an empty map, so that a route whose
// parameters simply were not measured cannot pass by looking the same.
var parameterlessVerbs = map[string]bool{"pause": true, "unpause": true}

// TestADependencyCannotBeDeclaredAtCreate is the test `start`'s `recursive`
// justification rests on, and it exists because that justification was PROSE
// citing a field nothing in this package named.
//
// `recursive=true` starts the container's declared DEPENDENCIES as well, which
// would be an ownership question the gate cannot answer — the gate is arity-1,
// it inspects one reference. It is not a question here only because a dependency
// cannot be declared: `dependencyContainers` is not in libpodcreate.go's field
// catalogue, so the default-deny sweep refuses it. That is the property, and a
// property a comment asserts and no test measures is one that can be deleted by
// an edit nobody reads as a security change.
func TestADependencyCannotBeDeclaredAtCreate(t *testing.T) {
	sock, eng, _ := startProxy(t)
	refuse(t, sock, eng, "/v6.0.2/libpod/containers/create",
		`{"image":"alpine","dependencyContainers":["deadbeef"]}`, "dependencyContainers")
}
