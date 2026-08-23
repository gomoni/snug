package dockerproxy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Issue #386. The ownership boundary between two sandbox runs sharing one
// engine store used to be enforced on DELETE and on nothing else.
//
// Measured live on podman 5.8.4, two runs on one target: run B answered 204 to
// `POST /containers/foreign2/start` against run A's exited container, then
// `POST /containers/{id}/exec` + `POST /exec/{id}/start` ran `id; cat
// /root/secretA` as uid=0 and printed run A's secret. `rename` answered 204
// cross-run, and racing that un-gated rename against the DELETE check destroyed
// run A's container in 6 attempts / 0.5s — the check inspected a NAME and
// forward() re-resolved the same name a second time.
//
// These tests are the permanent regression: every container-addressed route is
// refused cross-run, and every gated forward is addressed by the immutable id
// so no rename can re-point the object between the check and the forward.

const (
	ownLabel     = "snug.run=1234"
	ownValue     = "1234"
	foreignValue = "OTHER-SANDBOX"
)

// gatedRoute is one route that addresses a single container, with a marker that
// appears in the forwarded request-URI and nowhere else. Asserting on the marker
// rather than on "the engine was reached" is what separates the client's request
// from the gate's own inspect, which is also a GET to the engine.
type gatedRoute struct {
	name, method, path, body, marker string
}

// The routes, in both API spellings and in both directions of the method split
// this gate deliberately does NOT make. `{ref}` is substituted with the
// container reference under test.
var gatedRoutes = []gatedRoute{
	{"rm", http.MethodDelete, "/v1.41/containers/{ref}?force=true", "", "force=true"},
	{"start", http.MethodPost, "/v1.41/containers/{ref}/start", "", "/start"},
	{"stop", http.MethodPost, "/v1.41/containers/{ref}/stop?t=10", "", "t=10"},
	{"restart", http.MethodPost, "/v1.41/containers/{ref}/restart", "", "/restart"},
	{"kill", http.MethodPost, "/v1.41/containers/{ref}/kill?signal=KILL", "", "signal=KILL"},
	{"pause", http.MethodPost, "/v1.41/containers/{ref}/pause", "", "/pause"},
	{"unpause", http.MethodPost, "/v1.41/containers/{ref}/unpause", "", "/unpause"},
	{"rename", http.MethodPost, "/v1.41/containers/{ref}/rename?name=renamed", "", "name=renamed"},
	{"wait", http.MethodPost, "/v1.41/containers/{ref}/wait", "", "/wait"},
	{"resize", http.MethodPost, "/v1.41/containers/{ref}/resize?h=24&w=80", "", "w=80"},
	{"exec create", http.MethodPost, "/v1.41/containers/{ref}/exec", `{"Cmd":["id"]}`, "/exec"},
	{"inspect", http.MethodGet, "/v1.41/containers/{ref}/json?size=1", "", "size=1"},
	{"logs", http.MethodGet, "/v1.41/containers/{ref}/logs?stdout=1&tail=5", "", "tail=5"},
	{"stats", http.MethodGet, "/v1.41/containers/{ref}/stats?stream=0", "", "stream=0"},
	{"top", http.MethodGet, "/v1.41/containers/{ref}/top?ps_args=aux", "", "ps_args=aux"},
	{"changes", http.MethodGet, "/v1.41/containers/{ref}/changes", "", "/changes"},

	// attach and attach/ws are HIJACKS, taken before the switch. attach/ws is a
	// GET that hands over an interactive tty, which is the single sharpest
	// reason this gate does not split on method.
	{"attach", http.MethodPost, "/v1.41/containers/{ref}/attach?stream=1", "", "stream=1"},
	{"attach ws", http.MethodGet, "/v1.41/containers/{ref}/attach/ws", "", "/attach/ws"},

	// The libpod spelling of a read. It passes the libpod schema gate (GET is a
	// safe method), so without the ownership gate running on the NORMALISED
	// segments it would be an unchecked read path around the whole fix.
	{"libpod inspect", http.MethodGet, "/v5.0.0/libpod/containers/{ref}/json?size=1", "", "size=1"},
	{"libpod logs", http.MethodGet, "/v5.0.0/libpod/containers/{ref}/logs?tail=5", "", "tail=5"},
}

func routePath(r gatedRoute, ref string) string {
	return strings.ReplaceAll(r.path, "{ref}", ref)
}

// sawMarker reports whether any request the engine received carries the marker.
func sawMarker(rec *recorder, marker string) bool {
	for _, u := range rec.seenURIs() {
		if strings.Contains(u, marker) {
			return true
		}
	}
	return false
}

// TestEveryContainerAddressedRouteIsScopedToThisRun is #386's headline.
//
// The negative half — that the engine never received the operation — matters
// more than the 403. A 403 returned after the engine already started another
// run's container is the same breach.
func TestEveryContainerAddressedRouteIsScopedToThisRun(t *testing.T) {
	for _, tc := range gatedRoutes {
		t.Run(tc.name+"/another run's container is refused", func(t *testing.T) {
			sock, rec := startRecorded(t, ownLabel,
				inspectWithLabels(map[string]string{"snug.run": foreignValue}))
			code, resp := do(t, sock, tc.method, routePath(tc, "foreign"), tc.body)
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, resp)
			}
			if sawMarker(rec, tc.marker) {
				t.Errorf("the operation reached the engine: %v", rec.seenURIs())
			}
			if msg := denyMessage(resp); !strings.Contains(msg, "not created by this sandbox run") {
				t.Errorf("refused, but not for the reason this case exists to test: %s", msg)
			}
		})

		// POSITIVE CONTROL. Without it every assertion above would be equally
		// true of a proxy that refuses the whole container API — `docker run`,
		// `docker exec`, `docker logs` and `docker rm` dead, suite green.
		t.Run(tc.name+"/this run's own container still works", func(t *testing.T) {
			sock, rec := startRecorded(t, ownLabel,
				inspectWithLabels(map[string]string{"snug.run": ownValue}))
			code, resp := do(t, sock, tc.method, routePath(tc, "mine"), tc.body)
			if code == http.StatusForbidden {
				t.Errorf("this run's own container was refused: %s", denyMessage(resp))
			}
			if !sawMarker(rec, tc.marker) {
				t.Errorf("the operation never reached the engine: %v", rec.seenURIs())
			}
		})
	}
}

// TestTheOwnershipGateRunsBeforeTheHijackBranch pins the ORDERING, which is the
// fix rather than a detail.
//
// `POST /containers/{id}/start` carrying `Upgrade:` is what foreground
// `docker run` issues and is the exact route #386 measured at 204. isHijack
// takes it before the switch, so an ownership check placed in the switch — the
// obvious place — misses it entirely and the suite would still be green.
func TestTheOwnershipGateRunsBeforeTheHijackBranch(t *testing.T) {
	upgrade := map[string]string{"Upgrade": "tcp", "Connection": "Upgrade"}

	t.Run("another run's container is refused on the hijacked start", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel,
			inspectWithLabels(map[string]string{"snug.run": foreignValue}))
		code, resp := doHdr(t, sock, http.MethodPost, "/v1.41/containers/foreign/start", "", upgrade)
		if code != http.StatusForbidden {
			t.Errorf("status %d, want 403: %s", code, resp)
		}
		if sawMarker(rec, "/start") {
			t.Errorf("the hijacked start reached the engine: %v", rec.seenURIs())
		}
	})

	// POSITIVE CONTROL: the hijack still works for this run's own container, or
	// foreground `docker run` is broken and the assertion above proves nothing.
	t.Run("this run's own container still streams", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel,
			inspectWithLabels(map[string]string{"snug.run": ownValue}))
		doHdr(t, sock, http.MethodPost, "/v1.41/containers/mine/start", "", upgrade)
		if !sawMarker(rec, "/start") {
			t.Errorf("the hijacked start never reached the engine: %v", rec.seenURIs())
		}
	})
}

// TestTheGatedForwardIsAddressedByTheImmutableId closes the TOCTOU
// STRUCTURALLY, which is why it asserts on a URI rather than racing anything.
//
// The composition measured in #386: the proxy inspected the name `victim`,
// which resolved to this run's own container, and then forwarded
// `DELETE /containers/victim` — a string the engine resolves a SECOND time. A
// concurrent un-gated rename swapped `victim` onto another run's container in
// between, and the engine deleted that one. Six attempts, 0.5s.
//
// With the forward addressed by the 64-hex id the engine handed back, there is
// no second resolution to race: the object checked and the object acted on are
// the same immutable thing. A rename between the two now changes only a name
// nobody will look up again.
func TestTheGatedForwardIsAddressedByTheImmutableId(t *testing.T) {
	own := inspectWithLabels(map[string]string{"snug.run": ownValue})
	wantID := hex64("victim")

	t.Run("forward: DELETE by name arrives addressed by the id", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel, own)
		if code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/victim", ""); code != 200 {
			t.Fatalf("status %d: %s", code, resp)
		}
		uri := rec.forwardedURI(t, http.MethodDelete)
		if !strings.Contains(uri, wantID) {
			t.Errorf("the engine was asked to delete %q, which does not name the id the "+
				"ownership check was decided on (%s) — a name re-resolves and that is the "+
				"whole of #386's race", uri, wantID)
		}
		if strings.Contains(uri, "victim") {
			t.Errorf("the engine was asked to delete %q, still addressed by the client's name", uri)
		}
	})

	// The hijack half. http.Request.Write composes the request line from r.URL,
	// so reassigning the request in ServeHTTP reaches hijack() too — but nothing
	// in hijack() says so, and this is what notices if that stops being true.
	t.Run("hijack: an upgraded start arrives addressed by the id", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel, own)
		doHdr(t, sock, http.MethodPost, "/v1.41/containers/victim/start", "",
			map[string]string{"Upgrade": "tcp"})
		uri := rec.forwardedURI(t, http.MethodPost)
		if !strings.Contains(uri, wantID) || strings.Contains(uri, "victim") {
			t.Errorf("the hijacked start was forwarded as %q, want it addressed by %s — the "+
				"hijack path writes the request line itself and is the route #386 measured",
				uri, wantID)
		}
	})

	// A client that already used the canonical id must see it forwarded
	// unchanged. Without this the test above would pass on a proxy that mangled
	// every address.
	t.Run("control: an id the client already spelled is unchanged", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel, own)
		do(t, sock, http.MethodDelete, "/v1.41/containers/"+wantID, "")
		if uri := rec.forwardedURI(t, http.MethodDelete); !strings.Contains(uri, wantID) {
			t.Errorf("forwarded %q, want it to carry %s untouched", uri, wantID)
		}
	})
}

// TestTheGatedForwardCarriesTheQueryStringUnchanged.
//
// The gate rewrites one path segment. Everything else about the request is the
// client's, and a gate that dropped `?force=true` would turn `docker rm -f` into
// a silent no-op — invariant 5's shape, a capability that reports success and
// does nothing.
func TestTheGatedForwardCarriesTheQueryStringUnchanged(t *testing.T) {
	own := inspectWithLabels(map[string]string{"snug.run": ownValue})
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodDelete, "/v1.41/containers/mine?force=true&v=1", "?force=true&v=1"},
		{http.MethodPost, "/v1.41/containers/mine/stop?t=10", "?t=10"},
		{http.MethodPost, "/v1.41/containers/mine/rename?name=after", "?name=after"},
		{http.MethodGet, "/v1.41/containers/mine/logs?follow=0&stdout=1&tail=100",
			"?follow=0&stdout=1&tail=100"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			sock, rec := startRecorded(t, ownLabel, own)
			do(t, sock, tc.method, tc.path, "")
			uri := rec.forwardedURI(t, tc.method)
			if !strings.HasSuffix(uri, tc.want) {
				t.Errorf("forwarded %q, want it to end with %q", uri, tc.want)
			}
		})
	}
}

// TestExecIsScopedToTheContainerItRunsIn.
//
// `POST /exec/{id}/start` carries an EXEC instance id, not a container id, so
// the path-addressed rule reaches it only through the exec's own inspect. This
// is the second half of #386's measured exploit — the half that ran `cat
// /root/secretA` as uid=0 inside another run's container.
func TestExecIsScopedToTheContainerItRunsIn(t *testing.T) {
	execRoutes := []struct{ name, method, path, marker string }{
		{"start", http.MethodPost, "/v1.41/exec/{ref}/start", "/start"}, // hijacked
		{"resize", http.MethodPost, "/v1.41/exec/{ref}/resize?h=24&w=80", "w=80"},
		{"inspect", http.MethodGet, "/v1.41/exec/{ref}/json?x=1", "x=1"},
	}
	// execInspect maps every exec instance onto one container; whose it is comes
	// from the container inspect, which is the point of the two-step lookup.
	execInspect := func(ref string) (int, string) {
		return 200, fmt.Sprintf(`{"ID":%q,"ContainerID":%q}`, hex64(ref), hex64("its-container"))
	}

	for _, tc := range execRoutes {
		path := strings.ReplaceAll(tc.path, "{ref}", "eid")

		t.Run(tc.name+"/an exec in another run's container is refused", func(t *testing.T) {
			sock, rec := startRecordedWith(t, ownLabel, &recorder{
				inspect:     inspectWithLabels(map[string]string{"snug.run": foreignValue}),
				execInspect: execInspect,
			})
			code, resp := do(t, sock, tc.method, path, "")
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, resp)
			}
			if sawMarker(rec, tc.marker) {
				t.Errorf("the exec operation reached the engine: %v", rec.seenURIs())
			}
			if msg := denyMessage(resp); !strings.Contains(msg, "exec instance") {
				t.Errorf("refused, but not by the exec clause of the gate: %s", msg)
			}
		})

		t.Run(tc.name+"/an exec in this run's own container still works", func(t *testing.T) {
			sock, rec := startRecordedWith(t, ownLabel, &recorder{
				inspect:     inspectWithLabels(map[string]string{"snug.run": ownValue}),
				execInspect: execInspect,
			})
			code, resp := do(t, sock, tc.method, path, "")
			if code == http.StatusForbidden {
				t.Errorf("this run's own exec was refused: %s", denyMessage(resp))
			}
			if !sawMarker(rec, tc.marker) {
				t.Errorf("the exec operation never reached the engine: %v", rec.seenURIs())
			}
			// And it is addressed by the id the engine gave us, not by the
			// client's spelling — `eid` never reaches the engine as an address.
			for _, u := range rec.seenURIs() {
				if strings.Contains(u, "/exec/eid/") {
					t.Errorf("forwarded %q, still addressed by the client's exec reference", u)
				}
			}
		})
	}
}

// TestOwnershipFailsClosedWhenItCannotBeChecked.
//
// Fail-open IS the finding. A proxy that permits an operation it could not judge
// has the property that was measured, with one extra HTTP request in front of
// it — so every way the ownership question can fail to be answered must refuse,
// on every gated route rather than on the one the check was first written for.
func TestOwnershipFailsClosedWhenItCannotBeChecked(t *testing.T) {
	routes := []struct{ name, method, path, marker string }{
		{"start", http.MethodPost, "/v1.41/containers/abc/start", "/start"},
		{"logs", http.MethodGet, "/v1.41/containers/abc/logs?tail=5", "tail=5"},
		{"exec create", http.MethodPost, "/v1.41/containers/abc/exec", "/exec"},
		{"rm", http.MethodDelete, "/v1.41/containers/abc?force=true", "force=true"},
	}
	for _, tc := range []struct {
		name    string
		inspect func(string) (int, string)
	}{
		{"the engine answers 500", func(string) (int, string) { return 500, `{}` }},
		{"the engine answers 404", func(string) (int, string) { return 404, `{"message":"no such container"}` }},
		{"the answer is not JSON", func(string) (int, string) { return 200, `not json at all` }},
		{"the answer carries no Config", func(string) (int, string) { return 200, `{"Id":"abc"}` }},
		{"the answer carries a null Config", func(string) (int, string) { return 200, `{"Config":null}` }},
		{"the answer carries no labels", func(string) (int, string) { return 200, `{"Config":{}}` }},

		// New with the widened gate: the engine answered, the label matches, and
		// the id it named is not one. Forwarding on that would address the engine
		// by a name again, which is the race.
		{"the id is a name", func(string) (int, string) {
			return 200, `{"Id":"victim","Config":{"Labels":{"snug.run":"1234"}}}`
		}},
		{"the id is a short id", func(string) (int, string) {
			return 200, `{"Id":"08cfc5d47cf3","Config":{"Labels":{"snug.run":"1234"}}}`
		}},
		{"the id is 64 chars but not hex", func(string) (int, string) {
			return 200, `{"Id":"` + strings.Repeat("z", 64) + `","Config":{"Labels":{"snug.run":"1234"}}}`
		}},
	} {
		for _, rt := range routes {
			t.Run(tc.name+"/"+rt.name, func(t *testing.T) {
				sock, rec := startRecorded(t, ownLabel, tc.inspect)
				code, resp := do(t, sock, rt.method, rt.path, "")
				if code != http.StatusForbidden {
					t.Errorf("status %d, want 403 — a check that did not complete is not a pass: %s",
						code, resp)
				}
				if sawMarker(rec, rt.marker) {
					t.Errorf("the operation reached the engine: %v", rec.seenURIs())
				}
			})
		}
	}

	// The exec lookup has the same failure modes one step earlier.
	for _, tc := range []struct {
		name string
		exec func(string) (int, string)
	}{
		{"the exec inspect answers 404", func(string) (int, string) { return 404, `{}` }},
		{"the exec answer is not JSON", func(string) (int, string) { return 200, `nope` }},
		{"the exec answer carries no ContainerID", func(string) (int, string) {
			return 200, `{"ID":"` + hex64("eid") + `"}`
		}},
		{"the ContainerID is a name", func(string) (int, string) {
			return 200, `{"ID":"` + hex64("eid") + `","ContainerID":"victim"}`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, rec := startRecordedWith(t, ownLabel, &recorder{
				inspect:     inspectWithLabels(map[string]string{"snug.run": ownValue}),
				execInspect: tc.exec,
			})
			code, resp := do(t, sock, http.MethodPost, "/v1.41/exec/eid/resize?w=80", "")
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, resp)
			}
			if sawMarker(rec, "w=80") {
				t.Errorf("the exec operation reached the engine: %v", rec.seenURIs())
			}
		})
	}

	// The precondition, asserted rather than assumed: a proxy with no run label
	// stamps nothing, so nothing is recorded as its own and nothing is actionable.
	// A "skip the check when there is no label" branch would be a fail-open
	// switch reachable from a constructor argument.
	t.Run("no run label refuses rather than skipping the check", func(t *testing.T) {
		sock, rec := startRecorded(t, "", inspectWithLabels(map[string]string{"snug.run": ownValue}))
		code, resp := do(t, sock, http.MethodPost, "/v1.41/containers/abc/start", "")
		if code != http.StatusForbidden {
			t.Errorf("status %d, want 403: %s", code, resp)
		}
		if rec.requests.Load() != 0 {
			t.Errorf("the engine was reached at all: %v", rec.seen())
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "misconfiguration of snug itself") {
			t.Errorf("the refusal does not say whose fault it is: %s", msg)
		}
	})
}

// TestCollectionRoutesAreNotGated.
//
// The gate's exemption is a positive list of the COLLECTION routes, and it is
// method-scoped: podman accepts `json`, `create` and `prune` as container NAMES,
// so a word-only exemption would leave `DELETE /containers/create` — removing a
// container literally called `create` — ungated.
func TestCollectionRoutesAreNotGated(t *testing.T) {
	// Every container inspect refuses here, so any route that reaches the gate
	// cannot pass it: what these cases show is that the gate was never consulted.
	broken := func(string) (int, string) { return 500, `{}` }

	t.Run("the container list is forwarded", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel, broken)
		if code, resp := do(t, sock, http.MethodGet, "/v1.41/containers/json?all=1", ""); code != 200 {
			t.Fatalf("status %d listing containers, want 200: %s", code, resp)
		}
		if !sawMarker(rec, "all=1") {
			t.Errorf("the list never reached the engine: %v", rec.seenURIs())
		}
	})

	t.Run("create still reaches the create filter", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel, broken)
		code, resp := do(t, sock, http.MethodPost, "/v1.41/containers/create?name=x",
			`{"Image":"alpine","HostConfig":{"Privileged":true}}`)
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want the create filter's 403: %s", code, resp)
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "HostConfig.Privileged") {
			t.Errorf("refused, but not by handleCreate — the gate stole the refusal: %s", msg)
		}
		if rec.requests.Load() != 0 {
			t.Errorf("the engine was reached: %v", rec.seen())
		}
	})

	t.Run("prune keeps its own refusal", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel, broken)
		code, resp := do(t, sock, http.MethodPost, "/v1.41/containers/prune", "")
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "docker rm") {
			t.Errorf("refused, but not by the prune case — its message names what to do "+
				"instead and the gate's does not: %s", msg)
		}
		if rec.requests.Load() != 0 {
			t.Errorf("a prune spent an engine round-trip: %v", rec.seen())
		}
	})

	t.Run("a container named create is still gated", func(t *testing.T) {
		sock, rec := startRecorded(t, ownLabel,
			inspectWithLabels(map[string]string{"snug.run": foreignValue}))
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/create", "")
		if code != http.StatusForbidden {
			t.Errorf("status %d, want 403: %s", code, resp)
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "not created by this sandbox run") {
			t.Errorf("refused, but not by the ownership gate: %s", msg)
		}
		if rec.sawAny(http.MethodDelete) {
			t.Errorf("the removal reached the engine: %v", rec.seen())
		}
	})
}

// TestTheOwnershipGateIsTheOnlyOneAndRunsFirst is the structural guard.
//
// Both halves of #386's fix are properties of WHERE code sits, and both are
// undone by an ordinary-looking refactor that no behavioural test in this file
// would necessarily catch on the route it moved:
//
//   - ONE check. Two ownership checks in a package is the shape where one gets
//     updated and the other does not, which is how the DELETE-only gate came to
//     be the only gated verb in the first place.
//   - BEFORE isHijack. A gate moved into ServeHTTP's switch stops covering
//     `containers/{id}/start` with `Upgrade:` and `exec/{id}/start` — the two
//     routes the exploit actually used.
func TestTheOwnershipGateIsTheOnlyOneAndRunsFirst(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var callers []string
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, fn := range funcsCalling(t, f.Name(), string(src), "inspectContainer(") {
			callers = append(callers, f.Name()+":"+fn)
		}
	}
	// POSITIVE CONTROL first: the sweep found the one caller it must find. A
	// sweep matching nothing would pass the "exactly one" assertion for the
	// wrong reason.
	if len(callers) != 1 || callers[0] != "ownership.go:gate" {
		t.Errorf("want exactly one non-test caller of inspectContainer(, ownership.go:gate; got %v.\n"+
			"A second ownership check is how this package ended up enforcing the boundary on "+
			"DELETE and nothing else (issue #386).", callers)
	}

	body := funcBodySource(t, "proxy.go", "ServeHTTP")
	gateAt := strings.Index(body, "p.gate(")
	hijackAt := strings.Index(body, "isHijack(")
	if gateAt < 0 || hijackAt < 0 {
		t.Fatalf("ServeHTTP no longer calls both p.gate( (%d) and isHijack( (%d) — this sweep "+
			"cannot check an ordering between calls it cannot find", gateAt, hijackAt)
	}
	if gateAt > hijackAt {
		t.Errorf("ServeHTTP calls isHijack before p.gate. The hijacked routes — foreground " +
			"`docker run`'s start and exec/{id}/start — are exactly the ones issue #386 " +
			"measured, and a gate below them does not cover them.")
	}
}

// funcBodySource returns the exact source text of one top-level func or method
// body in filename.
func funcBodySource(t *testing.T, filename, name string) string {
	t.Helper()
	src, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s does not parse: %v", filename, err)
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		return string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
	}
	t.Fatalf("%s declares no func %s", filename, name)
	return ""
}

// doHdr is do() with extra request headers — an upgrade, in every case here.
func doHdr(t *testing.T, sock, method, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest(method, "http://d"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
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
