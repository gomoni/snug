package dockerproxy

import (
	"net/http"
	"strings"
	"testing"
)

// ── DELETE /containers/{name}, both wires (issue #459) ──────────────────────

// TestTheDependCascadeIsRefused is the finding this route was admitted around,
// and the measurement is what makes it a test rather than a precaution.
//
// MEASURED, podman 6.0.2, isolated store, one session:
//
//	run A: victimbase, Labels {"snug.run":"RUN-A"}
//	run B: otherrun,   Labels {"snug.run":"RUN-B"}, --network container:victimbase
//	DELETE /v6.0.2/libpod/containers/victimbase?depend=true&force=true
//	  -> 200 [{"Id":"451e869a..."},{"Id":"86e439cb..."}]   BOTH destroyed
//
// snug's ownership gate checked victimbase and never saw otherrun. The gate is
// arity-1 by construction — one reference inspected, one segment canonicalised
// — so a parameter that turns the request into a set operation is outside
// anything it can answer.
func TestTheDependCascadeIsRefused(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "1234"}))

	for _, tc := range []struct{ name, path string }{
		{"the measured cascade, libpod wire",
			"/v6.0.2/libpod/containers/mine?depend=true&force=true&ignore=true&volumes=false"},
		{"depend with a value that is not the literal the CLI sends",
			"/v6.0.2/libpod/containers/mine?depend=1&force=true"},
		{"depend with an empty value, which a bool parse might read as true",
			"/v6.0.2/libpod/containers/mine?depend=&force=true"},
		// The compat wire's handler does NOT decode depend — measured, it
		// answers 500 "has dependent containers which must be removed before
		// it" and destroys nothing. Refused anyway: that is a fact about this
		// engine version, and invariant 5 does not let a boundary rest on one.
		{"depend on the compat wire, where this engine ignores it today",
			"/v1.41/containers/mine?depend=true&force=true"},
		{"link, the compat wire's own second-object parameter",
			"/v1.41/containers/mine?link=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodDelete, tc.path, "")
			if code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", code, resp)
			}
			if rec.requests.Load()-rec.inspects.Load() != before {
				t.Errorf("the removal reached the engine: %v", rec.seen())
			}
		})
	}
}

// TestARepeatedRemovalParameterIsRefused pins the parser disagreement, and the
// measurement is the whole point: this is not a tidiness rule.
//
// MEASURED, podman 6.0.2:
//
//	DELETE /v6.0.2/libpod/containers/v2?depend=false&depend=true&force=true
//	  -> 200, the container AND its dependent destroyed
//
// The engine reads the LAST value; Go's url.Values.Get reads the FIRST. A check
// written as q.Get("depend") == "false" passes that request while the engine
// cascades, so multiplicity is refused rather than reasoned about.
func TestARepeatedRemovalParameterIsRefused(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "1234"}))

	for _, path := range []string{
		"/v6.0.2/libpod/containers/mine?depend=false&depend=true&force=true",
		"/v6.0.2/libpod/containers/mine?force=false&force=true",
	} {
		t.Run(path, func(t *testing.T) {
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodDelete, path, "")
			if code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", code, resp)
			}
			if msg := denyMessage(resp); !strings.Contains(msg, "appears more than once") {
				t.Errorf("refused, but not as a repeated parameter: %s", msg)
			}
			if rec.requests.Load()-rec.inspects.Load() != before {
				t.Errorf("the removal reached the engine: %v", rec.seen())
			}
		})
	}
}

// TestThePodmanCLIsOwnRemovalsReachTheEngine is the ergonomics half, and every
// URL is one podman 6.0.2 was measured sending. `depend=false` is on EVERY
// `podman rm`, which is why the parameter is JUDGED rather than left out of the
// admitted set — omitting it would refuse every removal there is.
func TestThePodmanCLIsOwnRemovalsReachTheEngine(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "1234"}))

	for _, tc := range []struct{ name, path string }{
		{"`podman rm`", "/v6.0.2/libpod/containers/mine?depend=false&force=false&ignore=false&volumes=false"},
		{"`podman rm -f`", "/v6.0.2/libpod/containers/mine?depend=false&force=true&ignore=true&volumes=false"},
		{"`podman rm -v`, whose volumes=true was measured NOT to cascade",
			"/v6.0.2/libpod/containers/mine?depend=false&force=true&ignore=true&volumes=true"},
		{"`podman rm -t 2`", "/v6.0.2/libpod/containers/mine?depend=false&force=true&ignore=true&timeout=2&volumes=false"},
		{"the compat wire's own removal", "/v1.41/containers/mine?force=1&v=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodDelete, tc.path, "")
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if rec.requests.Load()-rec.inspects.Load() == before {
				t.Error("the removal did not reach the engine, so this proves nothing " +
					"about the route being usable")
			}
		})
	}
}

// TestRemovalIsStillScopedToThisRun is the negative that must survive admitting
// the route: widening the PARAMETER surface must not widen the OBJECT surface.
// The ownership gate runs before this handler and is what answers here.
func TestRemovalIsStillScopedToThisRun(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "OTHER"}))

	for _, path := range []string{
		"/v6.0.2/libpod/containers/theirs?depend=false&force=true&ignore=true&volumes=false",
		"/v1.41/containers/theirs?force=1",
	} {
		t.Run(path, func(t *testing.T) {
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodDelete, path, "")
			if code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", code, resp)
			}
			if rec.requests.Load()-rec.inspects.Load() != before {
				t.Errorf("the removal reached the engine: %v", rec.seen())
			}
		})
	}
}

// TestRemovalRefusesAParameterItHasNotRead is default-deny on the wire whose
// client WAS measured. The compat wire is deliberately not default-deny — no
// docker CLI existed on the machine where this landed, so its surface is
// unmeasured and narrowing on an unmeasured client is the same error as
// widening on one. That asymmetry is asserted below rather than left implicit.
func TestRemovalRefusesAParameterItHasNotRead(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "1234"}))

	t.Run("libpod: a parameter from a podman that does not exist yet", func(t *testing.T) {
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodDelete,
			"/v6.0.2/libpod/containers/mine?depend=false&cascadeTo=everything", "")
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "has not read") {
			t.Errorf("refused, but not as an unread parameter: %s", msg)
		}
		if rec.requests.Load()-rec.inspects.Load() != before {
			t.Errorf("the removal reached the engine: %v", rec.seen())
		}
	})

	t.Run("compat: an unmeasured parameter is still forwarded, deliberately", func(t *testing.T) {
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/mine?force=1&noSuchThing=1", "")
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200 — the compat wire has no measured table and must "+
				"keep forwarding what it forwarded before: %s", code, resp)
		}
		if rec.requests.Load()-rec.inspects.Load() == before {
			t.Error("the removal did not reach the engine")
		}
	})
}

// TestRemovalRefusesABody keeps the route's own rule: neither CLI sends one,
// and bytes snug has not read are not forwarded.
func TestRemovalRefusesABody(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "1234"}))
	before := rec.requests.Load() - rec.inspects.Load()
	code, resp := do(t, sock, http.MethodDelete, "/v6.0.2/libpod/containers/mine", `{"depend":true}`)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if rec.requests.Load()-rec.inspects.Load() != before {
		t.Errorf("the removal reached the engine: %v", rec.seen())
	}
}

// TestAllowedNoLongerAuthorsRemoval is invariant 6, asserted against the
// function rather than through the wire. allowed()'s containers clause answered
// this route by forwarding the query unread; containerremove.go is its author
// now, and allowed() must refuse the shape so that deleting the switch case
// cannot quietly restore the old behaviour.
func TestAllowedNoLongerAuthorsRemoval(t *testing.T) {
	if allowed([]string{"containers", "abc"}, http.MethodDelete) {
		t.Error("allowed() still answers DELETE /containers/{id}; it is not the author of " +
			"removal semantics any more, and a second author is invariant 6 broken by the " +
			"exact mechanism it warns about")
	}
	// Positive control: the clause still answers everything else about a
	// container, so this is a refusal of one shape rather than of the segment.
	if !allowed([]string{"containers", "abc", "logs"}, http.MethodGet) {
		t.Error("allowed() stopped answering GET /containers/{id}/logs, which is a widening " +
			"of the refusal beyond the route that moved")
	}
}

// ── the negatives a redteam round on this branch asked to be locked in ──────

// TestEveryLifecycleVerbIsStillScopedToThisRun. The removal case above covers
// DELETE; this covers the POST verbs, on both wires, and it is the negative
// that must survive admitting five new routes: widening the PARAMETER surface
// must not widen the OBJECT surface.
//
// The ownership gate answers here, before any parameter table runs — which is
// also why a foreign id and a bad parameter must not produce the same message.
func TestEveryLifecycleVerbIsStillScopedToThisRun(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", inspectWithLabels(map[string]string{"snug.run": "OTHER"}))

	for _, verb := range []string{"start", "stop", "kill", "restart", "pause", "unpause", "wait"} {
		for _, prefix := range []string{"/v6.0.2/libpod", "/v1.41"} {
			path := prefix + "/containers/theirs/" + verb
			t.Run(path, func(t *testing.T) {
				before := rec.requests.Load() - rec.inspects.Load()
				code, resp := do(t, sock, http.MethodPost, path, "")
				if code != http.StatusForbidden {
					t.Fatalf("status %d, want 403: %s", code, resp)
				}
				if msg := denyMessage(resp); !strings.Contains(msg, "was not created by this sandbox run") {
					t.Errorf("refused, but not by the OWNERSHIP gate — a foreign id and an "+
						"unread parameter must not produce the same message, or the gate "+
						"ordering has moved: %s", msg)
				}
				if rec.requests.Load()-rec.inspects.Load() != before {
					t.Errorf("the request reached the engine: %v", rec.seen())
				}
			})
		}
	}
}
