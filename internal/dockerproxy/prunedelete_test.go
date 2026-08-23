package dockerproxy

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// recorder is an upstream that records every request it is asked to serve and
// answers with whatever the case needs.
//
// fakeEngine cannot serve these cases: the ownership check reads
// .Config.Labels out of an inspect, and fakeEngine answers `{"Id":"deadbeef"}`
// to everything — which is exactly the malformed answer the fail-closed case
// wants and exactly the wrong one for the case that must succeed.
type recorder struct {
	mu   atomic.Value // []string of "METHOD /path"
	uris atomic.Value // []string of "METHOD <request-uri>", query string included
	// inspect answers GET /containers/{ref}/json; execInspect answers
	// GET /exec/{ref}/json. Both are the ownership gate's lookups, and both are
	// RECORDED — unlike fakeEngine's, this recorder shows the gate's own traffic,
	// which is what lets a case assert the gate asked before it forwarded.
	inspect     func(ref string) (int, string)
	execInspect func(ref string) (int, string)
	requests    atomic.Int32
	// inspects counts the gate's own lookups, which requests counts too but
	// seen()/seenURIs() deliberately do not record.
	inspects atomic.Int32
}

func (rec *recorder) record(m, p, uri string) {
	prev, _ := rec.mu.Load().([]string)
	rec.mu.Store(append(append([]string{}, prev...), m+" "+p))
	prevU, _ := rec.uris.Load().([]string)
	rec.uris.Store(append(append([]string{}, prevU...), m+" "+uri))
	rec.requests.Add(1)
}

// ownershipLookup matches the two requests the gate makes — GET
// /containers/{ref}/json and GET /exec/{ref}/json — and nothing else. The
// segment BEFORE the reference is what separates them from the collection route
// GET /containers/json, which a suffix test alone would answer with an inspect.
func (rec *recorder) ownershipLookup(r *http.Request) (string, func(string) (int, string), bool) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		return "", nil, false
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[len(parts)-1] != "json" {
		return "", nil, false
	}
	ref := parts[len(parts)-2]
	switch parts[len(parts)-3] {
	case "containers":
		if rec.inspect != nil {
			return ref, rec.inspect, true
		}
	case "exec":
		if rec.execInspect != nil {
			return ref, rec.execInspect, true
		}
	}
	return "", nil, false
}

// seenURIs is seen() with the query string kept. Canonical addressing and
// query-string preservation are both assertions about the forwarded URI, and
// r.URL.Path cannot carry either.
func (rec *recorder) seenURIs() []string {
	v, _ := rec.uris.Load().([]string)
	return v
}

// forwardedURI returns the one request-URI the recorder saw for method. The
// gate's own lookups are not recorded, so this is the client's request as the
// engine received it. Fails the test if there is not exactly one.
func (rec *recorder) forwardedURI(t *testing.T, method string) string {
	t.Helper()
	var hits []string
	for _, r := range rec.seenURIs() {
		if strings.HasPrefix(r, method+" ") {
			hits = append(hits, strings.TrimPrefix(r, method+" "))
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one forwarded %s, saw %d: %v", method, len(hits), rec.seenURIs())
	}
	return hits[0]
}

func (rec *recorder) seen() []string {
	v, _ := rec.mu.Load().([]string)
	return v
}

func (rec *recorder) sawAny(method string) bool {
	for _, r := range rec.seen() {
		if strings.HasPrefix(r, method+" ") {
			return true
		}
	}
	return false
}

// startRecorded is startProxyMode against a recorder rather than fakeEngine.
func startRecorded(t *testing.T, runLabel string, inspect func(ref string) (int, string)) (string, *recorder) {
	t.Helper()
	return startRecordedWith(t, runLabel, &recorder{inspect: inspect})
}

// startRecordedWith takes the recorder ready-made, so a case can supply an
// execInspect too. Set before Serve starts: the handler goroutine reads those
// fields, and assigning them afterwards is a data race whether or not a request
// has been made yet.
func startRecordedWith(t *testing.T, runLabel string, rec *recorder) (string, *recorder) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "proj")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	up := filepath.Join(dir, "engine.sock")
	ln, err := net.Listen("unix", up)
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An ownership lookup is snug ASKING A QUESTION; it is counted but kept
		// out of seen()/seenURIs(), which therefore mean "what the CLIENT's
		// request turned into" throughout this package. Without the split, the
		// gate's own GET .../json is indistinguishable from a forwarded inspect
		// and every "did the operation reach the engine" assertion softens into
		// "was the engine touched at all".
		if ref, answer, ok := rec.ownershipLookup(r); ok {
			rec.requests.Add(1)
			rec.inspects.Add(1)
			code, body := answer(ref)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
			return
		}
		rec.record(r.Method, r.URL.Path, r.URL.RequestURI())
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"Id":"deadbeef"}`))
	}))
	t.Cleanup(func() { ln.Close() })

	pol := &policy.Policy{
		Target: target,
		Podman: policy.PodmanSocket,
		Mounts: map[string]policy.Mount{
			target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
		},
	}
	sock := filepath.Join(dir, "proxy.sock")
	p, err := New(pol, up, sock, runLabel, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return sock, rec
}

// inspectWithLabels answers every container inspect with the same labels and a
// CANONICAL id derived from the reference.
//
// Derived rather than echoed: the ownership gate refuses an engine answer that
// is not 64 lowercase hex, because a name — or a short id, which podman 5.8.4
// resolves (`GET /containers/08cfc5d47cf3/json` → 200) — checked here and
// re-resolved by the engine at forward time is issue #386's TOCTOU. Echoing the
// request string back would make every case in this file refuse for that reason
// instead of the one it was written for.
func inspectWithLabels(labels map[string]string) func(string) (int, string) {
	return func(ref string) (int, string) {
		b, _ := json.Marshal(map[string]any{
			"Id":     hex64(ref),
			"Config": map[string]any{"Labels": labels},
		})
		return 200, string(b)
	}
}

// TestNoPruneEndpointReachesTheEngine is issue #339's headline, asserted as a
// RULE over the router's own route set rather than as a list of five endpoints.
//
// Measured before the fix, through this proxy against a scratch podman 6.0.2
// service: a container carrying Labels {"snug.run":"OTHER-SANDBOX"} was removed
// by POST /v1.41/containers/prune (200, ContainersDeleted naming it), and
// POST /v5.0.0/libpod/system/prune?all=true&volumes=true removed
// localhost/warmcache:v1 from the read-write store.
//
// The negative half — that the engine received NOTHING — matters more than the
// 403. A 403 returned after the engine already pruned is the same loss.
func TestNoPruneEndpointReachesTheEngine(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", nil)

	for _, seg := range routerSegments(t) {
		for _, path := range []string{
			"/v1.41/" + seg + "/prune",
			"/v1.41/" + seg + "/prune?all=true&volumes=true",
			"/v5.0.0/libpod/" + seg + "/prune",
			"/v5.0.0/libpod/" + seg + "/prune?all=true&volumes=true",
			// No API-version prefix at all: normaliseFull strips one only if it
			// is there, and a client may omit it.
			"/" + seg + "/prune",
		} {
			t.Run(path, func(t *testing.T) {
				before := rec.requests.Load()
				code, resp := post(t, sock, path, "")
				if code != http.StatusForbidden {
					t.Errorf("status %d, want 403: %s", code, resp)
				}
				if rec.requests.Load() != before {
					t.Errorf("the prune reached the engine: %v", rec.seen())
				}
			})
		}
	}

	// POSITIVE CONTROL. Without it every assertion above is satisfied by a proxy
	// that refuses everything, and the suite would stay green on a proxy that
	// had stopped working entirely.
	t.Run("control: a non-prune route on the same prefix still reaches the engine", func(t *testing.T) {
		before := rec.requests.Load()
		code, resp := do(t, sock, http.MethodGet, "/v1.41/containers/json?all=1", "")
		if code != 200 {
			t.Fatalf("status %d listing containers, want 200: %s", code, resp)
		}
		if rec.requests.Load() == before {
			t.Error("listing containers did not reach the engine, so the refusals above " +
				"prove nothing about pruning specifically")
		}
	})

	// POSITIVE CONTROL: the refusal names what to do instead, per CLAUDE.md's
	// working agreement and isArchive's precedent.
	t.Run("control: the refusal names the alternative", func(t *testing.T) {
		_, resp := post(t, sock, "/v1.41/containers/prune", "")
		if msg := denyMessage(resp); !strings.Contains(msg, "docker rm") {
			t.Errorf("the refusal does not name an alternative: %s", msg)
		}
	})
}

// TestContainerRemovalIsScopedToThisRun is the direct regression for the
// measured reproduction: a container carrying another run's label, removed by id
// through this proxy.
//
// `GET /containers/json?all=1` still lists it — reading the engine's state was
// never the finding — so the id is enumerable and the check has to be on the
// removal.
func TestContainerRemovalIsScopedToThisRun(t *testing.T) {
	const label = "snug.run=1234"

	t.Run("a container this run created is removed", func(t *testing.T) {
		sock, rec := startRecorded(t, label,
			inspectWithLabels(map[string]string{"snug.run": "1234"}))
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/5e23ffa86800", "")
		if code != 200 {
			t.Fatalf("status %d removing this run's own container, want 200: %s", code, resp)
		}
		if !rec.sawAny(http.MethodDelete) {
			t.Errorf("the removal never reached the engine: %v — `docker run --rm` issues "+
				"exactly this request and must keep working", rec.seen())
		}
	})

	t.Run("a container another run created is not", func(t *testing.T) {
		sock, rec := startRecorded(t, label,
			inspectWithLabels(map[string]string{"snug.run": "OTHER-SANDBOX"}))
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/5e23ffa86800", "")
		if code != http.StatusForbidden {
			t.Errorf("status %d removing another run's container, want 403: %s", code, resp)
		}
		if rec.sawAny(http.MethodDelete) {
			t.Errorf("the removal reached the engine: %v", rec.seen())
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "not created by this sandbox run") {
			t.Errorf("refused, but not for the reason this case exists to test: %s", msg)
		}
	})

	t.Run("a container carrying no snug label at all is not", func(t *testing.T) {
		sock, rec := startRecorded(t, label, inspectWithLabels(map[string]string{"other": "x"}))
		code, _ := do(t, sock, http.MethodDelete, "/v1.41/containers/abc", "")
		if code != http.StatusForbidden {
			t.Errorf("status %d, want 403 — an unlabelled container is not this run's", code)
		}
		if rec.sawAny(http.MethodDelete) {
			t.Errorf("the removal reached the engine: %v", rec.seen())
		}
	})
}

// TestContainerRemovalFailsClosedWhenOwnershipCannotBeChecked.
//
// Fail-open IS the finding. A proxy that permits a removal it could not judge
// has the property that was measured, with one extra HTTP request in front of
// it — so every way the ownership question can fail to be answered must refuse.
func TestContainerRemovalFailsClosedWhenOwnershipCannotBeChecked(t *testing.T) {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, rec := startRecorded(t, "snug.run=1234", tc.inspect)
			code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/abc", "")
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403 — a check that did not complete is not a pass: %s", code, resp)
			}
			if rec.sawAny(http.MethodDelete) {
				t.Errorf("the removal reached the engine: %v", rec.seen())
			}
		})
	}

	// The precondition, asserted rather than assumed: a proxy with no run label
	// stamps nothing, so nothing is recorded as its own and nothing is removable.
	// A "skip the check when there is no label" branch would be a fail-open
	// switch reachable from a constructor argument.
	t.Run("no run label refuses rather than skipping the check", func(t *testing.T) {
		sock, rec := startRecorded(t, "", inspectWithLabels(map[string]string{"snug.run": "1234"}))
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/containers/abc", "")
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

// TestImageAndVolumeRemovalAreRefused.
//
// Neither noun admits a truthful partition by run: snug stamps CONTAINERS, and
// podman has no "label on pull", so a label-scoped image removal would answer
// 200 and delete nothing — a capability the user asked for, silently doing
// nothing, which is CLAUDE.md invariant 5. And the loss is not a cache: an image
// an earlier run BUILT exists nowhere else and no re-pull restores it.
func TestImageAndVolumeRemovalAreRefused(t *testing.T) {
	sock, rec := startRecorded(t, "snug.run=1234", nil)

	for _, path := range []string{
		"/v1.41/images/93b60fc641",
		// A name, not an id: it carries slashes, and an equality test on the
		// segment count would refuse one spelling and forward the other.
		"/v1.41/images/localhost/warmcache:v1",
		"/v5.0.0/libpod/images/93b60fc641",
		"/v1.41/volumes/scratch",
		"/v5.0.0/libpod/volumes/scratch",
	} {
		t.Run(path, func(t *testing.T) {
			before := rec.requests.Load()
			code, resp := do(t, sock, http.MethodDelete, path, "")
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, resp)
			}
			if rec.requests.Load() != before {
				t.Errorf("the removal reached the engine: %v", rec.seen())
			}
		})
	}

	// POSITIVE CONTROL: reading is not destroying. Without this the assertions
	// above pass on a proxy that refuses `images` and `volumes` wholesale, which
	// would break `docker images` and prove nothing about the verb.
	for _, path := range []string{"/v1.41/images/json", "/v1.41/volumes"} {
		t.Run("control: GET "+path, func(t *testing.T) {
			before := rec.requests.Load()
			code, resp := do(t, sock, http.MethodGet, path, "")
			if code != 200 {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if rec.requests.Load() == before {
				t.Error("the read did not reach the engine")
			}
		})
	}

	// A network holds no data, `networks/create` is allowed on TIER-B Q5's
	// containment argument (the engine holds no CAP_NET_ADMIN), and deleting one
	// costs the next run nothing. Allowed deliberately, asserted here so it reads
	// as a decision rather than as an endpoint somebody forgot.
	t.Run("control: a network is deletable, and that is deliberate", func(t *testing.T) {
		before := rec.requests.Load()
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/networks/br0", "")
		if code != 200 {
			t.Fatalf("status %d deleting a network, want 200: %s", code, resp)
		}
		if rec.requests.Load() == before {
			t.Error("the network deletion did not reach the engine")
		}
	})
}
