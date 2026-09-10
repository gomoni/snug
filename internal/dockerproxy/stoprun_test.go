package dockerproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// stopRunFixture is a Proxy wired to a fake engine this test drives, with the
// proxy's own listening socket in a TempDir. handler is the engine.
func stopRunFixture(t *testing.T, runLabel string, handler http.HandlerFunc) (*Proxy, *[]string, *sync.Mutex) {
	t.Helper()
	dir := t.TempDir()
	up := filepath.Join(dir, "engine.sock")
	ln, err := net.Listen("unix", up)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var seen []string
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		handler(w, r)
	}))

	p, err := New(&policy.Policy{}, up, filepath.Join(dir, "proxy.sock"), runLabel, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(filepath.Join(dir, "proxy.sock")) })
	return p, &seen, &mu
}

// TestStopRunStopsThisRunsContainersAndAsksForNoOthers is issue #174's positive
// half: the graceful stop reaches every container this run created, and the
// question it asks the engine is scoped by THIS run's label rather than
// filtered client-side afterwards.
//
// The scoping is the security half, not an optimisation. The image store is
// keyed on the target directory and persists across runs (ownership.go's ABUSE
// note), so an unscoped list returns containers earlier runs of this project
// left behind — and a stop addressed at one of those would be this run acting
// on another run's container, which is exactly what the ownership gate exists
// to refuse in the other direction.
func TestStopRunStopsThisRunsContainersAndAsksForNoOthers(t *testing.T) {
	var stopped []string
	var mu sync.Mutex
	p, seen, seenMu := stopRunFixture(t, "snug.run=RUN-A", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1.41/containers/json":
			// The engine answers only what the filter asked for, which is what
			// a real one does — so a proxy that sent no filter would get
			// nothing here and the test would fail on the count below.
			f := r.URL.Query().Get("filters")
			var got map[string][]string
			if err := json.Unmarshal([]byte(f), &got); err != nil {
				t.Errorf("filters is not JSON: %q", f)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if len(got["label"]) != 1 || got["label"][0] != "snug.run=RUN-A" {
				t.Errorf("the list request did not scope to this run's label: %q", f)
			}
			if len(got["status"]) != 1 || got["status"][0] != "running" {
				t.Errorf("the list request did not ask for running containers only: %q", f)
			}
			_, _ = w.Write([]byte(`[{"Id":"aaaaaaaaaaaabbbbbbbbbbbb","Labels":{"snug.run":"RUN-A"}},` +
				`{"Id":"ccccccccccccdddddddddddd","Labels":{"snug.run":"RUN-A"}}]`))
		case r.Method == http.MethodPost:
			mu.Lock()
			stopped = append(stopped, r.URL.Path)
			mu.Unlock()
			if r.URL.Query().Get("t") == "" {
				t.Errorf("the stop carried no t= bound, so the engine would use the "+
					"container's own StopTimeout — a value the payload chooses: %s",
					r.URL.RequestURI())
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	p.StopRunContainers(func(string) {})

	mu.Lock()
	defer mu.Unlock()
	if len(stopped) != 2 {
		seenMu.Lock()
		defer seenMu.Unlock()
		t.Fatalf("stopped %d containers, want 2 — the engine saw %v", len(stopped), *seen)
	}
	for _, want := range []string{
		"/v1.41/containers/aaaaaaaaaaaabbbbbbbbbbbb/stop",
		"/v1.41/containers/ccccccccccccdddddddddddd/stop",
	} {
		found := false
		for _, got := range stopped {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no stop addressed to %s; stops were %v", want, stopped)
		}
	}
}

// TestStopRunAddressesContainersByIDNeverByName pins the #386 rule on this new
// caller: every stop is addressed at the immutable 64-hex id the engine itself
// returned, so nothing the payload can rename between the list and the stop
// changes which container is stopped.
func TestStopRunAddressesContainersByIDNeverByName(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var paths []string
	var mu sync.Mutex
	p, _, _ := stopRunFixture(t, "snug.run=RUN-A", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// A real engine returns both, and the NAME is the trap: a caller
			// that used it would be resolving a string the payload controls.
			_, _ = w.Write([]byte(`[{"Id":"` + id + `","Names":["/renameable"],` +
				`"Labels":{"snug.run":"RUN-A"}}]`))
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	p.StopRunContainers(func(string) {})

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 {
		t.Fatalf("stops = %v, want exactly one", paths)
	}
	if want := "/v1.41/containers/" + url.PathEscape(id) + "/stop"; paths[0] != want {
		t.Errorf("stop addressed %q, want %q — a name is resolved a second time by the "+
			"engine and the payload can rename between the two (issue #386)", paths[0], want)
	}
}

// TestStopRunDoesNotHangWhenTheEngineNeverAnswers is the failure mode this
// whole step introduces, and the reason it carries a budget at all.
//
// The graceful stop is a SYNCHRONOUS engine round-trip in snug's exit path. An
// engine that accepts the connection and then never writes would hold snug open
// forever if the call had no deadline — and unlike every other engine request
// snug makes, there is no human waiting on this one to notice.
//
// The assertion is the BUDGET, not merely "it returned": a version that
// returned after the client's own default timeout would still pass a bare
// "did it finish" check, and http.Client's default is no timeout at all.
func TestStopRunDoesNotHangWhenTheEngineNeverAnswers(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	p, _, _ := stopRunFixture(t, "snug.run=RUN-A", func(w http.ResponseWriter, r *http.Request) {
		<-block // accept, then never answer
	})

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		p.StopRunContainers(func(string) {})
		done <- time.Since(start)
	}()

	select {
	case took := <-done:
		// Budget plus slack for a loaded machine. The point is that it is
		// bounded by SNUG's number, not that it is fast.
		if took > 5*time.Second {
			t.Errorf("the graceful stop took %s against a %s budget — a wedged engine is "+
				"holding snug's exit open", took, stopBudget)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the graceful stop never returned against an engine that accepts and never " +
			"answers: snug cannot exit until that engine does")
	}
}

// TestStopRunAsksNothingWithoutARunLabel: no label means the proxy stamped
// none, so there is no way to tell this run's containers from an earlier run's
// — and an unscoped stop would reach containers this run did not create.
// Refusing to ask at all is the only safe answer.
func TestStopRunAsksNothingWithoutARunLabel(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	p, _, _ := stopRunFixture(t, "", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	p.StopRunContainers(func(string) {})

	mu.Lock()
	got := asked
	mu.Unlock()
	if got != 0 {
		t.Errorf("the engine saw %d request(s) from a proxy with no run label; with no label "+
			"there is no way to scope a stop to this run's containers", got)
	}

	// POSITIVE CONTROL: the same fixture WITH a label does ask, so the zero
	// above is the label rule and not a broken fixture.
	p2, _, _ := stopRunFixture(t, "snug.run=RUN-A", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()
		_, _ = w.Write([]byte(`[]`))
	})
	p2.StopRunContainers(func(string) {})
	mu.Lock()
	defer mu.Unlock()
	if asked == 0 {
		t.Error("control: a proxy WITH a run label asked the engine nothing either, so the " +
			"assertion above passes on a fixture that could never reach the engine")
	}
}

// TestStopRunIsBoundedRegardlessOfContainerCount is what catches a serial loop,
// and a serial loop is not a performance defect here — it is the payload
// choosing snug's exit time.
//
// The budget is spent ONCE for the whole step. With one goroutine per id and a
// shared context, fifty containers that never answer cost the same second as
// one; issued serially they would cost fifty. Nothing else in the tree stops a
// payload from creating fifty containers before it exits.
func TestStopRunIsBoundedRegardlessOfContainerCount(t *testing.T) {
	const n = 50
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	var ids []byte
	ids = append(ids, '[')
	for i := 0; i < n; i++ {
		if i > 0 {
			ids = append(ids, ',')
		}
		ids = append(ids, []byte(fmt.Sprintf(`{"Id":"%064d","Labels":{"snug.run":"RUN-A"}}`, i))...)
	}
	ids = append(ids, ']')

	p, _, _ := stopRunFixture(t, "snug.run=RUN-A", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write(ids)
			return
		}
		<-block // every stop hangs
	})

	start := time.Now()
	p.StopRunContainers(func(string) {})
	took := time.Since(start)

	if took > 3*stopBudget {
		t.Errorf("stopping %d containers that never answer took %s against a %s budget — "+
			"the budget is being spent per container, so a payload sets snug's exit time "+
			"by creating containers", n, took, stopBudget)
	}
}

// TestStopRunNeverStopsAnotherRunsContainer is the adjacent negative: the
// engine answers with a container this run did NOT create, as a mis-scoped
// filter or a compromised engine would, and nothing may be addressed to it.
//
// The list filter is the first line of defence and TestStopRunStopsThisRuns...
// asserts it. This asserts the second: even handed an id it did not ask for,
// snug stops only what carries its own label. Without this, a filter that
// silently stopped filtering would pass every other test in this file.
func TestStopRunNeverStopsAnotherRunsContainer(t *testing.T) {
	const mine = "1111111111111111111111111111111111111111111111111111111111111111"
	const theirs = "2222222222222222222222222222222222222222222222222222222222222222"

	var mu sync.Mutex
	var stopped []string
	p, _, _ := stopRunFixture(t, "snug.run=RUN-A", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"Id":"` + mine + `","Labels":{"snug.run":"RUN-A"}},` +
				`{"Id":"` + theirs + `","Labels":{"snug.run":"RUN-B"}}]`))
			return
		}
		mu.Lock()
		stopped = append(stopped, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	p.StopRunContainers(func(string) {})

	mu.Lock()
	defer mu.Unlock()
	for _, got := range stopped {
		if strings.Contains(got, theirs) {
			t.Errorf("stopped %s, which carries another run's snug.run label — this run may "+
				"not act on another run's container (issue #386's rule, the other direction)",
				got)
		}
	}
	if len(stopped) == 0 {
		t.Error("control: nothing was stopped at all, so the assertion above passes on a " +
			"fixture that never reached the stop path")
	}
}
