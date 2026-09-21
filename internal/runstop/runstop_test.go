package runstop

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// stopRunFixture stands up a fake engine on a unix socket this test drives and
// returns that socket's path — which, with the run label, is the whole of what
// Stop needs. It needs no privileges, which is why this package is a leaf: the
// tests below are the security-critical half of issue #174 and they run in CI.
func stopRunFixture(t *testing.T, handler http.HandlerFunc) (sock string, seen *[]string, seenMu *sync.Mutex) {
	t.Helper()
	dir := t.TempDir()
	up := filepath.Join(dir, "engine.sock")
	ln, err := net.Listen("unix", up)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var saw []string
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		saw = append(saw, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		handler(w, r)
	}))

	return up, &saw, &mu
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
	p, seen, seenMu := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
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

	Stop(p, "snug.run=RUN-A")

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
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
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

	Stop(p, "snug.run=RUN-A")

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
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		<-block // accept, then never answer
	})

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		Stop(p, "snug.run=RUN-A")
		done <- time.Since(start)
	}()

	select {
	case took := <-done:
		// Budget plus slack for a loaded machine. The point is that it is
		// bounded by SNUG's number, not that it is fast.
		if took > 5*time.Second {
			t.Errorf("the graceful stop took %s against a %s budget — a wedged engine is "+
				"holding snug's exit open", took, Budget)
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
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	Stop(p, "")

	mu.Lock()
	got := asked
	mu.Unlock()
	if got != 0 {
		t.Errorf("the engine saw %d request(s) for a run with no label; with no label "+
			"there is no way to scope a stop to this run's containers", got)
	}

	// POSITIVE CONTROL: the same fixture WITH a label does ask, so the zero
	// above is the label rule and not a broken fixture.
	p2, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()
		_, _ = w.Write([]byte(`[]`))
	})
	Stop(p2, "snug.run=RUN-A")
	mu.Lock()
	defer mu.Unlock()
	if asked == 0 {
		t.Error("control: a run WITH a label asked the engine nothing either, so the " +
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

	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write(ids)
			return
		}
		<-block // every stop hangs
	})

	start := time.Now()
	Stop(p, "snug.run=RUN-A")
	took := time.Since(start)

	if took > 3*Budget {
		t.Errorf("stopping %d containers that never answer took %s against a %s budget — "+
			"the budget is being spent per container, so a payload sets snug's exit time "+
			"by creating containers", n, took, Budget)
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
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
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

	Stop(p, "snug.run=RUN-A")

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

// TestSplitRefusesARunLabelWithAnEmptyValue pins the rule Split's own doc
// comment names as the one that matters: a `key=` label with nothing after
// the `=` must be refused outright, never accepted as a label whose value
// happens to be "".
//
// The positive control is the bare fact Split's refusal exists to keep an
// empty value away from: a Go map lookup of a key that is not present at all
// yields "", the exact same string an unrefused empty value would carry. If
// this equality did not hold, Split's refusal above would be guarding
// against nothing — every container this run never labelled would otherwise
// read back as carrying an empty-valued "snug.run" label, and Stop would ask
// the engine to act on every container with no run label at all rather than
// this run's own.
func TestSplitRefusesARunLabelWithAnEmptyValue(t *testing.T) {
	if _, _, err := Split("snug.run="); err == nil {
		t.Fatal("Split(\"snug.run=\") returned no error for a label with an empty value")
	}

	noLabels := map[string]string{"other.key": "other-value"}
	if noLabels["snug.run"] != "" {
		t.Fatal("control: a Go map lookup of a missing key did not yield \"\" — Split's " +
			"empty-value refusal is not guarding against the failure mode its own doc " +
			"comment describes")
	}
}

// TestStopRunKeepsWhatItDecodedWhenTheListExceedsTheLimit is red-team finding
// F1: containerIDs' 1 MiB body limit bounds the answer, but the SIZE of that
// answer is partly the payload's own to choose — /v1.41/containers/json
// echoes container labels verbatim, and dockerproxy's create keeps a
// client's labels by design, overwriting only snug.run. Two throwaway
// containers carrying a large enough label push a run's own list past the
// limit, and a whole-array json.Decode on a body cut mid-stream used to fail
// with NO ids kept at all — silently suppressing the graceful stop for the
// ENTIRE run, including a victim container that would otherwise have
// flushed cleanly, for the cost of two containers the payload did not
// otherwise care about.
//
// This run's own container is listed FIRST and the padding comes AFTER —
// element-by-element decoding is what makes that ordering matter at all,
// which TestStopRunStopsEveryContainerWhenTheListIsUnderTheLimit's own
// unpadded shape stands as the control for: without it, "Asked >= 1" below
// could pass on a Stop() that stops only ever the first entry regardless of
// whether the list was cut at all.
func TestStopRunKeepsWhatItDecodedWhenTheListExceedsTheLimit(t *testing.T) {
	const mine = "1111111111111111111111111111111111111111111111111111111111111111"
	const padA = "2222222222222222222222222222222222222222222222222222222222222222"
	const padB = "3333333333333333333333333333333333333333333333333333333333333333"
	// Comfortably over the 1 MiB limit once both are in the same JSON array
	// alongside `mine`'s own small entry.
	pad := strings.Repeat("A", 700*1024)

	var mu sync.Mutex
	var stopped []string
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1.41/containers/json" {
			body := `[{"Id":"` + mine + `","Labels":{"snug.run":"RUN-A"}},` +
				`{"Id":"` + padA + `","Labels":{"pad":"` + pad + `"}},` +
				`{"Id":"` + padB + `","Labels":{"pad":"` + pad + `"}}]`
			_, _ = w.Write([]byte(body))
			return
		}
		mu.Lock()
		stopped = append(stopped, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	rep := Stop(p, "snug.run=RUN-A")

	if !rep.Ran {
		t.Fatal("Ran = false")
	}
	if rep.Asked < 1 {
		t.Fatalf("Asked = %d, want at least 1 (this run's own container, which was decoded "+
			"before the cut)", rep.Asked)
	}
	if rep.Stopped < 1 {
		t.Errorf("Stopped = %d, want at least 1 (note: %q)", rep.Stopped, rep.Note)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, s := range stopped {
		if strings.Contains(s, mine) {
			found = true
		}
	}
	if !found {
		t.Errorf("this run's own container %s was never stopped; stops were %v", mine, stopped)
	}
	if !strings.Contains(rep.Note, "exceeded") {
		t.Errorf("Note does not report the truncation, so a caller reading the audit line has "+
			"no way to tell a cut list from a fully-processed one: %q", rep.Note)
	}
}

// TestStopRunStopsEveryContainerWhenTheListIsUnderTheLimit is the control for
// TestStopRunKeepsWhatItDecodedWhenTheListExceedsTheLimit above: the SAME
// shape — this run's own containers, listed together — but comfortably under
// the 1 MiB limit, must stop every one of them. Without this, "Asked >= 1"
// in the sibling test could pass on a Stop() that silently drops every entry
// after the first REGARDLESS of the list's size, which would have nothing to
// do with the truncation this pair of tests is about.
func TestStopRunStopsEveryContainerWhenTheListIsUnderTheLimit(t *testing.T) {
	ids := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	var mu sync.Mutex
	var stopped []string
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			var b strings.Builder
			b.WriteByte('[')
			for i, id := range ids {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`{"Id":"` + id + `","Labels":{"snug.run":"RUN-A"}}`)
			}
			b.WriteByte(']')
			_, _ = w.Write([]byte(b.String()))
			return
		}
		mu.Lock()
		stopped = append(stopped, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	rep := Stop(p, "snug.run=RUN-A")
	if rep.Asked != len(ids) {
		t.Fatalf("Asked = %d, want %d (note: %q)", rep.Asked, len(ids), rep.Note)
	}
	if rep.Stopped != len(ids) {
		t.Errorf("Stopped = %d, want %d (note: %q)", rep.Stopped, len(ids), rep.Note)
	}
	if strings.Contains(rep.Note, "exceeded") {
		t.Errorf("Note reports a truncation that should not have happened for a list well under "+
			"the limit: %q", rep.Note)
	}
}

// TestNoteEscapesWhatTheEngineSupplied is red-team finding F4: Report.Note is
// snug's own sentence, but a stop failure interpolates the engine's own
// container id into it (short(id), stopOne's error path) — and an id is a
// value that arrives over a socket, not one the engine is trusted to have
// generated correctly. Against a fake engine answering an id containing an
// ESC-CSI sequence and a NUL, the note used to carry those bytes verbatim
// through to whatever eventually printed it; policy.VisibleText in P0's own
// audit sink was the only thing that actually held that line, a layer away
// and credited by nothing in this package's own tests.
func TestNoteEscapesWhatTheEngineSupplied(t *testing.T) {
	// U+001B (ESC) starting a CSI colour sequence, then a NUL — neither is
	// printable ASCII, and both are exactly the shape a terminal-forging
	// payload would reach for.
	hostile := "\x1b[31mPWNED\x00x"
	p, _, _ := stopRunFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// json.Marshal, not string concatenation: the hostile id carries
			// raw control bytes that are not legal unescaped inside a JSON
			// string, and this fixture must produce a well-formed answer —
			// exactly as a real engine's own JSON encoder would.
			list := []map[string]any{{"Id": hostile, "Labels": map[string]string{"snug.run": "RUN-A"}}}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		// Every stop fails, so stopOne's error path — the one that
		// interpolates short(id) — is what populates Note.
		w.WriteHeader(http.StatusInternalServerError)
	})

	rep := Stop(p, "snug.run=RUN-A")

	if rep.Note == "" {
		t.Fatal("Note is empty — this fixture failed to reach the code path under test at all")
	}
	if strings.ContainsRune(rep.Note, 0x1b) {
		t.Errorf("Note carries a raw ESC byte from the engine's own container id: %q", rep.Note)
	}
	if strings.ContainsRune(rep.Note, 0x00) {
		t.Errorf("Note carries a raw NUL byte from the engine's own container id: %q", rep.Note)
	}
	for _, r := range rep.Note {
		if r < 0x20 || r > 0x7e {
			t.Errorf("Note contains a non-printable-ASCII rune %q: %q", r, rep.Note)
			break
		}
	}
	// POSITIVE CONTROL: the id's own harmless prefix ("PWNED") survives —
	// without this, a note() that replaced its ENTIRE argument rather than
	// filtering rune by rune would pass every assertion above for the wrong
	// reason.
	if !strings.Contains(rep.Note, "PWNED") {
		t.Errorf("control: Note dropped the hostile id's harmless text too, not just its "+
			"forging bytes: %q", rep.Note)
	}
}
