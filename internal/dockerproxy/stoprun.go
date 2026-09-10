package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// StopRunContainers asks the engine to stop the containers THIS run created,
// gracefully, on the one path where the engine is still alive to be asked.
//
// # Why this exists at all, and why it is the clean path only (issue #174)
//
// The engine is pid 1 of its own pid namespace (issue #125's C0), so its death
// collapses the namespace and the kernel SIGKILLs every container process in
// it. MEASURED in #174: pre-C0 a container outlived the engine by more than
// 10s; with C0 every pid was gone in 250ms, and on a SIGKILL of snug the whole
// tree went in "engine gone at 50.19 ms, container token pids gone at 50.19 ms".
// That is stronger containment and it does not depend on snug cooperating —
// but a container doing buffered work gets no signal it can handle.
//
// So this runs at the ONE seam where a stop is possible: the payload has
// exited, snug's own Go code is running, and the engine is still up because
// nothing has torn it down yet (internal/cli's containerRun wires this into
// sandbox.Options.OnPayloadExit, which runs INSIDE the function whose deferred
// Close later collapses the namespace).
//
// THE OTHER TWO PATHS GET NOTHING AND MUST NOT BE DESCRIBED AS IF THEY DID.
// On a catchable signal to snug, confirmTeardown SIGKILLs the stage before this
// can run at all — the closure holding it is still blocked in st.Wait(). On a
// SIGKILL of snug no Go code runs anywhere. Invariant 5: what --dry-run says
// about this is phrased per path, never as a capability.
//
// # The budget is snug's, and that is the security half
//
// StopSignal and StopTimeout are top-level create-body fields the payload
// chooses and the proxy forwards verbatim (toplevel.go's containerProcessChoice
// rows, issue #375). Honouring StopTimeout here would let the payload decide
// how long snug takes to exit, so the `t` query parameter below is snug's own
// number and overrides it. StopSignal still selects WHICH signal the engine
// sends, which is the payload's business — what it cannot do is make the wait
// longer than stopBudget.
//
// MEASURED against a live podman 6.0.2 over its own socket, an isolated store:
// a container whose pid 1 installs a TERM handler stops in 134ms; one with no
// handler, or one ignoring TERM, costs the full default 10.059s and ends in
// SIGKILL regardless, because pid 1 of a pid namespace discards signals with
// default dispositions; `kill -s KILL` is 35ms; listing by label with no
// matches is 27ms. Against an in-tree baseline of "payload exit to snug exit is
// 15ms" (internal/cli/container.go), a one-second cap is the largest number
// that keeps the ordinary case — nothing to stop, or a container that handles
// its signal — inside the noise, and it turns the pathological case from 10s
// into 1s.
//
// # Failure is not an error here
//
// Every failure path proceeds to teardown, because teardown is what actually
// guarantees the containers die. A wedged engine, a socket that does not
// answer, a 500, a container that ignores everything: the namespace collapse
// behind this call fells all of them. The one thing this must never do is HANG
// — the context below bounds the whole step, and it is the only thing standing
// between a wedged engine and a snug that will not exit.
func (p *Proxy) StopRunContainers(audit func(string)) {
	if p.runLabel == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), stopBudget)
	defer cancel()

	ids, err := p.runContainerIDs(ctx)
	if err != nil {
		// Not a refusal and not a failure: say it only where a human asked for
		// detail, and get out of teardown's way.
		audit(fmt.Sprintf("graceful stop skipped: %v", err))
		return
	}
	// CONCURRENT, AND THAT IS THE SECURITY HALF RATHER THAN A SPEEDUP. A serial
	// loop spends the budget once per container, so the payload picks snug's
	// exit time by picking a container count: thirty containers ignoring their
	// stop signal would be thirty seconds. One shared context and one goroutine
	// per id makes the whole step cost the budget once, whatever N is.
	// MEASURED: three concurrent t=1 stops of containers whose pid 1 ignores
	// the signal complete in 1.055s together.
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if err := p.stopOne(ctx, id); err != nil {
				audit(fmt.Sprintf("graceful stop of %s: %v", short(id), err))
				return
			}
			audit("stopped " + short(id) + " gracefully")
		}(id)
	}
	wg.Wait()
}

// stopBudget bounds the WHOLE step — listing plus every stop — rather than
// each request. Per-container would multiply by a count the payload chooses:
// fifty containers ignoring TERM would be fifty budgets, and snug's exit would
// be the payload's to set. See StopRunContainers' comment for the measurements
// this number comes from.
const stopBudget = 1 * time.Second

// runContainerIDs lists the RUNNING containers carrying this run's label.
//
// The label is the same one stampRunLabel writes on every create (create.go),
// and the ownership gate reads to decide whether a route may act on a
// container — so this asks the engine the same question the gate asks, in the
// one direction the gate never needed: which are mine.
//
// `status=running` rather than filtering client-side: a stop of an already
// exited container is a 304 and harmless, but asking for the whole store is
// asking for every container an earlier run of this project left behind (the
// store is keyed on the target and persists — see ownership.go's ABUSE note),
// and this step must not scale with that history.
func (p *Proxy) runContainerIDs(ctx context.Context) ([]string, error) {
	key, value, ok := strings.Cut(p.runLabel, "=")
	if !ok {
		return nil, fmt.Errorf("internal: run label %q is not key=value", p.runLabel)
	}
	filters, err := json.Marshal(map[string][]string{
		"label":  {key + "=" + value},
		"status": {"running"},
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://engine/v1.41/containers/json?filters="+url.QueryEscape(string(filters)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking the engine which containers are this run's: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the engine answered %d when asked which containers are this run's",
			resp.StatusCode)
	}

	// 1 MiB, the same bound and the same reason as ownership.go's inspect: this
	// engine is snug's own, and a body read with no limit is a hang or an OOM
	// waiting for the first engine that misbehaves.
	var list []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("reading the engine's container list: %w", err)
	}

	// THE LABEL IS CHECKED AGAIN HERE, on the answer, and the filter above is
	// not trusted to be the only thing scoping this. The filter is a REQUEST:
	// it says what snug asked for, not what came back. An engine that ignores
	// an unknown filter key, a spelling that stops matching across an engine
	// version, or an engine answering more than it was asked would each turn
	// this step into snug stopping a container this run did not create — the
	// very thing the ownership gate refuses in the other direction (#386).
	// Measured cost of the check: one map lookup per container.
	ids := make([]string, 0, len(list))
	for _, c := range list {
		if c.ID == "" || c.Labels[key] != value {
			continue
		}
		ids = append(ids, c.ID)
	}
	return ids, nil
}

// stopOne sends one stop, addressed by the immutable 64-hex id the list
// returned rather than by any name — the same rule the ownership gate follows
// after issue #386's rename race, and for the same reason: a name is resolved a
// second time by the engine, and the payload can rename between the two.
func (p *Proxy) stopOne(ctx context.Context, id string) error {
	// t is seconds, and it is snug's number rather than the container's
	// StopTimeout. Zero would be a SIGKILL with no grace at all, which is what
	// this whole function exists to avoid; the engine sends the container's
	// StopSignal, waits t, then SIGKILLs.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://engine/v1.41/containers/"+url.PathEscape(id)+"/stop?t="+stopWaitSeconds, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	// 204 stopped it. 304 is "already stopped" and 404 is a container removed
	// between the list and this request — both are races this step does not
	// care about, because both mean there is nothing left to stop.
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotModified, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("the engine answered %d", resp.StatusCode)
	}
}

// stopWaitSeconds is what the ENGINE waits between the container's StopSignal
// and its own SIGKILL, and it EQUALS stopBudget on purpose: the engine must
// never be left waiting past snug's own deadline, because snug stops watching
// at the budget and the engine would then be holding a container open with
// nobody left to care.
//
// The trade is stated rather than hidden: a container that ignores its signal
// consumes the whole budget, so a container AFTER it in the list is not
// reached. That is deliberate — the alternative is a per-container budget,
// which multiplies by a count the payload chooses, and snug's exit time
// becomes the payload's to set. Whatever this step does not reach is felled by
// the pid-namespace collapse a few milliseconds later, which is the guarantee
// that was always doing the work.
const stopWaitSeconds = "1"

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
