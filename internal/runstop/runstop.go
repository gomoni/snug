// Package runstop stops the containers ONE run created, gracefully, through
// the engine's own socket — and owns the label that says which containers
// those are.
//
// # Why it is a leaf package (issue #174)
//
// The caller is P1, the stage: the process that reaps the payload and whose
// own exit Pdeathsigs the engine. That is not where this code started. It
// started as a method on dockerproxy.Proxy, called from P0 at
// sandbox.Options.OnPayloadExit, and it did not work: MEASURED 4/4 on a clean
// exit, the call reported
//
//	graceful stop skipped: asking the engine which containers are this run's:
//	dial unix /tmp/snug-1000-<pid>/sock/podman-<pid>.sock: connect: connection refused
//
// `connection refused` and not `no such file`: the socket was still on disk and
// nothing was listening. P1 exits the moment the payload is reaped, waiting for
// nothing P0 does, and P1's exit had already felled the engine. A process exit
// beats an HTTP round-trip essentially every time.
//
// So the stop has to run in the process whose exit is the thing being raced,
// and internal/stage is BELOW internal/dockerproxy — a listener, an
// http.Server and a policy filter built around a *Proxy that P1 does not and
// must not have. internal/sandbox states the same rule about internal/engine
// ("layering: this package is lower-level"), and internal/stage sits below
// internal/sandbox, so it inherits the rule rather than getting an exception
// to it. This package therefore depends on nothing of snug's, which is also
// what keeps its tests privilege-free: they run against an httptest unix
// server, in CI, with no user namespace.
//
// # One author for "which containers are this run's" (invariant 6)
//
// Split and Match are that author. internal/engine stamps the label at create,
// internal/dockerproxy's ownership gate and volume removal read it to decide
// whether a route may act, and Stop reads it to decide what to stop — four
// readers of one fact, which before this package were four hand-written
// strings.Cut calls and three hand-written map lookups.
//
// # The budget is snug's, and that is the security half
//
// StopSignal and StopTimeout are top-level create-body fields the payload
// chooses and the proxy forwards verbatim (dockerproxy/toplevel.go's
// containerProcessChoice rows, issue #375). Honouring StopTimeout here would
// let the payload decide how long snug takes to exit, so the `t` query
// parameter is snug's own number and overrides it. StopSignal still selects
// WHICH signal the engine sends, which is the payload's business — what it
// cannot do is make the wait longer than Budget.
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
// MEASURED from P1 at the reap, same engine, payload exited with a detached
// container running: stat of the socket ok, the labelled list 200 in 3ms
// carrying exactly this run's container, and a real stop 204 in 50ms.
//
// # Failure is not an error here
//
// Every failure path proceeds, because teardown is what actually guarantees
// the containers die: a wedged engine, a socket that does not answer, a 500, a
// container that ignores everything — the namespace collapse behind this call
// fells all of them. The one thing this must never do is HANG, and in P1 that
// is sharper than it was in P0: P0's read of the "exited" event is the one
// read on the control socket with no deadline (internal/stage/stage.go), so a
// P1 that blocks here is a snug that never exits. Stop therefore returns a
// Report and never an error, bounds the whole step with one context, waits for
// every goroutine it starts, and recovers a panic in each one — a panic in a
// child goroutine takes the process down whatever the parent recovers, which
// is why the recover is per-goroutine rather than around the step.
package runstop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Key is the label key snug stamps every container it creates with. The value
// is P0's pid: the store persists across runs and is shared by concurrent runs
// on one target, so the pid is the only thing that tells one live run's
// containers from its peer's.
const Key = "snug.run"

// For is the label ONE run stamps, and it is the only place its shape is
// spelled. internal/engine calls it with its own os.Getpid().
func For(pid int) string { return fmt.Sprintf("%s=%d", Key, pid) }

// Budget bounds the WHOLE step — listing plus every stop — rather than each
// request. Per-container would multiply by a count the payload chooses: fifty
// containers ignoring TERM would be fifty budgets, and snug's exit would be
// the payload's to set.
const Budget = 1 * time.Second

// waitSeconds is what the ENGINE waits between the container's StopSignal and
// its own SIGKILL, and it EQUALS Budget on purpose: the engine must never be
// left waiting past snug's own deadline, because snug stops watching at the
// budget and the engine would then be holding a container open with nobody
// left to care.
//
// The trade is stated rather than hidden: a container that ignores its signal
// consumes the whole budget, so a container AFTER it in the list is not
// reached. That is deliberate — the alternative is a per-container budget,
// which multiplies by a count the payload chooses. Whatever this step does not
// reach is felled by the pid-namespace collapse a few milliseconds later,
// which is the guarantee that was always doing the work.
const waitSeconds = "1"

// noteMax caps Report.Note. The report travels on the "exited" event, whose
// encoder refuses a message over 64 KiB — and a refused "exited" is a P0
// blocked forever on a read with no deadline.
const noteMax = 256

// Report is what one step did, in a shape that cannot overflow the wire: three
// scalars and one snug-authored sentence. Nothing an engine or a payload
// chose is interpolated whole into Note, and Note is truncated here rather
// than at the reader.
type Report struct {
	Ran     bool
	Asked   int
	Stopped int
	Note    string
}

func (r *Report) note(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if len(s) > noteMax {
		s = s[:noteMax]
	}
	r.Note = s
}

// Split is the validating split of a `key=value` run label, and it is the one
// author of what a well-formed label is.
//
// THE EMPTY VALUE IS THE RULE THAT MATTERS, and it is a correctness bound
// rather than a trust one. Match compares against a Go map lookup, and a
// missing key yields "" — so a label whose value is empty silently turns
// "containers carrying my label" into "every container that carries no label
// at all", which is exactly what TestStopRunNeverStopsAnotherRunsContainer
// exists to catch. The charset is deliberately narrower than the engine's own:
// this is a value snug writes, so anything outside it is a caller bug rather
// than a host with an unusual layout.
func Split(label string) (key, value string, err error) {
	key, value, ok := strings.Cut(label, "=")
	if !ok {
		return "", "", fmt.Errorf("run label %q is not key=value", label)
	}
	if key == "" {
		return "", "", fmt.Errorf("run label %q has an empty key", label)
	}
	if value == "" {
		return "", "", fmt.Errorf("run label %q has an empty value: an empty value matches "+
			"every container carrying no such label at all, which is the opposite of what a "+
			"run label is for", label)
	}
	if bad := firstBadRune(key); bad != "" {
		return "", "", fmt.Errorf("run label key %q carries %s; snug writes this value itself, "+
			"so anything outside [A-Za-z0-9._-] is a caller bug", key, bad)
	}
	if bad := firstBadRune(value); bad != "" {
		return "", "", fmt.Errorf("run label value %q carries %s; snug writes this value itself, "+
			"so anything outside [A-Za-z0-9._-] is a caller bug", value, bad)
	}
	return key, value, nil
}

func firstBadRune(s string) string {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Sprintf("the rune %q", r)
		}
	}
	return ""
}

// Match reports whether a container's own labels say it belongs to the run
// Split produced key and value for.
//
// It exists so that the ANSWER-side check has one author rather than one copy
// per caller. A filter sent to the engine is a REQUEST: it says what snug
// asked for, not what came back. An engine that ignores an unknown filter key,
// a spelling that stops matching across an engine version, or an engine
// answering more than it was asked would each turn a stop into snug stopping a
// container this run did not create.
func Match(labels map[string]string, key, value string) bool {
	if value == "" {
		return false
	}
	return labels[key] == value
}

// Stop asks the engine at engineSock to stop every RUNNING container carrying
// runLabel, concurrently, inside one Budget.
//
// It never returns an error and never panics out: see the package comment on
// why, in P1, those two are the same requirement.
func Stop(engineSock, runLabel string) (rep Report) {
	defer func() {
		if r := recover(); r != nil {
			rep.note("the graceful stop panicked: %v", r)
		}
	}()

	key, value, err := Split(runLabel)
	if err != nil {
		rep.note("%v", err)
		return rep
	}
	if engineSock == "" {
		rep.note("this run has no engine socket to ask")
		return rep
	}

	client := &http.Client{Transport: &http.Transport{
		// Explicit, and http.DefaultTransport is never used: that one carries
		// ProxyFromEnvironment and would read $HTTP_PROXY and try a TCP
		// connect. P1's environment is empty today, but that is a property of
		// the caller rather than of this code.
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", engineSock)
		},
		// No connection outlives the step: P1's fd set when it reports the
		// payload's exit is what it was when it reaped it.
		DisableKeepAlives: true,
	}}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), Budget)
	defer cancel()

	rep.Ran = true
	ids, err := containerIDs(ctx, client, key, value)
	if err != nil {
		rep.note("%v", err)
		return rep
	}
	rep.Asked = len(ids)

	// CONCURRENT, AND THAT IS THE SECURITY HALF RATHER THAN A SPEEDUP. A
	// serial loop spends the budget once per container, so the payload picks
	// snug's exit time by picking a container count: thirty containers
	// ignoring their stop signal would be thirty seconds. One shared context
	// and one goroutine per id makes the whole step cost the budget once,
	// whatever N is. MEASURED: three concurrent t=1 stops of containers whose
	// pid 1 ignores the signal complete in 1.055s together.
	var (
		mu      sync.Mutex
		stopped int
		failed  string
		wg      sync.WaitGroup
	)
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			// Per-goroutine, and this is the load-bearing recover: a panic
			// here would take the whole process down whatever the caller
			// recovers, and P1 dying without sending "exited" is a snug that
			// never exits.
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					failed = fmt.Sprintf("a stop panicked: %v", r)
					mu.Unlock()
				}
			}()
			err := stopOne(ctx, client, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = fmt.Sprintf("stopping %s: %v", short(id), err)
				return
			}
			stopped++
		}(id)
	}
	// Nothing this step started may outlive it: a request issued after the
	// "exited" event is a request from a process P0 has already begun
	// collapsing.
	wg.Wait()

	rep.Stopped = stopped
	if stopped < len(ids) {
		rep.note("%d of %d container(s) stopped within %s: %s",
			stopped, len(ids), Budget, failed)
	}
	return rep
}

// containerIDs lists the RUNNING containers carrying this run's label.
//
// `status=running` rather than filtering client-side: a stop of an already
// exited container is a 304 and harmless, but asking for the whole store is
// asking for every container an earlier run of this project left behind (the
// store is keyed on the target and persists — see dockerproxy/ownership.go's
// ABUSE note), and this step must not scale with that history.
func containerIDs(ctx context.Context, client *http.Client, key, value string) ([]string, error) {
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
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("asking the engine which containers are this run's: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the engine answered %d when asked which containers are this run's",
			resp.StatusCode)
	}

	// 1 MiB, the same bound and the same reason as dockerproxy's inspect: this
	// engine is snug's own, and a body read with no limit is a hang or an OOM
	// waiting for the first engine that misbehaves. Two fields and no more:
	// Names are payload-chosen and this step has no use for them, so they are
	// not decoded and never logged.
	var list []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("reading the engine's container list: %w", err)
	}

	// THE LABEL IS CHECKED AGAIN HERE, and in P1 the reason is stronger than
	// it was in P0. P0 saw every create body go past its own filter, so it had
	// a second handle on whose container a thing was; P1 has none, and the
	// engine's answer is its only source. Measured cost: one map lookup per
	// container.
	ids := make([]string, 0, len(list))
	for _, c := range list {
		if c.ID == "" || !Match(c.Labels, key, value) {
			continue
		}
		ids = append(ids, c.ID)
	}
	return ids, nil
}

// stopOne sends one stop, addressed by the immutable 64-hex id the list
// returned rather than by any name — the same rule the ownership gate follows
// after issue #386's rename race, and for the same reason: a name is resolved
// a second time by the engine, and the payload can rename between the two.
func stopOne(ctx context.Context, client *http.Client, id string) error {
	// t is seconds, and it is snug's number rather than the container's
	// StopTimeout. Zero would be a SIGKILL with no grace at all, which is what
	// this whole function exists to avoid; the engine sends the container's
	// StopSignal, waits t, then SIGKILLs.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://engine/v1.41/containers/"+url.PathEscape(id)+"/stop?t="+waitSeconds, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
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

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
