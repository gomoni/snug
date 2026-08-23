package dockerproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// The ownership gate: one rule, one place.
//
// THE RULE. A request whose route addresses ONE specific container — directly
// by path segment, or indirectly through an exec instance — is forwarded only
// if the engine says that container carries this run's snug.run label, and it
// is forwarded ADDRESSED BY the container's immutable 64-hex id.
//
// Two clauses, both load-bearing. The first is ownership. The second is what
// makes the first true of the object the ENGINE acts on rather than of a string
// the client wrote: forward() rebuilds the URI from r.URL.RequestURI() and
// hijack() writes the request line out of r.URL, so a name checked here is a
// name the engine resolves a SECOND time, independently. That divergence was
// measured (issue #386): a rename racing the check destroyed another run's
// container in 6 attempts / 0.5s. Canonicalising is the structural close; a
// timeout or a lock would not be.
//
// ABUSE: a hostile process inside the sandbox can still ENUMERATE every
// container the engine's store holds — the store is keyed on the target
// directory and persists, so `GET /containers/json?all=1` lists names, images,
// commands, labels and mount tables an earlier run of this project left behind
// — and it can run an image an earlier run built. What it can no longer do is
// ACT on another run's container: start, exec, rename, stop, kill, logs,
// inspect and rm are all refused unless this run created it. Visibility is a
// separate question from the boundary and is deliberately not answered here.
//
// WHY EVERY METHOD, not only the state-changing ones. Three reasons, in
// descending order of force:
//
//   - GET /containers/{id}/attach/ws is a GET that hands over an interactive
//     tty (isHijack matches segs[2] == "attach" at any length). A method split
//     would leave full stdin/stdout on another run's container open on the
//     safe-looking half of the split. Method is not a proxy for harm on this
//     API.
//   - The harm measured in #386 is a DATA READ (`cat /root/secretA`).
//     GET .../logs is the same read with less work; GET .../json returns
//     another run's Config.Env and HostConfig.Binds (host paths); .../top
//     returns another sandbox's process cmdlines; .../changes the files it
//     wrote. Refusing `start` while serving `logs` enforces the boundary
//     against the expensive route and not against the cheap one.
//   - One rule is one thing to keep in step. A method split is a second rule,
//     and the two would have to agree forever about which verbs read.
//
// The cost is one inspect round-trip on a local unix socket per gated request.
//
// FAIL CLOSED at every step. A proxy that permits an operation when it could
// not determine ownership has exactly the property that was measured, with one
// extra HTTP request in front of it — so a transport error, a non-200, an
// undecodable body, a missing Config, a missing label and an answer that is not
// a 64-hex id all refuse.

// refKind says what a path segment names.
type refKind int

const (
	refNone      refKind = iota
	refContainer         // the segment is a container name or id
	refExec              // the segment is an exec-instance id; the container it
	// runs in is the object whose ownership decides
)

// addressedObject reports which NORMALISED segment names the one object a route
// acts on, and what kind of name it is. refNone means the route addresses a
// collection rather than a member, and is not this gate's business.
//
// A POSITIVE classifier over the COLLECTION routes, not a catalogue of the
// dangerous ones — the same argument libpodExamined makes. It rots in the safe
// direction: a route podman adds at containers/<newword> arrives GATED, the
// gate asks the engine what <newword> is, the engine answers 404 and the
// request is refused. A list of dangerous verbs would arrive permitted.
func addressedObject(segs []string, method string) (idx int, kind refKind) {
	// A prune names no object — that is isPrune's whole argument for refusing it
	// — so there is nothing here to ask the engine about, and asking would spend
	// a round-trip only to replace prune's own refusal (which names what to do
	// instead) with a generic one.
	if isPrune(segs, method) {
		return 0, refNone
	}
	switch {
	case len(segs) >= 2 && segs[0] == "containers":
		if len(segs) == 2 && collectionRoute(segs[1], method) {
			return 0, refNone
		}
		return 1, refContainer
	case len(segs) >= 2 && segs[0] == "exec":
		return 1, refExec
	}
	return 0, refNone
}

// collectionRoute names the two container routes that address the collection
// rather than a member. (`containers/prune` is the third and is taken by
// addressedObject's isPrune clause, so it is not written twice.)
//
// METHOD-SCOPED, and that is not decoration: podman accepts `json` and `create`
// as container NAMES (the name grammar is [a-zA-Z0-9][a-zA-Z0-9_.-]*), so a
// word-only exemption would make `DELETE /containers/create` — removing a
// container literally called `create` — an ungated route. With the method in
// the test, each spelling is exempt only on the verb that makes it a collection
// route.
func collectionRoute(word, method string) bool {
	switch word {
	case "json":
		return safeMethod(method)
	case "create":
		return method == http.MethodPost
	}
	return false
}

// canonicalID reports whether s is a name the engine assigned and nothing can
// re-point: 64 lowercase hex.
//
// The forward is addressed by this and only this. A NAME forwarded after a
// check on a name is #386's TOCTOU with an extra round-trip in front of it, and
// a PREFIX is the same shape more quietly — measured against podman 5.8.4,
// `GET /containers/08cfc5d47cf3/json` answers 200, so a short id resolves and
// what it resolves to depends on what else is in the store at forward time.
func canonicalID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// noLabelError separates "this container carries no snug.run label at all" from
// every other way the ownership question can fail to be answered. Both refuse;
// they differ in what a human is told, because in this one case the check
// COMPLETED and the answer is that snug did not create the container.
type noLabelError struct{ id, key string }

func (e *noLabelError) Error() string {
	return fmt.Sprintf("container %s carries no %s label", e.id, e.key)
}

// gate is the single ownership check in this package. It returns the request
// every handler downstream must use — addressed by the immutable id — or writes
// a 403 and reports false.
//
// prefix is how many leading segments normaliseFull stripped (the API version
// and podman's `libpod`), so that a normalised index can be mapped back onto
// the raw path the client wrote.
func (p *Proxy) gate(w http.ResponseWriter, r *http.Request, segs []string, prefix, idx int, kind refKind) (*http.Request, bool) {
	route := strings.Join(segs, "/")

	if p.runLabel == "" {
		p.deny(w, "this proxy stamps no run label, so no container is recorded as this "+
			"run's and none can be acted on. That is a misconfiguration of snug itself, "+
			"not of your command.")
		return nil, false
	}
	key, want, ok := strings.Cut(p.runLabel, "=")
	if !ok {
		p.deny(w, "this proxy's run label %q is not key=value, so ownership cannot be "+
			"checked. That is a misconfiguration of snug itself, not of your command.",
			p.runLabel)
		return nil, false
	}

	ref := segs[idx]
	// what the addressed segment becomes on the way out, and which container
	// decides ownership. For an exec route they are two different objects.
	rewrite, ctrRef := ref, ref
	var execNote string

	if kind == refExec {
		execID, containerID, err := p.inspectExec(r.Context(), ref)
		if err != nil {
			p.deny(w, "snug could not confirm which container exec instance %s runs in "+
				"(%v), so it refuses %s /%s. Ownership is checked against the engine, and "+
				"a check that did not complete is not a pass.", ref, err, r.Method, route)
			return nil, false
		}
		if !canonicalID(execID) || !canonicalID(containerID) {
			p.deny(w, "the engine's answer for exec instance %s names it %q in container "+
				"%q, and one of those is not an id. snug forwards each operation addressed "+
				"by the immutable 64-hex id, so that the object it checked and the object "+
				"the engine acts on are the same one; it will not forward an operation "+
				"addressed by a name.", ref, execID, containerID)
			return nil, false
		}
		rewrite, ctrRef = execID, containerID
		execNote = fmt.Sprintf("exec instance %s runs in ", execID)
	}

	id, got, err := p.inspectContainer(r.Context(), ctrRef)
	if err != nil {
		if nl, ok := errors.AsType[*noLabelError](err); ok {
			p.deny(w, "%scontainer %s carries no %s label at all, so snug did not create "+
				"it, and %s /%s is refused. Every container snug creates is stamped at "+
				"create time; one without the stamp was made by something else sharing "+
				"this engine's store.", execNote, nl.id, key, r.Method, route)
			return nil, false
		}
		p.deny(w, "snug could not confirm that %scontainer %s belongs to this sandbox run "+
			"(%v), so it refuses %s /%s. Ownership is checked against the engine, and a "+
			"check that did not complete is not a pass.", execNote, ctrRef, err, r.Method, route)
		return nil, false
	}
	if !canonicalID(id) || (kind == refExec && id != ctrRef) {
		p.deny(w, "the engine's answer for %s names it %q, which is not the container id "+
			"snug asked about. snug forwards each operation addressed by the immutable "+
			"64-hex id, so that the object it checked and the object the engine acts on "+
			"are the same one; it will not forward an operation addressed by a name.",
			ctrRef, id)
		return nil, false
	}
	if got != want {
		p.deny(w, "%scontainer %s (%s) was not created by this sandbox run, so %s /%s is "+
			"refused. snug stamps every container it creates with %s and acts only on "+
			"those; this one carries %q. The engine's store is keyed on the target "+
			"directory and persists across runs — that sharing is what makes a warm "+
			"start warm — so it holds container records earlier runs of this project "+
			"left behind. Those belong to another sandbox: start, exec, rename, stop, "+
			"logs, inspect and rm are all refused on them, not just rm. Create your own "+
			"container instead; `docker ps -a --filter label=%s` lists the ones this run "+
			"may act on.",
			execNote, ctrRef, id, r.Method, route, p.runLabel, key+"="+got, p.runLabel)
		return nil, false
	}

	if kind == refContainer {
		rewrite = id
	}
	return requestAddressedBy(r, prefix+idx, rewrite), true
}

// inspectContainer asks the engine what a client's container reference IS: the
// immutable id the engine will act on, and the value of this run's label key.
//
// Ownership is asked of the ENGINE, not taken from the request, because the
// client's word for what a container is is the thing being checked.
//
// The docker-compat spelling on purpose: it is the schema this filter reads
// (package comment), and asking over libpod would mean reading a shape this
// package has spent three issues refusing to read.
//
// url.PathEscape on the reference is not decoration. It arrives from the
// request path and this function BUILDS a new request URI out of it, which is a
// request smuggling primitive if it is pasted raw; normaliseFull's `.`/`..`
// refusal guards the ROUTE and is not an escaper.
func (p *Proxy) inspectContainer(ctx context.Context, ref string) (id, label string, err error) {
	var body struct {
		ID     string `json:"Id"`
		Config *struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := p.inspect(ctx, "/v1.41/containers/"+url.PathEscape(ref)+"/json", ref, &body); err != nil {
		return "", "", err
	}
	if body.Config == nil {
		return "", "", fmt.Errorf("the engine's answer for %s carries no Config", ref)
	}
	key, _, _ := strings.Cut(p.runLabel, "=")
	v, ok := body.Config.Labels[key]
	if !ok {
		return "", "", &noLabelError{id: ref, key: key}
	}
	return body.ID, v, nil
}

// inspectExec is the same question for an exec instance: its own immutable id
// and the id of the container it runs in.
//
// An exec session's container is fixed at create and no route re-points it, so
// the pair is immutable and one lookup settles ownership for the whole exec
// lifetime. The exec id is canonicalised anyway — measured against podman
// 5.8.4, an exec inspect refuses a short id (404) while a container inspect
// accepts one (200), but the invariant is worth stating as one sentence (`the
// forwarded request is addressed by the id the engine gave us`) rather than as
// "except for exec, where we reason about what podman happens to resolve".
//
// REJECTED: remembering the exec ids this proxy created, by reading the
// containers/{id}/exec response. It is a second source of truth about ownership
// living beside the engine's, and it forces forward() to buffer a response it
// currently streams.
func (p *Proxy) inspectExec(ctx context.Context, ref string) (execID, containerID string, err error) {
	// encoding/json matches struct fields case-insensitively, which works FOR
	// us here: `ID`, `Id` and `id` all land on one field. Keep it distinct from
	// create.go's decodeObject hazard, which is about case-insensitivity on a
	// body snug CHECKS; here snug is the consumer of the engine's own answer.
	var body struct {
		ID          string `json:"ID"`
		ContainerID string `json:"ContainerID"`
	}
	if err := p.inspect(ctx, "/v1.41/exec/"+url.PathEscape(ref)+"/json", ref, &body); err != nil {
		return "", "", err
	}
	return body.ID, body.ContainerID, nil
}

// inspect is the shared GET-and-decode both ownership lookups need.
//
// 1 MiB is generous for an inspect and bounded on purpose: the engine is snug's
// own, but a body read with no limit is a hang or an OOM waiting for the first
// engine that misbehaves.
func (p *Proxy) inspect(ctx context.Context, path, ref string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://engine"+path, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("asking the engine what %s is: %w", ref, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the engine answered %d when asked what %s is", resp.StatusCode, ref)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return fmt.Errorf("reading the engine's answer for %s: %w", ref, err)
	}
	return nil
}

// requestAddressedBy returns a copy of r whose rawIdx'th non-empty path segment
// is replaced by id. Method, headers, body and QUERY STRING are untouched.
//
// The copy is what both consumers read: forward() builds its URI from
// r.URL.RequestURI(), and http.Request.Write — which hijack() uses — composes
// the request line from r.URL too, NOT from the server-side r.RequestURI field.
// So reassigning the request once in ServeHTTP reaches the hijacked routes as
// well, which is the half of #386 that was actually measured.
//
// Clearing RawPath is load-bearing, and it buys something extra. EscapedPath()
// prefers RawPath only when it is a valid encoding of Path, so a stale one
// would be ignored — but clearing it also means the gated request is forwarded
// as the path the proxy JUDGED (decoded) rather than as the bytes the client
// wrote: `containers/x/star%74` is judged as `start` and now forwarded as
// `start`. That closes a check-forward divergence of the #304/#371 shape for
// every gated route.
func requestAddressedBy(r *http.Request, rawIdx int, id string) *http.Request {
	r2 := r.Clone(r.Context())
	// Split keeps empty elements, so leading, trailing and duplicated slashes
	// survive the round trip; normaliseFull already dropped the empties and
	// refused `.`/`..`, so the non-empty walk and the normalised index cannot
	// disagree about which segment is which.
	parts := strings.Split(r2.URL.Path, "/")
	n := 0
	for i, s := range parts {
		if s == "" {
			continue
		}
		if n == rawIdx {
			parts[i] = id
			break
		}
		n++
	}
	r2.URL.Path = strings.Join(parts, "/")
	r2.URL.RawPath = ""
	return r2
}
