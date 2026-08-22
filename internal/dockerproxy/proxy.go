// Package dockerproxy is a filtering proxy for podman's HTTP API.
//
// The sandbox never speaks to a container engine directly. CONTAINER_HOST (and
// DOCKER_HOST) point at a socket snug owns; snug decides what each request is
// allowed to do before forwarding it to a per-sandbox engine.
//
// The rule that matters, and the reason this exists at all:
//
//	A container may bind a host path if and only if the SANDBOX itself can see
//	that path, at the same or greater access.
//
// Without it a container engine is a complete sandbox escape wearing an API.
// `podman run -v /:/host alpine cat /host/etc/shadow` runs OUTSIDE every mount
// grant snug made, because the engine is not in the sandbox's namespaces. Not
// hypothetical: verified against podman 5.8.3, which accepted a create request
// carrying Binds ["/etc:/etc"] and Privileged true without complaint.
//
// Because the same policy.Policy authors both the bwrap argv and the decisions
// here, the two cannot drift — the paths a container may bind are computed from
// the very mounts the sandbox itself received.
//
// snug targets podman. Docker compatibility is explicitly not a goal, which is
// why both the libpod and the docker-compat path shapes are recognised but only
// podman's semantics are considered.
package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gomoni/snug/internal/policy"
)

type Proxy struct {
	pol          *policy.Policy
	upstreamSock string
	// runLabel is `key=value`, stamped on every container this proxy creates so
	// that teardown can stop THIS run's containers and only those. Empty means
	// no stamping, which is only the case in tests that do not care.
	runLabel string
	client   *http.Client
	ln       net.Listener
	audit    func(string)

	srv  *http.Server
	once sync.Once

	// ensureEngine starts the per-sandbox engine on first use. Lazy so that
	// selecting the profile and never running a container costs nothing.
	ensureEngine func() error
	engineOnce   sync.Once
	engineErr    error
}

// New binds the socket the sandbox will see and prepares a client for the
// engine's socket.
func New(pol *policy.Policy, upstreamSock, socketPath, runLabel string, audit func(string), ensureEngine func() error) (*Proxy, error) {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("container proxy socket: %w", err)
	}
	if audit == nil {
		audit = func(string) {}
	}
	p := &Proxy{
		pol:          pol,
		upstreamSock: upstreamSock,
		runLabel:     runLabel,
		ln:           ln,
		audit:        audit,
		ensureEngine: ensureEngine,
		client: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", upstreamSock)
			},
			// Streaming endpoints (logs -f, wait, events) must not be buffered.
			DisableCompression: true,
		}},
	}
	p.srv = &http.Server{Handler: p}
	return p, nil
}

func (p *Proxy) Serve() { _ = p.srv.Serve(p.ln) }
func (p *Proxy) Close() { p.once.Do(func() { p.srv.Close(); p.ln.Close() }) }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.ensureEngine != nil {
		p.engineOnce.Do(func() { p.engineErr = p.ensureEngine() })
		if p.engineErr != nil {
			p.deny(w, "%v", p.engineErr)
			return
		}
	}

	segs, libpod, ok := normaliseFull(r.URL.Path)
	if !ok {
		p.deny(w, "malformed path %q", r.URL.Path)
		return
	}

	// The filter understands the docker-compat request schema only. Any libpod
	// endpoint that CARRIES A BODY we would have to inspect is refused rather
	// than forwarded unexamined — read-only libpod routes are harmless and stay
	// allowed.
	if libpod && bodyBearing(segs, r.Method) {
		p.deny(w, "the libpod-native API is not supported for %s /%s. snug filters the "+
			"docker-compat schema, and the libpod body is a different shape that this "+
			"filter cannot read — forwarding it unexamined would bypass every check. "+
			"Use the docker-compat endpoint (/v1.41/...).", r.Method, strings.Join(segs, "/"))
		return
	}

	// Attach and exec upgrade the connection and then speak a raw stream. They
	// cannot go through the normal request/response path.
	if isHijack(segs, r) {
		p.hijack(w, r)
		return
	}

	switch {
	case isBuild(segs):
		// Gated on the profile, not merely on the path: `@podman-socket` runs
		// containers, `@podman-build` also builds them. See policy.PodmanBuild.
		if p.pol.Podman < policy.PodmanBuild {
			p.deny(w, "building images is not permitted by this sandbox's profiles. "+
				"`@podman-socket` runs containers; add `@podman-build` to build them, "+
				"which opens a second set of options (a build can ask for host binds, "+
				"devices and host networking of its own).")
			return
		}
		p.handleBuild(w, r)
	case isContainerCreate(segs):
		p.handleCreate(w, r)
	case isExecCreate(segs, r.Method):
		p.handleExecCreate(w, r)
	case isVolumeCreate(segs):
		p.handleVolumeCreate(w, r)
	case isImageCreate(segs):
		p.handleImageCreate(w, r)
	case isPrune(segs, r.Method):
		p.deny(w, "pruning (%s /%s) is not permitted. A prune names no object, so this "+
			"proxy has nothing to check it against, and what it deletes OUTLIVES this "+
			"sandbox: the engine store is keyed on the target directory and is shared "+
			"with every LATER run on it — that sharing is what makes a warm start warm — "+
			"so a prune throws away images and container records this run never created. "+
			"Delete what you created, by id: `docker rm <id>`, `docker rmi <image>`, "+
			"`docker volume rm <name>`. There is no scoped form of `system/prune` to "+
			"offer: it names no object either.", r.Method, strings.Join(segs, "/"))
	case isArchive(segs):
		// A specific refusal, not the generic one below: this endpoint is
		// permanently refused (see the case "archive", "export" comment in
		// allowed()), and the generic message would leave a reader guessing at
		// an alternative. There is one, and it goes through the mount boundary
		// this proxy actually enforces.
		p.deny(w, "the container archive endpoint (%s /%s) is not permitted; it is "+
			"serviced by the ENGINE, outside the sandbox, as the host uid, so it is not "+
			"bounded by this sandbox's mount grants the way `exec` is. Read or write the "+
			"file with `docker exec <container> cat <path>` or `... | docker exec -i "+
			"<container> tar -x ...` instead.", r.Method, strings.Join(segs, "/"))
	case allowed(segs):
		p.forward(w, r, nil)
	default:
		p.deny(w, "endpoint %s /%s is not permitted", r.Method, strings.Join(segs, "/"))
	}
}

// normalise strips the API version prefix and podman's `libpod` segment, and
// splits the rest.
//
// Rejecting `.` and `..` outright is not paranoia: without it
// `/containers/../build` reaches the build endpoint while matching an allowed
// prefix.
func normalise(path string) ([]string, bool) {
	segs, _, ok := normaliseFull(path)
	return segs, ok
}

// normaliseFull also reports whether the path used podman's NATIVE libpod API.
//
// That distinction is load-bearing. An earlier version collapsed the `libpod`
// segment and forgot it, so /v5.0.0/libpod/containers/create routed into
// handleCreate — which only understands the docker-compat schema. The libpod
// SpecGenerator body is a completely different shape, with lowercase top-level
// `mounts`, `privileged`, `netns`, `cap_add`, `devices`. None were inspected and
// the body was forwarded verbatim. The redteam agent used it to bind the host's
// ~/.ssh into a privileged container with host networking and read a private key
// out. A filter that understands one schema MUST NOT be handed the other.
func normaliseFull(path string) (segs []string, libpod bool, ok bool) {
	var out []string
	for _, s := range strings.Split(strings.Trim(path, "/"), "/") {
		switch s {
		case "":
			continue
		case ".", "..":
			return nil, false, false
		}
		out = append(out, s)
	}
	// /v1.41/... (docker-compat) or /v5.0.0/libpod/... (podman native)
	if len(out) > 0 && len(out[0]) > 1 && out[0][0] == 'v' && strings.ContainsAny(out[0], "0123456789") {
		out = out[1:]
	}
	if len(out) > 0 && out[0] == "libpod" {
		out = out[1:]
		libpod = true
	}
	return out, libpod, true
}

// libpodExamined is the ALLOWLIST of first path segments whose POST or PUT this
// filter judges COMPLETELY without reading a libpod-shaped body — either
// because no such request carries a body at all, or because everything
// policy-relevant in it lives somewhere the filter does read. The value is why,
// and it is required: a segment listed with no reason is a segment nobody
// classified.
//
// An allowlist, not a denylist, is issue #340's fix. bodyBearing used to name
// the eight segments known to MATTER — containers, volumes, images, pods, play,
// generate, secrets, manifests — and omitted `networks` and `system`, so
// POST /v5.0.0/libpod/networks/create and POST /v5.0.0/libpod/system/prune
// reached the engine with the body forwarded unexamined while the 403 text a
// human reads claims that forwarding it unexamined "would bypass every check".
// A denylist over an engine's API is the catalogue shape CLAUDE.md's invariant 2
// calls a design smell: a segment podman adds next arrives PERMITTED because
// nobody had heard of it. Inverted, it arrives REFUSED until someone puts it
// here and says why.
//
// TestEveryReachableRouteIsClassified derives the segment set from allowed()'s
// own switch, so a route added to the router and not classified here fails the
// suite rather than shipping.
var libpodExamined = map[string]string{
	"_ping":   "GET only; no body in any spelling",
	"version": "GET only; no body in any spelling",
	"info":    "GET only; no body in any spelling",
	"events":  "GET only; no body in any spelling",
	"build":   "the body is the context tar, which handleBuild forwards unread by design; every policy-relevant build option is a QUERY parameter and handleBuild filters those with its own default-deny allowlist, identically for /v1.41/build and /libpod/build",
}

// bodyBearing reports whether a libpod-spelled request must be refused rather
// than forwarded: whether its BODY could carry policy-relevant fields this
// filter cannot read, because the libpod schema is not the docker-compat one.
func bodyBearing(segs []string, method string) bool {
	if method != http.MethodPost && method != http.MethodPut {
		return false
	}
	if len(segs) == 0 {
		return false
	}
	_, examined := libpodExamined[segs[0]]
	return !examined
}

func isContainerCreate(s []string) bool {
	return len(s) == 2 && s[0] == "containers" && s[1] == "create"
}

func isVolumeCreate(s []string) bool {
	return len(s) == 2 && s[0] == "volumes" && s[1] == "create"
}

// isExecCreate matches POST /containers/{id}/exec, which creates an exec
// instance that exec/{id}/start then runs.
func isExecCreate(s []string, method string) bool {
	return method == http.MethodPost && len(s) == 3 && s[0] == "containers" && s[2] == "exec"
}

// isBuild matches both the docker-compat /build and podman's own /libpod/build.
// The podman CLI uses the latter, which is worth knowing: an earlier reading of
// this endpoint assumed /v1.41/build and would have filtered a path no real
// client posts to.
func isBuild(s []string) bool {
	return len(s) == 1 && s[0] == "build"
}

func isImageCreate(s []string) bool {
	return len(s) == 2 && s[0] == "images" && s[1] == "create"
}

// isArchive matches GET/PUT /containers/{id}/archive — `docker cp`'s
// endpoint. Matched separately from allowed() (which already refuses it, see
// the case "archive", "export" comment below) purely so the refusal can name
// the alternative rather than fall through to the generic "not permitted".
// isPrune matches every endpoint whose last segment is `prune`, in both API
// spellings: containers/prune, images/prune, volumes/prune, networks/prune,
// build/prune and podman's own system/prune.
//
// A RULE rather than a list of five, deliberately. The list would be the
// catalogue shape CLAUDE.md's invariant 2 warns about — podman adding a sixth
// prune would arrive permitted because nobody had heard of it — and the rule
// costs nothing extra: an endpoint that spells itself `prune` is destruction of
// everything matching a filter, which is precisely the shape this proxy cannot
// judge.
//
// ABUSE: a hostile process inside the sandbox can use a prune to destroy the
// engine store's contents — images and the container records of earlier runs on
// this target — in one POST. Measured through this proxy against podman 6.0.2
// (issue #339): a container carrying Labels {"snug.run":"OTHER-SANDBOX"} was
// deleted by POST /v1.41/containers/prune (200, ContainersDeleted listing it),
// and POST /v5.0.0/libpod/system/prune?all=true&volumes=true removed
// localhost/warmcache:v1 from the read-write store. Not an escape: the store is
// snug's own, keyed on this target, and nothing outside it is reachable. What
// it costs is a re-pull and the container records of every earlier run.
//
// Refused rather than scoped, which is the choice worth stating. Scoping would
// mean forcing `filters={"label":["snug.run=<this run>"]}` onto every prune,
// and it fails on its own terms three times over: `system/prune` takes no label
// filter at all, an image carries no run label to filter ON (snug stamps
// containers, not images), and a filter merged into a client-supplied one has
// to be exactly right in a query-string schema that differs between the two
// APIs. `commit` and `update` are refused a few lines below for the analogous
// reason. A refusal is checkable by reading it; a scope is correct only if the
// merge is.
func isPrune(segs []string, method string) bool {
	return method == http.MethodPost && len(segs) >= 2 && segs[len(segs)-1] == "prune"
}

func isArchive(s []string) bool {
	return len(s) >= 3 && s[0] == "containers" && s[2] == "archive"
}

// handleImageCreate separates a pull from an import.
//
//	?fromImage=alpine&tag=latest   a pull from a registry — allowed
//	?fromSrc=-  or  ?fromSrc=URL   an import of a filesystem tarball — refused
//
// The distinction is entirely in the query string, which is why the endpoint
// cannot be judged by its path. Refusing the whole endpoint was the first
// implementation and it broke `docker pull`, i.e. the profile's main purpose.
func (p *Proxy) handleImageCreate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if src := q.Get("fromSrc"); src != "" {
		p.deny(w, "importing an image from %q is not permitted; pull from a registry instead", src)
		return
	}
	if q.Get("fromImage") == "" {
		p.deny(w, "images/create without fromImage is not a pull")
		return
	}
	p.forward(w, r, nil)
}

// allowed is the endpoint allowlist. The default verdict is DENY, so a new or
// unrecognised engine API cannot quietly widen what the sandbox can do.
func allowed(segs []string) bool {
	if len(segs) == 0 {
		return false
	}
	switch segs[0] {
	case "_ping", "version", "info", "events", "system":
		return true

	case "images":
		// Pull, list, inspect, tag, remove — prune is taken by isPrune above,
		// for every segment, before this switch runs. `load` and `import` bring in a
		// filesystem image from a stream the engine did not fetch and snug never
		// saw, so they stay refused. `create` is routed to handleImageCreate,
		// which distinguishes a pull from an import by query string — blocking it
		// outright breaks `docker pull` entirely, which it did.
		if len(segs) >= 2 && (segs[1] == "load" || segs[1] == "import") {
			return false
		}
		return true

	case "networks":
		// Settled Q5 (TIER-B.md, issue #63 Tier B): a client creating a
		// podman network object and connecting to it cannot escape N — the
		// engine holds no CAP_NET_ADMIN to bring one up in the first place,
		// and even a successful create/connect only ever composes namespaces
		// the engine itself already lives in. Relying on N's containment is
		// the answer, not a special-cased refusal list for this endpoint.
		return true

	case "volumes":
		return !(len(segs) >= 2 && segs[1] == "create")

	case "containers":
		if len(segs) == 1 {
			return true // list
		}
		if len(segs) >= 3 {
			switch segs[2] {
			case "archive", "export":
				// NOT because these are "unbounded by the mount policy" — that
				// reasoning, which used to live here, would indict `exec`
				// equally, and `exec` is (correctly) allowed below. The real
				// distinction is WHERE the request runs and AS WHOM: archive and
				// export are serviced by the ENGINE, outside the sandbox, as the
				// HOST UID — not confined by the container's own mount namespace
				// the way `exec` is — and archive path resolution is the home of
				// the CVE-2018-15664 symlink-escape class. Allowing it would rest
				// safety on PODMAN's path resolution rather than on snug's own
				// boundary (redteam, CONTAINER-CLIENT.md §9). isArchive() above
				// gives the refusal a named alternative; this stays a hard no.
				return false
			case "commit", "update":
				// commit turns a container into an image snug never inspected;
				// update rewrites host-config after creation, which would undo
				// the checks handleCreate just made.
				return false
			}
		}
		// attach and exec are ALLOWED. An earlier version refused them on the
		// grounds that they "hand over a live tty inside the container" — but the
		// container is already the sandbox's own, created under this policy, so a
		// shell in it grants nothing running it did not. Refusing attach broke
		// `docker run` outright, which fails with the memorable
		// "unable to upgrade to tcp, received 403".
		return true // start, stop, wait, logs, inspect, kill, rm, stats, attach, exec

	case "exec":
		// An exec INSTANCE is created by containers/{id}/exec, which the clause
		// above already permits, and these routes only inspect or resize that
		// instance. exec/{id}/start is a stream and isHijack takes it first.
		//
		// This case is new with the isHijack fix and is not a widening: the
		// header clause that used to hijack any upgraded request was what made
		// `docker exec` work, so these paths were reachable all along — just via
		// the hole rather than via the allowlist.
		return true

	case "build":
		// `podman build` arrives in M5 with a constrained build context.
		return false
	}
	return false
}

func (p *Proxy) deny(w http.ResponseWriter, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	p.audit("refused: " + msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cause":   "snug policy",
		"message": "snug refused this request: " + msg,
	})
}

// forward relays a request to the engine, streaming both ways.
//
// The Flush immediately after WriteHeader is load-bearing, and was learned the
// hard way by the previous generation of this project: the client calls
// ContainerWait BEFORE ContainerStart, so a proxy that buffers response headers
// deadlocks a foreground `run` — the client waits for headers the proxy is
// holding, and the engine waits for a start that never comes.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	var rc io.Reader = r.Body
	if body != nil {
		rc = strings.NewReader(string(body))
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method,
		"http://engine"+r.URL.RequestURI(), rc)
	if err != nil {
		p.deny(w, "%v", err)
		return
	}
	req.Header = r.Header.Clone()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(body))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		p.deny(w, "container engine unreachable: %v", err)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flush(w)

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			flush(w)
		}
		if err != nil {
			return
		}
	}
}

// isHijack reports whether this request becomes a raw bidirectional stream.
//
// It is decided by PATH, and that is the entire point. The previous version
// returned true whenever an `Upgrade:` or `Connection: upgrade` header was
// present, on ANY path — and ServeHTTP consults it BEFORE handleCreate, while
// hijack() forwards the request byte for byte with r.Write(up). So
// `POST /v1.41/containers/create` carrying `Upgrade: tcp` and
// {"Privileged":true,"Binds":["/:/host"]} reached the engine verbatim, 200 OK,
// with every check skipped. **The client chose whether snug's filter ran at
// all**, which is not a bug in a check but the absence of one. Found by
// mutation-testing the committed suite (M4 review); verified by forwarding real
// bytes to podman.
//
// A header may narrow this set (a detached start is an ordinary POST and must
// keep going through forward), but it may never widen it. Every path below
// operates on a container or exec instance that has already been through
// handleCreate, so the stream carries no authority the policy did not grant.
func isHijack(segs []string, r *http.Request) bool {
	switch {
	case len(segs) >= 3 && segs[0] == "containers" && segs[2] == "attach":
		// .../attach and .../attach/ws
		return true
	case len(segs) == 3 && segs[0] == "containers" && segs[2] == "start":
		// `docker run` in the foreground upgrades on start; `docker start -d`
		// does not, and must stay on the normal path.
		return upgradeRequested(r)
	case len(segs) == 3 && segs[0] == "exec" && segs[2] == "start":
		return true
	}
	return false
}

// upgradeRequested reports whether the client asked to upgrade the connection.
//
// `Connection:` is a comma-separated list — `keep-alive, Upgrade` is valid and
// common — so an equality test against "upgrade" reads a live upgrade as absent.
func upgradeRequested(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	for _, v := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(v), "upgrade") {
			return true
		}
	}
	return false
}

// hijack proxies an upgraded connection byte for byte in both directions.
//
// `docker run` in the foreground attaches, which upgrades the HTTP connection
// and then speaks a multiplexed stream that neither side frames as HTTP any
// more. Nothing here inspects it: by this point the container has already been
// through handleCreate, so the stream carries no authority the policy did not
// already grant.
func (p *Proxy) hijack(w http.ResponseWriter, r *http.Request) {
	up, err := net.Dial("unix", p.upstreamSock)
	if err != nil {
		p.deny(w, "container engine unreachable: %v", err)
		return
	}
	defer up.Close()

	if err := r.Write(up); err != nil {
		p.deny(w, "%v", err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		p.deny(w, "connection cannot be upgraded")
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
