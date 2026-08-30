package dockerproxy

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// libpodlifecycle.go is POST /libpod/containers/{id}/start and .../wait —
// the two body-less lifecycle routes `podman run -d` needs after
// containers/create (issue #459).
//
// WHY THESE CAN BE READ. Both carry an EMPTY body and put every parameter in
// the query string, the property that already earned /libpod/build and
// /libpod/images/pull their entry in libpodExamined. MEASURED, podman 6.0.2
// CLI against a socket that logs the request:
//
//	podman run -d --rm alpine:3.20 true
//	  POST /containers/create
//	  POST /containers/<id>/start?recursive=true
//
//	podman wait <id>
//	  POST /containers/<id>/wait?interval=250ms
//
// WHAT IS NOT HERE, and it is the half a reader needs: FOREGROUND `podman run`
// does not reach start at all. It posts attach BEFORE it, as a HIJACK —
//
//	POST /containers/<id>/attach?detachKeys=...&stderr=true&stdout=true&stream=true
//
// — and the CLI aborts with "incorrect server response code 200, expected 101"
// against anything that answers it as an ordinary request. Admitting that route
// is a decision about the libpod attach STREAM, not about an empty body, and it
// belongs to issues #465/#508. stop, kill, restart, pause and resize are absent
// for a smaller reason: their query surface was not measured, and a route is
// admitted here on a measurement or not at all.
//
// THE ABUSE SENTENCE. A hostile process inside the sandbox can use this to
// start or wait on a container THIS RUN CREATED, and nothing else. The
// ownership gate (ownership.go) runs before this handler on normalised segments
// identical for both wires, so the id is already this run's; every container in
// the engine reached it through containers/create, which is filtered.
//
// Both routes are gated on `libpod` at the call site, like containers/create.
// The compat spellings keep going through allowed() unchanged — this file is
// the libpod wire's reader, not a new rule for docker's. So
// `POST /v1.41/containers/{id}/start?checkpoint=/host/x` is FORWARDED where
// the libpod spelling refuses, and that is deliberate twice over: podman's
// compat start handler honours only detachKeys (measured, redteam round on
// this file), and admitting a parameter set here on anything but a
// measurement of the client that sends it is the rule this file is built on —
// the docker CLI is the client of that wire and measuring it is what a compat
// twin waits for.

// lifecycleRoute is one admitted route: the parameters it may carry, each with
// the reason it needs no judgement. Default-deny — a parameter outside the map
// is a 403 that names it, so a newer podman sending one refuses loudly instead
// of forwarding it unread (invariant 5).
type lifecycleRoute struct {
	verb     string
	metadata map[string]string
}

var libpodLifecycleRoutes = map[string]lifecycleRoute{
	"start": {
		verb: "start",
		metadata: map[string]string{
			// Sent by the CLI itself on every `podman run -d`. It starts the
			// container's DEPENDENCIES as well, which would be an ownership
			// question if a dependency could exist: it cannot. Dependencies are
			// declared at create time, and libpodcreate.go's field catalogue is
			// default-deny, so `dependencyContainers` refuses there. recursive
			// therefore has nothing to reach that create did not already admit.
			"recursive": "also start the container's declared dependencies (`--requires` at create)",
		},
	},
	"wait": {
		verb: "wait",
		metadata: map[string]string{
			"interval": "how often to poll for the exit status (`--interval`)",
			// Not measured being sent, and admitted anyway because it names a
			// container STATE to wait for and nothing outside the request.
			// A value podman does not know is podman's to refuse.
			"condition": "the container state to wait for (`--condition`)",
		},
	},
}

// isLibpodLifecycle matches POST /containers/{id}/{start,wait} against the
// routes above. The id is segs[1] and is never read here — the ownership gate
// has already canonicalised it and reassigned r.
func isLibpodLifecycle(segs []string, method string) (lifecycleRoute, bool) {
	if method != http.MethodPost || len(segs) != 3 || segs[0] != "containers" {
		return lifecycleRoute{}, false
	}
	route, ok := libpodLifecycleRoutes[segs[2]]
	return route, ok
}

func (p *Proxy) handleLibpodLifecycle(w http.ResponseWriter, r *http.Request, route lifecycleRoute) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		p.deny(w, "the query string of %s is malformed: %v", r.URL.Path, err)
		return
	}

	// A body is refused for the reason images/pull refuses one: the CLI sends
	// none on this route in every capture, and whether podman's own handler
	// would read one was not measured. Bytes snug has not read are not
	// forwarded.
	if r.ContentLength != 0 {
		p.deny(w, "containers/%s with a request body is not permitted: the podman CLI sends "+
			"none, every parameter of this route travels in the query string, and snug does "+
			"not forward bytes it has not read. Drop the body.", route.verb)
		return
	}

	var unknown []string
	for name := range q {
		if _, ok := route.metadata[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		p.deny(w, "the %s parameter %s is one snug's filter has not read, so it refuses the "+
			"request rather than forwarding it unexamined. snug reads this route's whole "+
			"measured parameter set (%s); a parameter outside it may name a host path, a "+
			"container this run does not own or a stream this proxy does not frame, and it "+
			"cannot be waved through on the strength of not being recognised.",
			route.verb, quoteList(unknown), strings.Join(lifecycleParameterNames(route), ", "))
		return
	}

	p.forward(w, r, nil)
}

// lifecycleParameterNames renders a route's admitted set for its refusal, in a
// stable order so the message is the same on every run.
func lifecycleParameterNames(route lifecycleRoute) []string {
	names := make([]string, 0, len(route.metadata))
	for name := range route.metadata {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// libpodLifecycleCase is the switch's predicate: a lifecycle route on the
// LIBPOD wire only. Written as a function rather than inline so the switch
// reads like its neighbours and the libpod condition cannot be dropped by an
// edit that only touches the route test.
func libpodLifecycleCase(segs []string, method string, libpod bool) bool {
	if !libpod {
		return false
	}
	_, ok := isLibpodLifecycle(segs, method)
	return ok
}
