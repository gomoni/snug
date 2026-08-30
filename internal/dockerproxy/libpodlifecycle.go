package dockerproxy

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// libpodlifecycle.go is the body-less POST lifecycle routes of the libpod wire —
// start, stop, kill, restart, pause, unpause and wait — the set `podman run -d`
// and the verbs that follow it need after containers/create (issue #459).
//
// REMOVAL IS NOT HERE. `DELETE /containers/{name}` has a compat twin, so its
// parameters are authored once for both wires in containerremove.go; this file
// is the libpod wire's reader and mixing a two-wire rule into it is how the two
// spellings drift apart.
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
//	podman start <id>            # an EXISTING container, unlike `run -d`'s start
//	  POST /containers/<id>/start?detachkeys=ctrl-p%2Cctrl-q
//
//	podman stop / kill / restart / pause / unpause <id>
//	  POST /containers/<id>/stop?ignore=false&timeout=1
//	  POST /containers/<id>/stop?ignore=true&timeout=3
//	  POST /containers/<id>/stop?ignore=false                 # no -t
//	  POST /containers/<id>/kill?signal=KILL                  # no -s
//	  POST /containers/<id>/kill?signal=SIGTERM
//	  POST /containers/<id>/restart?timeout=1
//	  POST /containers/<id>/pause                             # no query at all
//	  POST /containers/<id>/unpause                           # no query at all
//
// WHAT IS NOT HERE, and it is the half a reader needs: FOREGROUND `podman run`
// does not reach start at all. It posts attach BEFORE it, as a HIJACK —
//
//	POST /containers/<id>/attach?detachKeys=...&stderr=true&stdout=true&stream=true
//
// — and the CLI aborts with "incorrect server response code 200, expected 101"
// against anything that answers it as an ordinary request. Admitting that route
// is a decision about the libpod attach STREAM, not about an empty body, and it
// belongs to issues #465/#508, and the maintainer's ruling is that it stays
// refused. `podman run -d` completes end to end without it.
//
// STILL ABSENT, and each for its own reason. `resize` frames a stream this
// proxy does not frame. `checkpoint` and `restore` sit in the same CLI
// lifecycle family and are the sharpest thing to keep out: `checkpoint?export=`
// names a HOST PATH resolved in the ENGINE's derived view, which is isArchive's
// argument verbatim, and checkOne's rule — a field carrying a path is
// allowlistable only if snug both RESOLVES it and FORWARDS the resolved string
// — applies to a query parameter exactly as it applies to a body field. A path
// is never metadata. `init`, `mount`, `unmount`, `commit`, `update`, `rename`
// and `export` need no arm: default-deny already has them.
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
			// MEASURED, and it is the lowercase spelling that is sent:
			//
			//	podman start <name>
			//	  POST /containers/<id>/start?detachkeys=ctrl-p%2Cctrl-q
			//
			// `podman run -d` does not send it; `podman start` on an EXISTING
			// container always does, which is why the first capture of this
			// route missed it. It names the key sequence that detaches from an
			// attached stream — no object, no path — and on a start with
			// nothing attached the engine ignores it.
			//
			// The CAMEL spelling `detachKeys` is deliberately NOT admitted:
			// podman's own `attach` sends BOTH spellings and its `start` sends
			// only this one, so admitting the other would be admitting a
			// parameter no measured client sends on this route.
			"detachkeys": "the key sequence that detaches from an attached stream (`--detach-keys`)",
		},
	},
	// EVERY parameter below changes how the ADDRESSED container behaves. None
	// of them changes WHICH containers the engine acts on — that criterion is
	// containerremove.go's, written out there because removal is where it bites,
	// and it is the question to ask of anything added here.
	"stop": {
		verb: "stop",
		metadata: map[string]string{
			"ignore":  "answer 200 rather than 404 when the container is already gone (`--ignore`)",
			"timeout": "seconds to wait for a graceful stop before the kill (`-t`)",
		},
	},
	"kill": {
		verb: "kill",
		metadata: map[string]string{
			// Metadata, and the justification has to be checkable rather than
			// "it is just a number": the signal is delivered to PID 1 of a
			// container THIS RUN CREATED, inside that container. A payload that
			// can stop it can already end it. A signal name podman does not
			// know is podman's to refuse.
			//
			// This holds because `signal` is the COMPLETE measured surface of
			// the route. Do NOT extend it by analogy to a parameter that selects
			// WHICH PROCESSES are signalled; default-deny already refuses one.
			"signal": "the signal delivered to PID 1 of this run's container (`-s`)",
		},
	},
	"restart": {
		verb: "restart",
		metadata: map[string]string{
			// A restart re-runs the spec containers/create already judged. It
			// reads no new spec and takes no new configuration.
			"timeout": "seconds to wait for a graceful stop before the kill (`-t`)",
		},
	},
	// pause and unpause carry NO query at all, measured. The empty map is the
	// whole surface and default-deny gives the refusal for free.
	"pause":   {verb: "pause", metadata: map[string]string{}},
	"unpause": {verb: "unpause", metadata: map[string]string{}},
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

	// A repeated parameter is refused on this route for the reason
	// containerremove.go refuses one, and it retro-hardens start and wait:
	// MEASURED against podman 6.0.2, the engine reads the LAST value of a
	// repeated query parameter where Go's own url.Values.Get reads the FIRST.
	// No rule here should depend on two parsers agreeing about which end wins.
	var repeated []string
	for name, values := range q {
		if len(values) > 1 {
			repeated = append(repeated, name)
		}
	}
	if len(repeated) > 0 {
		sort.Strings(repeated)
		p.deny(w, "the %s parameter %s appears more than once, and snug refuses a repeated "+
			"parameter rather than picking an end: the engine reads the LAST value where Go's "+
			"own parser reads the FIRST (measured, podman 6.0.2). Send each parameter once.",
			route.verb, quoteList(repeated))
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
			route.verb, quoteList(unknown), lifecycleParameterSet(route))
		return
	}

	p.forward(w, r, nil)
}

// lifecycleParameterNames renders a route's admitted set for its refusal, in a
// stable order so the message is the same on every run.
func lifecycleParameterSet(route lifecycleRoute) string {
	if len(route.metadata) == 0 {
		return "none — this route carries no query string at all"
	}
	names := make([]string, 0, len(route.metadata))
	for name := range route.metadata {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
