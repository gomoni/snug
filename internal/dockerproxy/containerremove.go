package dockerproxy

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// containerremove.go is DELETE /containers/{name} — `docker rm`, `podman rm`,
// and what `--rm` issues after the container exits. It is the SINGLE AUTHOR of
// removal-parameter semantics for BOTH wires (invariant 6).
//
// It exists because removal is the one lifecycle route with a compat twin. The
// libpod verbs in libpodlifecycle.go have none, which is why that file can be
// the libpod wire's reader and this one cannot.
//
// # The criterion, which is the part to read before adding a parameter
//
// The ownership gate (ownership.go) is ARITY-1 BY CONSTRUCTION: it inspects one
// reference, canonicalises one segment and rewrites one request. So the question
// each parameter must answer is not "is this dangerous" but:
//
//	does this parameter change WHICH OBJECTS the engine acts on?
//
// If it does, it is outside anything the gate can ever answer, and the
// alternative — modelling podman's dependency graph inside snug — is
// re-implementing the engine. This is isPrune's argument ("a prune names no
// object, so this proxy has nothing to check it against") applied to a route
// that DOES name an object but does not act on only that one. Written as a
// criterion rather than as the list {depend, link} so podman's next cascade
// parameter arrives refused.
//
// `force` is the clean contrast: it changes HOW the addressed container dies,
// not WHICH objects die.
//
// # Measured, podman 6.0.2, isolated store, one session
//
// The cascade is real, and it crosses run labels:
//
//	run A: victimbase, Labels {"snug.run":"RUN-A"}
//	run B: otherrun,   Labels {"snug.run":"RUN-B"}, --network container:victimbase
//	DELETE /v6.0.2/libpod/containers/victimbase?depend=true&force=true
//	  -> 200 [{"Id":"451e869a..."},{"Id":"86e439cb..."}]   BOTH destroyed
//
// The gate checked victimbase and never saw otherrun.
//
// The compat handler does NOT decode `depend`, measured against the same store
// seconds apart:
//
//	DELETE /v1.41/containers/victimbase?depend=true&force=true
//	  -> 500 "has dependent containers which must be removed before it"
//	  -> both containers survive
//
// so this is not a live hole in shipped code. `depend` is refused on the compat
// wire anyway: "the engine ignores it today" is a claim about a moving engine,
// and invariant 5 does not let a boundary rest on one.
//
// `volumes=true` is NOT a cascade and is admitted as metadata. Measured twice:
// a NAMED volume mounted by the removed container survives it (`NAMEDVOL` still
// listed after a 200), and an anonymous volume a container of another run still
// references survives it too (the engine logs "volume ... is being used by the
// following container(s)"). So it reaches only the removed container's own
// unreferenced anonymous volumes, and it is not a second author for
// `DELETE /volumes/{name}`.
//
// # THE ABUSE SENTENCE
//
// A hostile process inside the sandbox can use this to destroy a container THIS
// RUN CREATED, and nothing else. The ownership gate has already proved the
// addressed container carries this run's `snug.run` label and has rewritten the
// path to its 64-hex id; every parameter admitted below acts on that one
// container, and the two that do not (`depend`, `link`) are refused by name.
type removeParams struct {
	// metadata are parameters that change how the ADDRESSED container dies.
	// Value unread — a value podman does not know is podman's to refuse.
	metadata map[string]string
	// cascade are parameters that change WHICH objects die. Refused by name,
	// with one exception carved out below because the CLI sends it always.
	cascade map[string]string
}

// libpodRemoveParams is the measured surface of `podman rm`, podman 6.0.2.
// Copied from a recording proxy in front of a real engine:
//
//	DELETE /v6.0.2/libpod/containers/{name}?depend=false&force=true&ignore=true&volumes=false
//	DELETE /v6.0.2/libpod/containers/{name}?depend=false&force=true&ignore=true&volumes=true
//	DELETE /v6.0.2/libpod/containers/{name}?depend=true&force=true&ignore=true&volumes=false
//	DELETE /v6.0.2/libpod/containers/{name}?depend=false&force=true&ignore=true&timeout=2&volumes=false
//	DELETE /v6.0.2/libpod/containers/{name}?depend=false&force=false&ignore=false&volumes=false
//
// Default-deny: a parameter outside both maps refuses by name.
var libpodRemoveParams = removeParams{
	metadata: map[string]string{
		"force":   "SIGKILL a running container instead of refusing to remove it (`-f`)",
		"ignore":  "answer 200 rather than 404 when no such container exists (`--ignore`)",
		"timeout": "seconds to wait for a graceful stop before the kill (`-t`)",
		"volumes": "also remove the container's own unreferenced ANONYMOUS volumes (`-v`); measured not to reach a named volume, nor one another container still references",
	},
	cascade: map[string]string{
		"depend": "`--depend`, which removes every container that depends on this one",
	},
}

// compatRemoveParams is the docker-compat wire. There is NO default-deny table
// here and that is deliberate: no `docker` CLI exists on the machine where this
// was written, so its parameter surface is UNMEASURED, and a default-deny table
// built on recall would refuse a `docker rm` that works today. The rule this
// package is built on — a route's parameter set is admitted on a measurement of
// the client that sends it or not at all — cuts both ways, and narrowing on an
// unmeasured client is the same error as widening on one.
//
// So the compat wire keeps forwarding what it forwards today, minus the two
// parameters that name a second object. Replace this with a measured table the
// first time a `docker` binary is available.
var compatRemoveParams = removeParams{
	metadata: nil, // nil means "forward an unrecognised parameter", not "refuse it"
	cascade: map[string]string{
		"depend": "`--depend`; podman's compat handler ignores it today (measured: 500, both containers survive), which is a fact about this engine version and not a boundary",
		"link":   "legacy container-link teardown, which names a link record this proxy never saw",
	},
}

// isContainerDelete matches DELETE /containers/{name} on BOTH wires. The name
// is segs[1] and is never read here — the ownership gate has already proved it
// is this run's and rewritten it to the canonical id.
//
// len == 2 exactly: `DELETE /containers/{id}/archive` is isArchive's, and no
// removal route is deeper than two segments on either wire.
func isContainerDelete(segs []string, method string) bool {
	return method == http.MethodDelete && len(segs) == 2 && segs[0] == "containers"
}

// judgeRemoveQuery is the single author. It returns nil to forward.
func judgeRemoveQuery(q url.Values, libpod bool) error {
	params := compatRemoveParams
	wire := "the docker-compat"
	if libpod {
		params = libpodRemoveParams
		wire = "the libpod"
	}

	// A repeated parameter is refused before anything is judged, and this is
	// load-bearing rather than tidy. MEASURED, podman 6.0.2:
	//
	//	DELETE /v6.0.2/libpod/containers/v2?depend=false&depend=true&force=true
	//	  -> 200, BOTH the container and its dependent destroyed
	//
	// podman takes the LAST value; Go's url.Values.Get takes the FIRST. So a
	// check written as q.Get("depend") == "false" passes on that request while
	// the engine cascades. Refused outright rather than reasoned about, so no
	// rule here depends on two parsers agreeing.
	var repeated []string
	for name, values := range q {
		if len(values) > 1 {
			repeated = append(repeated, name)
		}
	}
	if len(repeated) > 0 {
		sort.Strings(repeated)
		return fmt.Errorf("the query parameter %s appears more than once, and snug refuses "+
			"a repeated parameter rather than picking an end: MEASURED against podman 6.0.2, "+
			"`?depend=false&depend=true` removes the container AND its dependents, because "+
			"the engine reads the LAST value where Go's own parser reads the FIRST. Send each "+
			"parameter once", quoteList(repeated))
	}

	for name := range q {
		if why, ok := params.cascade[name]; ok {
			// depend=false is sent by the CLI on EVERY `podman rm`, so omitting
			// it from the admitted set refuses every removal. It is JUDGED, and
			// judged against the literal string rather than through
			// strconv.ParseBool: a bool parse would make this refusal depend on
			// Go and podman agreeing about `1`, `t`, `TRUE` and the empty
			// string. The CLI sends exactly `false`; nothing else is admitted.
			if name == "depend" && len(q[name]) == 1 && q[name][0] == "false" {
				continue
			}
			return fmt.Errorf("the removal parameter %q (%s) is not permitted on %s wire. "+
				"snug's ownership gate checks ONE container per request — it inspects one "+
				"reference and canonicalises one segment — and this parameter makes the "+
				"engine act on a set the gate never saw. MEASURED against podman 6.0.2, "+
				"`?depend=true` on a container of one run also destroyed a container "+
				"carrying a DIFFERENT snug.run label. Remove each container by id instead",
				name, why, wire)
		}
		if params.metadata == nil {
			continue // unmeasured wire: forward, as this route does today
		}
		if _, ok := params.metadata[name]; !ok {
			return fmt.Errorf("the removal parameter %q is one snug's filter has not read, "+
				"so it refuses the request rather than forwarding it unexamined. snug reads "+
				"this route's whole measured parameter set on %s wire (%s); a parameter "+
				"outside it may name objects beyond the one container the ownership gate "+
				"checked, and it cannot be waved through on the strength of not being "+
				"recognised", name, wire, strings.Join(removeParameterNames(params), ", "))
		}
	}
	return nil
}

// removeParameterNames renders a wire's admitted set for its refusal, in a
// stable order so the message is the same on every run. `depend` is in it: the
// value `false` IS admitted, and a reader told it is refused outright would not
// understand why their `podman rm` works.
func removeParameterNames(params removeParams) []string {
	names := make([]string, 0, len(params.metadata)+len(params.cascade))
	for name := range params.metadata {
		names = append(names, name)
	}
	for name := range params.cascade {
		names = append(names, name+"=false only")
	}
	sort.Strings(names)
	return names
}

func (p *Proxy) handleContainerRemove(w http.ResponseWriter, r *http.Request, libpod bool) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		p.deny(w, "the query string of %s is malformed: %v", r.URL.Path, err)
		return
	}
	// Refused for the reason the lifecycle routes refuse one: no client sends a
	// body on this route in any capture, and bytes snug has not read are not
	// forwarded.
	if r.ContentLength != 0 {
		p.deny(w, "removing a container with a request body is not permitted: neither CLI "+
			"sends one, every parameter of this route travels in the query string, and snug "+
			"does not forward bytes it has not read. Drop the body.")
		return
	}
	if err := judgeRemoveQuery(q, libpod); err != nil {
		p.deny(w, "%s.", err)
		return
	}
	p.forward(w, r, nil)
}
