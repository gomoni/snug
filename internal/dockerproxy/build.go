package dockerproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
)

// handleBuild filters `podman build`.
//
// THE SHAPE OF THIS ENDPOINT, established by recording what the podman CLI
// actually sends rather than from the API docs, because the docs do not agree
// with it:
//
//   - the podman CLI posts to /v5.x/libpod/build, NOT the docker-compat
//     /v1.41/build. Both are handled here.
//   - EVERY policy-relevant option is a QUERY PARAMETER. The body is only the
//     tar of the build context.
//   - that context tar was assembled by the client, INSIDE the sandbox, from
//     files the sandbox can already read. It reaches nothing new, so it is
//     forwarded unread. (Same for `--secret`: the CLI reads the file itself and
//     ships the bytes in the tar under a generated name — INDEX §7.2's advice
//     to reject type=secret was written before that was checked, and rejecting
//     it would buy nothing.)
//
// So the filter is a DEFAULT-DENY ALLOWLIST OVER THE QUERY STRING, which is the
// same shape as allowed() and for the same reason: build options are a large,
// fast-moving set, and a new one must fail closed rather than pass because
// nobody had heard of it. An unrecognised parameter is a 403 that names it.
//
// The escapes this closes, each verified to be expressible:
//
//	-v /etc:/x               volume=/etc:/x                      host bind during RUN
//	--build-context x=/etc   additionalbuildcontexts={...}       host bind by another name
//	--device /dev/fuse       devices=["/dev/fuse"]               host device
//	--network=none          networkmode=1 AND nsoptions=[...]   TWO independent spellings
//	--network=bridge/pasta  networkmode=2, name in nsoptions    the name rides in Path
//	--cgroup-parent foo      cgroupparent=foo                    a cgroup snug did not choose
//	--add-host h:1.2.3.4     extrahosts=[...]                    name redirection
//	--security-opt seccomp=  seccomp=unconfined | /host/path     hardening downgrade, host read
//
// A private network namespace for the build step is the one to look at twice
// (issue #401). It sets networkmode AND an nsoptions entry, either of which
// alone gives the RUN step a netns of its own — the same shape as pasta's
// --map-host-loopback and -T/-U, where closing three of four flags left the
// hole wide open. Both are checked here, and both have a test.
// `--network=host` is NOT in this table: since the containers.conf pin
// (engine.go's writeContainersConf), it names this sandbox's own network
// namespace, not the machine's, and is accepted rather than refused.
func (p *Proxy) handleBuild(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	forwardQ, rewritten, reason := p.filterBuildQuery(q)
	if reason != "" {
		// Drain the streamed tar context BEFORE answering. `libpod/build` (and
		// docker-compat `/build`) is the one endpoint where the client uploads a
		// large body and only reads the response AFTER its upload finishes — so a
		// refusal that writes the 403 and returns with the body unread makes
		// net/http close the connection mid-upload, and the client sees EPIPE on
		// `sendall` before it ever reads the 403 (issue #255, measured: a refused
		// `build -v /etc:/x` surfaced as a BrokenPipe, not snug's message).
		// Consuming the body lets the client finish sending and then read the
		// refusal it was owed. Bounded, because a refused build is not owed an
		// unbounded read of attacker-streamed data.
		drainBeforeRefusing(r)
		p.deny(w, "%s", reason)
		return
	}

	// FORWARD WHAT WAS JUDGED, not what the client wrote. handleCreate has
	// always substituted the RESOLVED bind source into the body it forwards;
	// this endpoint used to call p.forward on the ORIGINAL URI while its
	// checks resolved and then DISCARDED the resolved path, so
	// hostPathVisible, the #251/#255 dangling-symlink refusal and the
	// writable-seccomp refusal all judged a string the engine never resolves
	// (issue #304, sev:high). `ln -sfT /snug/engine/store <target>/link` in a
	// loop then made `build -v <link>:/x:ro` read the cross-run image store,
	// and `seccomp=<link>` swapped to {"defaultAction":"SCMP_ACT_ALLOW"} ran
	// the build container unconfined.
	//
	// RawQuery is only replaced when a value actually CHANGED. url.Values.Encode
	// sorts and re-escapes, so assigning unconditionally would rewrite every
	// build's URI — a diff in the forwarded bytes for every request, hiding the
	// one case that matters inside noise nobody reads.
	if rewritten {
		enc := forwardQ.Encode()
		p.audit("build: forwarding resolved paths, not the client's own: " + enc)
		r.URL.RawQuery = enc
	}

	p.audit("build: " + summarise(forwardQ))
	p.forward(w, r, nil)
}

// buildRefusalReason returns the refusal message for a build whose parameters
// are not permitted, or "" if the build may proceed. Split out of handleBuild
// so the refusal is decided BEFORE the body is touched: handleBuild drains the
// streamed context on the refusal path (issue #255), and mixing that drain into
// the decision loop would drain on the allowed path too.
//
// The rule is unchanged: an unknown parameter fails closed, and a known one is
// judged by its own check.
func (p *Proxy) filterBuildQuery(q url.Values) (url.Values, bool, string) {
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make(url.Values, len(q))
	rewritten := false

	for _, name := range names {
		lower := strings.ToLower(name)
		if _, unexamined := unexaminedBuildParams[lower]; unexamined {
			out[name] = append([]string(nil), q[name]...) // forwarded as-is
			continue
		}
		check, known := buildParams[lower]
		if !known {
			return nil, false, fmt.Sprintf("build parameter %q is not permitted. snug allows a named set of "+
				"build options and refuses the rest, so an option it has not been taught "+
				"about fails closed rather than reaching the engine unexamined. If this "+
				"one is harmless, it belongs in unexaminedBuildParams with the abuse "+
				"sentence for why.", name)
		}
		if check == nil {
			// Unreachable while buildParams has no nil entry, and a REFUSAL
			// rather than a pass-through so that adding one fails closed. A
			// nil forwarded verbatim is the defect this map's split exists to
			// remove; a nil that panics would be worse than either.
			return nil, false, fmt.Sprintf("build parameter %q has a nil check. A parameter snug does "+
				"not judge belongs in unexaminedBuildParams with its abuse sentence, not in "+
				"buildParams with no validator.", name)
		}
		for _, v := range q[name] {
			forward, err := check(p, v)
			if err != nil {
				return nil, false, fmt.Sprintf("build parameter %s: %v", name, err)
			}
			if forward != v {
				rewritten = true
			}
			out[name] = append(out[name], forward)
		}
	}
	return out, rewritten, ""
}

// maxRefusedBuildDrain bounds how much of a refused build's body handleBuild
// will read to unblock the client. Generous enough for an ordinary build
// context, bounded so a pathologically large refused upload is not an
// unbounded read on snug itself — that one still gets EPIPE, which is the
// correct outcome for a multi-hundred-megabyte context the sandbox was never
// allowed to build.
const maxRefusedBuildDrain = 64 << 20

// drainBeforeRefusing consumes up to maxRefusedBuildDrain of a request body the
// handler is about to refuse, so the client can finish its upload and read the
// response (issue #255). io.Copy to io.Discard streams in O(1) memory; nothing
// is retained.
func drainBeforeRefusing(r *http.Request) {
	if r.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxRefusedBuildDrain))
}

// buildParamCheck validates one value AND returns the value to forward.
//
// The return of a string is the whole of issue #304's fix, and it is a type
// change rather than three call-site edits on purpose: the defect was that
// checkBuildVolume and checkAdditionalContexts computed a resolved path and
// then threw it away (`_, err := p.checkOne(...)`), while handleBuild forwarded
// the client's original URI. A check that cannot report what it judged makes
// that mistake unrepresentable — every future host-reaching parameter has to
// hand back the string the engine will see, or it does not compile.
//
// A check that changes nothing returns its input. There is no nil check: a
// parameter snug does not judge lives in unexaminedBuildParams, which requires
// the abuse sentence for why not.
type buildParamCheck func(p *Proxy, value string) (string, error)

// unexaminedBuildParams is every parameter forwarded to the engine without its
// value being looked at, each carrying the abuse sentence for why that is safe.
//
// It is a second map rather than a nil in buildParams because a nil cannot
// carry a reason and nothing can make it. The string is documentation the
// COMPILER requires and a test reads — the same device as refuseBuildParam's
// reason one map down, which the client sees in the 403.
//
// What this shape guarantees, stated exactly: an unexamined parameter cannot be
// SILENT. It cannot guarantee the sentence is true. Two entries here were host
// reads while carrying a justification comment — `secrets`, a four-line note
// with a recorded verification, and `idmappingoptions`, "rootless bounds this;
// the CLI always sends it". Both comments described what the friendly CLI does,
// which is not a security argument and is why the required form is the abuse
// sentence: it is written from the attacker's side, so it cannot be satisfied
// by describing benign behaviour.
//
// A sentence written for a CLASS is shared by every member, which is what keeps
// one claim in one place for the twenty-nine ordinary parameters. Membership is
// then the author's explicit choice rather than a consequence of which line an
// entry was appended to — `manifest` and `createdannotation` sit immediately
// below forcecompressionformat's justification, with no blank line, and
// inherited its authority by position alone.
var unexaminedBuildParams = map[string]string{
	// ── naming and output ────────────────────────────────────────────────
	"t": notYetAnalysed, // image tag
	// "output" is JUDGED, in buildParams: checkBuildOutput.
	"outputformat": notYetAnalysed,

	// ── ordinary build behaviour ─────────────────────────────────────────
	"buildargs": ordinaryBuildBehaviour, "labels": ordinaryBuildBehaviour,
	"target": ordinaryBuildBehaviour, "platform": ordinaryBuildBehaviour,
	"nocache": ordinaryBuildBehaviour, "rm": ordinaryBuildBehaviour,
	"forcerm": ordinaryBuildBehaviour, "layers": ordinaryBuildBehaviour,
	"squash": ordinaryBuildBehaviour, "pull": ordinaryBuildBehaviour,
	"pullpolicy": ordinaryBuildBehaviour, "q": ordinaryBuildBehaviour,
	"quiet": ordinaryBuildBehaviour, "unsetenv": ordinaryBuildBehaviour,
	"unsetlabel": ordinaryBuildBehaviour, "compatvolumes": ordinaryBuildBehaviour,
	"inheritannotations": ordinaryBuildBehaviour, "inheritlabels": ordinaryBuildBehaviour,
	"omithistory": ordinaryBuildBehaviour, "rewritetimestamp": ordinaryBuildBehaviour,
	"timestamp": ordinaryBuildBehaviour, "sourcedateepoch": ordinaryBuildBehaviour,
	"jobs": ordinaryBuildBehaviour, "retry": ordinaryBuildBehaviour,
	"retry-delay": ordinaryBuildBehaviour, "identitylabel": ordinaryBuildBehaviour,
	"compression": ordinaryBuildBehaviour, "compressionformat": ordinaryBuildBehaviour,
	"compressionlevel": ordinaryBuildBehaviour,

	// The fourth of the compression family, and the one that makes an
	// ORDINARY podman 6.0.2 build possible at all — 6.0.2 sends it on every
	// build, so without this entry the profile cannot build (issue #314).
	"forcecompressionformat": forceCompressionFormat,

	"manifest": manifestNamesALocalList, "createdannotation": notYetAnalysed,

	// ── resource limits ──────────────────────────────────────────────────
	"shmsize": resourceLimit, "memory": resourceLimit, "memswap": resourceLimit,
	"ulimits": resourceLimit, "cpushares": resourceLimit,
	"cpusetcpus": resourceLimit, "cpusetmems": resourceLimit,
	"cpuperiod": resourceLimit, "cpuquota": resourceLimit,

	"httpproxy": notYetAnalysed,
}

// The abuse sentences. Each is written once and shared by its class, so the
// claim a reader has to judge is one paragraph rather than one per parameter.
const (
	ordinaryBuildBehaviour = "A hostile process inside the sandbox can use these to change how its own " +
		"image is built and labelled: cache use, layer and squash behaviour, build arguments, " +
		"labels, retries, timestamps and compression. None of them names a path, selects a " +
		"destination, or reaches a host resource."

	resourceLimit = "A hostile process inside the sandbox can use these to choose how much memory, " +
		"CPU and shared memory its own build may use. They bound the build rather than widening " +
		"it, and cgroupparent — the one parameter that would name a cgroup snug did not choose " +
		"— is refused."

	// Inert for an ordinary build, measured in the source rather than assumed:
	// buildah 1.44.1 imagebuildah/stage_executor.go:2748-2756 applies
	// CompressionFormat, CompressionLevel and ForceCompressionFormat only when
	// imageRef.Transport().Name() != is.Transport.Name(), and `podman build -t
	// x` commits to containers-storage, which is the local transport.
	// define/build.go:173 states its only job: ensure the algorithm in
	// CompressionFormat is used exclusively and blobs of other compression
	// algorithms are not reused.
	forceCompressionFormat = "A hostile process inside the sandbox can use this to force the chosen " +
		"compression algorithm to be used exclusively (no blob reuse) when an image is committed " +
		"to a non-local transport. That is the whole of it: a boolean modifier of " +
		"compressionformat, which is already allowed. It names no path, reaches no host resource, " +
		"and does not select the transport. cachefrom and cacheto, which would supply a non-local " +
		"destination, are refused, and manifest names a list in the engine's own store."

	// MEASURED against podman 6.0.2, because "it names a destination" was the
	// worry and the answer is that this endpoint does not read it at all.
	//
	// Raw POSTs to /v5.0.0/libpod/build against a real `podman system service`,
	// bypassing the CLI entirely (the CLI is not the boundary — see
	// checkBuildSecrets for why that reasoning is a trap):
	//
	//	output=type=local,dest=/tmp/pwn424, no t  -> built, NOTHING at /tmp/pwn424
	//	output=plaintag424:v1, no t               -> built, image is <none>:<none>
	//
	// So the tag comes from `t` alone and `output` is inert on the libpod
	// endpoint; the podman CLI sends it redundantly beside `t` (both recorded
	// fixtures carry output=probe%3Ax next to t=probe%3Ax) and refuses the
	// destination form client-side anyway: `podman --remote build --output
	// type=local,dest=/tmp/pwn` is `Error: '--output' option is not supported
	// in remote mode`. The compat endpoint's own spelling is `outputs`, plural,
	// which is in neither map and therefore fails closed as unknown; a raw
	// /v1.41/build?outputs=type=local,dest=... also wrote nothing.
	//
	// "podman ignores it today" is a fact about a version, not a property, so
	// this is a VALUE check rather than a pass: a plain tag forwards, and the
	// buildkit `type=…,dest=…` syntax is refused. `=` and `,` cannot occur in a
	// legal image tag, so the refusal cannot reject a tag a client meant.
	buildOutputIsATagOnly = "A hostile process inside the sandbox can use this to name the tag " +
		"the built image is committed under, and nothing else. The libpod endpoint does not read " +
		"this parameter at all — the tag comes from `t` — and the buildkit type=/dest= syntax " +
		"that WOULD name a filesystem destination is refused here rather than left to podman's " +
		"continued disinterest in it."

	// MEASURED against podman 6.0.2: --manifest names a LOCAL manifest list in
	// the engine's own store, and nothing else. Raw POSTs as above:
	//
	//	manifest=mylist424:1                    -> localhost/mylist424:1 in the store
	//	manifest=registry.snug-test.invalid/x:1 -> registry.snug-test.invalid/x:1
	//	                                           in the store; NO network dial,
	//	                                           no push, and the run did not
	//	                                           fail on an unreachable registry
	//
	// A registry-shaped name is therefore just a local name with a
	// registry-shaped prefix — the same thing `podman tag` can already produce.
	// Pushing is a separate endpoint with its own gate, it needs egress the
	// engine only has when the sandbox itself does (a container runs in N), and
	// REGISTRY_AUTH_FILE points at snug's own generated auth.json, so a push
	// authenticates as nobody (issue #142's regression is that the host's
	// credentials stay unreachable).
	manifestNamesALocalList = "A hostile process inside the sandbox can use this to create a " +
		"manifest list in the engine's own store under a name it chooses, including one shaped " +
		"like a registry reference. That is a store object, not a destination: it is written " +
		"where every other image this engine builds is written, reaches no path and dials " +
		"nothing. cachefrom and cacheto, which WOULD supply a non-local destination, are refused."

	// The honest class, and a claim about the state of the review rather than
	// about the parameter. An entry here is permitted and unexamined exactly as
	// a nil was, and says so in a name that greps.
	notYetAnalysed = "A hostile process inside the sandbox can use this to ___ — nobody has " +
		"established what. The value reaches the engine unexamined and no analysis has been " +
		"done. Membership here is not a justification; it is the absence of one, named."
)

// buildParams is every parameter snug JUDGES or REFUSES. A parameter forwarded
// without its value being looked at belongs in unexaminedBuildParams above,
// with its abuse sentence; there is no nil here, and filterBuildQuery refuses
// one rather than forwarding it.
var buildParams = map[string]buildParamCheck{
	"annotations": refuseBuildParam("podman honours run.oci.* annotations, which reach the runtime"),

	// The tag the image is committed under, and only that — buildOutputIsATagOnly
	// carries the measurement.
	"output": checkBuildOutput,

	// ── the Dockerfile, which must stay inside the context ───────────────
	"dockerfile": checkDockerfile,

	// "version" selects which BUILDER handles the request, not a capability —
	// same shape as "isolation" and "networkmode" below, which is why it is a
	// checked selector and not a bare `nil`. `1` is the classic builder, which
	// POSTs the tar to THIS endpoint and is the one snug's filter reads;
	// `docker build` sends it on every request once DOCKER_BUILDKIT=0 forces
	// the classic path (see internal/cli/container.go). `2` selects a BuildKit
	// backend whose option surface is a different set from the one enumerated
	// here and is refused by name rather than silently accepted.
	"version": checkBuilderVersion,

	"secrets": checkBuildSecrets,

	// ── the host-reaching set ────────────────────────────────────────────
	"volume":                  checkBuildVolume,
	"volumes":                 checkBuildVolume,
	"additionalbuildcontexts": checkAdditionalContexts,
	"networkmode":             checkNetworkMode,
	"nsoptions":               checkNSOptions,
	"seccomp":                 checkSeccompProfile,
	"idmappingoptions":        checkIDMappingOptions,

	"devices": refuseBuildParam("the engine's /dev is the sandbox's own synthetic tree since " +
		"Tier C (issue #125), with no host device nodes, and the engine holds no CAP_MKNOD to " +
		"make one — so a device request has nothing host-shaped to pass through"),
	// The create-side twin, refusalReason["CgroupParent"], is the wording this
	// matches: the engine is forked with CLONE_NEWCGROUP
	// (internal/stage/enginefork.go) and mounts a fresh cgroup2 over
	// /sys/fs/cgroup (modelled in internal/cli/engineview.go), so a client-named
	// parent is resolved against the ENGINE's cgroup root, not the host's. This said
	// "outside this sandbox's own" — the pre-Tier-C model the create side was
	// already corrected for, and the same door on the other path (issue #372).
	"cgroupparent": refuseBuildParam("snug authors the build's cgroup placement; a " +
		"client-named parent is a path snug did not choose, resolved inside the engine's " +
		"own cgroup namespace"),
	"isolation":  checkIsolation,
	"extrahosts": refuseBuildParam("name redirection"),
	"dnsservers": refuseBuildParam("resolver redirection"),
	"dnsoptions": refuseBuildParam("resolver redirection"),
	"dnssearch":  refuseBuildParam("resolver redirection"),
	"addcapabilities": refuseBuildParam(
		"added capabilities apply to the host kernel, not to the sandbox"),
	"runtime": refuseBuildParam("an alternate OCI runtime is an arbitrary host binary"),
	"remote": refuseBuildParam("a remote build context is fetched by the ENGINE, from a place " +
		"snug never sees — the context must be the tar the client sends"),
	"cachefrom": refuseBuildParam("a cache source is resolved by the engine and may name a " +
		"local path; not yet modelled"),
	"cacheto": refuseBuildParam("a cache destination is written by the engine; not yet modelled"),
}

// knownBuildParam reports whether a query parameter is modelled at all —
// judged, refused, or forwarded unexamined with its abuse sentence. The
// question "does snug know this name" has one answer across two maps, and this
// is the one place that joins them.
func knownBuildParam(name string) bool {
	lower := strings.ToLower(name)
	if _, ok := unexaminedBuildParams[lower]; ok {
		return true
	}
	_, ok := buildParams[lower]
	return ok
}

func refuseBuildParam(reason string) buildParamCheck {
	return func(*Proxy, string) (string, error) {
		return "", fmt.Errorf("is not permitted: %s", reason)
	}
}

// checkBuildSecrets keeps a secret's source inside the build context.
//
// REGRESSION (redteam, M5): this was waved through, on the reasoning that the
// podman CLI reads a --secret's file ITSELF, client-side, and ships the bytes in
// the context tar under a generated name — verified by recording, and true.
//
// It is also not a security argument, and the mistake is worth naming because it
// is easy to repeat: what the CLI does is a description of BENIGN behaviour. The
// threat model is an agent with full control of its own execution, which does not
// use the CLI at all — it POSTs to $CONTAINER_HOST directly and sends whatever
// value it likes. "The friendly client would never send that" is never a reason
// to skip a check.
//
// What it cost: buildah resolves src= against the context directory but does not
// clamp `..`, so
//
//	secrets=["id=leak,src=../../../../../../home/u/.ssh/id_ed25519"]
//	RUN --mount=type=secret,id=leak,target=/leak cat /leak
//
// read a host file the sandbox is not granted and streamed it back — an arbitrary
// host-filesystem READ primitive. Verified end to end: the same file was
// FileNotFoundError to a direct open() inside the sandbox and TOP-SECRET on the
// build stream.
//
// The rule is the one checkDockerfile already applies, for the same reason: a
// legitimate src names something in the context, and a context name cannot climb
// out of it.
// The value is forwarded unchanged: a secret source is relative to the build
// CONTEXT, which the engine unpacks from the tar the client sent, so there is
// no host path here to resolve.
func checkBuildSecrets(_ *Proxy, v string) (string, error) {
	var specs []string
	if strings.HasPrefix(strings.TrimSpace(v), "[") {
		if err := json.Unmarshal([]byte(v), &specs); err != nil {
			return "", fmt.Errorf("is not a JSON list of secret specs")
		}
	} else {
		specs = []string{v}
	}
	for _, spec := range specs {
		for _, field := range strings.Split(spec, ",") {
			k, val, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "src", "source":
				if err := insideContext(val); err != nil {
					return "", fmt.Errorf("secret source %w", err)
				}
			}
		}
	}
	return v, nil
}

// insideContext refuses a name that does not stay within the build context.
// Shared by the Dockerfile and secret-source rules so the two cannot drift —
// they are the same question asked about different fields.
func insideContext(n string) error {
	if n == "" {
		return nil
	}
	if strings.Contains(n, "://") {
		return fmt.Errorf("%q is a URL; it must come from the context the client sent, "+
			"not from somewhere the engine fetches", n)
	}
	if path.IsAbs(n) {
		return fmt.Errorf("%q is absolute; it must name a file inside the build context", n)
	}
	if cleaned := path.Clean(n); cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%q escapes the build context", n)
	}
	return nil
}

// checkDockerfile keeps the Dockerfile inside the context.
//
// podman sends a JSON array of names; the compat endpoint sends a bare string.
// Both are relative to the context root, so an absolute path or a `..` reaches
// out of the directory the engine unpacked into.
// Forwarded unchanged, for checkBuildSecrets's reason: a Dockerfile name is
// relative to the context the client shipped, not a host path.
func checkDockerfile(_ *Proxy, v string) (string, error) {
	names := []string{v}
	if strings.HasPrefix(strings.TrimSpace(v), "[") {
		var list []string
		if err := json.Unmarshal([]byte(v), &list); err != nil {
			return "", fmt.Errorf("is not a name or a JSON list of names")
		}
		names = list
	}
	for _, n := range names {
		if err := insideContext(n); err != nil {
			return "", err
		}
	}
	return v, nil
}

// checkBuildVolume applies the rule in the package comment to `build -v`, which
// is the same host bind that HostConfig.Binds is, spelled differently.
//
// It returns the volume respelled with checkOne's RESOLVED source. The old body
// was `_, err := p.checkOne(...)` — it resolved the symlink, judged the
// resolved path, and threw it away while handleBuild forwarded the client's
// original string (issue #304). checkOne's own comment already says why the
// resolved path is what must be forwarded: the link can be swapped between the
// check and the engine's own resolution, so the engine has to be asked for the
// thing that was actually approved. That sentence was true of the create path
// and false of this one.
func checkBuildVolume(p *Proxy, v string) (string, error) {
	parts := strings.Split(v, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", fmt.Errorf("%q is not src:dst[:opts]", v)
	}
	ro := false
	if len(parts) == 3 {
		for _, o := range strings.Split(parts[2], ",") {
			switch o {
			case "ro":
				ro = true
			case "rw", "z", "Z", "":
			default:
				return "", fmt.Errorf("option %q is not permitted", o)
			}
		}
	}
	m, err := p.checkOne(parts[0], parts[1], ro)
	if err != nil {
		return "", err
	}
	// Only the SOURCE is respelled. The destination and the options are the
	// client's own and were validated above, not resolved — rewriting them
	// would be snug authoring a request nobody made.
	parts[0] = m.Source
	return strings.Join(parts, ":"), nil
}

// idMappingFields is the DEFAULT-DENY ALLOWLIST over idmappingoptions' own
// fields: #313's rule for a build context's fields, applied to the OTHER
// waved-through parameter that turned out to carry a host path (issue #323).
//
// It was `nil` — "rootless bounds this; the CLI always sends it" — and that was
// true of the value podman 5.8.3 sent. RECORDED, both versions this file has
// fixtures for:
//
//	5.8.3: {"HostUIDMapping":true}
//	6.0.2: {"HostUIDMapping":true,"HostGIDMapping":true,"UIDMap":[],"GIDMap":[],
//	        "AutoUserNs":false,"AutoUserNsOpts":{"Size":0,"InitialSize":0,
//	        "PasswdFile":"","GroupFile":"","AdditionalUIDMappings":null,
//	        "AdditionalGIDMappings":null}}
//
// One podman major later the same parameter name carries a struct with two host
// PATHS in it. That is what a `nil` entry actually is: a known NAME with an
// unmodelled VALUE, and the value is free to grow.
//
// UIDMap/GIDMap/HostUIDMapping/HostGIDMapping stay permitted with content: they
// carry integers, name nothing, and the build container's user namespace is a
// CHILD of the sandbox's, so every host id in a map must already be mapped
// there. That bound is REASONED FROM SOURCE AND FROM THE USERNS HIERARCHY — it
// was NOT measured inside snug's own U, and it is not a licence to relax them.
var idMappingFields = map[string]string{
	"hostuidmapping": "HostUIDMapping",
	"hostgidmapping": "HostGIDMapping",
	"uidmap":         "UIDMap",
	"gidmap":         "GIDMap",
	"autouserns":     "AutoUserNs",
	"autousernsopts": "AutoUserNsOpts",
}

// autoUserNsFields is the same allowlist one level down. Every one of these may
// only be EMPTY, so the map's job is to refuse a field snug has not been taught
// about rather than to say which are dangerous — a seventh field arriving is a
// value reaching the engine unexamined, which is the thing this file refuses.
var autoUserNsFields = map[string]string{
	"size":                  "Size",
	"initialsize":           "InitialSize",
	"passwdfile":            "PasswdFile",
	"groupfile":             "GroupFile",
	"additionaluidmappings": "AdditionalUIDMappings",
	"additionalgidmappings": "AdditionalGIDMappings",
}

// allowlistJSONFields applies the two rules #310 and #311 cost us, over one JSON
// object's keys: every key must be modelled, and no field may appear twice under
// different casing. It returns canonical field name -> the key that carried it.
//
// The duplicate rule is not "pick a winner". Picking works only if snug and the
// engine agree on the rule, and the bug WAS that they do not: encoding/json is
// case-insensitive LAST-WINS after a sort, so a second spelling is a way to have
// snug judge one value and the engine use another (#310). Keys are sorted first
// so a refusal names the same key on every run — a message that varies with map
// order cannot be pinned by a test.
func allowlistJSONFields(raw json.RawMessage, allow map[string]string,
	what string) (map[string]json.RawMessage, map[string]string, error) {
	// THE KEYS COME FROM THE BYTES, NOT FROM THE MAP, and that is the whole of
	// the exact-duplicate defence. json.Unmarshal into a map COLLAPSES an
	// exact-duplicate key to the last occurrence before any check can see it,
	// while the engine decodes the same bytes into a STRUCT — where duplicate
	// OBJECT fields are MERGED field by field, so a first occurrence's scalar
	// survives a later empty one. Measured, Go encoding/json, on
	// {"AutoUserNsOpts":{"PasswdFile":"/etc/passwd"},"AutoUserNsOpts":{}}:
	//
	//	map[string]json.RawMessage  ->  AutoUserNsOpts = {}          (empty)
	//	the struct                  ->  PasswdFile = "/etc/passwd"   (survives)
	//
	// Same divergence as #310, different spelling of "twice": snug would judge
	// the empty one and the engine would use the planted path. A decoder that
	// reports the keys as WRITTEN is the only way to see it.
	fields := map[string]json.RawMessage{}
	keys, err := jsonObjectKeys(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %w", what, err)
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, nil, fmt.Errorf("%s is not the JSON object podman sends", what)
	}
	sort.Strings(keys)

	spelling := make(map[string]string, len(keys))
	for _, k := range keys {
		canon, known := allow[strings.ToLower(k)]
		if !known {
			return nil, nil, fmt.Errorf("%s carries the field %q, which snug does not model. "+
				"Its fields are an allowlist for the same reason the build parameters are: "+
				"a field snug has not been taught about may name a host path and would reach "+
				"the engine unexamined. Drop it; if it is harmless it belongs in this file's "+
				"allowlist with a note saying why", what, k)
		}
		if prev, dup := spelling[canon]; dup {
			if prev == k {
				return nil, nil, fmt.Errorf("%s carries the key %q twice. Send it once: snug "+
					"and the engine do not read a repeated key the same way — a map keeps the "+
					"LAST occurrence, a struct MERGES two objects field by field, so a value "+
					"in the first can survive an empty second and be used by the engine after "+
					"snug judged the empty one", what, k)
			}
			return nil, nil, fmt.Errorf("%s carries %s twice, as %q and %q. Send it once: snug "+
				"and the engine do not agree on which duplicate wins — encoding/json takes the "+
				"LAST after a sort, so a second spelling is a way to have snug judge one value "+
				"and the engine use another (issue #310)", what, canon, prev, k)
		}
		spelling[canon] = k
	}
	return fields, spelling, nil
}

// jsonObjectKeys returns one JSON object's keys IN THE ORDER WRITTEN, repeats
// included. json.Unmarshal into a map cannot answer this — it has already
// collapsed the repeats — so the bytes are walked with a Decoder: a key token,
// then its value consumed whole, until the object closes.
func jsonObjectKeys(raw json.RawMessage) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("is not the JSON object podman sends")
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("is not the JSON object podman sends")
	}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("is not the JSON object podman sends")
		}
		k, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("is not the JSON object podman sends")
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, fmt.Errorf("is not the JSON object podman sends")
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// checkIDMappingOptions judges the id-mapping request a build carries.
//
// THE MEASUREMENT (issue #323, sev:low). AutoUserNsOpts.PasswdFile and
// .GroupFile are HOST PATHS, and the engine opens them: containers/storage
// userns.go:101 `parseMountedFiles` calls os.Open on a non-empty override,
// absolute, resolved in the ENGINE's own mount namespace. A planted
//
//	snugmarker:x:99123:99123::/x:/bin/sh
//
// came back as "the container needs a user namespace with size 99124", which is
// the planted uid + 1 — the engine read and parsed a file the caller named. It
// is bounded (EnterEngine confines the engine to a private copy of the
// sandbox's view plus the engine-only grafts, and the observable is one
// integer, not content) and it is still a path-bearing field with no check
// behind it, forwarded by a parameter --dry-run says nothing about.
//
// ONLY-EMPTY IS NOT A WEAKER RULE THAN REFUSING THE FIELD, and the difference
// is worth stating because a diff shows only the word "allowed". An ordinary
// podman 6.0.2 build SENDS AutoUserNsOpts, with every field zero; refusing the
// field's presence would break every 6.0.2 build, which is issue #314 again one
// level down. Permitting the NAME and refusing all CONTENT closes the measured
// primitive exactly, and leaves "a real workflow needs a non-empty one" where it
// belongs: a grant decision with its own abuse sentence.
//
// The value is forwarded unchanged; nothing here resolves a path, because
// nothing here is permitted to carry one.
func checkIDMappingOptions(_ *Proxy, v string) (string, error) {
	raw, spelling, err := allowlistJSONFields(json.RawMessage(v), idMappingFields, "idmappingoptions")
	if err != nil {
		return "", err
	}

	// AutoUserNs=true is what makes the engine go looking for a passwd/group
	// file at all. An ordinary build sends false, so only false is permitted:
	// drop --userns=auto.
	if k, ok := spelling["AutoUserNs"]; ok && !isEmptyJSON(raw[k]) {
		return "", fmt.Errorf("%s asks the engine to allocate a user namespace automatically "+
			"(--userns=auto), which makes it READ AND PARSE files to size the range. Only "+
			"false is permitted — drop --userns=auto", k)
	}

	if k, ok := spelling["AutoUserNsOpts"]; ok {
		if err := checkAutoUserNsOpts(raw[k], k); err != nil {
			return "", err
		}
	}
	return v, nil
}

// checkAutoUserNsOpts permits the sub-object podman sends and refuses every
// value inside it. `{}`, `null` and the all-zero object an ordinary build sends
// are the shapes that pass.
func checkAutoUserNsOpts(rawOpts json.RawMessage, key string) error {
	if isEmptyJSON(rawOpts) {
		return nil
	}

	// The nested level gets the SAME two rules, because the last-wins trap
	// works just as well one field down: {"AutoUserNsOpts":{...zero...},
	// "autousernsopts":{"PasswdFile":"/etc/passwd"}} is caught above, and
	// {"PasswdFile":"","passwdfile":"/etc/passwd"} is caught here.
	fields, spelling, err := allowlistJSONFields(rawOpts, autoUserNsFields, key)
	if err != nil {
		return err
	}

	canon := make([]string, 0, len(spelling))
	for c := range spelling {
		canon = append(canon, c)
	}
	sort.Strings(canon)

	for _, c := range canon {
		k := spelling[c]
		if isEmptyJSON(fields[k]) {
			continue
		}
		switch c {
		case "PasswdFile", "GroupFile":
			return fmt.Errorf("%s.%s must be empty — it names a HOST FILE the engine opens and "+
				"parses to size a user namespace (issue #323), and snug does not forward a "+
				"host path here. Drop it", key, k)
		default:
			return fmt.Errorf("%s.%s must be empty — snug does not model what the engine does "+
				"with it, and an ordinary build sends it zero. Drop it", key, k)
		}
	}
	return nil
}

// additionalContextFields is the DEFAULT-DENY ALLOWLIST over one entry's own
// fields, and it is the same rule buildParams applies to the query one level
// up — applied one level down, which is where issues #310 and #311 both live.
//
// RECORDED, not guessed, in the spelling this file's other fixtures follow: a
// `podman 6.0.2 build --build-context extra=<dir>` against a listening socket
// sends exactly
//
//	{"extra":{"IsURL":false,"IsImage":false,"Value":"<dir>","DownloadedCache":""}}
//
// so four fields, with DownloadedCache empty on an ordinary build. A fifth one
// arriving is a field snug has not been taught about reaching the engine
// unexamined, which is precisely what the parameter-level rule refuses.
var additionalContextFields = map[string]string{
	"isurl":           "IsURL",
	"isimage":         "IsImage",
	"value":           "Value",
	"downloadedcache": "DownloadedCache",
}

// checkAdditionalContexts judges `--build-context name=VALUE`.
//
// An image reference is fine — it is content the engine pulls under the same
// rules as any other image. A URL is not: the engine fetches it from somewhere
// snug never sees. Anything else is a host path, and gets the mount rule, read
// only, because a build context is only ever read.
//
// Like checkBuildVolume it returns the value respelled with the RESOLVED path
// (issue #304).
//
// THE SHAPE THIS FUNCTION HAD BETWEEN #306 AND #310, because it is the mistake
// worth not repeating. It re-marshalled each entry through
// map[string]json.RawMessage and preserved every field snug does not model,
// writing the resolved path back "under the key spelling actually present":
//
//	key := "Value"
//	for k := range fields { if strings.EqualFold(k, "Value") { key = k; break } }
//	fields[key] = enc
//
// Two holes, one cause. The preserve-what-we-do-not-model instinct is the
// OPPOSITE of the rule this file states four hundred lines up — "an option it
// has not been taught about fails closed rather than reaching the engine
// unexamined" — and applying it inside an allowed parameter re-opened by hand
// what the parameter-level allowlist closes:
//
//   - #310 (sev:high). Two case-variant spellings of Value in one entry:
//     {"Value":"<link>","value":"<link>"}. The loop rewrites whichever the map
//     yields FIRST — range order, so a coin flip, freely retriable — and
//     json.Marshal then emits keys SORTED, putting "value" (0x76) after
//     "Value" (0x56). The engine decodes with encoding/json, which is
//     case-insensitive LAST-WINS, so it takes the raw one. Measured ~38/40
//     trials: forwarded {"x":{"Value":"/usr","value":"<target>/link"}}, engine
//     effective Value = the raw link. #304's primitive, reopened.
//   - #311 (sev:medium, engine consumption unverified). DownloadedCache is a
//     path-bearing field snug never validated, forwarded verbatim. Its
//     documented role is the materialised local directory for a URL or archive
//     context, so if buildah honours one supplied over the API it is a direct
//     host-path read with no symlink and no race at all.
//
// The fix is one rule rather than two patches: an entry's fields are an
// allowlist, no field may appear twice under different casing, and the one
// path-bearing field snug does not model may only be empty. Then the resolved
// Value is written under a CANONICAL key with every other spelling of it
// deleted — so "which duplicate wins" is not a question either side has to
// answer, because there is never more than one.
func checkAdditionalContexts(p *Proxy, v string) (string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(v), &raw); err != nil {
		return "", fmt.Errorf("is not the JSON object podman sends")
	}
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	sort.Strings(names)

	changed := false
	for _, name := range names {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw[name], &fields); err != nil {
			return "", fmt.Errorf("context %q is not the JSON object podman sends", name)
		}

		// Default-deny over the fields, and at most one spelling of each.
		// Sorted so a refusal names the same key every time — a message that
		// varies with map order is one a test cannot pin.
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		spelling := map[string]string{} // canonical field -> the key that carried it
		for _, k := range keys {
			canon, known := additionalContextFields[strings.ToLower(k)]
			if !known {
				return "", fmt.Errorf("context %q carries the field %q, which snug does not "+
					"model. A build context's fields are an allowlist for the same reason the "+
					"build parameters are: a field snug has not been taught about may name a "+
					"second host path, and would reach the engine unexamined. If it is "+
					"harmless it belongs in additionalContextFields with a note saying why",
					name, k)
			}
			if prev, dup := spelling[canon]; dup {
				return "", fmt.Errorf("context %q carries %s twice, as %q and %q. snug and the "+
					"engine do not agree on which duplicate wins — encoding/json takes the "+
					"LAST after a sort, so a second spelling is a way to have snug judge one "+
					"value and the engine use another (issue #310)", name, canon, prev, k)
			}
			spelling[canon] = k
		}

		// The one modelled field that carries a path and that snug does not
		// resolve. Empty is what an ordinary build sends; anything else is a
		// host path arriving through a field with no check behind it (#311).
		if k, ok := spelling["DownloadedCache"]; ok && !isEmptyJSON(fields[k]) {
			return "", fmt.Errorf("context %q sets %s, which names a host directory the engine "+
				"may read the context from — a second path beside Value, and one snug does "+
				"not resolve or judge. Only an empty value is permitted", name, k)
		}

		var c struct {
			IsURL   bool
			IsImage bool
			Value   string
		}
		if err := json.Unmarshal(raw[name], &c); err != nil {
			return "", fmt.Errorf("context %q is not the JSON object podman sends", name)
		}
		switch {
		case c.IsURL:
			return "", fmt.Errorf("context %q is a URL, which the ENGINE fetches from a place "+
				"snug never sees", name)
		case c.IsImage:
			continue
		}
		m, err := p.checkOne(c.Value, "/", true)
		if err != nil {
			return "", fmt.Errorf("context %q: %w", name, err)
		}

		// CANONICALISE rather than write back in place. Deleting the key that
		// carried Value and emitting "Value" is what makes the duplicate
		// question unaskable; the refusal above already makes it unreachable,
		// and both are kept because they fail in opposite directions — the
		// refusal stops a request, this stops a request snug rewrote from
		// carrying a spelling it did not intend.
		if k, ok := spelling["Value"]; ok {
			delete(fields, k)
		}
		enc, err := json.Marshal(m.Source)
		if err != nil {
			return "", fmt.Errorf("context %q: %v", name, err)
		}
		fields["Value"] = enc

		out, err := json.Marshal(fields)
		if err != nil {
			return "", fmt.Errorf("context %q: %v", name, err)
		}
		if string(out) != string(raw[name]) {
			raw[name] = out
			changed = true
		}
	}
	if !changed {
		return v, nil
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("%v", err)
	}
	return string(out), nil
}

// checkNetworkMode refuses a build step a network namespace of its own
// (issue #401), which since the containers.conf pin (engine.go's
// writeContainersConf) is the only network mode this tier's engine can
// actually deliver.
//
// The libpod endpoint sends an integer and the compat one a string, so both
// spellings are enumerated. Default-deny: an unrecognised value is refused
// rather than assumed benign, because the numbers are buildah's internal enum
// and a new one could mean anything.
//
// Inverted from the pre-#401 reading, which refused exactly the one value
// that works and admitted everything that does not:
//
//	accept  ""  "0"  "default"   — not a request; the containers.conf pin
//	                                decides, and it decides N.
//	accept  "2" "host"           — Tier B's inversion: here "host" means the
//	                                ENGINE's netns, which is N, not the
//	                                machine's.
//	refuse  "1" "none" "private" "bridge" "slirp4netns" "pasta" — every one
//	                                of these asks buildah to give the RUN
//	                                step a network namespace OF ITS OWN,
//	                                which needs CAP_NET_ADMIN to bring lo up
//	                                in that namespace and the engine does not
//	                                have it (policy.EngineCapBounding,
//	                                2026-08-18). MEASURED dead on both podman
//	                                5.8.4 and 6.0.2, with and without the
//	                                pin: `ioctl SIOCSIFFLAGS: Operation not
//	                                permitted` (crun) or `netavark: Netlink
//	                                error: Operation not permitted` (libpod).
//
// "" and "default" are kept for robustness rather than for a known caller —
// no measured client sends either; the podman CLI's libpod endpoint only
// ever sends 0, 1 or 2 (no flag -> 0, --network=none -> 1, --network=host ->
// 2, everything else -> 2 with the name carried in nsoptions instead), and
// docker 29.4.0-ce's compat endpoint omits the parameter for no-flag AND for
// --network=default. They are safe to accept because they are not a
// request: the containers.conf pin is what binds them, not this check.
//
// Accepting "2"/"host" grants nothing the accepted default does not:
// networkmode=2 puts the RUN step in exactly the netns the default already
// puts it in, MEASURED. The engine is guaranteed to be running inside this
// sandbox's own netns by construction: deriveTopology's podman branch raises
// Netns to at least NetnsStage, which is the top of that order, so no
// selection can hand the engine a namespace that is not this sandbox's.
//
// v is returned UNCHANGED on the accept path rather than normalised to one
// spelling — filterBuildQuery marks a build "rewritten" when the forwarded
// value differs from the client's, so translating here would mark every
// accepted build as carrying a snug-modified parameter it does not.
func checkNetworkMode(_ *Proxy, v string) (string, error) {
	// Normalised ONCE and used by every arm below. The switch used to be the
	// only reader, so the container:/ns: arm compared the raw value and a
	// "Container:abc" fell past it into the generic refusal — the right
	// outcome reached by the wrong sentence, which is the half of "errors
	// name the fix" that a default-deny hides.
	norm := strings.ToLower(strings.TrimSpace(v))
	switch norm {
	case "", "0", "default", "2", "host":
		return v, nil
	case "1", "none", "private", "bridge", "slirp4netns", "pasta":
		return "", fmt.Errorf("%q is not permitted: it asks for a network namespace of the "+
			"BUILD STEP's own, and the engine holds no CAP_NET_ADMIN to configure one (a "+
			"deliberate limit — a compromised engine must not be able to reconfigure this "+
			"sandbox's network). A build that gets one dies at "+
			"`ioctl SIOCSIFFLAGS: Operation not permitted`. Inside this sandbox "+
			"`--network=host` does NOT mean the machine's network: the engine runs in THIS "+
			"sandbox's own network namespace, so it means exactly what the sandbox itself "+
			"has, and it is what a build with no --network flag already gets.\n"+
			"       Fix: drop the --network flag, or use --network=host.", v)
	}
	if strings.HasPrefix(norm, "container:") || strings.HasPrefix(norm, "ns:") {
		return "", fmt.Errorf("%q is not permitted: it names a network namespace snug did not "+
			"author — another container's. What a build may have is this sandbox's own, "+
			"which is the default.", v)
	}
	return "", fmt.Errorf("%q is not permitted; snug allows a named set of network modes and "+
		"refuses the rest, so a value it has not been taught about fails closed", v)
}

// checkNSOptions is the second spelling of the same request checkNetworkMode
// judges (issue #401 both narrowed and widened this): `--network=host` sets
// networkmode AND an nsoptions entry, and either alone can re-open a request
// checkNetworkMode already refused or accepted differently. That is the shape
// of the pasta bug this project already paid for once: three of four closing
// flags passed, and the fourth left every host loopback service reachable.
//
// The NAME axis fails closed, and did not always: the loop judged Host and
// Path and let any other name with Host:false and an empty Path fall through
// to the accept. `nsoptions=[{"Name":"net","Host":false}]` was ACCEPTED here,
// and what refused it was buildah — `adding new "net" namespace for run:
// unrecognized namespace "net"`, from runtime-tools' mapStrToNamespace. Closed
// by the helper rather than by snug, which is the arrangement checkNetworkMode
// one screen up already argues against, and closed only by luck of spelling:
// buildah's setupNamespaces has no default: arm, so `mount` and `time` — both
// accepted by mapStrToNamespace — were configured into the OCI spec verbatim.
//
// The accepted set is the six names a real client can send, RECORDED from
// `podman --remote build` 6.0.2 against a listening socket of our own: `user`
// always (the rootless default, sent with no flag at all), plus one entry per
// namespace flag — `network`, `pid`, `ipc`, `uts`, `cgroup`. A FLAG is the
// only source: a containers.conf naming all six of netns/pidns/ipcns/utsns/
// cgroupns/userns contributed nothing to nsoptions (measured). docker
// 29.4.0-ce's compat builder sends no nsoptions at all — it spells --network
// as a word in networkmode, which checkNetworkMode judges.
//
// `mount` and `time` stay OUT although buildah accepts both: no measured
// client sends either, so refusing them costs a request nobody makes, and it
// is the whole difference between "closed by snug" and "closed by buildah".
// For the same reason the shape is an allowlist rather than a patch naming
// `net` — a catalogue of known-bad spellings is the subtractive shape
// invariant 2 calls a design smell, and it would leave every future name open.
//
// Host:false with an empty Path on pid/ipc/uts/cgroup asks for one of the
// BUILD STEP's own, which is strictly less than it had, so `--pid=private`
// and its three siblings stay accepted. Unlike `network` that is NOT measured
// to need a capability the engine lacks — it is accepted today and this
// allowlist carries no new grant.
//
// A hostile process inside the sandbox can use the accept path to put a build
// step in the engine's own network or user namespace (Host:true on network/
// user) — N and U, which the sandbox already has — or in a fresh pid/ipc/uts/
// cgroup namespace of its own, which is strictly less than it had. What the
// name allowlist closes: handing the engine a namespace request under a name
// snug has never judged, and getting whatever the runtime does with it.
//
// Host:true never reaches the MACHINE's namespace for any of the six names,
// which is why the refusal below says "the namespace the engine calls host":
// the engine clones pid, ipc, uts and cgroup for itself
// (internal/stage/enginefork.go). Two of the six are accepted, each named
// rather than pattern-matched:
//
//   - `user`, the rootless default the CLI always sends — the engine already
//     runs in that user namespace.
//   - `network`, since Tier B: the engine's own network namespace IS this
//     sandbox's (N), so Host:true here means N, not the machine's — the same
//     inversion checkNetworkMode applies to networkmode=2/"host". Host:false
//     on `network` is the other spelling of asking for a namespace of the
//     BUILD STEP's own, MEASURED dead for the same reason networkmode=1 is:
//     it needs CAP_NET_ADMIN to bring lo up and the engine does not have it.
func checkNSOptions(_ *Proxy, v string) (string, error) {
	var opts []struct {
		Name string
		Host bool
		Path string
	}
	if err := json.Unmarshal([]byte(v), &opts); err != nil {
		return "", fmt.Errorf("is not the JSON list podman sends")
	}
	for _, o := range opts {
		// FIRST, so that every check below operates on a name snug has
		// modelled. The fold can only refuse more ("NETWORK" with Host:false
		// is refused) or admit a spelling buildah then rejects
		// case-sensitively; it cannot grant.
		name := strings.ToLower(o.Name)
		switch name {
		case "user", "network", "pid", "ipc", "uts", "cgroup":
		default:
			// o.Name, the client's own spelling, not the folded name — and %q
			// rather than %s, because p.deny feeds p.audit unsanitised and %q
			// escapes a control character that would otherwise author a lie
			// in the audit line or the 403 body.
			return "", fmt.Errorf("%q names a namespace snug has not been taught about; snug "+
				"allows a named set of namespace names and refuses the rest, so a name it "+
				"has not been taught about fails closed rather than reaching the engine "+
				"unexamined. A podman build sends user, network, pid, ipc, uts and cgroup "+
				"and nothing else (MEASURED, podman 6.0.2); a docker build sends no "+
				"nsoptions at all.\n"+
				"       Fix: drop the namespace flag that produced this entry. If a real "+
				"client sends this name, it belongs in checkNSOptions' switch with the "+
				"judgement for what Host and Path mean for it — not in the fall-through.",
				o.Name)
		}
		if o.Host && name != "user" && name != "network" {
			return "", fmt.Errorf("%q asks for the %s namespace the engine calls \"host\", "+
				"which is the ENGINE's own and not the machine's — it clones pid, ipc, uts "+
				"and cgroup for itself. Refused because snug authors this build's "+
				"namespaces, and joining the engine's own is what HostConfig.PidMode is "+
				"refused for at create", o.Name, name)
		}
		if name == "network" && o.Host {
			continue // Host:true means N, this sandbox's own netns (issue #401).
		}
		if o.Path != "" {
			if name == "network" {
				// Path here is a network NAME (bridge, pasta, slirp4netns), not a
				// namespace path — it names the mode buildah would configure for
				// the build step's own netns, which is exactly what
				// checkNetworkMode refuses for the same value under networkmode.
				return "", fmt.Errorf("%q names the network %q, which asks for a network "+
					"namespace of the BUILD STEP's own rather than the engine's; see the "+
					"networkmode refusal for why that needs a capability the engine does "+
					"not have", o.Name, o.Path)
			}
			return "", fmt.Errorf("%q names an existing namespace at %q, which snug did not "+
				"create and cannot vouch for", o.Name, o.Path)
		}
		if name == "network" {
			return "", fmt.Errorf("%q with Host:false asks for a network namespace of the "+
				"BUILD STEP's own; see the networkmode refusal for why that needs a "+
				"capability the engine does not have", o.Name)
		}
	}
	return v, nil
}

// checkSeccompProfile keeps the profile one the sandbox can READ but did not
// AUTHOR.
//
// The CLI sends /usr/share/containers/seccomp.json on every build, so this
// cannot simply be refused; `unconfined` must be, because turning the filter off
// is not the sandbox's call.
//
// The first version stopped there and applied the ordinary mount rule — "a path
// the sandbox can see" — which the redteam pointed out is the wrong test, and it
// was right. The sandbox's target is both visible AND writable, so the agent
// wrote {"defaultAction":"SCMP_ACT_ALLOW"} into its own project and passed that:
// `unconfined` by another name, through the check meant to prevent it.
//
// Visibility is the right test for a MOUNT, where the question is what the
// container may reach. It is the wrong test for a file the engine applies AS THE
// SECURITY POLICY, where the question is who wrote it. So the rule here is
// readable-but-not-writable: a distro profile under /usr passes, anything the
// sandbox could have authored does not.
func checkSeccompProfile(p *Proxy, v string) (string, error) {
	if v == "" {
		return v, nil
	}
	if strings.EqualFold(v, "unconfined") {
		return "", fmt.Errorf("`unconfined` is not permitted; the sandbox does not get to " +
			"turn off the build container's seccomp filter")
	}
	// Through resolveForwardable, not resolveExisting: a seccomp profile named
	// by a symlink that dangles in snug's namespace is the same two-namespace
	// divergence a bind is (issue #251). The writable-refusal below already
	// stops the measured route (the symlink sits in the writable target), but
	// the divergence is the general defect and belongs in one place.
	real, err := resolveForwardable(v)
	if err != nil {
		return "", fmt.Errorf("%q cannot be resolved: %v", v, err)
	}
	if !p.hostPathVisible(real, false) {
		return "", fmt.Errorf("%q is not a path this sandbox can see", v)
	}
	if p.hostPathVisible(real, true) {
		return "", fmt.Errorf("%q is writable by this sandbox, so it is a profile the sandbox "+
			"could have written itself — which is `unconfined` with extra steps. A seccomp "+
			"profile must be one the sandbox can read but did not author", v)
	}
	// The ENGINE opens this file, in its own DERIVED view, and everything above
	// judged a HOST path (issue #371). Those are two spaces, and every mount
	// whose Host and Guest differ makes them give different answers — @claude's
	// `{home}/.local/bin/claude:/snug/bin/claude` is a shipped example whose
	// Host string, read in guest space, lands on the writable $HOME tmpfs.
	// Without this the host spelling passes both checks above while the engine
	// reads whatever this sandbox's own mount set puts at that name: a file the
	// payload wrote, which is `unconfined` by the third route this function has
	// had to close.
	//
	// It also discharges CheckEngineBindSource's documented precondition, which
	// this caller did not establish before — that function's parameter is named
	// `guest`, and every predicate inside it walks Mount.Guest, while this one
	// was handing it `real`, a host path (issue #371).
	if err := p.pol.CheckEngineForwardedPath(real); err != nil {
		return "", err
	}
	// The engine reads this path itself, a second time, when it applies the
	// profile — the same create/start TOCTOU checkOne closes for a bind
	// source (issue #284): a name on the path swapped after this check and
	// before the engine reads it re-points what gets applied as security
	// policy.
	//
	// THIS AND THE `return real` BELOW ARE LAYERED, NOT ALTERNATIVES, and the
	// rebase that brought them together is where that could have been lost.
	// Forwarding the RESOLVED path narrows the window — the engine no longer
	// re-walks the symlink the caller named — and does not close it, because
	// the resolved string is still a string and every name on it is still
	// re-pointable until this predicate says otherwise. Deleting either one
	// leaves a real gap.
	if err := p.pol.CheckEngineBindSource(real); err != nil {
		return "", err
	}
	// The RESOLVED path is what the engine is asked for. Returning v here
	// would leave the swap window open on the one parameter whose whole job is
	// to decide the build container's security posture.
	return real, nil
}

// checkBuilderVersion allows only the classic builder. `version=2` selects
// BuildKit, whose options (secrets, mounts, cache imports, exporters) are a
// DIFFERENT SET from the ones buildParams enumerates here — accepting it
// would mean this allowlist stopped being the whole story for a request
// that took that path. `""` is the CLI's own default when the flag is not
// sent at all, and is treated the same as `1`.
func checkBuilderVersion(_ *Proxy, v string) (string, error) {
	switch strings.TrimSpace(v) {
	case "", "1":
		return v, nil
	}
	return "", fmt.Errorf("%q is not permitted: `version` selects the BUILDER, and `2` is "+
		"BuildKit — a backend whose build options are a different set from the ones snug "+
		"filters here. Only the classic builder (version 1, docker's DOCKER_BUILDKIT=0 path) "+
		"is supported", v)
}

// checkIsolation allows only the default. `--isolation chroot` sends 2, and an
// isolation mode is a runtime selector by another name.
func checkIsolation(_ *Proxy, v string) (string, error) {
	switch strings.TrimSpace(v) {
	case "", "0", "default", "oci":
		return v, nil
	}
	return "", fmt.Errorf("%q is not permitted: an isolation mode is a runtime selector "+
		"by another name", v)
}

// summarise renders the audit line: what was built, and whether anything
// host-reaching was asked for and allowed.
func summarise(q url.Values) string {
	var b strings.Builder
	if t := q.Get("t"); t != "" {
		fmt.Fprintf(&b, "%s", t)
	} else {
		b.WriteString("(untagged)")
	}
	if v := q["volume"]; len(v) > 0 {
		fmt.Fprintf(&b, ", %d host volume(s) allowed", len(v))
	}
	return b.String()
}

// checkBuildOutput keeps `output` to a plain image tag.
//
// buildOutputIsATagOnly carries the measurement: the libpod endpoint does not
// read this parameter at all, the podman CLI sends it redundantly beside `t`,
// and the buildkit destination syntax is refused client-side in remote mode.
// None of that is a property snug can rely on — a later podman that starts
// honouring `output` would silently gain a filesystem destination behind a
// parameter snug had waved through, which is the shape cacheto and cachefrom
// are already refused for.
//
// The discriminator is `=` and `,`: both are illegal in an image reference
// (docker's grammar allows alphanumerics with `_`, `.`, `-`, `/` and the `:`
// before a tag, and `@` before a digest) and both are structural to
// `type=local,dest=/path`. So this cannot refuse a tag a client meant, which is
// what makes it narrow enough to ship — an ordinary build sends
// output=probe%3Ax and is unaffected.
//
// The value is returned UNCHANGED on the accept path, never normalised:
// filterBuildQuery marks a build "rewritten" when the forwarded value differs
// from the client's, so translating here would mark every accepted build as
// carrying a snug-modified parameter it does not.
func checkBuildOutput(_ *Proxy, v string) (string, error) {
	if strings.ContainsAny(v, "=,") {
		return "", fmt.Errorf("%q is not permitted: an `output` carrying `=` or `,` is the "+
			"buildkit `type=<kind>,dest=<path>` form, which names a destination the ENGINE "+
			"writes rather than an image tag. snug allows this parameter only as the tag the "+
			"built image is committed under.\n"+
			"       Fix: pass the tag with -t, which is where podman sends it anyway.", v)
	}
	return v, nil
}
