package dockerproxy

import (
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
//	--network=host           networkmode=2 AND nsoptions=[...]   TWO independent spellings
//	--cgroup-parent foo      cgroupparent=foo                    a cgroup outside the sandbox's
//	--add-host h:1.2.3.4     extrahosts=[...]                    name redirection
//	--security-opt seccomp=  seccomp=unconfined | /host/path     hardening downgrade, host read
//
// `--network=host` is the one to look at twice. It sets networkmode AND a
// nsoptions entry, either of which alone re-opens the host network — the same
// shape as pasta's --map-host-loopback and -T/-U, where closing three of four
// flags left the hole wide open. Both are checked here, and both have a test.
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
		check, known := buildParams[strings.ToLower(name)]
		if !known {
			return nil, false, fmt.Sprintf("build parameter %q is not permitted. snug allows a named set of "+
				"build options and refuses the rest, so an option it has not been taught "+
				"about fails closed rather than reaching the engine unexamined. If this "+
				"one is harmless, it belongs in buildParams with a note saying why.", name)
		}
		if check == nil {
			out[name] = append([]string(nil), q[name]...) // allowed as-is
			continue
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
// A check that changes nothing returns its input. A nil check means the
// parameter carries nothing snug needs to judge, and its values are forwarded
// verbatim.
type buildParamCheck func(p *Proxy, value string) (string, error)

var buildParams = map[string]buildParamCheck{
	// ── naming and output ────────────────────────────────────────────────
	"t":            nil, // image tag
	"output":       nil, // podman sends the tag here too
	"outputformat": nil,
	"annotations":  refuseBuildParam("podman honours run.oci.* annotations, which reach the runtime"),

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

	// ── ordinary build behaviour, none of it host-reaching ───────────────
	"buildargs": nil, "labels": nil, "target": nil, "platform": nil,
	"nocache": nil, "rm": nil, "forcerm": nil, "layers": nil, "squash": nil,
	"pull": nil, "pullpolicy": nil, "q": nil, "quiet": nil,
	"unsetenv": nil, "unsetlabel": nil, "compatvolumes": nil,
	"inheritannotations": nil, "inheritlabels": nil, "omithistory": nil,
	"rewritetimestamp": nil, "timestamp": nil, "sourcedateepoch": nil,
	"jobs": nil, "retry": nil, "retry-delay": nil, "identitylabel": nil,
	"compression": nil, "compressionformat": nil, "compressionlevel": nil,
	"manifest": nil, "createdannotation": nil,

	// Resource limits. They bound the build rather than widening it.
	"shmsize": nil, "memory": nil, "memswap": nil, "ulimits": nil,
	"cpushares": nil, "cpusetcpus": nil, "cpusetmems": nil,
	"cpuperiod": nil, "cpuquota": nil,

	"secrets": checkBuildSecrets,

	// The engine's own proxy environment, not the sandbox's, and the CLI sends
	// it on every build.
	"httpproxy": nil,

	// ── the host-reaching set ────────────────────────────────────────────
	"volume":                  checkBuildVolume,
	"volumes":                 checkBuildVolume,
	"additionalbuildcontexts": checkAdditionalContexts,
	"networkmode":             checkNetworkMode,
	"nsoptions":               checkNSOptions,
	"seccomp":                 checkSeccompProfile,
	"idmappingoptions":        nil, // rootless bounds this; the CLI always sends it

	"devices": refuseBuildParam("the engine's /dev is the sandbox's own synthetic tree since " +
		"Tier C (issue #125), with no host device nodes, and the engine holds no CAP_MKNOD to " +
		"make one — so a device request has nothing host-shaped to pass through"),
	"cgroupparent": refuseBuildParam("it places the build in a cgroup outside this sandbox's own"),
	"isolation":    checkIsolation,
	"extrahosts":   refuseBuildParam("name redirection"),
	"dnsservers":   refuseBuildParam("resolver redirection"),
	"dnsoptions":   refuseBuildParam("resolver redirection"),
	"dnssearch":    refuseBuildParam("resolver redirection"),
	"addcapabilities": refuseBuildParam(
		"added capabilities apply to the host kernel, not to the sandbox"),
	"runtime": refuseBuildParam("an alternate OCI runtime is an arbitrary host binary"),
	"remote": refuseBuildParam("a remote build context is fetched by the ENGINE, from a place " +
		"snug never sees — the context must be the tar the client sends"),
	"cachefrom": refuseBuildParam("a cache source is resolved by the engine and may name a " +
		"local path; not yet modelled"),
	"cacheto": refuseBuildParam("a cache destination is written by the engine; not yet modelled"),
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

// checkAdditionalContexts judges `--build-context name=VALUE`.
//
// An image reference is fine — it is content the engine pulls under the same
// rules as any other image. A URL is not: the engine fetches it from somewhere
// snug never sees. Anything else is a host path, and gets the mount rule, read
// only, because a build context is only ever read.
// Like checkBuildVolume it returns the value respelled with the RESOLVED path
// (issue #304). The re-marshal goes through json.RawMessage per entry rather
// than through a struct, so every field podman sends that snug does not model
// — buildah's AdditionalBuildContext has grown fields before — survives the
// round trip byte for byte. Rewriting through a three-field struct would
// silently DELETE the rest, which is a different bug in the same line of code.
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
		if m.Source == c.Value {
			continue
		}
		// Write back under the key spelling that was actually present.
		// encoding/json matches field names case-insensitively on the way in,
		// so assuming "Value" here would leave a lowercase "value" in place
		// and add a second key the engine might prefer either way.
		key := "Value"
		for k := range fields {
			if strings.EqualFold(k, "Value") {
				key = k
				break
			}
		}
		enc, err := json.Marshal(m.Source)
		if err != nil {
			return "", fmt.Errorf("context %q: %v", name, err)
		}
		fields[key] = enc
		out, err := json.Marshal(fields)
		if err != nil {
			return "", fmt.Errorf("context %q: %v", name, err)
		}
		raw[name] = out
		changed = true
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

// checkNetworkMode refuses host networking for the build.
//
// The libpod endpoint sends an integer and the compat one a string, so both
// spellings are enumerated. Default-deny: an unrecognised value is refused
// rather than assumed benign, because the numbers are buildah's internal enum
// and a new one could mean anything.
func checkNetworkMode(_ *Proxy, v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "1", "default", "none", "private", "bridge", "slirp4netns", "pasta":
		return v, nil
	}
	return "", fmt.Errorf("%q is not permitted; a build may not join the host's network "+
		"namespace (the sandbox's own network is what it gets)", v)
}

// checkNSOptions is the second spelling of the same hole.
//
// `--network=host` sets networkmode AND an nsoptions entry, and either alone
// re-opens the host network. That is the shape of the pasta bug this project
// already paid for once: three of four closing flags passed, and the fourth
// left every host loopback service reachable.
//
// `user` with Host:true is the rootless default the CLI always sends — the
// engine already runs in that user namespace — so it is the one exception, and
// it is named rather than pattern-matched.
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
		name := strings.ToLower(o.Name)
		if o.Host && name != "user" {
			return "", fmt.Errorf("%q asks for the HOST's %s namespace, which is outside this "+
				"sandbox", o.Name, name)
		}
		if o.Path != "" {
			return "", fmt.Errorf("%q names an existing namespace at %q, which snug did not "+
				"create and cannot vouch for", o.Name, o.Path)
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
