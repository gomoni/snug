package dockerproxy

import (
	"encoding/json"
	"fmt"
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

	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		check, known := buildParams[strings.ToLower(name)]
		if !known {
			p.deny(w, "build parameter %q is not permitted. snug allows a named set of "+
				"build options and refuses the rest, so an option it has not been taught "+
				"about fails closed rather than reaching the engine unexamined. If this "+
				"one is harmless, it belongs in buildParams with a note saying why.", name)
			return
		}
		if check == nil {
			continue // allowed as-is
		}
		for _, v := range q[name] {
			if err := check(p, v); err != nil {
				p.deny(w, "build parameter %s: %v", name, err)
				return
			}
		}
	}

	p.audit("build: " + summarise(q))
	p.forward(w, r, nil)
}

// buildParamCheck validates one value. A nil check means the parameter carries
// nothing snug needs to judge.
type buildParamCheck func(p *Proxy, value string) error

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
	return func(*Proxy, string) error { return fmt.Errorf("is not permitted: %s", reason) }
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
func checkBuildSecrets(_ *Proxy, v string) error {
	var specs []string
	if strings.HasPrefix(strings.TrimSpace(v), "[") {
		if err := json.Unmarshal([]byte(v), &specs); err != nil {
			return fmt.Errorf("is not a JSON list of secret specs")
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
					return fmt.Errorf("secret source %w", err)
				}
			}
		}
	}
	return nil
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
func checkDockerfile(_ *Proxy, v string) error {
	names := []string{v}
	if strings.HasPrefix(strings.TrimSpace(v), "[") {
		var list []string
		if err := json.Unmarshal([]byte(v), &list); err != nil {
			return fmt.Errorf("is not a name or a JSON list of names")
		}
		names = list
	}
	for _, n := range names {
		if err := insideContext(n); err != nil {
			return err
		}
	}
	return nil
}

// checkBuildVolume applies the rule in the package comment to `build -v`, which
// is the same host bind that HostConfig.Binds is, spelled differently.
func checkBuildVolume(p *Proxy, v string) error {
	parts := strings.Split(v, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return fmt.Errorf("%q is not src:dst[:opts]", v)
	}
	ro := false
	if len(parts) == 3 {
		for _, o := range strings.Split(parts[2], ",") {
			switch o {
			case "ro":
				ro = true
			case "rw", "z", "Z", "":
			default:
				return fmt.Errorf("option %q is not permitted", o)
			}
		}
	}
	_, err := p.checkOne(parts[0], parts[1], ro)
	return err
}

// checkAdditionalContexts judges `--build-context name=VALUE`.
//
// An image reference is fine — it is content the engine pulls under the same
// rules as any other image. A URL is not: the engine fetches it from somewhere
// snug never sees. Anything else is a host path, and gets the mount rule, read
// only, because a build context is only ever read.
func checkAdditionalContexts(p *Proxy, v string) error {
	var m map[string]struct {
		IsURL   bool
		IsImage bool
		Value   string
	}
	if err := json.Unmarshal([]byte(v), &m); err != nil {
		return fmt.Errorf("is not the JSON object podman sends")
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		c := m[name]
		switch {
		case c.IsURL:
			return fmt.Errorf("context %q is a URL, which the ENGINE fetches from a place "+
				"snug never sees", name)
		case c.IsImage:
			continue
		}
		if _, err := p.checkOne(c.Value, "/", true); err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
	}
	return nil
}

// checkNetworkMode refuses host networking for the build.
//
// The libpod endpoint sends an integer and the compat one a string, so both
// spellings are enumerated. Default-deny: an unrecognised value is refused
// rather than assumed benign, because the numbers are buildah's internal enum
// and a new one could mean anything.
func checkNetworkMode(_ *Proxy, v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "1", "default", "none", "private", "bridge", "slirp4netns", "pasta":
		return nil
	}
	return fmt.Errorf("%q is not permitted; a build may not join the host's network "+
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
func checkNSOptions(_ *Proxy, v string) error {
	var opts []struct {
		Name string
		Host bool
		Path string
	}
	if err := json.Unmarshal([]byte(v), &opts); err != nil {
		return fmt.Errorf("is not the JSON list podman sends")
	}
	for _, o := range opts {
		name := strings.ToLower(o.Name)
		if o.Host && name != "user" {
			return fmt.Errorf("%q asks for the HOST's %s namespace, which is outside this "+
				"sandbox", o.Name, name)
		}
		if o.Path != "" {
			return fmt.Errorf("%q names an existing namespace at %q, which snug did not "+
				"create and cannot vouch for", o.Name, o.Path)
		}
	}
	return nil
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
func checkSeccompProfile(p *Proxy, v string) error {
	if v == "" {
		return nil
	}
	if strings.EqualFold(v, "unconfined") {
		return fmt.Errorf("`unconfined` is not permitted; the sandbox does not get to " +
			"turn off the build container's seccomp filter")
	}
	// Through resolveForwardable, not resolveExisting: a seccomp profile named
	// by a symlink that dangles in snug's namespace is the same two-namespace
	// divergence a bind is (issue #251). The writable-refusal below already
	// stops the measured route (the symlink sits in the writable target), but
	// the divergence is the general defect and belongs in one place.
	real, err := resolveForwardable(v)
	if err != nil {
		return fmt.Errorf("%q cannot be resolved: %v", v, err)
	}
	if !p.hostPathVisible(real, false) {
		return fmt.Errorf("%q is not a path this sandbox can see", v)
	}
	if p.hostPathVisible(real, true) {
		return fmt.Errorf("%q is writable by this sandbox, so it is a profile the sandbox "+
			"could have written itself — which is `unconfined` with extra steps. A seccomp "+
			"profile must be one the sandbox can read but did not author", v)
	}
	return nil
}

// checkBuilderVersion allows only the classic builder. `version=2` selects
// BuildKit, whose options (secrets, mounts, cache imports, exporters) are a
// DIFFERENT SET from the ones buildParams enumerates here — accepting it
// would mean this allowlist stopped being the whole story for a request
// that took that path. `""` is the CLI's own default when the flag is not
// sent at all, and is treated the same as `1`.
func checkBuilderVersion(_ *Proxy, v string) error {
	switch strings.TrimSpace(v) {
	case "", "1":
		return nil
	}
	return fmt.Errorf("%q is not permitted: `version` selects the BUILDER, and `2` is "+
		"BuildKit — a backend whose build options are a different set from the ones snug "+
		"filters here. Only the classic builder (version 1, docker's DOCKER_BUILDKIT=0 path) "+
		"is supported", v)
}

// checkIsolation allows only the default. `--isolation chroot` sends 2, and an
// isolation mode is a runtime selector by another name.
func checkIsolation(_ *Proxy, v string) error {
	switch strings.TrimSpace(v) {
	case "", "0", "default", "oci":
		return nil
	}
	return fmt.Errorf("%q is not permitted: an isolation mode is a runtime selector "+
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
