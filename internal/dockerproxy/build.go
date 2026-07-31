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
//     ships the bytes in the tar under a generated name — DESIGN §7.2's advice
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

	// The CLI reads a --secret's file ITSELF, inside the sandbox, and ships the
	// bytes in the context tar under a generated name. So this names no host
	// path and grants no read the sandbox did not already have. Verified by
	// recording: --secret id=s,src=/etc/hostname became
	// secrets=["id=s,src=podman-build-secret-4284765652"].
	"secrets": nil,

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

	"devices":      refuseBuildParam("device passthrough reaches hardware the sandbox cannot see"),
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
		if n == "" {
			continue
		}
		if strings.Contains(n, "://") {
			return fmt.Errorf("%q is a URL; the Dockerfile must come from the context "+
				"the client sent, not from somewhere the engine fetches", n)
		}
		if path.IsAbs(n) {
			return fmt.Errorf("%q is absolute; it must name a file inside the build context", n)
		}
		if cleaned := path.Clean(n); cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			return fmt.Errorf("%q escapes the build context", n)
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

// checkSeccompProfile keeps the profile a path the SANDBOX can see.
//
// The CLI sends /usr/share/containers/seccomp.json on every build, so this
// cannot simply be refused. What it must not be is `unconfined` — a hardening
// downgrade the sandbox chooses for itself — or an arbitrary host path, which
// would have the engine read a file on snug's behalf from outside every grant.
// The same rule as a mount, for the same reason.
func checkSeccompProfile(p *Proxy, v string) error {
	if v == "" {
		return nil
	}
	if strings.EqualFold(v, "unconfined") {
		return fmt.Errorf("`unconfined` is not permitted; the sandbox does not get to " +
			"turn off the build container's seccomp filter")
	}
	if _, err := p.checkOne(v, "/", true); err != nil {
		return err
	}
	return nil
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
