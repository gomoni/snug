package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// libpodcreate.go is POST /libpod/containers/create — podman's own
// SpecGenerator body, and the route that was refused outright while
// containers/create's docker-compat twin worked (issue #459). It is the
// second decoder createjudge.go's phase 1 extraction was built for: every
// namespace-mode and mount decision below is judged by the EXACT same
// function create.go's docker-compat path calls (judgeNamespaceMode,
// checkMountRequests), so the two wires cannot drift about what "host",
// "container:<id>" or an unresolvable bind means — invariant 6, one Policy
// one author, applied to the judge rather than only to the bwrap argv.
//
// THE CATALOGUE IS NOT COMPLETE, AND THAT IS THE DESIGN, NOT A GAP TO CLOSE
// LATER. SpecGenerator has roughly 45 top-level fields and this file names
// perhaps two thirds of them; `podman run` has on the order of 120 flags and
// seven flag variants were tried building this list. What makes an
// incomplete catalogue SAFE is libpodUnexaminedFields' own sweep at the
// bottom: a non-empty field that is neither refused, judged nor named
// unexamined REFUSES BY NAME. A podman version that adds a 46th field, or a
// flag this session never tried, breaks `podman run` loudly rather than
// forwarding an unread field — the same trade issue #478's ruling makes for
// the engine version itself. Completeness against a podman that moves was
// never the bar; not-forwarding-what-was-never-read is.
//
// Every field below carries the MEASUREMENT that put it where it is:
// captured against a real podman 6.0.2 CLI posting to a unix socket that
// logs the request and answers it (VERIFY.md §22's method, no engine
// needed), and cross-checked against a live snug engine
// (`@podman-build -p @net`, podman 6.0.2) for the fields that needed a real
// create+start round trip to be sure of.
func (p *Proxy) handleLibpodContainerCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		p.deny(w, "reading request: %v", err)
		return
	}
	req, err := decodeLibpodObject(body)
	if err != nil {
		p.deny(w, "containers/create body: %v", err)
		return
	}
	examined := map[string]bool{}

	// 1. Namespace modes — the SAME judge create.go's HostConfig loop calls,
	//    fed from podman's {"nsmode":"...","value":"..."} shape instead of a
	//    docker-compat string. MEASURED, podman 6.0.2 `podman run`:
	//
	//	netns:    {} (unset, default) | {"nsmode":"host"} | {"nsmode":"none"}
	//	          {"nsmode":"bridge"} | {"nsmode":"private"}
	//	          {"nsmode":"container","value":"<id>"} | {"nsmode":"path","value":"<path>"}
	//	pidns/utsns:  {} | {"nsmode":"host"} | {"nsmode":"container","value":"<id>"}
	//	ipcns:    {} | {"nsmode":"host"} | {"nsmode":"none"} | {"nsmode":"shareable"}
	//	          | {"nsmode":"container","value":"<id>"}
	//	userns:   {} | {"nsmode":"keep-id"} | {"nsmode":"auto"} | {"nsmode":"no-map"}
	//	cgroupns: {} | {"nsmode":"host"} | {"nsmode":"private"}
	for _, ns := range libpodNamespaceFields {
		examined[ns.field] = true
		raw, ok := req[ns.field]
		if !ok || isEmptyJSON(raw) {
			continue
		}
		spec, err := decodeLibpodNSMode(raw)
		if err != nil {
			p.deny(w, "%s: %v", ns.field, err)
			return
		}
		if spec.Mode == "" {
			continue // {"nsmode":""} or a bare {} with no mode: not a request
		}
		if err := judgeNamespaceMode(ns.canonical, spec, libpodFieldSpelling); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// 2. Networks — per-network settings, independent of netns.nsmode.
	//    MEASURED: `podman run --ip 10.0.0.5 ...` sets
	//    Networks={"default":{"static_ips":["10.0.0.5"],"interface_name":""}}
	//    while netns STAYS ABSENT — so a client can ask for per-network
	//    addressing on the sandbox's own default network without ever
	//    tripping the namespace-mode check above. This mirrors
	//    checkNetworkingConfig's own rule for docker-compat's
	//    NetworkingConfig.EndpointsConfig: every per-network field must be
	//    empty, whatever the network is called.
	examined["Networks"] = true
	examined["networkOrder"] = true
	if raw, ok := req["Networks"]; ok && !isEmptyJSON(raw) {
		if err := judgeLibpodNetworks(raw); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// 3. Fields refused outright when asked, sharing refusalReason with the
	//    docker-compat path — same engine, same danger, only the spelling
	//    differs. MEASURED field names: `podman run --privileged`,
	//    `--cap-add ALL`, `--device /dev/null`,
	//    `--device-cgroup-rule 'c 1:1 rwm'`, `--cgroup-parent /foo`,
	//    `--sysctl net.ipv4.ip_forward=1`, `--add-host foo:1.2.3.4`,
	//    `-p 8080:80`.
	for _, rf := range libpodRefusedFields {
		examined[rf.field] = true
		v, ok := req[rf.field]
		if !ok || isEmptyJSON(v) {
			continue
		}
		p.deny(w, "%v", judgeAskedField(rf.canonical, libpodFieldSpelling))
		return
	}

	// publish_image_ports is PortBindings/PublishAllPorts' bool spelling:
	// MEASURED present (false) on every plain `podman run`; true is what a
	// client asking to publish the image's own EXPOSEd ports would send.
	// Same reasoning as PublishAllPorts: nothing to publish TO, the
	// container already shares this sandbox's network namespace.
	examined["publish_image_ports"] = true
	if boolField(req, "publish_image_ports") {
		p.deny(w, "%v", judgeAskedField("PublishAllPorts", libpodFieldSpelling))
		return
	}

	// weightDevice: MEASURED top-level (not nested under resource_limits),
	// `podman run --blkio-weight-device /dev/null:100` ->
	// weightDevice={"/dev/null":{"major":0,"minor":0,"weight":100}}. Same
	// stat-oracle reasoning as the docker-compat Blkio*Device* fields:
	// snug neither resolves nor rewrites a device path here, and the
	// sandbox's /dev is bwrap's synthetic tree, so there is nothing this
	// field could reach that the refusal costs.
	examined["weightDevice"] = true
	if raw, ok := req["weightDevice"]; ok && !isEmptyJSON(raw) {
		p.deny(w, "%s is not permitted: %s", libpodFieldSpelling("weightDevice"), blkioPathField)
		return
	}

	// resource_limits is an OCI LinuxResources OBJECT, not a number, and two
	// of its sub-objects are the NESTED spelling of content refused above:
	// resource_limits.devices carries device_cgroup_rule's own content, and
	// resource_limits.unified is an open key/value channel into the
	// container's cgroup. Judged rather than forwarded whole — see
	// judgeLibpodResourceLimits for the sub-key table and its measurements.
	examined["resource_limits"] = true
	if raw, ok := req["resource_limits"]; ok && !isEmptyJSON(raw) {
		if err := judgeLibpodResourceLimits(raw); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// volumes: the named/anonymous volume array, MEASURED distinct from
	// `mounts` — `podman run -v NAMEDVOL:/data` and
	// `--mount type=volume,source=NAMEDVOL,destination=/m` both produce
	// volumes=[{"Name":"NAMEDVOL","Dest":"/data",...}] and never touch
	// `mounts`. NAMED entries are judged (issue #464); an ANONYMOUS one is
	// still refused, for the reason docker-compat's top-level Volumes is.
	examined["volumes"] = true
	if raw, ok := req["volumes"]; ok && !isEmptyJSON(raw) {
		judged, err := judgeLibpodVolumes(r.Context(), p, raw)
		if err != nil {
			p.deny(w, "%v", err)
			return
		}
		enc, err := json.Marshal(judged)
		if err != nil {
			p.deny(w, "re-encoding volumes: %v", err)
			return
		}
		req["volumes"] = enc
	}

	// healthconfig: MEASURED, `podman run --health-cmd=true` sets
	// healthconfig={"Test":["CMD-SHELL","true"],"Interval":30000000000,...};
	// a plain run sends healthconfig={} (empty, isEmptyJSON true). Same
	// hazard as docker-compat's top-level Healthcheck: podman schedules a
	// `systemd-run --user` unit and timer on the HOST user's own session
	// manager, outliving this sandbox's teardown.
	examined["healthconfig"] = true
	if raw, ok := req["healthconfig"]; ok && !isEmptyJSON(raw) {
		p.deny(w, "%s is not permitted: %s", libpodFieldSpelling("healthconfig"), topLevelRefusalReason["Healthcheck"])
		return
	}
	// healthLogDestination/healthMaxLogCount/healthMaxLogSize are three
	// SIBLING fields, present on every create (measured defaults "local", 5,
	// 500) whether or not a healthcheck was asked for. MEASURED,
	// `--health-log-destination=/etc` (paired with --health-cmd, since the
	// flag needs one to be accepted) sets healthLogDestination to that path
	// verbatim — refused independently of healthconfig, in case a future
	// podman decouples the two the way it already decoupled the userns
	// annotation from userns.nsmode.
	examined["healthLogDestination"] = true
	examined["healthMaxLogCount"] = true
	examined["healthMaxLogSize"] = true
	if err := judgeLibpodHealthLogFields(req); err != nil {
		p.deny(w, "%v", err)
		return
	}

	// seccomp_policy: MEASURED "default" on every plain run and every
	// variant tried, never observed to change. Refused when it is anything
	// else rather than assumed benign, because "empty"/other enum values
	// are unmeasured and the field selects HOW seccomp is applied.
	examined["seccomp_policy"] = true
	if s := stringField(req, "seccomp_policy"); s != "" && s != "default" {
		p.deny(w, "%s = %q is not permitted; only \"default\" is (MEASURED unchanged across "+
			"every podman 6.0.2 flag tried this session — an unmeasured value is refused "+
			"rather than assumed benign)", libpodFieldSpelling("seccomp_policy"), s)
		return
	}

	// seccomp_profile_path / apparmor_profile: MEASURED,
	// `--security-opt seccomp=unconfined` sets seccomp_profile_path and
	// `--security-opt apparmor=unconfined` sets apparmor_profile; both
	// absent on a plain run. Same reasoning as docker-compat's SecurityOpt:
	// snug sets this sandbox's own protections and a client value could
	// undo them.
	examined["seccomp_profile_path"] = true
	examined["apparmor_profile"] = true
	if s := stringField(req, "seccomp_profile_path"); s != "" {
		p.deny(w, "%s is not permitted: %s", libpodFieldSpelling("seccomp_profile_path"), refusalReason["SecurityOpt"])
		return
	}
	if s := stringField(req, "apparmor_profile"); s != "" {
		p.deny(w, "%s is not permitted: %s", libpodFieldSpelling("apparmor_profile"), refusalReason["SecurityOpt"])
		return
	}

	// no_new_privileges: ABSENT on every plain run this session measured —
	// podman's own OCI spec generation applies the protection by default
	// without the client naming it. `--security-opt no-new-privileges=false`
	// is the one spelling that sends it, and sends it `false`: a client
	// asking snug's own hardening to be turned off. Refused rather than
	// silently overridden (a silent downgrade a client can no longer see is
	// invariant 5's failure mode), and INJECTED true regardless — the
	// libpod-side twin of create.go step 7's
	// `hc["SecurityOpt"] = ["no-new-privileges:true"]`, because this
	// sandbox does not trust an ABSENT field to mean the engine's own
	// default either.
	// NOT gated on isEmptyJSON: for every OTHER field in this file "false"
	// means "asks for nothing", but here false IS the ask — the one that
	// weakens this sandbox's own hardening. isEmptyJSON would read the
	// client's explicit `false` as absent and let it pass silently.
	examined["no_new_privileges"] = true
	if raw, ok := req["no_new_privileges"]; ok {
		var v bool
		_ = json.Unmarshal(raw, &v)
		if !v {
			p.deny(w, "%s = false is not permitted: %s", libpodFieldSpelling("no_new_privileges"),
				refusalReason["SecurityOpt"])
			return
		}
	}
	req["no_new_privileges"] = json.RawMessage("true")

	// env_host: MEASURED false on every plain run. true asks the ENGINE to
	// copy its OWN full process environment into the container — the
	// libpod-native spelling of docker-compat's `Env: ["*"]` hazard
	// (checkEnv's own measurement), except broader: env_host is a single
	// bool covering the WHOLE environment, not a per-name opt-in.
	examined["env_host"] = true
	if boolField(req, "env_host") {
		p.deny(w, "%s = true is not permitted: it copies the ENGINE's own process environment "+
			"into the container — this run's graft layout among it (the runroot, the config "+
			"directory, the registry auth file), the same class of leak checkEnv refuses for "+
			"docker-compat's Env:[\"*\"], but covering the whole environment rather than one "+
			"name at a time", libpodFieldSpelling("env_host"))
		return
	}

	// envmerge / unsetenv / unsetenvall: MEASURED absent/false on a plain
	// run. docker-compat's top-level inversion (toplevel.go) refuses these
	// same three PODMAN-ONLY fields today because nothing has modelled
	// them; libpod's own catalogue keeps that verdict rather than loosening
	// it just because the field is native here.
	examined["envmerge"] = true
	examined["unsetenv"] = true
	examined["unsetenvall"] = true
	if raw, ok := req["envmerge"]; ok && !isEmptyJSON(raw) {
		p.deny(w, "%s is not permitted: not modelled — see toplevel.go's EnvMerge, refused for "+
			"the same reason on the docker-compat path", libpodFieldSpelling("envmerge"))
		return
	}
	if raw, ok := req["unsetenv"]; ok && !isEmptyJSON(raw) {
		p.deny(w, "%s is not permitted: not modelled — see toplevel.go's UnsetEnv, refused for "+
			"the same reason on the docker-compat path", libpodFieldSpelling("unsetenv"))
		return
	}
	if boolField(req, "unsetenvall") {
		p.deny(w, "%s = true is not permitted: not modelled — see toplevel.go's UnsetEnvAll, "+
			"refused for the same reason on the docker-compat path", libpodFieldSpelling("unsetenvall"))
		return
	}

	// timezone: MEASURED, an IANA zone name ("UTC") is resolved from the
	// CONTAINER's own zoneinfo database — container-internal, allowed
	// unexamined below. "local" is podman's own spelling for "bind-mount
	// the HOST's /etc/localtime", a host-file read no grant here approved;
	// refused by name rather than by value, since every OTHER value stays
	// container-internal.
	examined["timezone"] = true
	if s := stringField(req, "timezone"); strings.EqualFold(s, "local") {
		p.deny(w, `%s = "local" is not permitted: it asks the ENGINE to bind-mount the HOST's `+
			"own /etc/localtime into the container, which is a host file no grant here "+
			"approved. Any other zone name (\"UTC\", \"America/New_York\", ...) is resolved "+
			"from the container's OWN zoneinfo database and stays allowed",
			libpodFieldSpelling("timezone"))
		return
	}

	// restart_policy / restart_tries: judgeRestartPolicyName is the same
	// function checkRestartPolicy calls on the docker-compat side; podman's
	// own field is already a bare string, so there is no shape to decode.
	examined["restart_policy"] = true
	examined["restart_tries"] = true
	restartName := stringField(req, "restart_policy")
	if err := judgeRestartPolicyName(restartName, libpodFieldSpelling); err != nil {
		p.deny(w, "%v", err)
		return
	}
	if n := intField(req, "restart_tries"); n != 0 {
		p.deny(w, "%s = %d is not permitted; %s is only permitted when %s asks for nothing "+
			"(\"\" or \"no\")", libpodFieldSpelling("restart_tries"), n,
			libpodFieldSpelling("restart_tries"), libpodFieldSpelling("restart_policy"))
		return
	}

	// idmappings: the SAME struct build.go's own `idmappingoptions` query
	// parameter carries (issue #323) — MEASURED identical field set,
	// HostUIDMapping/HostGIDMapping/UIDMap/GIDMap/AutoUserNs/AutoUserNsOpts —
	// so checkIDMappingOptions is reused rather than re-authored: AutoUserNs
	// must stay false (true makes the engine READ AND PARSE a passwd/group
	// file to size the range) and AutoUserNsOpts must stay empty (its
	// PasswdFile/GroupFile are host paths the engine opens).
	examined["idmappings"] = true
	if raw, ok := req["idmappings"]; ok && !isEmptyJSON(raw) {
		if _, err := checkIDMappingOptions(p, string(raw)); err != nil {
			p.deny(w, "idmappings: %v", err)
			return
		}
	}

	// image: reuses checkPullReference, the SAME shape check images/pull's
	// own `reference` parameter is judged by (imagepull.go). Defense in
	// depth for a raw client posting directly to containers/create without
	// ever calling images/pull first — the podman CLI always pulls first,
	// but this proxy does not get to assume every client is the CLI.
	examined["image"] = true
	if s := stringField(req, "image"); s != "" {
		if err := checkPullReference(p, s); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// annotations: MEASURED, several ordinary flags echo their own value
	// here as `io.podman.annotations.*` metadata —
	// --userns keep-id/auto/nomap -> io.podman.annotations.userns,
	// --security-opt seccomp=... -> io.podman.annotations.seccomp,
	// --security-opt apparmor=... -> io.podman.annotations.apparmor,
	// --cidfile -> io.podman.annotations.cid-file,
	// --pids-limit -> io.podman.annotations.pids-limit.
	// Podman honours run.oci.* annotations at the runtime (the same fact
	// refusalReason["Annotations"] states for docker-compat), so an
	// UNRECOGNISED key here is refused rather than forwarded — this session
	// measured five flags producing an annotation; `podman run` has roughly
	// 120, and any flag this session did not try that also writes one
	// refuses by name rather than silently.
	examined["annotations"] = true
	if raw, ok := req["annotations"]; ok && !isEmptyJSON(raw) {
		if err := judgeLibpodAnnotations(raw, usernsRawValue(req)); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// mounts: bind mounts share checkMountRequests with the docker-compat
	// path (create.go's checkedMounts calls the same function). tmpfs
	// mounts carry no host source — same reasoning as docker-compat's
	// Tmpfs field — and are forwarded unexamined. Any other type (volume,
	// image, devpts, ...) is refused: MEASURED, `--mount type=volume,...`
	// does NOT appear here at all, it lands in the separate `volumes` array
	// refused above, so this file has never observed a `mounts` entry typed
	// anything but "bind" or "tmpfs".
	examined["mounts"] = true
	if raw, ok := req["mounts"]; ok && !isEmptyJSON(raw) {
		out, err := judgeLibpodMounts(r.Context(), p, raw)
		if err != nil {
			p.deny(w, "%v", err)
			return
		}
		enc, _ := json.Marshal(out)
		req["mounts"] = enc
	}

	// labels: stamped with this run's ownership label the same way
	// create.go's stampRunLabel does for docker-compat — the ownership
	// gate (ownership.go) reads a container's Labels back through the
	// COMPAT inspect route regardless of which wire created it, so the
	// same key/value here is what makes a libpod-created container
	// recognisable as this run's.
	examined["labels"] = true
	if p.runLabel != "" {
		if err := stampLibpodRunLabel(req, p.runLabel); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// Everything else: a named-and-understood field is forwarded unread by
	// design (containerProcessChoice/ordinaryContainerBehaviour-class
	// metadata); anything else, empty is dropped and audited, non-empty
	// fails closed. This is toplevel.go/create.go's own inversion, run a
	// second time over podman's own field names.
	var dropped []string
	for _, k := range sortedKeysOf(req) {
		if examined[k] {
			continue
		}
		if libpodUnexaminedFields[strings.ToLower(k)] {
			continue
		}
		if isEmptyJSON(req[k]) {
			dropped = append(dropped, k)
			delete(req, k)
			continue
		}
		p.deny(w, "%s is not permitted. snug reads a named set of podman's own SpecGenerator "+
			"fields and refuses the rest, so a field it has not been taught about fails closed "+
			"rather than reaching the engine unexamined. If this one is harmless it belongs in "+
			"libpodUnexaminedFields with the abuse sentence for why", k)
		return
	}
	sort.Strings(dropped)

	out, err := json.Marshal(req)
	if err != nil {
		p.deny(w, "%v", err)
		return
	}
	audit := "libpod container create: accepted"
	if len(dropped) > 0 {
		audit += fmt.Sprintf("; dropped %d empty unmodelled field(s): %s", len(dropped), strings.Join(dropped, ", "))
	}
	p.audit(audit)
	p.forward(w, r, out)
}

// libpodNamespaceFields pairs a SpecGenerator field with the canonical judge
// key namespaceModeReason and judgeNamespaceMode already use for the
// docker-compat spelling — the six keys mean the same six facts regardless
// of which wire asked.
var libpodNamespaceFields = []struct{ field, canonical string }{
	{"netns", "NetworkMode"},
	{"pidns", "PidMode"},
	{"ipcns", "IpcMode"},
	{"utsns", "UTSMode"},
	{"userns", "UsernsMode"},
	{"cgroupns", "CgroupnsMode"},
}

// libpodRefusedFields pairs a SpecGenerator field with the canonical key
// whose refusalReason entry already states the abuse — the same fact, the
// docker-compat wire just spells the field differently.
//
// An ORDERED SLICE, not a map: a body carrying more than one refused field
// must refuse for the SAME one every time, the same reason sortedKeysOf
// exists elsewhere in this package — a map iterates in random order, so an
// identical request could refuse for a different field on a different run.
var libpodRefusedFields = []struct{ field, canonical string }{
	{"privileged", "Privileged"},
	{"cap_add", "CapAdd"},
	{"devices", "Devices"},
	{"device_cgroup_rule", "DeviceCgroupRules"},
	{"cgroup_parent", "CgroupParent"},
	{"sysctl", "Sysctls"},
	{"hostadd", "ExtraHosts"},
	{"portmappings", "PortBindings"},
}

// libpodFieldSpelling renders a canonical judge key in podman's own
// SpecGenerator spelling, for judgeNamespaceMode/judgeAskedField/
// judgeRestartPolicyName shared with create.go's docker-compat decoder.
var libpodFieldNames = map[string]string{
	"NetworkMode":       "netns.nsmode",
	"PidMode":           "pidns.nsmode",
	"IpcMode":           "ipcns.nsmode",
	"UTSMode":           "utsns.nsmode",
	"UsernsMode":        "userns.nsmode",
	"CgroupnsMode":      "cgroupns.nsmode",
	"Privileged":        "privileged",
	"CapAdd":            "cap_add",
	"Devices":           "devices",
	"DeviceCgroupRules": "device_cgroup_rule",
	"CgroupParent":      "cgroup_parent",
	"Sysctls":           "sysctl",
	"ExtraHosts":        "hostadd",
	"PortBindings":      "portmappings",
	"PublishAllPorts":   "publish_image_ports",
	"RestartPolicy":     "restart_policy",
	"Volumes":           "volumes",
	"Healthcheck":       "healthconfig",
}

func libpodFieldSpelling(canonical string) string {
	if s, ok := libpodFieldNames[canonical]; ok {
		return s
	}
	return canonical
}

// libpodUnexaminedFields is every SpecGenerator field forwarded to the
// engine without its value being looked at, mirroring
// unexaminedCreateFields/unexaminedTopLevelFields's own shape: a field snug
// does not judge cannot be silent about it. Reuses this package's existing
// abuse-sentence constants where the claim is the same one docker-compat
// already makes about the same engine.
var libpodUnexaminedFields = func() map[string]bool {
	names := []string{
		// process choice — command.Cmd/Entrypoint's own class
		"command", "entrypoint", "env", "hostname", "work_dir", "user", "name",
		"stdin", "terminal", "stop_timeout",
		// resolved/echoed by the engine, container-scoped
		"raw_image_name", "image_volume_mode",
		// resource limits — numbers, no path, no namespace. resource_limits
		// is NOT here: it is an object, and judgeLibpodResourceLimits reads it.
		"shm_size", "r_limits", "oom_score_adj",
		// ordinary container behaviour
		"remove", "volatile", "init", "init_container_type",
		"read_only_filesystem", "read_write_tmpfs", "umask", "cap_drop",
		// systemd/session metadata, container-scoped
		"systemd", "sdnotifyMode", "manage_password",
		"use_image_hostname", "use_image_hosts", "use_image_resolve_conf",
		"httpproxy",
		// pure echo of the client's own argv, kept for `podman inspect`
		"containerCreateCommand",
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[strings.ToLower(n)] = true
	}
	return m
}()

// decodeLibpodObject is decodeObject's ASCII/case-fold safety net, run
// without decodeObject's own canonicalKey substitution: that table is
// authored around docker-compat's PascalCase field names
// ("Privileged" -> "privileged"), and applying it here would silently
// rename a libpod key this file already spells correctly (podman's own
// "privileged" already folds to "privileged"; the two schemes only look
// alike because both are case-insensitive, not because they share names).
// Duplicated rather than shared with decodeObject on purpose — decodeObject
// is compat-specific tested code and this file changes its OWN wire only.
func decodeLibpodObject(raw []byte) (map[string]json.RawMessage, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]json.RawMessage, len(in))
	seen := make(map[string]string, len(in))
	for _, k := range keys {
		if !isASCII(k) {
			return nil, fmt.Errorf("key %q is not ASCII; podman's own JSON decoder folds "+
				"non-ASCII letters onto ASCII field names while snug's comparison does not, so "+
				"the two would disagree about which field this is", k)
		}
		fold := strings.ToLower(k)
		if prev, dup := seen[fold]; dup {
			return nil, fmt.Errorf("keys %q and %q differ only in case; podman would read one "+
				"of them and snug the other, so this request is refused rather than guessed at",
				prev, k)
		}
		seen[fold] = k
		out[k] = in[k]
	}
	return out, nil
}

// decodeLibpodNSMode decodes podman's {"nsmode":"...", "value":"..."} shape
// into the SAME nsSpec docker-compat's single-string spelling normalises to
// (createjudge.go's compatNSMode). Raw combines both fields so a refusal
// message quotes what the client actually sent, the way create.go's own
// namespace loop quotes the raw HostConfig string.
func decodeLibpodNSMode(raw json.RawMessage) (nsSpec, error) {
	var v struct {
		NsMode string `json:"nsmode"`
		Value  string `json:"value"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nsSpec{}, fmt.Errorf("is not the {\"nsmode\":...} object podman sends: %v", err)
	}
	mode := strings.ToLower(strings.TrimSpace(v.NsMode))
	// podman's own enum already uses "container" and "path" where
	// docker-compat spells "container:<id>" and "ns:<path>" as one string —
	// no prefix classification needed here, unlike compatNSMode.
	raw2 := v.NsMode
	if v.Value != "" {
		raw2 = v.NsMode + ":" + v.Value
	}
	return nsSpec{Mode: mode, Raw: raw2}, nil
}

// judgeLibpodNetworks refuses any per-network setting other than "asks for
// nothing", independent of netns.nsmode — see handleLibpodContainerCreate's
// own comment for the measurement that makes this its own check rather than
// folded into the namespace-mode judge.
func judgeLibpodNetworks(raw json.RawMessage) error {
	nets, err := decodeLibpodObject(raw)
	if err != nil {
		return fmt.Errorf("Networks: %v", err)
	}
	for _, name := range sortedKeysOf(nets) {
		if isEmptyJSON(nets[name]) {
			continue
		}
		settings, err := decodeLibpodObject(nets[name])
		if err != nil {
			return fmt.Errorf("Networks[%q]: %v", name, err)
		}
		for _, f := range sortedKeysOf(settings) {
			if isEmptyJSON(settings[f]) {
				continue
			}
			return fmt.Errorf("Networks[%q].%s is not permitted; it asks for %s. snug authors "+
				"this sandbox's network namespace and every container runs in it, so per-network "+
				"addressing, aliases and driver options are not the client's to choose — the "+
				"libpod spelling of the same refusal docker-compat's NetworkingConfig.EndpointsConfig "+
				"carries. An entry that asks for NOTHING is accepted, which is what a plain "+
				"`podman run` sends", name, f, string(settings[f]))
		}
	}
	return nil
}

// libpodResourceLimitFields is every OCI LinuxResources sub-object snug
// forwards inside `resource_limits`, and it is a NAMED SET for the same
// reason the top-level sweep is one: a sub-object this file has not read
// fails closed rather than reaching the engine inside a field whose abuse
// sentence (containerResourceLimit) promises "no value names a path or a
// device".
//
// MEASURED, podman 6.0.2, `podman create <flag> alpine true` posted to a
// socket that logs the body (VERIFY.md §22's method):
//
//	no flag              resource_limits absent (null)
//	--memory 100m        {"memory":{"limit":104857600,"swap":209715200}}
//	--oom-kill-disable   {"memory":{"disableOOMKiller":true}}
//	--cpus 1             {"cpu":{"quota":100000,"period":100000}}
//	--cpuset-cpus 0      {"cpu":{"cpus":"0"}}
//	--pids-limit 10      {"pids":{"limit":10}}
//	--blkio-weight 100   {"blockIO":{"weight":100}}
//	--cgroup-conf memory.high=1G  {"unified":{"memory.high":"1G"}}
//
// No flag writes `devices`, and the two DEVICE-naming flags write a TOP-LEVEL
// field rather than a nested one — `--blkio-weight-device /dev/null:100` and
// `--device-read-bps /dev/null:1mb` both leave `blockIO` as `{}` and set
// weightDevice / throttleReadBpsDevice keyed by the host path. A client
// posting raw JSON is not limited to the CLI's spelling, which is the whole
// reason this is judged rather than forwarded.
// `blockio` is not here: it has its own named set one level down.
var libpodResourceLimitFields = map[string]bool{
	"memory": true,
	"cpu":    true,
	"pids":   true,
}

// libpodBlockIOFields is the same named set one level further down. The four
// throttle arrays and the nested weightDevice identify a device by
// major:minor instead of by the path the top-level spelling uses, so
// blkioPathField's sentence does not fit them and they get their own.
var libpodBlockIOFields = map[string]bool{
	"weight":     true,
	"leafweight": true,
}

// judgeLibpodResourceLimits refuses the two sub-objects of the OCI
// LinuxResources shape that are the nested spelling of content refused at
// the top level, and refuses by name anything else it has not measured.
//
// `devices` is device_cgroup_rule's own content: refusing one spelling and
// forwarding the other is the divergence invariant 6 exists to prevent, and
// it is the "same danger, different spelling" shape issue #459 was about,
// one level down. `unified` is an open key/value channel into the cgroup
// filesystem — the catalogue that makes this file safe cannot bound a field
// whose keys are the kernel's, not podman's.
func judgeLibpodResourceLimits(raw json.RawMessage) error {
	lim, err := decodeLibpodObject(raw)
	if err != nil {
		return fmt.Errorf("resource_limits: %v", err)
	}
	for _, k := range sortedKeysOf(lim) {
		if isEmptyJSON(lim[k]) {
			continue
		}
		switch strings.ToLower(k) {
		case "devices":
			return fmt.Errorf("resource_limits.%s is not permitted: %s. It is %s's own "+
				"content one level down, and the two spellings refuse together", k,
				refusalReason["DeviceCgroupRules"], libpodFieldSpelling("DeviceCgroupRules"))
		case "unified":
			return fmt.Errorf("resource_limits.%s is not permitted: it writes arbitrary "+
				"cgroup-v2 controller keys, so its key space is the kernel's rather than "+
				"podman's and this file's catalogue cannot bound it. The numeric limits "+
				"beside it (memory, cpu, pids, blockIO.weight) are forwarded", k)
		case "blockio":
			if err := judgeLibpodBlockIO(k, lim[k]); err != nil {
				return err
			}
		default:
			if libpodResourceLimitFields[strings.ToLower(k)] {
				continue
			}
			return fmt.Errorf("resource_limits.%s is not permitted. snug reads a named set "+
				"of the OCI LinuxResources sub-objects and refuses the rest, so one it has "+
				"not been taught about fails closed rather than reaching the engine inside "+
				"a field documented as carrying numbers", k)
		}
	}
	return nil
}

// judgeLibpodBlockIO refuses every blockIO sub-field that identifies a
// device, leaving the two container-wide weights. The top-level weightDevice
// is already refused; this is the nested spelling, which no measured flag
// writes but a raw client can.
func judgeLibpodBlockIO(spelling string, raw json.RawMessage) error {
	bio, err := decodeLibpodObject(raw)
	if err != nil {
		return fmt.Errorf("resource_limits.%s: %v", spelling, err)
	}
	for _, k := range sortedKeysOf(bio) {
		if isEmptyJSON(bio[k]) || libpodBlockIOFields[strings.ToLower(k)] {
			continue
		}
		return fmt.Errorf("resource_limits.%s.%s is not permitted: it names a device by "+
			"major:minor, which is the nested spelling of the top-level %s this file "+
			"already refuses. Only the container-wide weight and leafWeight are forwarded",
			spelling, k, libpodFieldSpelling("weightDevice"))
	}
	return nil
}

// judgeLibpodHealthLogFields refuses healthLogDestination naming anything
// but podman's own default, independent of whether healthconfig itself was
// asked for — defence in depth against a future podman decoupling the two,
// the same way the userns annotation is decoupled from userns.nsmode today.
func judgeLibpodHealthLogFields(req map[string]json.RawMessage) error {
	if s := stringField(req, "healthLogDestination"); s != "" && s != "local" {
		return fmt.Errorf("healthLogDestination = %q is not permitted; only \"local\" is "+
			"(MEASURED default on every podman 6.0.2 create this session). A directory value "+
			"asks the engine to write health-check event logs to a host path", s)
	}
	if n, ok := intFieldOK(req, "healthMaxLogCount"); ok && n != 5 {
		return fmt.Errorf("healthMaxLogCount = %d is not permitted; only the default 5 is", n)
	}
	if n, ok := intFieldOK(req, "healthMaxLogSize"); ok && n != 500 {
		return fmt.Errorf("healthMaxLogSize = %d is not permitted; only the default 500 is", n)
	}
	return nil
}

// libpodAnnotationEcho is every io.podman.annotations.* key MEASURED to be
// written by an ordinary flag rather than authored freestanding by a client.
// A value of "" means "refuse unconditionally, using the named canonical
// reason" (the annotation mirrors a field already refused above, so this is
// defence in depth for a raw client that sets only the annotation); a
// non-empty value names the canonical field whose OWN judged value the
// annotation must match, so a raw client cannot set the annotation without
// the field agreeing.
var libpodAnnotationEcho = map[string]string{
	"io.podman.annotations.userns":     "UsernsMode",
	"io.podman.annotations.seccomp":    "",
	"io.podman.annotations.apparmor":   "",
	"io.podman.annotations.cid-file":   "",
	"io.podman.annotations.pids-limit": "*", // "*" = any value: a plain resource number
}

// judgeLibpodAnnotations refuses any annotation this file has not measured,
// and cross-checks the ones it has against the field they echo rather than
// trusting the annotation on its own — see handleLibpodContainerCreate's own
// comment for which five flags were measured to write one.
func judgeLibpodAnnotations(raw json.RawMessage, usernsRaw string) error {
	ann, err := decodeLibpodObject(raw)
	if err != nil {
		return fmt.Errorf("annotations: %v", err)
	}
	for _, k := range sortedKeysOf(ann) {
		if isEmptyJSON(ann[k]) {
			continue
		}
		fold := strings.ToLower(k)
		echoOf, known := libpodAnnotationEcho[fold]
		if !known {
			return fmt.Errorf("annotations[%q] is not permitted: podman honours run.oci.* "+
				"annotations at the runtime, the same fact refusalReason[\"Annotations\"] states "+
				"for docker-compat, and this key is not one this file has measured a flag write. "+
				"snug names what a container may touch", k)
		}
		switch echoOf {
		case "":
			return fmt.Errorf("annotations[%q] is not permitted: %s", k, refusalReason["SecurityOpt"])
		case "*":
			continue // pids-limit: a plain resource number, no path, no namespace
		default:
			var v string
			_ = json.Unmarshal(ann[k], &v)
			if v != usernsRaw {
				return fmt.Errorf("annotations[%q] = %q does not match the judged %s value %q; "+
					"a client setting this annotation independently of the field it echoes is "+
					"refused rather than trusted on its own", k, v, libpodFieldSpelling(echoOf), usernsRaw)
			}
		}
	}
	return nil
}

// usernsRawValue reads userns.nsmode's raw string straight from the
// request, for judgeLibpodAnnotations to cross-check the userns annotation
// against — called AFTER the namespace-mode loop already judged and
// accepted it, so any value reaching here already passed judgeNamespaceMode.
func usernsRawValue(req map[string]json.RawMessage) string {
	raw, ok := req["userns"]
	if !ok {
		return ""
	}
	spec, err := decodeLibpodNSMode(raw)
	if err != nil {
		return ""
	}
	return spec.Raw
}

// judgeLibpodMounts decodes podman's `mounts` array and runs every bind
// entry through checkMountRequests — the same function create.go's
// checkedMounts calls — passing tmpfs entries through untouched. Any other
// type refuses: MEASURED, `--mount type=volume,...` never appears in
// `mounts` at all (it is the separate `volumes` array, refused above).
func judgeLibpodMounts(ctx context.Context, p *Proxy, raw json.RawMessage) ([]libpodMount, error) {
	var ms []libpodMount
	if err := json.Unmarshal(raw, &ms); err != nil {
		return nil, fmt.Errorf("mounts is not a list of mounts: %v", err)
	}
	var out []libpodMount
	var binds []mount
	var bindIdx []int
	for i, m := range ms {
		switch m.Type {
		case "bind":
			// The forwarded Options are REBUILT from judgeBindOptions, never
			// copied from m: this array is the one place the libpod wire can
			// carry a mount flag compat's Binds parser refuses, and copying it
			// through is exactly how the two decoders disagreed (issue #459).
			ro, forward, oerr := judgeBindOptions(m.Options)
			if oerr != nil {
				return nil, oerr
			}
			m.Options = forward
			binds = append(binds, mount{Type: "bind", Source: m.Source, Target: m.Destination, ReadOnly: ro})
			bindIdx = append(bindIdx, i)
			out = append(out, m)
		case "tmpfs":
			// Options are forwarded UNREAD, unlike a bind's, and this is the
			// asymmetry a reader will otherwise take for an oversight. A
			// tmpfs entry carries no host source, so there is nothing for
			// checkMountRequests to judge, and the two options worth naming
			// reach nothing: `dev` needs a device node, and creating one in
			// a userns-owned mount is refused by the kernel to an
			// unprivileged user; `suid` on fresh RAM the container itself
			// writes yields a uid inside the container's OWN userns, which
			// the container's root already has. MEASURED, podman 6.0.2:
			// `--tmpfs /x` sends no options, `--tmpfs /x:rw,size=64m,exec`
			// sends ["rw","size=64m","exec"], `--mount
			// type=tmpfs,destination=/y,tmpfs-size=1m` sends ["size=1m"].
			// Same claim containerResourceLimit makes for the docker-compat
			// HostConfig.Tmpfs this matches — the two wires agree.
			out = append(out, m)
		default:
			return nil, fmt.Errorf("mount type %q is not permitted; only bind and tmpfs are "+
				"(a volume mount arrives in the separate `volumes` field, refused there)", m.Type)
		}
	}
	if len(binds) > 0 {
		checked, err := p.checkMountRequests(ctx, binds)
		if err != nil {
			return nil, err
		}
		for i, c := range checked {
			out[bindIdx[i]].Source = c.Source
			out[bindIdx[i]].Destination = c.Target
		}
	}
	return out, nil
}

// judgeLibpodVolumes decodes podman's `volumes` array — the one a `-v` or a
// `--mount type=volume` lands in — and runs every NAMED entry through
// checkMountRequests, the same function the bind path uses, so the two wires
// cannot disagree about what a volume name means (issue #464).
//
// MEASURED, podman 6.0.2, element by element:
//
//	-v NAMEDVOL:/data        {"Name":"NAMEDVOL","Dest":"/data","Options":null,"IsAnonymous":false,"SubPath":""}
//	--mount type=volume,...  {"Name":"NAMEDVOL","Dest":"/m","Options":null,"IsAnonymous":false,"SubPath":""}
//	-v NAMEDVOL:/ro:ro       {"Name":"NAMEDVOL","Dest":"/ro","Options":["ro"],...}
//	-v NAMEDVOL:/z:z         {"Name":"NAMEDVOL","Dest":"/z","Options":["z"],...}
//	-v /anon                 {"Name":"","Dest":"/anon","Options":null,"IsAnonymous":false,"SubPath":""}
//
// READ THE LAST LINE TWICE. An anonymous volume arrives with an EMPTY Name and
// `IsAnonymous: FALSE` — the engine fills both in later. So anonymity is
// detected by the empty name, and a check written on IsAnonymous would forward
// every anonymous volume while looking like it refused them.
func judgeLibpodVolumes(ctx context.Context, p *Proxy, raw json.RawMessage) ([]libpodVolume, error) {
	var vs []libpodVolume
	if err := json.Unmarshal(raw, &vs); err != nil {
		return nil, fmt.Errorf("volumes is not a list of volumes: %v", err)
	}
	var reqs []mount
	for i, v := range vs {
		if v.Name == "" {
			return nil, fmt.Errorf("%s is not permitted for an anonymous volume: %s",
				libpodFieldSpelling("volumes"), topLevelRefusalReason["Volumes"])
		}
		// SubPath names a directory INSIDE the volume, and a path is never
		// metadata (checkOne's rule). Measured empty on every capture; a
		// non-empty one is resolved by the engine inside a directory snug does
		// not walk, so it is refused rather than forwarded unread.
		if v.SubPath != "" {
			return nil, fmt.Errorf("volumes[%d].SubPath %q is not permitted: it is a path "+
				"resolved by the ENGINE inside the volume, and snug neither walks that "+
				"directory nor forwards a path it did not resolve. Mount the volume at its "+
				"root", i, v.SubPath)
		}
		// The forwarded Options are REBUILT from judgeBindOptions rather than
		// copied, for the reason judgeLibpodMounts rebuilds a bind's: this array
		// is where the libpod wire can carry a flag the compat parser refuses.
		ro, forward, err := judgeBindOptions(v.Options)
		if err != nil {
			return nil, err
		}
		vs[i].Options = forward
		reqs = append(reqs, mount{Type: "volume", Source: v.Name, Target: v.Dest, ReadOnly: ro})
	}
	if _, err := p.checkMountRequests(ctx, reqs); err != nil {
		return nil, err
	}
	return vs, nil
}

// libpodVolume is podman's own volumes[] element shape. Only the fields snug
// judges are modelled; re-serialising through this struct is what stops an
// unmodelled sibling reaching the engine, the same reason `mount` is four
// fields and no more.
type libpodVolume struct {
	Name    string   `json:"Name"`
	Dest    string   `json:"Dest"`
	Options []string `json:"Options,omitempty"`
	SubPath string   `json:"SubPath,omitempty"`
}

// libpodMount is podman's own mounts[] element shape — snake_case, and
// Destination/Options where docker-compat's HostConfig.Mounts spells
// Target/ReadOnly. Kept separate from the `mount` type create.go re-encodes
// Binds/Mounts into, rather than reusing it directly, because forwarding
// THIS wire's own field names is what a libpod client expects back.
type libpodMount struct {
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Options     []string `json:"options,omitempty"`
}

// stampLibpodRunLabel is stampRunLabel's libpod twin: the same merge
// semantics (client labels kept, snug's own key wins), reading and writing
// `labels` (a flat map[string]string) rather than compat's nested
// req["Labels"].
func stampLibpodRunLabel(req map[string]json.RawMessage, runLabel string) error {
	key, value, ok := strings.Cut(runLabel, "=")
	if !ok {
		return fmt.Errorf("internal: run label %q is not key=value", runLabel)
	}
	labels := map[string]string{}
	if raw, ok := req["labels"]; ok && !isEmptyJSON(raw) {
		if err := json.Unmarshal(raw, &labels); err != nil {
			return fmt.Errorf("labels is not a map of strings")
		}
	}
	labels[key] = value
	enc, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	req["labels"] = enc
	return nil
}

func boolField(req map[string]json.RawMessage, key string) bool {
	raw, ok := req[key]
	if !ok {
		return false
	}
	var v bool
	_ = json.Unmarshal(raw, &v)
	return v
}

func stringField(req map[string]json.RawMessage, key string) string {
	raw, ok := req[key]
	if !ok {
		return ""
	}
	var v string
	_ = json.Unmarshal(raw, &v)
	return v
}

func intField(req map[string]json.RawMessage, key string) int {
	n, _ := intFieldOK(req, key)
	return n
}

func intFieldOK(req map[string]json.RawMessage, key string) (int, bool) {
	raw, ok := req[key]
	if !ok {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, false
	}
	return int(f), true
}
