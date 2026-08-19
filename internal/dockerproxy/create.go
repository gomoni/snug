package dockerproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
)

// maxBody bounds a request body read from the sandbox. Unbounded, it is a
// memory-exhaustion primitive aimed at snug itself.
const maxBody = 4 << 20

// handleCreate is the security core of this package.
//
// Strategy, and the deviation from the original design worth naming: the design
// specified strict decoding of the WHOLE create request into pinned types, so
// any unmodelled field is a 403. In practice that rejects most real invocations,
// because clients send a large and moving set of benign fields. So the strictness
// is applied where the danger is — HostConfig — and the rest of the body is
// passed through as opaque JSON.
//
// That is a real, stated weakening: a NEW dangerous field added to podman's
// top-level create body would pass. It is bounded by the fact that essentially
// every escape primitive lives in HostConfig, and by the denylist below being
// checked against the raw JSON rather than a struct, so a field does not have to
// be modelled to be refused.
func (p *Proxy) handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		p.deny(w, "reading request: %v", err)
		return
	}

	req, err := decodeObject(body)
	if err != nil {
		p.deny(w, "create body: %v", err)
		return
	}

	// Anonymous volumes named in the top-level Config. A volume is a host path
	// by another name.
	if v, ok := req["Volumes"]; ok && !isEmptyJSON(v) {
		p.deny(w, "Volumes is not permitted; snug decides what a container may mount")
		return
	}

	hc := map[string]json.RawMessage{}
	if raw, ok := req["HostConfig"]; ok && !isEmptyJSON(raw) {
		hc, err = decodeObject(raw)
		if err != nil {
			p.deny(w, "HostConfig: %v", err)
			return
		}
	}

	// 1. Refuse outright. Each of these is either a direct escape or a way to
	//    reach something the sandbox itself cannot.
	for _, k := range refusedHostConfig {
		v, ok := hc[k]
		if !ok || isEmptyJSON(v) {
			continue
		}
		// LogConfig is refused for its `path` option, not for existing: the
		// docker CLI sends {"Type":"","Config":{}} on EVERY create, which is the
		// driver default and asks for nothing. isEmptyJSON does not see that
		// object as empty, so the denylist refused every `docker run` there has
		// ever been through this proxy — the profile's whole purpose, failing
		// with a message about log drivers.
		if k == "LogConfig" && isDefaultLogConfig(v) {
			delete(hc, k)
			continue
		}
		p.deny(w, "HostConfig.%s is not permitted: %s", k, refusalReason[k])
		return
	}

	// 2. Namespace modes must not join the host's or another container's.
	//
	// NetworkMode="host" is the ONE exception, and it inverts what it meant
	// before issue #63 Tier B: the container engine itself now runs INSIDE
	// this sandbox's own network namespace N (setns'd there by the stage,
	// internal/stage's EnterEngine) rather than on the real host's — so
	// "join the engine's current netns", which is exactly what podman's
	// `--network=host` / HostConfig.NetworkMode="host" means, now joins N,
	// not the host's. That is the "share N host-mode" design the maintainer
	// settled (TIER-B-POLICY.md, the NET_ADMIN decision): no per-container
	// bridge, no `-p` publishing (the engine holds no CAP_NET_ADMIN to set
	// one up even if asked), a container reaches exactly what the sandbox
	// reaches. Every OTHER namespace mode stays refused unconditionally,
	// PidMode="host" above all: __inengine does NOT unshare pid, so the
	// engine's own pid namespace IS the real host's, and letting a container
	// join it would be a genuine escape that Tier B does nothing to close.
	for _, k := range namespaceModeKeys {
		var mode string
		if v, ok := hc[k]; ok {
			_ = json.Unmarshal(v, &mode)
		}
		if mode == "" {
			continue
		}
		if k == "NetworkMode" && mode == "host" {
			continue
		}
		if mode == "host" || strings.HasPrefix(mode, "container:") || strings.HasPrefix(mode, "ns:") {
			p.deny(w, "HostConfig.%s = %q would join a namespace outside this sandbox", k, mode)
			return
		}
	}

	// 3. Every requested mount must name a host path the SANDBOX can already
	//    see, at the access it asks for. This is the rule in the package
	//    comment, and it is checked rather than assumed.
	//
	//    Silently STRIPPING what the client asked for was the first
	//    implementation and it was wrong in a way worth recording: a request to
	//    bind /etc was dropped and forwarded, so the container started happily
	//    without it. A user whose legitimate -v vanishes has no way to tell that
	//    from a bug. Refusing names the path and the reason.
	mounts, err := p.checkedMounts(hc)
	if err != nil {
		p.deny(w, "%v", err)
		return
	}
	delete(hc, "Binds")
	delete(hc, "Mounts")
	if len(mounts) > 0 {
		enc, _ := json.Marshal(mounts)
		hc["Mounts"] = enc
	}

	// HostConfig.Tmpfs is FORWARDED, and used to be deleted here — silently,
	// two comments below the paragraph saying nothing is silently dropped.
	//
	// ABUSE: a hostile process inside the sandbox can use this to allocate host
	// RAM as a container tmpfs, and to give itself an exec/suid filesystem
	// inside its own container.
	//
	// Neither reaches a host resource, which is why it is forwarded rather than
	// refused: a tmpfs has no source, so the mount rule in the package comment
	// has nothing to check — there is no host path to be visible or not. The RAM
	// is the same RAM any process in the container could allocate anyway, and it
	// is the tmpfs-sizing gap snug already has on its own mounts (TODO R8), not
	// a new one. `docker run --tmpfs /run` is ordinary and worked nowhere.

	// 4. Inject the hardening the sandbox cannot rely on the client to set.
	hc["Privileged"] = json.RawMessage(`false`)
	hc["SecurityOpt"] = json.RawMessage(`["no-new-privileges:true"]`)

	// And stamp this run's label, which is what lets teardown stop the
	// containers THIS sandbox started and no others. The engine store is shared
	// with any concurrent sandbox that resolved to the same key — deliberately,
	// so a warm start is warm — so without the label `stop --all` was collateral
	// damage on a sibling that was still working.
	//
	// MERGED into whatever labels the client sent, and merged by REPLACING our
	// own key only: a client that sets its own labels keeps them, and a client
	// that tries to set ours loses, because teardown correctness is not the
	// sandbox's to negotiate.
	if p.runLabel != "" {
		if err := stampRunLabel(req, p.runLabel); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// 5. Re-encode from our own map. This is a second, independent drift guard:
	//    only what survived the checks above reaches the engine.
	encHC, err := json.Marshal(hc)
	if err != nil {
		p.deny(w, "%v", err)
		return
	}
	req["HostConfig"] = encHC

	out, err := json.Marshal(req)
	if err != nil {
		p.deny(w, "%v", err)
		return
	}
	p.audit(fmt.Sprintf("container create: %d mount(s) allowed", len(mounts)))
	p.forward(w, r, out)
}

// namespaceModeKeys are the HostConfig fields that can join a namespace outside
// this sandbox. Named rather than inline so canonicalKey covers them too.
var namespaceModeKeys = []string{
	"NetworkMode", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode",
}

var refusedHostConfig = []string{
	"Privileged", "CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules",
	"SecurityOpt", "Runtime", "VolumesFrom", "VolumeDriver",
	"Sysctls", "DNS", "DNSSearch", "DNSOptions", "ExtraHosts",
	"MaskedPaths", "ReadonlyPaths", "Annotations",
	"PortBindings", "PublishAllPorts",
	"LogConfig", "StorageOpt", "CgroupParent", "Isolation",
}

var refusalReason = map[string]string{
	"Privileged":        "it disables essentially every container protection at once",
	"CapAdd":            "added capabilities apply to the host kernel, not to the sandbox",
	"Devices":           "device passthrough reaches hardware the sandbox cannot see",
	"DeviceRequests":    "device passthrough reaches hardware the sandbox cannot see",
	"DeviceCgroupRules": "device passthrough reaches hardware the sandbox cannot see",
	"SecurityOpt":       "snug sets this itself; a client value could undo no-new-privileges or seccomp",
	"Runtime":           "an alternate OCI runtime is an arbitrary host binary",
	"VolumesFrom":       "it inherits another container's mounts, which snug never approved",
	"VolumeDriver":      "a non-local driver can name a host path or a remote share",
	"Sysctls":           "kernel tunables are not namespaced the way you would hope",
	"DNS":               "resolver redirection",
	"DNSSearch":         "resolver redirection",
	"DNSOptions":        "resolver redirection",
	"ExtraHosts":        "name redirection",
	"MaskedPaths":       "it edits the container's own /proc protections",
	"ReadonlyPaths":     "it edits the container's own /proc protections",
	"Annotations":       "podman honours run.oci.* annotations, which reach the runtime",
	"PortBindings": "published ports land on the engine's side of the world, where " +
		"the sandbox cannot reach them, and create a host-visible surface nobody asked for",
	"PublishAllPorts": "published ports land where the sandbox cannot reach them",
	"LogConfig": "podman's k8s-file/json-file drivers honour a `path` option, and conmon " +
		"then writes that file ON THE HOST as your uid — an arbitrary host-file write, " +
		"needing no privileges. The redteam agent used it to create a file in a $HOME " +
		"the sandbox sees only as an empty tmpfs",
	"StorageOpt":   "storage driver options reach the host's storage layer",
	"CgroupParent": "it places the container in a cgroup outside this sandbox's own",
	"Isolation":    "an isolation mode is a runtime selector by another name",
}

// checkedMounts validates every mount the client asked for against what the
// sandbox itself can see, and returns the set to send to the engine.
//
// Nothing is invented and nothing is silently dropped: a request either names
// paths the sandbox already has, or it is refused with the offending path in the
// message.
func (p *Proxy) checkedMounts(hc map[string]json.RawMessage) ([]mount, error) {
	var out []mount

	// Legacy "src:dst[:opts]" strings.
	if raw, ok := hc["Binds"]; ok && !isEmptyJSON(raw) {
		var binds []string
		if err := json.Unmarshal(raw, &binds); err != nil {
			return nil, fmt.Errorf("HostConfig.Binds is not a list of strings")
		}
		for _, b := range binds {
			parts := strings.Split(b, ":")
			if len(parts) < 2 || len(parts) > 3 {
				return nil, fmt.Errorf("bind %q is not src:dst[:opts]", b)
			}
			ro := false
			if len(parts) == 3 {
				for _, o := range strings.Split(parts[2], ",") {
					switch o {
					case "ro":
						ro = true
					case "rw", "z", "Z", "":
					default:
						// Option smuggling is a real class: propagation modes
						// like rshared reach back out of the container.
						return nil, fmt.Errorf("bind option %q is not permitted", o)
					}
				}
			}
			m, err := p.checkOne(parts[0], parts[1], ro)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
	}

	// The structured form.
	if raw, ok := hc["Mounts"]; ok && !isEmptyJSON(raw) {
		var ms []mount
		if err := json.Unmarshal(raw, &ms); err != nil {
			return nil, fmt.Errorf("HostConfig.Mounts is not a list of mounts")
		}
		for _, m := range ms {
			if m.Type != "bind" {
				// A volume's backing store is not knowable here, and tmpfs is
				// harmless but unnecessary; neither is worth the surface.
				return nil, fmt.Errorf("mount type %q is not permitted; only bind is", m.Type)
			}
			c, err := p.checkOne(m.Source, m.Target, m.ReadOnly)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}

func (p *Proxy) checkOne(source, dest string, ro bool) (mount, error) {
	if !filepath.IsAbs(source) {
		return mount{}, fmt.Errorf("mount source %q must be an absolute path", source)
	}

	// Resolve symlinks BEFORE deciding, and forward the resolved path.
	//
	// Checking the literal string was a real hole: the sandbox's writable target
	// is attacker-controlled, so `ln -s ~/.ssh $TARGET/link` produced a source
	// that passed the visibility check while podman resolved it on the host to
	// ~/.ssh. Found by the redteam agent. A residual TOCTOU remains — the link
	// can be swapped between here and podman's own resolution — which is why the
	// RESOLVED path is what gets forwarded, so podman is asked for the thing we
	// actually approved.
	real, err := resolveExisting(source)
	if err != nil {
		return mount{}, fmt.Errorf("mount source %q cannot be resolved: %v", source, err)
	}
	if real != filepath.Clean(source) {
		p.audit(fmt.Sprintf("mount source %s resolves to %s; judging the resolved path", source, real))
	}
	source = real

	if !p.hostPathVisible(source, !ro) {
		access := "read-only"
		if !ro {
			access = "writable"
		}
		return mount{}, fmt.Errorf("this sandbox cannot see %s as %s, so a container may not "+
			"mount it either. Grant it to the sandbox first, or mount a path inside %s",
			source, access, p.pol.Target)
	}
	return mount{Type: "bind", Source: filepath.Clean(source), Target: dest, ReadOnly: ro}, nil
}

type mount struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly,omitempty"`
}

// handleExecCreate refuses a privileged exec.
//
// Found by the redteam agent right after the hijack fix: `containers/{id}/exec`
// matched the allowlist and was forwarded unexamined, so a client refused
// `Privileged` at create time could simply ask for it again on the way in —
// {"Privileged":true,"Cmd":["id"]} reached the engine verbatim.
//
// Severity is genuinely low and worth stating so nobody reads this as a
// second escape: the exec body carries no mount, device or namespace fields, so
// it reaches no host resource the container did not already have, and the
// engine is rootless — "privileged" here means capabilities inside a user
// namespace snug already owns. What it does buy is kernel attack surface and a
// seccomp profile dropped for that process, and it left create-time and
// exec-time posture disagreeing about the same word. Cheaper to close than to
// explain.
//
// Everything else about an exec stays forwarded: the container is the sandbox's
// own, created under this policy, so a shell in it grants nothing that running
// it did not.
func (p *Proxy) handleExecCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		p.deny(w, "reading request: %v", err)
		return
	}
	req, err := decodeObject(body)
	if err != nil {
		p.deny(w, "exec create body: %v", err)
		return
	}
	if v, ok := req["Privileged"]; ok && !isEmptyJSON(v) {
		p.deny(w, "exec Privileged is not permitted: %s. It is refused at container "+
			"create, and an exec must not be the way back in", refusalReason["Privileged"])
		return
	}
	p.forward(w, r, body)
}

// handleVolumeCreate permits only a plain local volume with no driver options.
//
// That single rule kills `type=none,o=bind,device=/host`, `device=/dev/*`, and
// NFS/CIFS `o=addr=` remotes at their source — the separate call that plants a
// host path under a volume name, to be referenced innocently later.
func (p *Proxy) handleVolumeCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		p.deny(w, "reading request: %v", err)
		return
	}
	req, err := decodeObject(body)
	if err != nil {
		p.deny(w, "volume create body: %v", err)
		return
	}

	var driver string
	if v, ok := req["Driver"]; ok {
		_ = json.Unmarshal(v, &driver)
	}
	if driver != "" && driver != "local" {
		p.deny(w, "volume driver %q is not permitted; only the local driver is", driver)
		return
	}
	for _, k := range []string{"Options", "DriverOpts", "ClusterVolumeSpec"} {
		if v, ok := req[k]; ok && !isEmptyJSON(v) {
			p.deny(w, "volume %s is not permitted: a local-driver option can name a host path "+
				"(type=none,o=bind,device=/) or a remote share", k)
			return
		}
	}
	p.forward(w, r, body)
}

// decodeObject decodes a JSON object into a map whose keys are spelled the way
// the checks below expect, and refuses any object that spells one key two ways.
//
// Both halves close the same escape, and it exists because Go's decoder and a
// Go map disagree about what a key IS. encoding/json matches struct fields
// CASE-INSENSITIVELY, so podman reads {"privileged":true} as Privileged — while
// a map[string]json.RawMessage does not, so every exact-key lookup here missed
// it. json.Marshal then sorts map keys, and "Privileged" sorts before
// "privileged", so snug's injected `"Privileged":false` was emitted FIRST and
// the attacker's variant, arriving last, won the decode. Verified reaching the
// engine: {"hostconfig":{"privileged":true,"binds":["/:/host"]}} started a
// privileged container with the host root bound, with snug's own
// `"Privileged":false` sitting harmlessly beside it. Found by mutation-testing
// the committed suite (M4 review).
//
// Canonicalising cannot change what podman does with the request, precisely
// BECAUSE podman is case-insensitive: `binds` and `Binds` are the same field to
// it. What changes is that snug now sees the same field podman will.
//
// Rejecting a case-fold collision outright, rather than picking a winner, is
// the deliberate part. Go's map decode is last-wins over an order the JSON text
// chose, so any rule for which spelling to keep is a rule about text order —
// and getting it wrong is silent. There is no legitimate reason for one object
// to carry both spellings.
//
// NON-ASCII KEYS ARE REFUSED, and that line is the load-bearing one.
//
// The first version of this function folded with strings.ToLower and its
// comment asserted that snug's fold and podman's were the same. They are not:
// encoding/json folds with EqualFold semantics, which additionally unify LONG S
// (U+017F) with `s` — and `strings.ToLower("Bindſ")` is `"bindſ"`, because ſ is
// ALREADY lowercase. So `{"HostConfig":{"Bindſ":["/:/host"]}}` missed the
// canonical lookup AND the collision check, was re-marshalled verbatim, and
// podman folded it back to Binds and bind-mounted host `/` into the container —
// which the engine, running as the host uid outside bwrap, was happy to do.
// checkedMounts never saw a mount at all. Found by the redteam agent within an
// hour of the ASCII fix landing; reproduced against the proxy with the bytes.
// (Kelvin sign U+212A is not a bypass — ToLower does fold it to `k`. Long s was
// the one divergent rune, which is exactly why a rule aimed at one rune would
// have been the wrong fix.)
//
// Refusing non-ASCII is what makes the two folds provably equal rather than
// approximately equal: over ASCII, ToLower-equality and EqualFold agree by
// definition. Every key in the docker-compat create schema and in HostConfig is
// ASCII; non-ASCII text that legitimately appears in a create body (label keys,
// env values) lives inside RawMessages this function never walks. So the cost
// is nil and the class — not the rune — is closed.
func decodeObject(raw []byte) (map[string]json.RawMessage, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("not a JSON object")
	}

	// Sorted so a collision is reported the same way every time; map order is
	// random and an error message that changes run to run is one nobody trusts.
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(map[string]json.RawMessage, len(in))
	seen := make(map[string]string, len(in))
	for _, k := range keys {
		if !isASCII(k) {
			return nil, fmt.Errorf("key %q is not ASCII; podman folds non-ASCII letters onto "+
				"ASCII field names (long s is the letter s) while snug's own comparison does "+
				"not, so the two would disagree about which field this is", k)
		}
		fold := strings.ToLower(k)
		if prev, dup := seen[fold]; dup {
			return nil, fmt.Errorf("keys %q and %q differ only in case; podman would read one "+
				"of them and snug the other, so this request is refused rather than guessed at",
				prev, k)
		}
		seen[fold] = k
		name := k
		if c, ok := canonicalKey[fold]; ok {
			name = c
		}
		out[name] = in[k]
	}
	return out, nil
}

// stampRunLabel merges snug's own container label into the create body's
// top-level Labels, replacing any value the client set for that key.
//
// Client labels are kept: they are container metadata, they reach nothing, and
// dropping them would be the silent-strip mistake this file already learned
// once. Only snug's key is authoritative, because teardown correctness is not
// the sandbox's to negotiate — a container that lies about which run owns it
// would either survive its own sandbox or be stopped by a sibling's.
//
// Labels is a map[string]string in the docker-compat schema; anything else is a
// request podman would reject anyway, and it is refused here rather than
// silently reshaped.
func stampRunLabel(req map[string]json.RawMessage, runLabel string) error {
	key, value, ok := strings.Cut(runLabel, "=")
	if !ok {
		return fmt.Errorf("internal: run label %q is not key=value", runLabel)
	}

	labels := map[string]string{}
	if raw, ok := req["Labels"]; ok && !isEmptyJSON(raw) {
		if err := json.Unmarshal(raw, &labels); err != nil {
			return fmt.Errorf("Labels is not a map of strings")
		}
	}
	labels[key] = value

	enc, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	req["Labels"] = enc
	return nil
}

// isDefaultLogConfig reports whether a LogConfig asks for nothing at all.
//
// The hazard in LogConfig is entirely in its two fields: a `Type` selects a
// driver, and `Config` carries the k8s-file/json-file `path` option that makes
// conmon write a file ON THE HOST as your uid. {"Type":"","Config":{}} selects
// no driver and sets no option — it is what the docker CLI sends on every
// create, and refusing it refuses everything.
//
// Decoded into a pinned struct rather than pattern-matched on the raw bytes,
// so key order, whitespace and a case variant of either field name all reach
// the same verdict. (decodeObject has already refused non-ASCII keys and
// case-fold collisions by the time this runs, so this decode sees what podman
// will see.)
func isDefaultLogConfig(raw json.RawMessage) bool {
	var lc struct {
		Type   string          `json:"Type"`
		Config json.RawMessage `json:"Config"`
	}
	if err := json.Unmarshal(raw, &lc); err != nil {
		return false // not the shape we understand; let the refusal stand
	}
	return lc.Type == "" && isEmptyJSON(lc.Config)
}

// isASCII reports whether every byte is below 0x80. Checked on the raw string
// rather than by decoding runes: a key is a JSON string and the question is
// only whether anything outside ASCII is present at all.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// canonicalKey maps a case-folded key to the spelling the code below tests
// against. Only keys snug DECIDES on need to be here — an unrecognised key is
// passed through untouched, and the collision check above covers it either way.
//
// Keeping it derived from the same lists the checks use is what stops it from
// drifting: a new entry in refusedHostConfig is canonicalised automatically,
// and TestEveryCheckedKeyIsCanonicalised fails if a hand-written one is missed.
var canonicalKey = func() map[string]string {
	m := map[string]string{}
	add := func(names ...string) {
		for _, n := range names {
			m[strings.ToLower(n)] = n
		}
	}
	add(refusedHostConfig...)
	add(namespaceModeKeys...)
	add("HostConfig", "Volumes")                                // top-level create
	add("Binds", "Mounts", "Tmpfs")                             // what checkedMounts consumes
	add("Driver", "Options", "DriverOpts", "ClusterVolumeSpec") // volume create
	return m
}()

func isEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "", "null", "{}", "[]", "false", `""`, "0":
		return true
	}
	return false
}

// resolveExisting canonicalises as much of a path as exists, then rejoins the
// remainder lexically.
//
// Plain EvalSymlinks fails outright on a path that is not there yet, and
// `-v ./build:/out` where ./build does not exist is an ordinary thing to write —
// the engine creates it. Resolving the longest existing prefix keeps that
// working while still defeating a symlink planted anywhere along the part that
// DOES exist, which is the whole point.
func resolveExisting(p string) (string, error) {
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("no existing ancestor")
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// hostPathVisible reports whether the sandbox can itself see a host path at the
// given access — the rule the package comment states. Kept here (unused by the
// current replace-everything strategy) because any future opt-in submount mode
// must use exactly this and nothing else.
//
// A one-line call to policy.HostPathVisible rather than its own walk (issue
// #55): that predicate is now also G4's graft-source check, and invariant 6
// says one author of "can the sandbox see this host path", not two
// implementations that eventually disagree.
// TestContainerBindFilterMatchesPolicyVisibility exercises it through here
// unchanged.
func (p *Proxy) hostPathVisible(host string, needWrite bool) bool {
	return p.pol.HostPathVisible(host, needWrite)
}
