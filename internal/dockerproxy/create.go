package dockerproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"snug/internal/policy"
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
		if v, ok := hc[k]; ok && !isEmptyJSON(v) {
			p.deny(w, "HostConfig.%s is not permitted: %s", k, refusalReason[k])
			return
		}
	}

	// 2. Namespace modes must not join the host's or another container's.
	for _, k := range namespaceModeKeys {
		var mode string
		if v, ok := hc[k]; ok {
			_ = json.Unmarshal(v, &mode)
		}
		if mode == "" {
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
	delete(hc, "Tmpfs")
	if len(mounts) > 0 {
		enc, _ := json.Marshal(mounts)
		hc["Mounts"] = enc
	}

	// 4. Inject the hardening the sandbox cannot rely on the client to set.
	hc["Privileged"] = json.RawMessage(`false`)
	hc["SecurityOpt"] = json.RawMessage(`["no-new-privileges:true"]`)

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
func (p *Proxy) hostPathVisible(host string, needWrite bool) bool {
	host = filepath.Clean(host)
	for _, m := range p.pol.Mounts {
		if m.Kind != policy.KindBind {
			continue
		}
		if host != m.Host && !strings.HasPrefix(host, m.Host+"/") {
			continue
		}
		if needWrite && m.Access != policy.AccessRW {
			continue
		}
		return true
	}
	return false
}
