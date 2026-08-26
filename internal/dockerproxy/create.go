package dockerproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// maxBody bounds a request body read from the sandbox. Unbounded, it is a
// memory-exhaustion primitive aimed at snug itself.
const maxBody = 4 << 20

// handleCreate is the security core of this package.
//
// Strategy: every key of the create body is either judged, allowlisted with an
// abuse sentence, or refused — at BOTH levels. The top level is inverted by
// step 1 below and HostConfig by step 5, and the two use the same machinery for
// the same reason.
//
// THE SENTENCE THIS COMMENT USED TO CARRY, because the shape it conceded is the
// one issues #375 and #397 closed and a later reader needs to know it was
// deliberate before it was fixed: *"the strictness is applied where the danger
// is — HostConfig — and the rest of the body is passed through as opaque JSON …
// That is a real, stated weakening: a NEW dangerous field added to podman's
// top-level create body would pass."* It was bounded by the claim that
// "essentially every escape primitive lives in HostConfig".
//
// That claim was measured wrong by ONE field, which is the useful part. Of 18
// top-level keys in a recorded real-client body, 6 were non-empty and only two —
// Volumes and HostConfig — were judged; `Healthcheck` was among the unjudged,
// and a healthcheck asks the ENGINE to run
//
//	systemd-run --user --unit <cid> --on-unit-inactive=<interval> <podman> healthcheck run <cid>
//
// — a transient unit AND TIMER on the host user's session manager, as the host
// uid, able to outlive the run. That is invariant 4 ("no process the user did
// not start and no state that survives them") reached from the object nobody
// was reading, and it is why "the danger lives in HostConfig" is not a boundary
// anybody should have been resting on.
//
// Read topLevelRefusalReason["Healthcheck"] before touching that refusal: it is
// on the OBJECT and not on the interval, and it says why with the measurement.
// "A non-zero Interval schedules the timer" is the intuitive reading and it is
// FALSE — absent, zero and negative all record podman's own 30s default — so a
// gate on Interval would admit the unsafe case and refuse the opt-out. This
// comment carried that wrong sentence itself until the measurement came back.
//
// The scope this inversion has to cover is BOUNDED, which is what makes it
// shippable where the original design was not: ServeHTTP refuses every
// state-changing libpod-native request outright (see normaliseFull and
// libpodExamined), so handleCreate only ever sees the docker-compat schema —
// docker's container.Config plus HostConfig plus NetworkingConfig rather than
// podman's open-ended SpecGenerator. Bounded, NOT closed — podman's compat
// handler takes three top-level keys docker does not define, and toplevel.go's
// own header says which and why the inversion is unharmed by them.
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

	// 1. THE TOP-LEVEL INVERSION (issues #375, #397). Judged, allowlisted, or
	//    refused — the same three verdicts step 5 applies to HostConfig, one
	//    level up, so a sibling of HostConfig cannot reach the engine on the
	//    strength of nobody having looked at it.
	//
	//    Ordered BEFORE the HostConfig work deliberately: the body is judged
	//    outside in, so a refusal names the outermost thing that is wrong. The
	//    only key this ordering matters for is HostConfig itself, which is
	//    `judged` here and decided below.
	droppedTop, err := p.checkTopLevel(req)
	if err != nil {
		p.deny(w, "%v", err)
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

	// 2. Refuse outright. Each of these is either a direct escape or a way to
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

	// 3. Namespace modes must not join the host's or another container's.
	//
	// NetworkMode="host" is the ONE exception, and it inverts what it meant
	// before issue #63 Tier B: the container engine itself now runs INSIDE
	// this sandbox's own network namespace N (setns'd there by the stage,
	// internal/stage's EnterEngine) rather than on the real host's — so
	// "join the engine's current netns", which is exactly what podman's
	// `--network=host` / HostConfig.NetworkMode="host" means, now joins N,
	// not the host's. That is the "share N host-mode" design the maintainer
	// settled (the NET_ADMIN decision, 2026-08-18 —
	// policy.EngineCapBounding's own comment): no per-container
	// bridge, no `-p` publishing (the engine holds no CAP_NET_ADMIN to set
	// one up even if asked), a container reaches exactly what the sandbox
	// reaches. Every OTHER namespace mode stays refused unconditionally.
	//
	// The RULE that inversion follows, stated once here because it decides
	// every mode below rather than just NetworkMode (issue #145): an
	// inversion is safe only when the namespace's membership set is a SUBSET
	// of what the sandbox already has. N contains the sandbox's own network
	// and nothing else, so "join the engine's netns" is idempotent with
	// respect to authority. A pid namespace fails that test even after issue
	// #125's C0 gave the engine one of its own (CLONE_NEWPID at
	// internal/stage/enginefork.go's clone, plus a fresh procfs): pid
	// namespace membership is not "seeing more pids", it is the only kind of
	// membership that is a HANDLE to every other namespace a member holds.
	// procfs dereferences a name into the member's mount namespace
	// (/proc/<pid>/root, /proc/<pid>/cwd), its open file descriptions
	// (/proc/<pid>/fd/N, including a detached open_tree mount fd — issue #55,
	// read AND write), its setns handles (/proc/<pid>/ns/*), and its
	// environment and command line — none of it syscall-shaped, so no
	// seccomp filter can name it (issue #47). The engine's pid namespace
	// contains the engine itself — pid 1, root-in-U, policy.EngineCapBounding,
	// the full delegated subuid range, and a mount namespace that is a
	// private COPY of the entire host tree — so joining it is not a subset of
	// the sandbox's authority, it is a superset: PidMode="host" would mean a
	// container reading and writing that copy through /proc/1/root/..., at
	// the host user's uid, with CAP_DAC_OVERRIDE in U, bypassing the proxy's
	// bind filter entirely — the exact thing the bind filter exists to stop,
	// reached by a different noun. MEASURED (issue #145): a container placed
	// in a sibling container's pid namespace read the sibling's whole
	// filesystem through /proc/<pid>/root and listed its open file
	// descriptions through /proc/<pid>/fd, at plain uid, no capability and no
	// ptrace — exactly the shape PidMode="host" would reproduce against the
	// engine. This refusal does not lapse as the engine's own namespaces grow
	// more isolated; it gets stronger, because the thing behind pid 1 keeps
	// being something with more to lose. See namespaceModeReason below for
	// the reason handed to each key.
	for _, k := range namespaceModeKeys {
		var mode string
		if v, ok := hc[k]; ok {
			_ = json.Unmarshal(v, &mode)
		}
		if mode == "" {
			// An UNSET or empty mode is not a request, and since issue #401 that is
			// load-bearing rather than incidental: snug pins `netns = "host"` in the
			// generated containers.conf, so a body that says nothing about the
			// network gets N — the engine's own netns, which is this sandbox's.
			// MEASURED (podman 6.0.2): absent and "" both come back recorded as
			// "host" and the container's /proc/self/ns/net is the payload's.
			// "default" reaches the same place by the other route, falling through
			// the checks below unrefused. Do NOT turn this into a gate that
			// substitutes "host": that is translating a request nobody made, and
			// the pin is the place that binds it. What the pin does NOT do is
			// override a request that IS made — NetworkMode="bridge" still reaches
			// the engine and still fails (netavark: Netlink error: Operation not
			// permitted), which is why build.go's allowlist is not cosmetic.
			continue
		}
		// Normalised ONCE and used by every arm below, the same correction
		// checkNetworkMode already carries on its side (build.go): the arms
		// compared the raw value, so "Container:abc" and "HOST" fell past
		// them. On BUILD, falling past a refusal arm lands in a generic
		// default-deny; here it lands in FORWARD, so the two files disagreed
		// about which direction a missed spelling fails in. Whether the engine
		// then honoured such a spelling was never measured here — which is the
		// point: a refusal snug states must not depend on the answer. Folding
		// can only refuse more; it cannot grant.
		norm := strings.ToLower(strings.TrimSpace(mode))
		if k == "NetworkMode" && norm == "host" {
			continue
		}
		if norm == "host" || strings.HasPrefix(norm, "container:") || strings.HasPrefix(norm, "ns:") {
			p.deny(w, "HostConfig.%s = %q: %s", k, mode, namespaceModeReason[k])
			return
		}
	}

	// 4. A restart policy that asks for something is refused; the one the CLI
	//    always sends asks for nothing.
	if raw, ok := hc["RestartPolicy"]; ok && !isEmptyJSON(raw) {
		if err := checkRestartPolicy(raw); err != nil {
			p.deny(w, "%v", err)
			return
		}
	}

	// 5. THE INVERSION (issue #338). Every remaining HostConfig field must be
	//    one snug has been taught about — judged above, or allowlisted with an
	//    abuse sentence. A field nobody has modelled fails closed.
	//
	//    Before this, the two loops above were a DENYLIST over a schema snug
	//    does not model: 38 of docker's 71 HostConfig fields reached the engine
	//    verbatim, five of them carrying a host path the engine stats. Adding
	//    those five to refusedHostConfig would have closed the instance and left
	//    the shape; this closes the shape, and the build query and the build
	//    context had already been inverted the same way.
	//
	//    An EMPTY unmodelled field is deleted rather than refused, and that is
	//    what makes the inversion shippable at all. MEASURED: a stock docker
	//    29.4.0-ce sends 62 HostConfig fields on `docker run --rm alpine true`,
	//    of which exactly six are non-empty by isEmptyJSON — AutoRemove,
	//    ConsoleSize, LogConfig, MemorySwappiness, NetworkMode, RestartPolicy
	//    (testdata/docker-run-create-body.json). An allowlist evaluated on raw
	//    PRESENCE would 403 every `docker run` on 62 keys, which is the LogConfig
	//    trap at schema scale — that one shipped a message about log drivers to
	//    users who had asked for nothing of the sort. So isEmptyJSON is part of
	//    the security boundary here, not a formatting helper.
	//
	//    Deleting an empty value inherits isDefaultLogConfig's justification
	//    rather than being an exception to it: docker and podman decode the
	//    create body into a struct with non-pointer fields, so for those the
	//    engine cannot distinguish absent from zero-valued. The residual, stated
	//    rather than hidden: for a POINTER field an explicit zero and an absent
	//    key do differ — MemorySwappiness *int64 is the live example, which is
	//    exactly why the CLI sends -1 rather than 0 — and the direction of the
	//    miss is always "the engine's own default applies", a tightening, never
	//    attacker-chosen. It reaches only fields nobody has modelled.
	//
	//    And it is not silent: invariant 5 forbids a silent downgrade, not a
	//    downgrade, so every dropped name goes in the audit line below.
	var droppedEmpty []string
	for k, v := range hc {
		lower := strings.ToLower(k)
		if judgedCreateField[lower] || unexaminedCreateField[lower] {
			continue
		}
		if isEmptyJSON(v) {
			droppedEmpty = append(droppedEmpty, k)
			delete(hc, k)
			continue
		}
		p.deny(w, "HostConfig.%s is not permitted. snug allows a named set of HostConfig "+
			"fields and refuses the rest, so a field it has not been taught about fails "+
			"closed rather than reaching the engine unexamined. If this one is harmless it "+
			"belongs in unexaminedCreateFields with the abuse sentence for why — and if it "+
			"carries a host path it does not belong there at all, because snug can only "+
			"forward a path it rewrote (see the Blkio*Device* entries)", k)
		return
	}
	sort.Strings(droppedEmpty)

	// 6. Every requested mount must name a host path the SANDBOX can already
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
	// The abuse sentence that used to sit here now lives in
	// containerResourceLimit, which Tmpfs and ShmSize share. That move IS a
	// finding of issue #338: build.go carried the argument for `shmsize`, this
	// file carried it for Tmpfs in a comment nothing read, and ShmSize — the
	// same noun on the same schema — carried none at all. An allowlist forces
	// the two paths to agree, because a member without a sentence does not
	// compile into the map.
	//
	// What the sentence says, unchanged: neither reaches a host resource. A
	// tmpfs has no source, so the mount rule in the package comment has nothing
	// to check — there is no host path to be visible or not. The RAM is the same
	// RAM any process in the container could allocate anyway, and it is the
	// tmpfs-sizing gap snug already has on its own mounts (TODO R8), not a new
	// one. `docker run --tmpfs /run` is ordinary and worked nowhere.

	// 7. Inject the hardening the sandbox cannot rely on the client to set.
	hc["Privileged"] = json.RawMessage(`false`)
	hc["SecurityOpt"] = json.RawMessage(`["no-new-privileges:true"]`)

	// And stamp this run's label. Its consumer is INBOUND, in this proxy: it is
	// how a DELETE is judged to name a container THIS run created
	// (handleContainerDelete, issue #339).
	//
	// RE-DERIVED, because the reason this was written for is gone twice over.
	// It used to say the store was "shared with any concurrent sandbox that
	// resolved to the same key" — false since issue #276: engineKey is
	// sha256(target) alone and S = L exactly (internal/engine/paths.go), so at
	// most one LIVE run uses a given store. And it used to say teardown filtered
	// on the label — false since issue #167 deleted the host-side `podman stop`.
	// Between #167 and #339 nothing read this label at all; it was write-only.
	//
	// What survives is TIME-ORDERED, not concurrent. The store persists, and
	// teardown removes no container: the engine's pid namespace collapses, the
	// kernel SIGKILLs the processes, and the RECORDS stay. So a later run of the
	// same target opens a store holding every earlier run's containers, and this
	// label is what separates them.
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

	// 8. Re-encode from our own map. This is a second, independent drift guard:
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
	audit := fmt.Sprintf("container create: %d mount(s) allowed", len(mounts))
	if len(droppedEmpty) > 0 {
		audit += fmt.Sprintf("; dropped %d empty unmodelled HostConfig field(s): %s",
			len(droppedEmpty), strings.Join(droppedEmpty, ", "))
	}
	if len(droppedTop) > 0 {
		audit += fmt.Sprintf("; dropped %d empty unmodelled top-level field(s): %s",
			len(droppedTop), strings.Join(droppedTop, ", "))
	}
	p.audit(audit)
	p.forward(w, r, out)
}

// namespaceModeKeys are the HostConfig fields that can join a namespace outside
// this sandbox. Named rather than inline so canonicalKey covers them too.
var namespaceModeKeys = []string{
	"NetworkMode", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode",
}

// namespaceModeReason is why each key in namespaceModeKeys is refused when it
// names "host", a sibling container, or a raw ns:<path> — one entry per key,
// mirroring refusalReason. Written per key rather than as one generic
// sentence because the six keys are not refused for the same reason: pid and
// cgroup name the ENGINE's own namespaces (issue #125's C0), ipc and uts
// still name the MACHINE's (the engine unshares neither — issue #182), userns
// names U, and network is the one key that is not always refused at all.
//
// PidMode is worth reading in full: joining a pid namespace is not "seeing
// more pids", it is acquiring procfs's naming rights into everything every
// member holds, and the engine is what sits behind pid 1 there.
// The value axis here is a DENYLIST, and build.go's is an allowlist — say it
// out loud, because each reason string below reads as though the key were
// closed. What the loop refuses is "host", "container:<id>" and "ns:<path>";
// every OTHER value is FORWARDED to the engine unjudged. Real spellings that
// go through today: NetworkMode "bridge"/"none"/"private"/"pasta"/
// "slirp4netns", PidMode "private", IpcMode "shareable"/"none", CgroupnsMode
// "private", UsernsMode "keep-id"/"nomap"/"auto". They are closed by the
// engine failing (netavark: Netlink error: Operation not permitted), not by
// snug. Making this an allowlist is an ergonomic behaviour change on a path
// that works today by FAILING — the engine refuses, not snug — so it is a
// maintainer call, not something to fold into an unrelated change. Whoever
// takes it must keep "" AND "default" accepted, and this is the measurement
// that says so: a stock docker 29.4.0-ce sends NetworkMode:"default" on a
// plain `docker run` with no --network flag (testdata/docker-run-create-body.json,
// re-measured against API v1.54 — every --network=X spelling maps 1:1 onto
// NetworkMode:"X", so "default" is the no-flag value and nothing else produces
// it). podman's compat handler maps "" and "default" through the
// containers.conf netns pin to N.
var namespaceModeReason = map[string]string{
	"NetworkMode": `"host" is allowed here and means THIS sandbox's own network ` +
		`namespace N (issue #63, Tier B). What is refused is naming a namespace ` +
		`snug did not author — another container's, or a raw ns:<path>`,
	"PidMode": `inside this sandbox "host" is not the machine. The engine has had a ` +
		`pid namespace of its own since issue #125's C0, so this asks to join THE ` +
		`ENGINE'S — and pid visibility is not merely visibility: /proc/<pid>/root ` +
		`and /proc/<pid>/cwd walk into a namespace member's own MOUNT namespace, ` +
		`and /proc/<pid>/fd/N reopens its open descriptors, both at plain uid with ` +
		`no capability at all (measured). Pid 1 there is the engine, whose mount ` +
		`namespace since Tier C (issue #125) is its DERIVED view — the sandbox's ` +
		`own, plus this run's grafts: the container store, the runroot, the config ` +
		`directory. So this is a filesystem escape by another route, reaching the ` +
		`same grafts issue #251 reached through a -v symlink — not the whole host ` +
		`tree it once was, but the read-write store is enough. There is no flag ` +
		`that enables it and no narrower spelling: PidMode=container:<id> reaches ` +
		`a sibling container the same way`,
	"IpcMode": `the engine has its OWN IPC namespace since issue #182, so "host" ` +
		`here names the ENGINE's, not the machine's: joining it reaches only the ` +
		`System V shared memory, semaphores and message queues the engine itself ` +
		`holds — none, podman creates no host segment — not the host's, which the ` +
		`sandbox has no route to. "host" is refused whether or not it would ` +
		`disclose anything, the same way CgroupnsMode's is`,
	"UTSMode": `the engine has its OWN UTS namespace since issue #182, so "host" ` +
		`here names the ENGINE's hostname, not the machine's real one, which the ` +
		`sandbox is otherwise never told (bwrap gives the payload --unshare-uts ` +
		`and a hostname snug chooses). "host" is refused whether or not it ` +
		`would disclose anything`,
	"UsernsMode": `the only user namespace on offer is U, the engine's own — ` +
		`root-in-U with the full delegated subuid range and ` +
		`policy.EngineCapBounding. snug decides a container's user namespace; ` +
		`"host", container:<id> and ns:<path> are refused whether or not they ` +
		`would have changed anything`,
	"CgroupnsMode": `"host" names the ENGINE's cgroup namespace, which it clones for ` +
		`itself (CLONE_NEWCGROUP): joining it discloses the engine's own cgroup ` +
		`path and the placement of every other container this sandbox started. ` +
		`snug authors that placement, which is why HostConfig.CgroupParent is ` +
		`refused too`,
}

var refusedHostConfig = []string{
	"Privileged", "CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules",
	"SecurityOpt", "Runtime", "VolumesFrom", "VolumeDriver",
	"Sysctls", "DNS", "DNSSearch", "DNSOptions", "ExtraHosts",
	"MaskedPaths", "ReadonlyPaths", "Annotations",
	"PortBindings", "PublishAllPorts",
	"LogConfig", "ContainerIDFile", "StorageOpt", "CgroupParent", "Isolation",
	"Cgroup",
	// The five path-bearing fields of issue #338. Listed together because they
	// share one reason and one shape, and refused rather than resolved for the
	// reason blkioPathField states.
	"BlkioWeightDevice", "BlkioDeviceReadBps", "BlkioDeviceWriteBps",
	"BlkioDeviceReadIOps", "BlkioDeviceWriteIOps",
}

var refusalReason = map[string]string{
	"Privileged": "it disables essentially every container protection at once",
	"CapAdd":     "added capabilities apply to the host kernel, not to the sandbox",
	"Devices": "device passthrough would name a host device, but since Tier C (issue #125) " +
		"the engine's /dev is the sandbox's own synthetic tree (measured: null, zero, " +
		"tty, pts, shm, random and the like, with none of the host's nvme/dri/kvm/mem " +
		"nodes), and the engine holds no CAP_MKNOD to create one — so there is no host " +
		"device to pass through. Refused as defence-in-depth, not as the only barrier",
	"DeviceRequests": "device passthrough would name a host device, but since Tier C (issue #125) " +
		"the engine's /dev is the sandbox's own synthetic tree (measured: null, zero, " +
		"tty, pts, shm, random and the like, with none of the host's nvme/dri/kvm/mem " +
		"nodes), and the engine holds no CAP_MKNOD to create one — so there is no host " +
		"device to pass through. Refused as defence-in-depth, not as the only barrier",
	"DeviceCgroupRules": "device passthrough would name a host device, but since Tier C (issue #125) " +
		"the engine's /dev is the sandbox's own synthetic tree (measured: null, zero, " +
		"tty, pts, shm, random and the like, with none of the host's nvme/dri/kvm/mem " +
		"nodes), and the engine holds no CAP_MKNOD to create one — so there is no host " +
		"device to pass through. Refused as defence-in-depth, not as the only barrier",
	"SecurityOpt":   "snug sets this itself; a client value could undo no-new-privileges or seccomp",
	"Runtime":       "an alternate OCI runtime is an arbitrary host binary",
	"VolumesFrom":   "it inherits another container's mounts, which snug never approved",
	"VolumeDriver":  "a non-local driver can name a host path or a remote share",
	"Sysctls":       "kernel tunables are not namespaced the way you would hope",
	"DNS":           "resolver redirection",
	"DNSSearch":     "resolver redirection",
	"DNSOptions":    "resolver redirection",
	"ExtraHosts":    "name redirection",
	"MaskedPaths":   "it edits the container's own /proc protections",
	"ReadonlyPaths": "it edits the container's own /proc protections",
	"Annotations":   "podman honours run.oci.* annotations, which reach the runtime",
	// Both of these described the PRE-TIER-B world until issue #154 §B:
	// "published ports land on the engine's side of the world, where the
	// sandbox cannot reach them". The engine is IN the sandbox's netns now, so
	// its side of the world is the sandbox's, and the old sentence sent a
	// reader looking for a host-visible surface to close or a flag to turn
	// publishing on. There is neither. The comment above checkCreate's
	// namespace loop already carried the correct reason; only the string the
	// user actually sees was stale.
	"PortBindings": "there is nothing to publish TO — the container already shares this " +
		"sandbox's network namespace, so it is reachable from inside at the port it binds. " +
		"Publishing would also need the engine to reconfigure that namespace, and it holds " +
		"no CAP_NET_ADMIN",
	"PublishAllPorts": "the container already shares this sandbox's network namespace, so " +
		"every port it binds is reachable from inside without publishing anything",
	// The reason said conmon "writes that file ON THE HOST as your uid" and
	// named a $HOME "the sandbox sees only as an empty tmpfs". That was true
	// when a redteam round used it to plant a file, and Tier C (issue #125)
	// narrowed it: the engine resolves a client-named path in its DERIVED
	// view, not on the host. Its sibling ContainerIDFile below was corrected
	// for exactly this and is the wording to match. No measurement of the
	// write is claimed here — unlike ContainerIDFile, this one has not been
	// re-measured against a post-Tier-C engine, and the refusal does not rest
	// on it either way.
	"LogConfig": "podman's k8s-file/json-file drivers honour a `path` option, and conmon " +
		"then opens that file as your uid, resolved in the engine's derived view — the " +
		"sandbox's own tree plus this run's grafts, the read-write container store among " +
		"them. snug names what a container may touch",
	// Issue #305, found by a redteam sweep of this proxy. Same SHAPE as
	// LogConfig one line up — a client-named path an engine component opens on
	// snug's side of the proxy — and it was the one field of that shape the
	// list did not carry.
	//
	// MEASURED against podman 6.0.2 over its own API socket, because the issue
	// filed the write side as the open question and the answer turned out to
	// be the wrong question:
	//
	//	create with ContainerIDFile   201, and `inspect` echoes the path back
	//	start                         204, and NO file appears. podman does NOT
	//	                              write the cidfile server-side; the docker
	//	                              CLI writes its own, client-side
	//	DELETE the container          the host file AT THAT PATH IS UNLINKED
	//
	// So it is not an arbitrary-write primitive, it is an arbitrary-DELETE
	// one, and it is cheaper than the write would have been: create + delete,
	// two calls, no start, no image ever run. A file planted at the path
	// beforehand was gone after removal; the control — the identical sequence
	// with no ContainerIDFile — left it untouched. Executed by the engine, as
	// the host user, on a path the client chose.
	//
	// The refusal does not rest on any of that. It rests on the same sentence
	// every other entry here rests on: snug names what a container may touch.
	// The measurement decides the SEVERITY, not the decision.
	"ContainerIDFile": "it is a client-named host path the engine records against the " +
		"container and UNLINKS when the container is removed — measured on podman 6.0.2: " +
		"create then delete, no start needed, and a file planted at that path was gone. " +
		"That is an arbitrary host-file delete, running as your uid, resolved in the " +
		"engine's derived view — the sandbox's own tree plus this run's grafts, the " +
		"read-write container store among them. snug names what a container may touch",
	"StorageOpt": "storage driver options reach the host's storage layer",
	// Not "outside this sandbox's own" any more, which is what this said
	// before issue #154 §B. __inengine clones with CLONE_NEWCGROUP and mounts
	// a fresh cgroup2 over /sys/fs/cgroup, so a client-supplied path is
	// interpreted relative to the engine's own cgroup root rather than the
	// host's. The refusal stands on the narrower, still-true ground.
	"CgroupParent": "snug authors the container's cgroup placement; a client-named parent " +
		"is a path snug did not choose, resolved inside the engine's own cgroup namespace",
	"Isolation": "an isolation mode is a runtime selector by another name",
	// Issue #338. A third spelling of the grant CgroupParent and CgroupnsMode
	// already carry, and deliberately NOT a member of namespaceModeKeys: that
	// loop matches the "host" / "container:" / "ns:" prefixes, and CgroupSpec
	// has only the one spelling, so a row there would read like the other six
	// while covering less than they do.
	//
	// Named explicitly even though the allowlist sweep in handleCreate would
	// refuse it unnamed, because the sweep's message tells a reader to ask for
	// the field to be allowlisted and that is the wrong advice for this one.
	"Cgroup": "it names another container's cgroup (container:<id>), which snug did not " +
		"author — the same grant CgroupParent and CgroupnsMode are refused for, spelled a " +
		"third way. Measured ignored by podman 6.0.2, so it is latent rather than open; it " +
		"is refused so that it does not become open when podman starts honouring it",
	"BlkioWeightDevice":    blkioPathField,
	"BlkioDeviceReadBps":   blkioPathField,
	"BlkioDeviceWriteBps":  blkioPathField,
	"BlkioDeviceReadIOps":  blkioPathField,
	"BlkioDeviceWriteIOps": blkioPathField,
}

// blkioPathField is why the five Blkio*Device* fields are refused rather than
// checked, and it is the one refusal in this file that turns on snug being
// unable to REWRITE rather than unable to judge.
//
// A bind source is resolved AND forwarded as the resolved string: checkOne
// returns mount{Source: filepath.Clean(real)}, handleCreate deletes Binds and
// Mounts and re-encodes only what came back, so the engine is asked for the
// path snug approved. A blkio entry is an array of objects with a .Path inside;
// snug would have to rewrite each element in place to make a check mean
// anything, and a check that judges a string the engine will not be asked for
// is judging the wrong string (the shape issue #304 cost, one schema over).
//
// The capability is dead inside a snug sandbox anyway, which is why refusing it
// costs nothing: block-IO throttling needs a block device NODE, an ordinary
// bwrap bind is nodev (only --dev-bind grants device access, and
// internal/cli/devicebind_test.go asserts no builtin emits one), and the
// sandbox's /dev is bwrap's synthetic character-device tree — the same
// measurement refusalReason["Devices"] already carries. If a human's own
// profile ever --dev-binds a block device that leg stops holding; the other
// three still refuse, so re-derive rather than assume.
const blkioPathField = "it names a host path the ENGINE stats, and snug neither resolves nor " +
	"rewrites it — unlike a bind source, which checkOne resolves and forwards as the " +
	"resolved string. Inside this sandbox the field cannot do its job at all: block-IO " +
	"throttling needs a block device node, an ordinary bind is nodev, and the sandbox's " +
	"/dev is bwrap's synthetic character-device tree. What is left is a stat oracle — " +
	"measured against podman 6.0.2, `not a block device` and `no such file or directory` " +
	"are distinguishable, one bit per request, over the engine's derived view. There is no " +
	"narrower spelling to ask for: podman's own guard is lexical (must be under /dev/) and " +
	"/dev/../ defeats it"

// unexaminedCreateFields is every HostConfig field forwarded to the engine
// without its value being looked at, each carrying the abuse sentence for why
// that is safe. It is the create body's half of the shape build.go already has
// (unexaminedBuildParams), and it exists for the same reason: a field snug does
// not judge cannot be SILENT about it.
//
// Issue #338. Before this, handleCreate was the last denylist in this package —
// enumerated danger refused, everything else forwarded verbatim, 38 of docker's
// 71 HostConfig fields among them — while the build query and the build context
// had both already been inverted to "unmodelled is refused".
//
// Keys are canonical docker spellings; every lookup folds through
// strings.ToLower, because podman folds and snug must agree with podman about
// which field a name is. Membership here is authored one entry at a time. It is
// NOT derived from what the docker CLI sends: the CLI sends 62 fields on a
// plain `docker run`, and allowlisting all 62 on the authority of a friendly
// client is the mistake unexaminedBuildParams' own comment records for
// `secrets` and `idmappingoptions`.
var unexaminedCreateFields = map[string]string{
	// ── resource limits ──────────────────────────────────────────────────
	"ShmSize":            containerResourceLimit,
	"Tmpfs":              containerResourceLimit,
	"Memory":             containerResourceLimit,
	"MemoryReservation":  containerResourceLimit,
	"MemorySwap":         containerResourceLimit,
	"MemorySwappiness":   containerResourceLimit,
	"NanoCpus":           containerResourceLimit,
	"CpuShares":          containerResourceLimit,
	"CpuPeriod":          containerResourceLimit,
	"CpuQuota":           containerResourceLimit,
	"CpuRealtimePeriod":  containerResourceLimit,
	"CpuRealtimeRuntime": containerResourceLimit,
	"CpusetCpus":         containerResourceLimit,
	"CpusetMems":         containerResourceLimit,
	"CpuCount":           containerResourceLimit,
	"CpuPercent":         containerResourceLimit,
	"PidsLimit":          containerResourceLimit,
	"Ulimits":            containerResourceLimit,
	"BlkioWeight":        containerResourceLimit,
	"IOMaximumIOps":      containerResourceLimit,
	"IOMaximumBandwidth": containerResourceLimit,

	// ── ordinary container behaviour ─────────────────────────────────────
	"AutoRemove":  ordinaryContainerBehaviour,
	"ConsoleSize": ordinaryContainerBehaviour,

	// ── the honest class ─────────────────────────────────────────────────
	"OomScoreAdj":    notYetAnalysed,
	"OomKillDisable": notYetAnalysed,
	"ReadonlyRootfs": notYetAnalysed,
	"GroupAdd":       notYetAnalysed,
	"CapDrop":        notYetAnalysed,
	"Init":           notYetAnalysed,
}

// The abuse sentences for the create body, written per CLASS so the claim a
// reader has to judge is one paragraph rather than one per field. notYetAnalysed
// is build.go's and is shared deliberately: it is a claim about the state of the
// review, and the review is one review.
const (
	// Deliberately the same claim build.go's resourceLimit makes, extended to
	// the container fields. ShmSize and Tmpfs are the RAM half and are named
	// together because the two paths had drifted: build.go carried the
	// argument for `shmsize`, create.go carried it for Tmpfs in a comment, and
	// ShmSize — the same noun on the same schema — carried nothing.
	containerResourceLimit = "A hostile process inside the sandbox can use these to choose how " +
		"much memory, swap, CPU, pids, block-IO weight and shared memory its own container may " +
		"use, and — through ShmSize and Tmpfs — to allocate host RAM as a container filesystem. " +
		"They bound the container rather than widening it: the RAM is the same RAM any process " +
		"in the sandbox could allocate anyway, no value names a path or a device, and " +
		"CgroupParent, the one field that would move the container into a cgroup outside this " +
		"sandbox's own, is refused."

	ordinaryContainerBehaviour = "A hostile process inside the sandbox can use these to change " +
		"how its own container is run and reaped: whether the engine removes it when it exits, " +
		"and what terminal size it reports. Neither names a path, selects a namespace, or " +
		"reaches a host resource."
)

// judgedCreateField reports whether handleCreate itself decides on a HostConfig
// key — refuses it, reads it as a namespace mode, consumes it as a mount, or
// validates it.
//
// DERIVED rather than written out, so a key added to refusedHostConfig or
// namespaceModeKeys does not also have to be remembered here. The four written
// names are the ones no list already holds: Binds and Mounts are consumed by
// checkedMounts, RestartPolicy is validated by checkRestartPolicy, and Privileged
// and SecurityOpt are on refusedHostConfig already but are also INJECTED, which
// is worth reading in one place.
var judgedCreateField = func() map[string]bool {
	m := map[string]bool{}
	add := func(names ...string) {
		for _, n := range names {
			m[strings.ToLower(n)] = true
		}
	}
	add(refusedHostConfig...)
	add(namespaceModeKeys...)
	add("Binds", "Mounts", "RestartPolicy")
	return m
}()

// unexaminedCreateField is the folded index of unexaminedCreateFields, built
// once. decodeObject canonicalises a client's spelling through canonicalKey, but
// this is what the sweep consults, so the two agree on a name whatever case it
// arrived in.
var unexaminedCreateField = func() map[string]bool {
	m := make(map[string]bool, len(unexaminedCreateFields))
	for k := range unexaminedCreateFields {
		m[strings.ToLower(k)] = true
	}
	return m
}()

// checkRestartPolicy permits only the policy that asks for nothing.
//
// It is isDefaultLogConfig generalised: the docker CLI sends
// {"Name":"no","MaximumRetryCount":0} on EVERY create, which isEmptyJSON does
// not see as empty, so an allowlist without this check would refuse every
// `docker run` — the LogConfig trap a second time.
//
// A restart policy is judged rather than given an abuse sentence because the
// sentence would be a containment claim with no test behind it: a container the
// engine restarts outlives the request that created it, and nobody has
// established what it outlives inside this sandbox.
func checkRestartPolicy(raw json.RawMessage) error {
	var rp struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(raw, &rp); err != nil {
		return fmt.Errorf("HostConfig.RestartPolicy is not the docker-compat shape: %v", err)
	}
	switch rp.Name {
	case "", "no":
		return nil
	}
	return fmt.Errorf("HostConfig.RestartPolicy = %q is not permitted; only \"no\" is. A "+
		"container the engine restarts outlives the request that created it, and nobody has "+
		"established what it outlives inside this sandbox", rp.Name)
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

// checkOne is a REWRITER, not a validator, and that is the sentence this file
// turns on.
//
// It does not answer "may the client have this path". It returns the mount snug
// will ask the engine for — `mount{Source: filepath.Clean(real)}` — and
// handleCreate then deletes Binds and Mounts and re-encodes only what came back.
// So the engine is asked for THE PATH SNUG APPROVED, not the path the client
// wrote, and the residual TOCTOU is bounded by that rewrite rather than by the
// check.
//
// The consequence for anything added to this file later, which is why the
// sentence is here and not only at its one current use (blkioPathField): a
// create-body field that carries a path is allowlistable only if snug both
// RESOLVES it and FORWARDS the resolved string. A field snug can judge but
// cannot rewrite is refused, because judging a string the engine will never be
// asked for is judging the wrong string — the shape issue #304 cost on the
// build path, where checkBuildVolume computed a resolved path and threw it away
// while handleBuild forwarded the client's original.
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
	real, err := resolveForwardable(source)
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

	// The engine resolves a bind SOURCE in its own derived view, not in the
	// sandbox's — sound only while the two name it identically. checkOne has
	// so far sampled the HOST filesystem and is about to forward the host
	// string as-is; splitSpec accepts host:guest grants where they diverge
	// (issue #284 §3.3). Refuse rather than forward a spelling the engine
	// would resolve to something else — or to nothing this check ever judged.
	//
	// Asked in GUEST space, and asked AFTER hostPathVisible, both on purpose
	// (issue #371). Authorization is a host-space question and stays one:
	// EngineGuestPath, which this check used to be written with, matches
	// GRAFTS by Graft.Host and so answers "visible at /snug/engine/store" for
	// exactly the engine-owned host paths hostPathVisible refuses — the hole
	// issue #251 closed. CheckEngineForwardedPath asks the other question, the
	// one the engine actually answers: what does the engine find at this NAME.
	if err := p.pol.CheckEngineForwardedPath(source); err != nil {
		return mount{}, err
	}

	// The engine re-resolves this same path string a SECOND time, from a
	// separate process, at container START — a distinct client request with
	// an attacker-controlled gap after this check. Refuse any source where a
	// name on the path can still be re-pointed in that gap (issue #284).
	if err := p.pol.CheckEngineBindSource(source); err != nil {
		return mount{}, err
	}

	return mount{Type: "bind", Source: source, Target: dest, ReadOnly: ro}, nil
}

// mount is deliberately these four fields and no others: HostConfig.Mounts
// from the client is re-serialised through this struct rather than forwarded
// verbatim, so a field this package has not modelled — notably
// BindOptions.NonRecursive or a propagation mode — cannot be smuggled through
// to the engine. That matters for CheckEngineBindSource's M4 clause (issue
// #284): an unmodelled propagation setting is exactly the kind of thing that
// could make a submount visible or invisible in a way the anchored-source
// rule did not account for, so re-serialising to this fixed shape is
// load-bearing, not incidental.
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
	for k := range unexaminedCreateFields { // issue #338's allowlist
		add(k)
	}
	add("RestartPolicy") // checkRestartPolicy

	// The create body's TOP level (issues #375, #397). Derived from the same
	// lists checkTopLevel consults, for the reason this map's own comment
	// gives: a name missing here arrives in whatever case the client spelled
	// it, and the sweep would then judge a key the engine reads as a
	// different one. TestEveryCheckedTopLevelKeyIsCanonicalised fails if one
	// is missed.
	add(refusedTopLevel...)
	add(topLevelChecked...)
	for k := range unexaminedTopLevelFields {
		add(k)
	}
	// HostConfig and Labels are judged and held by no list above.
	//
	// `Labels` FIXES A LIVE BUG rather than completing a set, so it is named
	// here: stampRunLabel does an exact-key req["Labels"] lookup, and without a
	// canonical spelling a client sending lowercase "labels" kept its own key,
	// stampRunLabel saw no "Labels" and added its own, json.Marshal sorted
	// "Labels" (0x4C) before "labels" (0x6C), and podman — which folds
	// case-insensitively and takes the LAST key — read the client's. So snug's
	// run label was DISCARDED by a lowercase spelling, and the container became
	// invisible to handleContainerDelete's ownership check (#339). It failed
	// closed for deletion, which is why nothing caught it. The exact mechanism
	// decodeObject's own comment records for {"privileged":true}, one map over.
	// TestALowercaseLabelsKeyDoesNotDiscardTheRunLabel is the regression test.
	add("HostConfig", "Labels")

	// The endpoint fields checkNetworkingConfig walks. It judges them by
	// EMPTINESS and never by name, so it needs no canonical spelling of its
	// own — but EndpointsConfig itself is compared as a string, so that one
	// does.
	add("EndpointsConfig")

	add("Binds", "Mounts", "Tmpfs")                             // what checkedMounts consumes
	add("Driver", "Options", "DriverOpts", "ClusterVolumeSpec") // volume create
	return m
}()

// isEmptyJSON is PART OF THE SECURITY BOUNDARY, not a formatting helper.
//
// Every check in this file is evaluated on non-empty VALUES rather than on the
// presence of a key, so what this function calls empty decides what the create
// allowlist admits. MEASURED (issue #338): a stock docker 29.4.0-ce sends 62
// HostConfig fields on `docker run --rm alpine true` and exactly six of them are
// non-empty by this predicate. Widen it and a field stops being examined;
// narrow it and the proxy 403s ordinary `docker run` — which has already
// happened once at one-field scale, when the LogConfig denylist entry refused
// every create there had ever been with a message about log drivers.
//
// So do not "simplify" it, and do not add a case without deciding what stops
// being read. TestTheCreateAllowlistAdmitsWhatDockerActuallySends is the set
// assertion that catches the change.
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
// A one-line call to policy.ResolveExistingHostPath rather than its own walk
// (issue #55, F6): that function is now the second half of "can the sandbox
// see this host path" (the first half is policy.HostPathVisible, already
// shared the same way), and invariant 6 says one author, not two
// implementations that eventually drift. OSEnviron{}.EvalSymlinks IS
// filepath.EvalSymlinks, so this is behaviour-identical to the walk it
// replaces. TestResolveExistingHasOneAuthor pins that no EvalSymlinks loop
// survives in this package.
func resolveExisting(p string) (string, error) {
	return policy.ResolveExistingHostPath(policy.OSEnviron{}, p)
}

// resolveForwardable is resolveExisting plus the ONE refusal Tier C's derived
// view made necessary: a source containing a symlink whose target does not
// exist in snug's OWN namespace, but may exist in the engine's DERIVED one.
//
// THE DIVERGENCE, stated as the mechanism and not as one path. Every proxy
// check that vets a host path — this one for a bind, checkSeccompProfile for a
// profile file — resolves the source in snug's mount namespace and then judges
// it, while the engine bind-mounts it in a namespace DERIVED from the sandbox's
// with this run's grafts on top (issue #125). For almost every path the two
// namespaces agree. They diverge in exactly one direction that matters: a name
// that resolves to NOTHING here (`/snug/engine/store`, `/snug/engine/toolchain`
// and every other `/snug/engine/*` graft) resolves to a REAL object there. A
// payload cannot bind such a path directly — hostPathVisible refuses it,
// because no sandbox grant covers `/snug` — so it reaches it through a symlink
// in its own writable target: resolveExisting cannot follow the dangling link,
// walks up to the target, and returns the link's own path, which hostPathVisible
// then approves because the target IS a writable bind. crun follows the symlink
// on the far side and lands in the graft (issue #251, measured: the engine's
// whole read-write container store).
//
// THE TEST IS "does a symlink on this path dangle on the host", not "does it
// point at /snug". Keying on the destination string would miss the next graft
// namespace and read as a fix while a spelling slips past; keying on the
// divergence itself — a symlink snug cannot resolve is a symlink that may mean
// something else where the mount actually happens — covers the class. A path
// whose tail is plain-missing (a name podman will CREATE under a real,
// host-visible directory) is left alone: it means nothing in either namespace,
// and refusing it would break a legitimate bind for no security gain.
//
// os.Stat, which FOLLOWS symlinks, is what distinguishes the two: on a dangling
// symlink it returns a not-exist error while os.Lstat (which does not follow)
// says the component is a symlink. No filepath.EvalSymlinks and no walk of its
// own — resolveExisting stays the one author of "resolve as far as it exists"
// (TestResolveExistingHasOneAuthor).
func resolveForwardable(source string) (string, error) {
	if where, dangling := danglingSymlinkOn(source); dangling {
		return "", fmt.Errorf("its component %s is a symlink whose target does not exist in this "+
			"sandbox's own namespace. The container engine resolves a bind in a namespace derived "+
			"from the sandbox's, where the same name can point at one of snug's own /snug/engine "+
			"grafts (the container store, the toolchain) that no grant exposes here — so a source "+
			"snug cannot follow is one it will not forward (issue #251)", where)
	}
	return resolveExisting(source)
}

// danglingSymlinkOn walks source component by component and reports the first
// one that is a symlink whose target does not resolve on the host. It uses
// os.Lstat (to see a symlink without following it) and os.Stat (to ask whether
// following it lands on a real object) — deliberately NOT filepath.EvalSymlinks,
// so it neither re-implements resolveExisting's resolve-as-far-as-exists walk
// nor trips the one-author sweep that forbids a second EvalSymlinks loop in this
// package.
//
// A symlink that resolves to a real HOST path is not flagged here: it fully
// resolves, so the source either resolves entirely (and is judged canonically)
// or fails on a plain-missing tail below it (and hostPathVisible judges the
// resolved prefix). Only the symlink that dangles HERE is the divergence.
func danglingSymlinkOn(source string) (string, bool) {
	cur := "/"
	for _, elem := range strings.Split(filepath.Clean(source), "/") {
		if elem == "" {
			continue
		}
		cur = filepath.Join(cur, elem)
		fi, err := os.Lstat(cur)
		if err != nil {
			// Plain-missing from here down: nothing below this exists on the
			// host, symlink or otherwise, so there is no symlink left to dangle.
			return "", false
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if _, err := os.Stat(cur); err != nil {
			return cur, true
		}
	}
	return "", false
}

// hostPathVisible reports whether the sandbox can itself see a host path at the
// given access — the rule the package comment states. This is a LIVE, shared
// boundary, not dead code kept for a future mode: checkOne calls it for every
// `-v` bind request (the proxy's own filter), and checkSeccompProfile calls it
// twice more for a seccomp profile path. A future opt-in submount mode must
// use exactly this and nothing else, same as the callers above already do.
//
// A one-line call to policy.HostPathVisible rather than its own walk (issue
// #55): that predicate is now also G4's graft-source check, and invariant 6
// says one author of "can the sandbox see this host path", not two
// implementations that eventually disagree — so a future weakening of
// policy.HostPathVisible weakens this filter too, not a copy of it.
// TestContainerBindFilterMatchesPolicyVisibility exercises it through here
// unchanged.
func (p *Proxy) hostPathVisible(host string, needWrite bool) bool {
	return p.pol.HostPathVisible(host, needWrite)
}
