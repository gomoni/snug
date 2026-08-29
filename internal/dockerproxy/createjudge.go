package dockerproxy

import (
	"fmt"
	"strings"
)

// createjudge.go is the schema-free half of "make a container", split out of
// create.go so a second protocol decoder can feed it (issue #459 phase 1).
// Nothing here changes what handleCreate does — every function is called
// from create.go exactly where the inline logic used to be, with the same
// inputs and the same message text. What moves is the SHAPE: the docker-compat
// spellings ("container:<id>", "ns:<path>") are normalised into nsSpec before
// judgeNamespaceMode runs, so the judge itself never sees a docker string.
//
// libpodcreate.go (phase 2) feeds the same judgeNamespaceMode and
// checkMountRequests from podman's own SpecGenerator shapes. The refusal
// TEXT — refusalReason, namespaceModeReason, noNetnsOfItsOwn — already lived
// at package scope and needed no move at all; a canonical key ("NetworkMode",
// "Privileged", ...) means the same fact regardless of which wire spelled it.

// nsSpec is one namespace-mode request, normalised across both protocols.
// docker-compat spells it as a single string ("host", "container:<id>",
// "ns:<path>"); podman's SpecGenerator spells it as {"nsmode":"container",
// "value":"<id>"}. Both collapse to this before judgeNamespaceMode runs.
//
// Raw is the client's own spelling, unmodified, because every refusal message
// below quotes it — a user who typed `--pid container:abc` should see that
// string back, not snug's internal name for the class it falls into.
type nsSpec struct {
	Mode string // "", "host", "container", "path", "default", or a passthrough value
	Raw  string
}

// compatNSMode normalises a docker-compat HostConfig namespace-mode string.
// This is the exact classification handleCreate's namespace loop used to do
// inline; moved here unchanged so judgeNamespaceMode can be shared with
// libpodcreate.go.
func compatNSMode(raw string) nsSpec {
	norm := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case norm == "host":
		return nsSpec{Mode: "host", Raw: raw}
	case strings.HasPrefix(norm, "container:"):
		return nsSpec{Mode: "container", Raw: raw}
	case strings.HasPrefix(norm, "ns:"):
		return nsSpec{Mode: "path", Raw: raw}
	default:
		return nsSpec{Mode: norm, Raw: raw}
	}
}

// judgeNamespaceMode is namespaceModeKeys' loop body, generalised to take an
// already-classified nsSpec instead of a docker-compat string. key is the
// CANONICAL name ("NetworkMode", "PidMode", "IpcMode", "UTSMode",
// "UsernsMode", "CgroupnsMode") that namespaceModeReason and the per-protocol
// spell function both index by.
//
// NetworkMode is the one ALLOWLISTED key (issue #424): absent, "default" and
// "host" are accepted, everything else refused, "none" included. The other
// five stay a DENYLIST: "host", "container:<id>"/"container" and
// "ns:<path>"/"path" are refused, every other value forwarded — see
// namespaceModeReason's own comment for why one word set cannot cover all six.
//
// "none" is REFUSED, and it CONVERGES with build.go rather than diverging from
// it. The reasoning that once kept it accepted was that a netns nobody brings
// `lo` up in needs no netlink. That is wrong, and this is the measurement:
// crun brings `lo` up ITSELF whenever it creates a network namespace — before
// it mounts devpts — and that ioctl needs CAP_NET_ADMIN in the new namespace.
//
// MEASURED on the docker-compat create+start path, podman 6.0.2 + crun,
// against a podman running as root in a user namespace whose bounding set has
// bit 12 cleared (CapBnd 000001ffffffefff — CAP_NET_ADMIN absent, which is
// what policy.EngineCapBounding gives the engine):
//
//	NetworkMode:"none"    create 201, start 500
//	                      crun: ioctl SIOCSIFFLAGS: Operation not permitted
//	NetworkMode:"bridge"  create 201, start 500
//	                      netavark: setns: IO error: Operation not permitted
//	NetworkMode:"host"    create 201, start past network setup entirely
//
// Isolated, because "it failed" is not "it failed for THIS reason": the same
// harness dropping CAP_SYS_BOOT instead of CAP_NET_ADMIN gets past the
// network step, and so does CAP_NET_ADMIN-dropped "host". One bit and one
// mode are the only variables. With a FULL bounding set "none" runs to
// completion with `lo` up in a netns of its own — which is why a plain
// rootless podman on the host reports that it works and the engine does not,
// and why ENGINE-NETNS.md §2's "--network=none works" (measured with the cap
// present, before the NET_ADMIN decision) is not authority here.
//
// So accepting it returned 201 for a container that cannot start: snug
// admitting a capability the engine refuses, which is invariant 5 facing the
// other way.
//
// ABUSE, on what stays accepted: "host" is N, which the sandbox already has.
// What the refusal CLOSES: a create body naming a namespace snug did not
// author, forwarded unjudged, on an engine that may one day satisfy it
// (enginecaps.go records a bounding set reset to full inside a NESTED
// userns — which a rootless podman creates per container and this engine,
// running as root in U, does not) while --dry-run still tells the human
// containers run in N.
func judgeNamespaceMode(key string, spec nsSpec, spell func(string) string) error {
	switch spec.Mode {
	case "host":
		if key == "NetworkMode" {
			return nil // this sandbox's own network namespace N, issue #63 Tier B
		}
		return fmt.Errorf("%s = %q: %s", spell(key), spec.Raw, namespaceModeReason[key])
	case "container", "path":
		return fmt.Errorf("%s = %q: %s", spell(key), spec.Raw, namespaceModeReason[key])
	default:
		if key == "NetworkMode" && spec.Mode != "default" {
			return fmt.Errorf("%s = %q: %s.\n       Fix: drop --network, or use --network=host "+
				"(which is this sandbox's own network). --network=none is refused too: crun "+
				"brings `lo` up in any namespace it creates and that ioctl needs the same "+
				"capability.", spell(key), spec.Raw, noNetnsOfItsOwn)
		}
		return nil
	}
}

// judgeAskedField refuses a canonical field the client asked for, using the
// shared reason table both protocols read (refusalReason). spell renders the
// field in the caller's own wire spelling ("HostConfig.Privileged" for
// docker-compat, "privileged" for libpod); the REASON is the same fact about
// the same engine either way, which is why refusalReason carries no protocol
// of its own.
func judgeAskedField(canonical string, spell func(string) string) error {
	return fmt.Errorf("%s is not permitted: %s", spell(canonical), refusalReason[canonical])
}

// judgeRestartPolicyName is checkRestartPolicy's verdict, split from its
// decode step so a second protocol whose restart policy is already a bare
// string (podman's `restart_policy`, not an object with a `Name` docker
// nests it in) can share the one sentence without re-decoding anything.
func judgeRestartPolicyName(name string, spell func(string) string) error {
	switch name {
	case "", "no":
		return nil
	}
	return fmt.Errorf("%s = %q is not permitted; only \"no\" is. A container the engine "+
		"restarts outlives the request that created it, and nobody has established what it "+
		"outlives inside this sandbox", spell("RestartPolicy"), name)
}

// checkMountRequests is checkedMounts' tail end: given the REQUESTED mounts —
// already parsed out of whichever wire shape asked for them — it runs each
// one through checkOne and returns the set to forward. This is the part
// create.go's own comment calls already schema-free: checkOne takes a path
// and a bool, nothing about docker or podman.
func (p *Proxy) checkMountRequests(reqs []mount) ([]mount, error) {
	var out []mount
	for _, m := range reqs {
		c, err := p.checkOne(m.Source, m.Target, m.ReadOnly)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// judgeBindOptions is the ONE allowlist of bind-mount options, and it is
// shared by both wires on purpose. Option smuggling is a real class:
// propagation modes like rshared reach back out of the container, `dev` and
// `suid` strip the nodev/nosuid a bind otherwise gets, and podman's `U`
// recursively chowns the bind SOURCE — a mutation of granted host files.
//
// It returns the options to FORWARD rather than echoing what arrived, because
// the libpod wire carries them as an array snug re-marshals: copying that
// array through is how the two decoders came to disagree (issue #459). Only
// ro/z/Z survive; rw and "" are the default and need not be spelled.
func judgeBindOptions(opts []string) (ro bool, forward []string, err error) {
	for _, o := range opts {
		switch o {
		case "ro":
			ro = true
		case "rw", "":
		case "z", "Z":
			forward = append(forward, o)
		default:
			return false, nil, fmt.Errorf("bind option %q is not permitted", o)
		}
	}
	if ro {
		forward = append([]string{"ro"}, forward...)
	}
	return ro, forward, nil
}
