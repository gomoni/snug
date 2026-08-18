package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/stage"
)

// containerPreflight runs P1-P6 (ENGINE-WIRING.md §4) on the HOST, before
// anything is created — before the stage, before the engine, before a single
// namespace exists. Every probe below is fatal except P5, which SELECTS a
// flag rather than refusing. Ordered cheapest-and-most-decisive first, so the
// common misconfiguration fails instantly rather than after several seconds
// of setup:
//
//	P6  ptrace_scope           REFUSE iff 0 (the in-U cap-drop argument holds
//	                            only on 1; 2/3 are stricter and pass)
//	P1  real podman, not a shim
//	P2  /etc/subuid + /etc/subgid have a range for this user
//	P3  newuidmap/newgidmap on PATH
//	P5  cgroup write probe — SELECTS cgroups=disabled, never fatal on its own
//
// P4 (overlay + MS_REC|MS_PRIVATE in a fresh userns) is NOT implemented as a
// separate throwaway probe here — see the doc comment on containerPreflight
// itself in the caller (container.go) for why, and what covers it instead.
//
// Every refusal names the fix, per CLAUDE.md's "errors name the fix" rule,
// and none of them falls back to a weaker guarantee: invariant 5 applies to
// the whole tier, not just to the engine's own capability drop.
type containerPreflight struct {
	Podman          string
	CgroupsDisabled bool
}

func runContainerPreflight() (containerPreflight, error) {
	if err := preflightPtraceScope(); err != nil {
		return containerPreflight{}, err
	}
	podman, err := preflightPodmanBinary()
	if err != nil {
		return containerPreflight{}, err
	}
	if err := stage.CheckSubuidDelegation(); err != nil {
		return containerPreflight{}, fmt.Errorf("the container engine needs a delegated subuid/"+
			"subgid range and could not get one: %w", err)
	}
	cgroupsDisabled := preflightCgroupsWritable()
	return containerPreflight{Podman: podman, CgroupsDisabled: cgroupsDisabled}, nil
}

// preflightPtraceScope is P6. The whole argument that dropping CAP_SYS_PTRACE
// from the engine's capability set closes the in-U peer-read (capdrop.go's
// own doc comment, policy.EngineCapBounding) holds only when
// /proc/sys/kernel/yama/ptrace_scope is 1: at 0 the kernel's own same-uid
// rule alone admits ptrace of a non-descendant peer, with no capability check
// involved at all, and M6's re-measurement under that setting was never run
// (TIER-B-POLICY.md §1, "Maintainer decisions, settled" — Q2, REFUSE). 2 and
// 3 are STRICTER than 1 (they narrow ptrace further) and pass.
func preflightPtraceScope() error {
	data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		// Absent means no Yama LSM at all, i.e. the kernel enforces nothing
		// beyond the ordinary same-uid rule — the same failure mode as 0.
		return fmt.Errorf("cannot read /proc/sys/kernel/yama/ptrace_scope (%w): the container "+
			"engine's capability drop is only a meaningful boundary against a same-uid peer when "+
			"Yama's ptrace_scope is enforced at 1 or stricter; refusing rather than assuming it is", err)
	}
	scope := strings.TrimSpace(string(data))
	if scope == "0" {
		return fmt.Errorf("this host's /proc/sys/kernel/yama/ptrace_scope is 0: any same-uid " +
			"process can ptrace any other, with no capability check at all — the container " +
			"engine's own capability drop (dropping CAP_SYS_PTRACE) is not a meaningful boundary " +
			"under this setting, and snug will not run a container engine while pretending it is.\n" +
			"      Fix: sysctl kernel.yama.ptrace_scope=1 (or stricter)")
	}
	return nil
}

// preflightPodmanBinary is P1: a real podman binary, not a host-escape shim.
// Promoted from a warning (podmanshim.go's warnAboutPodmanClient, which still
// covers the CLIENT-inside-the-sandbox case) to a REFUSAL here, because a
// shim on the ENGINE path reaches the host's own podman over a filesystem
// socket that no netns touches — the whole tier's guarantee evaporates while
// everything looks healthy (ENGINE-WIRING.md §4, P1).
func preflightPodmanBinary() (string, error) {
	// $SNUG_PODMAN is checked FIRST and, when set, is trusted outright rather
	// than run back through detectHostShim's own PATH lookup below — a
	// caller pointing this at an explicit path (e.g. a pinned static bundle,
	// .claude/design/PODMAN-STATIC.md) is BYPASSING PATH resolution on
	// purpose, and re-resolving "podman" from PATH here would ask the wrong
	// question ("is whatever PATH finds a shim") about a binary the caller
	// never asked to use.
	if custom := os.Getenv("SNUG_PODMAN"); custom != "" {
		if fi, err := os.Stat(custom); err != nil || fi.IsDir() {
			return "", fmt.Errorf("$SNUG_PODMAN=%s does not name a usable file", custom)
		}
		return custom, nil
	}
	if shim, ok := detectHostShim("podman"); ok {
		return "", fmt.Errorf("podman resolves to %s, a host-escape helper (%s) that forwards "+
			"to the HOST's own podman over a channel no network namespace touches — a container "+
			"started through it would land on the host, silently contradicting everything "+
			"--dry-run says about this sandbox's network. snug will not run the container engine "+
			"through it.\n"+
			"      Fix: bring your own engine — a statically linked podman not shadowed by this "+
			"shim (see .claude/design/PODMAN-STATIC.md) — and put it ahead of %s on PATH, or set "+
			"$SNUG_PODMAN to its absolute path.",
			shim.Path, filepath.Base(shim.Resolved), shim.Path)
	}
	path, err := exec.LookPath("podman")
	if err != nil {
		return "", fmt.Errorf("the podman profile is selected but podman is not installed.\n" +
			"      snug will not silently hand the sandbox no engine, or the host's.\n" +
			"      Install podman, or point $SNUG_PODMAN at a static build " +
			"(.claude/design/PODMAN-STATIC.md)")
	}
	return path, nil
}

// preflightCgroupsWritable is P5: a real (if approximate) probe of whether
// this host's cgroup delegation is usable, so podman does not fail opaquely
// mid-run the first time it tries to write a controller file. It is NOT a
// fatal probe — it SELECTS podman's `cgroups = "disabled"` default
// (engine.go's Spec) rather than refusing, per ENGINE-WIRING.md §4 P5.
//
// SCOPED DOWN from the design's own probe: the design measured this from
// INSIDE a fresh cgroup namespace (the same CLONE_NEWCGROUP shape
// __inengine's own fork gets), because that is what changes the answer on a
// host where /proc/self/cgroup reads a path OUTSIDE the namespace root
// (ENGINE-NETNS.md §3's "0::/../../app.slice/..." case). This probe instead
// reads THIS process's own /proc/self/cgroup and tests a write there — a
// reasonable approximation, not the same measurement, and it can be WRONG in
// either direction versus what __inengine will actually see once it has its
// own private cgroup namespace. If it is wrong, the real mount/cgroup setup
// inside __inengine still fails loudly (never silently) — this probe only
// affects which default podman starts with, not whether an actual failure
// is reported.
func preflightCgroupsWritable() bool {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return true // cannot tell; ask podman to assume the worse case
	}
	path := parseCgroupPath(string(data))
	// A path containing ".." (measured, live on this development host: an
	// outer container's own cgroup mount root already needs ".." to express
	// — ENGINE-NETNS.md §3's case) cannot be safely joined onto
	// /sys/fs/cgroup at all: naively doing so would walk OUTSIDE the
	// intended probe location. Treat it the same as "cannot tell" and ask
	// podman to assume the worse case, rather than mkdir somewhere this
	// probe never meant to touch.
	if path == "" || strings.Contains(path, "..") {
		return true
	}
	dir := filepath.Join("/sys/fs/cgroup", path)
	probe := filepath.Join(dir, "snug-preflight-probe-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(probe, 0o755); err != nil {
		return true
	}
	_ = os.Remove(probe)
	return false
}

// parseCgroupPath reads the cgroup v2 unified line ("0::<path>") out of
// /proc/self/cgroup content. Empty on anything else (cgroup v1, or a
// malformed read), which the caller treats as "cannot tell".
func parseCgroupPath(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}
