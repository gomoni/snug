package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/hostread"
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
//	P7  bind over /etc/resolv.conf in a throwaway userns+mountns — WARNS
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

	// ResolvConfBind is P7's answer: nil when snug's generated resolv.conf can
	// be bound over the engine's own, non-nil (naming why) when it cannot.
	// Not fatal — see preflightResolvConfBind.
	ResolvConfBind error

	// SignaturePolicy is P8's answer: nil when the host's own signature
	// policy is the same permissive default snug generates (or absent
	// entirely), non-nil when snug's generated policy.json is WEAKER than
	// what this host configured. Not fatal — see preflightSignaturePolicy.
	SignaturePolicy *signaturePolicyNotice

	// ToolchainRoot is P9's answer: the one host directory holding the
	// engine's own program files, or "" when this host names none. Empty is
	// the ordinary case and is not a failure — see preflightToolchainRoot.
	ToolchainRoot string
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
	toolchainRoot, err := preflightToolchainRoot(podman)
	if err != nil {
		return containerPreflight{}, err
	}
	return containerPreflight{
		Podman:          podman,
		CgroupsDisabled: cgroupsDisabled,
		ResolvConfBind:  preflightResolvConfBind(),
		SignaturePolicy: preflightSignaturePolicy(),
		ToolchainRoot:   toolchainRoot,
	}, nil
}

// preflightToolchainRoot is P9: which host directory the engine's own program
// files live in, for Tier C's derived view (issue #125).
//
// WHY THIS EXISTS AT ALL. Today the engine runs in the stage's private copy of
// the HOST tree, so a podman anywhere on the host is reachable. Under the
// derived view it is not: the engine's view becomes the SANDBOX's plus a
// handful of grafts, and a binary the sandbox's own grants do not expose has
// to be one of them. G4 will not admit a graft of a path nobody named, which
// is the point of G4 — so somebody has to name it, once, before the run.
//
// WHY IT IS USUALLY EMPTY, and why empty is not a failure. An ordinary
// distribution podman lives in /usr/bin, and @sys already binds the OS
// runtime, so `/usr/bin/podman` passes G4's FIRST disjunct — the sandbox can
// see it — and there is nothing for this to record. Empty is the answer for
// every host that has not deliberately installed an engine outside every
// grant.
//
// WHY IT IS NAMED RATHER THAN DERIVED, which is the decision in this function.
// A bundle root is NOT recoverable from the binary path: this host's pinned
// bundle keeps podman at $ROOT/usr/local/bin/podman, others keep it at
// $ROOT/bin/podman, and a distribution podman has no bundle at all — so any
// "walk up N directories" rule is a guess that is wrong on some real layout,
// and grafting one directory too high hands the engine's view a tree nobody
// argued for. $SNUG_PODMAN_ROOT is not invented here either: the pinned
// bundle's OWN wrapper (bin/snug-podman, .claude/design/PODMAN-STATIC.md)
// already reads that exact variable, so this adopts the vocabulary the
// bundle already speaks rather than adding a second one beside it.
//
// The one check it makes is the one that can be made: the resolved engine
// binary must be INSIDE the named root. A root that does not contain the
// binary is a misconfiguration whose symptom would otherwise be an engine
// that cannot exec, and naming it here costs one stat.
func preflightToolchainRoot(podman string) (string, error) {
	root := os.Getenv("SNUG_PODMAN_ROOT")
	if root == "" {
		return "", nil
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("$SNUG_PODMAN_ROOT=%s is not an absolute path.\n"+
			"      It names the host directory the container engine's program files live in, and\n"+
			"      snug resolves it before the sandbox exists — a relative path here would be\n"+
			"      resolved against snug's own working directory and mean something else to every\n"+
			"      other process that reads it.", root)
	}
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("$SNUG_PODMAN_ROOT=%s is not a directory on this host.\n"+
			"      It must name the ROOT of the engine's own installation — the directory that\n"+
			"      contains its binary, its helpers and its configuration — because that whole\n"+
			"      tree is what the engine gets to see once its view stops being a copy of the\n"+
			"      host's.", root)
	}
	if !filepath.IsAbs(podman) {
		return "", fmt.Errorf("$SNUG_PODMAN_ROOT is set but the engine %q is not an absolute path, "+
			"so snug cannot check that the engine lives inside the root it was told about.\n"+
			"      Set $SNUG_PODMAN to an absolute path.", podman)
	}
	if podman != root && !strings.HasPrefix(podman, root+string(filepath.Separator)) {
		return "", fmt.Errorf("$SNUG_PODMAN_ROOT=%s does not contain the engine snug resolved (%s).\n"+
			"      The root is what the engine will be able to execute out of once its view is\n"+
			"      derived from the sandbox's, so a root that does not contain the binary is an\n"+
			"      engine that cannot start — named here rather than as an exec failure later.\n"+
			"      Fix: point $SNUG_PODMAN_ROOT at the directory the engine really lives under, or\n"+
			"      unset it if the engine is somewhere the sandbox's own profiles already grant.",
			root, podman)
	}
	return root, nil
}

// maxSignaturePolicyBytes bounds what P8 reads. A signature policy is a small
// hand-written JSON document — this host's is 233 bytes — and the cap exists
// to make the read finite, not to judge the file: over it, P8 says it could
// not compare rather than pretending the file is permissive.
const maxSignaturePolicyBytes = 1 << 20

// signaturePolicyNotice is what P8 found: a host signature policy that snug's
// generated one does not reproduce, and which file it came from.
type signaturePolicyNotice struct {
	Path   string
	Detail string
}

// String is the whole message, built here rather than at the print site so
// that it can be tested without a preflight, an engine or a host.
//
// BOTH FIELDS GO THROUGH visibleValue. Detail carries a decoder's rendering of
// the host's own file and Path carries $HOME, and this is a stderr message —
// the sink issue #58's red-team round found sitting outside
// TestNoSnugScreenEmitsARawControlCharacter's reach, where a crafted value
// erased the real refusal and wrote a fabricated one in its place. Not
// payload-reachable (it is the host user's own file), so this is screen
// integrity rather than an escape; asserted anyway, because the rule is to
// name every sink a value reaches rather than the site where it was noticed.
func (n *signaturePolicyNotice) String() string {
	return fmt.Sprintf("snug: container images inside this sandbox are NOT signature-verified.\n"+
		"      snug generates the signature policy the engine reads, so that a file snug does "+
		"not control cannot decide which bytes become an image (issue #137).\n"+
		"      Your host's %s is stricter: %s.\n"+
		"      Nothing outside the sandbox is affected: the host's own podman, skopeo and "+
		"buildah keep reading that file.\n", visibleValue(n.Path), visibleValue(n.Detail))
}

// hostSignaturePolicyPaths are the two files containers/image reads a
// signature policy from, in order. $HOME/.config first, then the system one —
// the same order podman prints when it finds neither:
//
//	Error: no policy.json file found at any of the following:
//	  "/home/u/.config/containers/policy.json", "/etc/containers/policy.json"
//
// A distribution file outside these two (openSUSE ships
// /usr/share/containers/policy.json) is deliberately NOT read here: podman
// 5.8.4 does not look at it, so reporting on it would be reporting a
// difference that does not exist.
var hostSignaturePolicyPaths = []string{
	filepath.Join(os.Getenv("HOME"), ".config", "containers", "policy.json"),
	"/etc/containers/policy.json",
}

// preflightSignaturePolicy is P8: does snug's generated policy.json make this
// host's container images LESS verified than the host's own configuration
// would?
//
// snug now authors the signature policy (engine.go's signaturePolicyJSON),
// because it is the one file podman requires and the one with no environment
// variable to point at it — so on a host with no policy.json at all, pulls
// went from failing to working, and on a host with the ordinary permissive
// default nothing changed. On a host that configured signature ENFORCEMENT,
// though, snug has quietly relaxed it, and invariant 5 says a downgrade is
// never silent.
//
// WARNS rather than refuses, for the same reason P7 does: refusing would
// refuse a run over the sandbox's images being verified no more strictly
// than a stock podman verifies them. What it must not do is say nothing.
//
// A file that does not parse is reported too. "snug could not tell whether it
// weakened your policy" is a different sentence from "it did not", and only
// one of them is honest.
func preflightSignaturePolicy() *signaturePolicyNotice {
	for _, path := range hostSignaturePolicyPaths {
		// hostread.Optional rather than os.ReadFile, for the reasons issue
		// #58's third red-team finding measured on the credential path: a FIFO
		// at this path would hang the run in open(2) forever with no output,
		// and a symlink to /dev/zero would be read until memory ran out. A
		// preflight probe that can hang is worse than the probe not existing.
		// (nil, "") is ABSENT, which is the ordinary case and says nothing.
		raw, note := hostread.Optional(path, maxSignaturePolicyBytes)
		if note != "" {
			return &signaturePolicyNotice{Path: path, Detail: note}
		}
		if raw == nil {
			continue // absent, or not ours to read: nothing to compare against
		}
		strict, err := signaturePolicyIsStricterThanSnugs(raw)
		if err != nil {
			return &signaturePolicyNotice{Path: path, Detail: err.Error()}
		}
		if strict {
			return &signaturePolicyNotice{
				Path:   path,
				Detail: "it requires images to satisfy a signature policy, and snug's does not",
			}
		}
		return nil // the host's own is the permissive default: nothing was weakened
	}
	return nil
}

// signaturePolicyIsStricterThanSnugs reports whether raw (a host policy.json)
// demands anything of an image that snug's generated policy does not.
//
// The test is the one that cannot be fooled by structure: EVERY requirement
// in the file — the default list and every transport's — must be
// `insecureAcceptAnything`, which is what snug writes. Anything else (a
// signedBy, a sigstoreSigned, a reject) is strictness this run will not
// reproduce. Unknown keys are ignored on purpose: a requirement type this
// code has never heard of is still not insecureAcceptAnything, so it counts
// as stricter by the same rule.
func signaturePolicyIsStricterThanSnugs(raw []byte) (bool, error) {
	var doc struct {
		Default []struct {
			Type string `json:"type"`
		} `json:"default"`
		Transports map[string]map[string][]struct {
			Type string `json:"type"`
		} `json:"transports"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("snug could not parse it (%v), so it cannot say whether "+
			"the generated policy is weaker", err)
	}
	for _, req := range doc.Default {
		if req.Type != "insecureAcceptAnything" {
			return true, nil
		}
	}
	for _, scopes := range doc.Transports {
		for _, reqs := range scopes {
			for _, req := range reqs {
				if req.Type != "insecureAcceptAnything" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// preflightResolvConfBind is P7: can a file be bind-mounted over
// /etc/resolv.conf at all on this host? __inengine does exactly that, to give
// the engine snug's generated resolver configuration instead of the host's
// (issue #126), and issue #128 measured a perfectly ordinary host where it
// cannot: this distrobox's /etc/resolv.conf is itself a bind mount over a
// DELETED inode, so reading it works and mounting ONTO it returns ENOENT.
//
// WARNS, never refuses, and the difference matters. Since #126's second half
// a container's DNS comes from the generated containers.conf, which needs no
// mount — so this bind failing costs the ENGINE fast offline failure, and
// costs a container nothing. Refusing to start would be refusing over a
// degradation that leaks nothing.
//
// The probe is a throwaway user + mount namespace and NOTHING else: no netns,
// no engine, no podman, no cgroup, and it touches no path except a temporary
// file of its own and the mountpoint it tests. It is an approximation of
// __inengine's real situation in the same way P5 is — __inengine binds inside
// the sandbox's user namespace U with the full delegated subuid range, this
// probe inside a single-uid throwaway one — and the backstop for the two
// disagreeing is __inengine's own warning on the same mount.
//
// It reports by NAME, not by errno: the caller's message says what stopped
// working, because "operation not permitted" from a preflight probe costs an
// hour (CLAUDE.md, "errors name the fix").
func preflightResolvConfBind() error {
	f, err := os.CreateTemp("", "snug-resolvbind-probe-")
	if err != nil {
		return fmt.Errorf("could not create the probe file: %w", err)
	}
	defer os.Remove(f.Name())
	f.Close()

	// A CHILD, because a multithreaded Go process cannot unshare a user
	// namespace itself; /proc/self/exe, never a path from argv or the
	// environment, for the reason stage.execSelf states. The environment is
	// empty for the reason CLAUDE.md's "/proc/1/environ leaked everything"
	// states.
	cmd := exec.Command("/proc/self/exe", "__probebind", f.Name())
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// Denied before the mappings are written; without it the child cannot
		// map its own gid and the probe fails for a reason that is not the
		// one it is asking about.
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// THREE outcomes, not two, and conflating the third with the second was
	// measured wrong in CI: a host that cannot create the throwaway user
	// namespace at all fails here with "fork/exec /proc/self/exe: permission
	// denied", which is the probe being UNABLE TO ASK — not the host
	// answering no. Reporting that as an answer would tell the user their
	// /etc/resolv.conf cannot be replaced when nothing of the sort was
	// measured.
	//
	// The discriminator is an ExitError: the child ran, reached the question
	// and exited 1 with its reason on stderr. Anything else — clone refused,
	// exec refused — never got that far.
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return &probeUnavailableError{err: err}
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	return errors.New(detail)
}

// probeUnavailableError says the P7 probe could not be RUN on this host, as
// distinct from the host answering that the bind fails. The caller stays
// silent on it: a bind that was never attempted is not a degradation to
// announce, and __inengine's own warning still fires loudly if the real bind
// then fails. Not a silent downgrade — nothing was downgraded, and nothing was
// measured either.
type probeUnavailableError struct{ err error }

func (e *probeUnavailableError) Error() string {
	return "preflight P7 could not run its probe: " + e.err.Error()
}
func (e *probeUnavailableError) Unwrap() error { return e.err }

// probeBindResolvConf is the hidden `__probebind` verb's whole body, run in
// the throwaway namespaces preflightResolvConfBind created. It makes its own
// tree private first — so nothing it does can propagate to the host — and then
// performs the ONE mount P7 exists to ask about.
func probeBindResolvConf(argv []string) error {
	if len(argv) != 1 || argv[0] == "" {
		return errors.New("__probebind: usage: __probebind FILE")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making / private: %w", err)
	}
	if err := unix.Mount(argv[0], "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("mounting a file over /etc/resolv.conf: %w", err)
	}
	return nil
}

// preflightPtraceScope is P6. The whole argument that dropping CAP_SYS_PTRACE
// from the engine's capability set closes the in-U peer-read (capdrop.go's
// own doc comment, policy.EngineCapBounding) holds only when
// /proc/sys/kernel/yama/ptrace_scope is 1: at 0 the kernel's own same-uid
// rule alone admits ptrace of a non-descendant peer, with no capability check
// involved at all, and M6's re-measurement under that setting was never run
// (TIER-B.md §1, "Maintainer decisions, settled" — Q2, REFUSE). 2 and
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
