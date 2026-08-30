package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
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

	// OCIRuntime is P10's answer: the runtime name the generated
	// containers.conf pins, or "" for "author no runtime key". Only ever ""
	// or "crun" — see preflightOCIRuntime.
	OCIRuntime string

	// OCIRuntimePath is the absolute path P10 found that name at, and it is
	// authored ALONGSIDE the name so podman's own runtime search list stops
	// being a second, invisible author.
	//
	// Measured on this host: podmanHelperDirs() and podman's default
	// [engine.runtimes] search list are DIFFERENT sets — snug also stats
	// /usr/libexec/podman, /usr/local/libexec/podman, /usr/lib/podman, which
	// podman does not search for a RUNTIME (they are the helper lookup, which
	// is what helper_binaries_dir covers, and a runtime is not a helper). A
	// crun installed only under one of those made P10 author runtime = "crun"
	// for a podman that could then resolve nothing — the exact "fails at
	// create in podman's voice" outcome P10 exists to prevent, reintroduced by
	// P10's own arm. Naming the file removes the disagreement rather than
	// copying podman's list into snug, which would be a copy of state that
	// drifts on a podman upgrade.
	OCIRuntimePath string

	// ResolvConfBind is P7's answer: nil when snug's generated resolv.conf can
	// be bound over the engine's own, non-nil (naming why) when it cannot.
	// Not fatal — see preflightResolvConfBind.
	ResolvConfBind error

	// ToolchainRoot is P9's answer: the one host directory holding the
	// engine's own program files, or "" when this host names none. Empty is
	// the ordinary case and is not a failure — see preflightToolchainRoot.
	ToolchainRoot string
}

func runContainerPreflight(env policy.Environ, pol *policy.Policy) (containerPreflight, error) {
	if err := preflightPtraceScope(); err != nil {
		return containerPreflight{}, err
	}
	podman, err := preflightPodmanBinary(env, pol)
	if err != nil {
		return containerPreflight{}, err
	}
	if err := stage.CheckSubuidDelegation(); err != nil {
		return containerPreflight{}, fmt.Errorf("the container engine needs a delegated subuid/"+
			"subgid range and could not get one: %w", err)
	}
	cgroupsDisabled := preflightCgroupsDisabled()
	crunPath, runcPath := findPodmanHelper("crun"), findPodmanHelper("runc")
	ociRuntime, err := preflightOCIRuntime(crunPath != "", runcPath != "", cgroupsDisabled)
	if err != nil {
		return containerPreflight{}, err
	}
	// The decision above is a pure table over three booleans so it stays
	// testable on a host where the failing case cannot be constructed; the
	// PATH is looked up here, beside it, because only "crun" is ever returned.
	ociRuntimePath := ""
	if ociRuntime == "crun" {
		ociRuntimePath = crunPath
	}
	toolchainRoot, err := preflightToolchainRoot(env, podman)
	if err != nil {
		return containerPreflight{}, err
	}
	return containerPreflight{
		Podman:          podman,
		CgroupsDisabled: cgroupsDisabled,
		OCIRuntime:      ociRuntime,
		OCIRuntimePath:  ociRuntimePath,
		ResolvConfBind:  preflightResolvConfBind(),
		ToolchainRoot:   toolchainRoot,
	}, nil
}

// preflightOCIRuntime is P10, and it exists because P5 SELECTS rather than
// refuses.
//
// P5's `cgroups = "disabled"` is servable only by a runtime that implements
// the mode, and runc does not. Without this, three steps ran in order and
// nobody exited: P5 silently selected the degraded mode, writeContainersConf
// wrote it, and the run then served a working-looking container API that
// failed at create in PODMAN's voice — the 500 quoted in reportPodmanHelpers,
// "requested OCI runtime runc is not compatible with NoCgroups", measured in a
// Tumbleweed CI container with runc present and crun absent. A silent
// downgrade is invariant 5's own case, and the downgrade was snug's.
//
// THE REFUSAL PREDICATE IS ociRuntimeMissing, called rather than restated.
// That function already held this rule, and its only consumers were `snug
// doctor` and doctor's own test — a report that starts nothing and that a user
// need never run. The package that CREATES the condition never asked it. One
// decision, two consumers: doctor reports on it, the run refuses on it.
//
// Returns ("", nil) for "author no runtime key". Where cgroups work both
// runtimes serve, and pinning crun there would refuse nothing but would break
// a runc-only host that works today — a downgrade in the other direction.
//
// The returned name is a snug literal from the closed set {"", "crun"}, never
// a value from a profile, a flag or the environment. Not krun either: a VM
// runtime is in podman's own runtime_supports_nocgroups list and is still not
// an automatic substitution for crun.
//
// The three inputs are parameters rather than lookups so the whole table is
// testable on a host where the failing case cannot be constructed — the same
// seam, for the same reason, that ociRuntimeMissing itself already has.
//
// THE FALSE-REFUSAL COST, stated rather than hidden: P5's probe can be wrong
// in either direction, so a wrong positive on a crun-less host now refuses a
// run that runc might have served. That is invariant 5's preferred direction —
// refuse naming the fix rather than run and fail in a foreign voice — and the
// fix needs no flag and no maintainer decision. It is in the refusal text
// rather than only here.
func preflightOCIRuntime(crun, runc, cgroupsDisabled bool) (string, error) {
	if !ociRuntimeMissing(crun, runc, cgroupsDisabled) {
		if cgroupsDisabled {
			// crun is present — ociRuntimeMissing returns false for
			// cgroupsDisabled only in that case — and it is the only runtime
			// here that implements the mode written four lines away in the
			// same generated file. Pinning it is not choosing a security
			// posture the way default_capabilities or seccomp_profile would
			// be; it is naming the one implementation of a mode snug itself
			// selected, which is why writeContainersConf leaves those
			// unwritten and writes this.
			return "crun", nil
		}
		return "", nil
	}
	if !crun && !runc {
		return "", fmt.Errorf("podman needs an OCI runtime and neither crun nor runc is in any "+
			"directory it searches (%s).\n"+
			"      Fix: install crun", strings.Join(podmanHelperDirs(), ", "))
	}
	return "", errors.New("this host needs crun. snug measured that cgroup delegation is not " +
		"usable here (preflight P5), so every container runs with cgroups disabled — and runc " +
		"does not implement that mode: podman refuses the create with \"requested OCI runtime " +
		"runc is not compatible with NoCgroups\". runc is present and cannot serve here; " +
		"\"crun or runc\" is true of podman and false of snug's configuration.\n" +
		"      This refuses the container engine only; the sandbox itself is unaffected.\n" +
		"      Fix: install crun (package name: crun on openSUSE, Fedora, Debian and Ubuntu)")
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
// engine's own wrapper conventionally
// already reads that exact variable, so this adopts the vocabulary the
// bundle already speaks rather than adding a second one beside it.
//
// The one check it makes is the one that can be made: the resolved engine
// binary must be INSIDE the named root. A root that does not contain the
// binary is a misconfiguration whose symptom would otherwise be an engine
// that cannot exec, and naming it here costs one stat and one resolution of
// root to the same fixed point JudgeEngineToolchain resolves it to — a
// trailing slash, a `..` segment or root itself being a symlink into the
// real installation directory must judge the same way here as it does
// there, or this containment test and JudgeEngineToolchain's own disagree
// about an ordinary human spelling (issue #417 F2).
//
// The variable, the stat and the resolution all come off the INJECTED
// Environ, not os directly. Identical in production (OSEnviron.Getenv is
// os.Getenv, OSEnviron.Stat is os.Stat), and the point is that the run and
// --dry-run read ONE host: buildContainersReport judges this same value
// through JudgeEngineToolchain off the same seam (issue #422), and a
// preflight reading a second sample is how the two screens start
// disagreeing about which string was judged.
func preflightToolchainRoot(env policy.Environ, podman string) (string, error) {
	root := env.Getenv("SNUG_PODMAN_ROOT")
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
	fi, err := env.Stat(root)
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
	// podman is already policy.ResolveEngineBinary's fully-resolved return
	// (preflightPodmanBinary's own doc comment), so comparing it against root
	// AS SPELLED judges two different samples of the host: a trailing slash, a
	// `..` segment, or root itself being a symlink into the real installation
	// directory (a versioned install kept current by relinking, e.g.
	// /opt/podman -> /opt/podman-1.2.3) all made this containment test fail
	// while JudgeEngineToolchain (graft.go), which resolves root the same way
	// this does, clears the identical string — a screen/run disagreement of
	// exactly the kind issue #422 removed everywhere else.
	resolvedRoot, err := policy.ResolveExistingHostPath(env, root)
	if err != nil {
		resolvedRoot = filepath.Clean(root)
	}
	if podman != resolvedRoot && !strings.HasPrefix(podman, resolvedRoot+string(filepath.Separator)) {
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
// involved at all, and the re-measurement under that setting was never run.
// So: REFUSE the run, never warn-and-continue (maintainer decision,
// 2026-08-18; invariant 5). 2 and 3 are STRICTER than 1 (they narrow ptrace
// further) and pass.
// The THRESHOLD is not typed here. It is inheritedSysctl's row (issue #526),
// which `snug doctor` reports from and this function refuses on, so the two
// cannot drift into disagreeing about the number — the ticket asks for
// exactly that, and a second literal `1` in this file is how it would fail.
func preflightPtraceScope() error {
	row := inheritedSysctl("kernel.yama.ptrace_scope")
	// HOSTREAD-EXEMPT: row.path() is "/proc/sys/kernel/yama/ptrace_scope"
	// built from the constant table, a kernel pseudo-file — the same
	// exemption hostsysctl.go's own reader states.
	data, err := os.ReadFile(row.path())
	return judgePtraceScope(row, string(data), err)
}

// judgePtraceScope is P6's DECISION with the host read out of it, so the
// refusal is tested at every value rather than at whatever the machine
// running the suite happens to be set to. The threshold is the caller's row,
// never a literal here.
func judgePtraceScope(row hostSysctl, data string, readErr error) error {
	if readErr != nil {
		// Absent means no Yama LSM at all, i.e. the kernel enforces nothing
		// beyond the ordinary same-uid rule — the same failure mode as 0.
		return fmt.Errorf("cannot read %s (%w): the container "+
			"engine's capability drop is only a meaningful boundary against a same-uid peer when "+
			"Yama's ptrace_scope is enforced at %d or stricter; refusing rather than assuming it is",
			row.path(), readErr, row.want)
	}
	scope, cerr := strconv.Atoi(strings.TrimSpace(data))
	if cerr != nil {
		return fmt.Errorf("%s does not hold a number (%q): refusing rather than assuming Yama "+
			"is enforcing", row.path(), strings.TrimSpace(data))
	}
	if scope < row.want {
		return fmt.Errorf("this host's %s is %d: any same-uid "+
			"process can ptrace any other, with no capability check at all — the container "+
			"engine's own capability drop (dropping CAP_SYS_PTRACE) is not a meaningful boundary "+
			"under this setting, and snug will not run a container engine while pretending it is.\n"+
			"      Fix: sysctl %s=%d (or stricter), or `sudo snug fix sysctl -w`",
			row.path(), scope, row.knob, row.want)
	}
	return nil
}

// preflightPodmanBinary is P1: a real podman binary, not a host-escape shim.
// Promoted from a warning (podmanshim.go's warnAboutPodmanClient, which still
// covers the CLIENT-inside-the-sandbox case) to a REFUSAL here, because a
// shim on the ENGINE path reaches the host's own podman over a filesystem
// socket that no netns touches — the whole tier's guarantee evaporates while
// everything looks healthy (ENGINE-WIRING.md §4, P1).
//
// Every return is pol.ResolveEngineBinary'd immediately before it leaves this
// function, so the value handed to preflightToolchainRoot's containment check
// (below, called on this return value) and to, one field over,
// policy.(*Policy).CheckEngineBinary (container.go's field gate) is the one
// string ResolveEngineBinary already resolved AND judged — not a spelling for
// either of them to judge a second time. Order is load-bearing: the shim
// check above runs on the name AS GIVEN, so issue #396's behaviour and
// message are unchanged — ResolveEngineBinary runs only once a value has
// already cleared that check and is about to be returned.
//
// This comment used to read "no in-model attack needs it" here, arguing the
// resolve step was defence in depth because a writable symlink component
// would already sit inside a rw grant the literal check's ancestor arm
// caught. MEASURED WRONG (redteam): a payload-writable symlink
// $TARGET/podman -> /usr/bin/true was ACCEPTED and exec'd, and the run then
// failed with "the container engine did not create its socket ... within
// 30s" (exit 69) instead of the refusal the regular-file poison got (exit
// 77) — the literal check judged /usr/bin/true, read-only and correctly
// accepted, never the symlinked NAME the payload had actually chosen.
// Measured on this development host: readlink -f $(command -v podman) is
// /usr/bin/podman, already a regular file with no symlink component, so
// neither of ResolveEngineBinary's arms fires here and no existing golden
// moves.
func preflightPodmanBinary(env policy.Environ, pol *policy.Policy) (string, error) {
	// $SNUG_PODMAN is checked FIRST and, when set, is trusted outright rather
	// than run back through DetectHostShim's own PATH lookup below — a caller
	// pointing this at an explicit path is BYPASSING PATH resolution on
	// purpose, and re-resolving "podman" from PATH here would ask the wrong
	// question ("is whatever PATH finds a shim") about a binary the caller
	// never asked to use.
	//
	// THAT BYPASS IS ISSUE #396: the named path is never checked for being a
	// shim itself, so $SNUG_PODMAN pointing at a host-escape helper is
	// accepted by the function whose whole purpose is refusing one.
	if custom := env.Getenv("SNUG_PODMAN"); custom != "" {
		// !IsRegular, not IsDir: a FIFO, a bound AF_UNIX socket or a device
		// node all pass fi.IsDir() == false and were exec'd unrefused, while
		// describeEngineSource's screen already required IsRegular to clear —
		// a screen/run disagreement (issue #417 F3) on top of an exec that
		// would fail in whatever voice the object answers with, not this
		// one's.
		if fi, err := env.Stat(custom); err != nil || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("$SNUG_PODMAN=%s does not name a usable file", custom)
		}
		// ISSUE #396. The named path gets the SAME shim check as a path from
		// PATH. It did not, and the bypass had a rationale that no longer
		// exists: pointing at an explicit path used to mean "a bundle snug
		// ships", so the check was skipped as asking the wrong question. With
		// the fallback retired the variable is a testing seam, and skipping the
		// check means `$SNUG_PODMAN=/usr/bin/podman` on a host where that IS
		// distrobox-host-exec is accepted by the function whose entire purpose
		// is refusing one — which was the configuration this whole subject
		// existed because of.
		//
		// DetectHostShim needs no change to take an absolute path: MEASURED,
		// exec.LookPath("/usr/bin/podman") returns it directly and never
		// consults PATH, while a nonexistent or non-executable path errors. So
		// the fix is asking the question, not building a mechanism.
		if shim, ok := DetectHostShim(custom); ok {
			return "", fmt.Errorf("$SNUG_PODMAN=%s resolves to %s, a host-escape helper (%s) "+
				"that forwards to the HOST's own podman over a channel no network namespace "+
				"touches — a container started through it would land on the host, silently "+
				"contradicting everything --dry-run says about this sandbox's network. snug "+
				"will not run the container engine through it, however it was named.\n"+
				"      Fix: point $SNUG_PODMAN at a real engine binary, or unset it and "+
				"install the distribution podman package.",
				custom, shim.Path, filepath.Base(shim.Resolved))
		}
		// Resolved and judged here, after the shim check ran on custom AS
		// GIVEN (issue #396's ordering), and here specifically because this
		// is the last point before the value leaves this function — see this
		// function's own doc comment for what this discharges and why it is
		// a no-op on this development host.
		return pol.ResolveEngineBinary(env, custom)
	}
	if shim, ok := DetectHostShim("podman"); ok {
		return "", fmt.Errorf("podman resolves to %s, a host-escape helper (%s) that forwards "+
			"to the HOST's own podman over a channel no network namespace touches — a container "+
			"started through it would land on the host, silently contradicting everything "+
			"--dry-run says about this sandbox's network. snug will not run the container engine "+
			"through it.\n"+
			"      Fix: install the distribution podman package, so %s is a real engine binary "+
			"rather than a symlink. To reach the HOST's engine on purpose, add a connection to "+
			"its socket (podman system connection add) — never a symlink here, and never a "+
			"global CONTAINER_HOST, because snug execs podman to run its own engine.",
			shim.Path, filepath.Base(shim.Resolved), shim.Path)
	}
	path, err := env.LookPath("podman")
	if err != nil {
		return "", fmt.Errorf("the podman profile is selected but podman is not installed.\n" +
			"      snug will not silently hand the sandbox no engine, or the host's.\n" +
			"      Install the distribution podman package.")
	}
	// Same resolution and judgement, same reasoning, as the $SNUG_PODMAN
	// return above.
	return pol.ResolveEngineBinary(env, path)
}

// preflightCgroupsDisabled is P5: a real (if approximate) probe of whether
// this host's cgroup delegation is usable, so podman does not fail opaquely
// mid-run the first time it tries to write a controller file.
//
// It returns TRUE when cgroups must be DISABLED — i.e. when the probe could
// not write. It was named ...Writable while returning exactly that, which is
// the opposite of what the name says; the caller's own variable
// (`cgroupsDisabled`) had it right. It is NOT a
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
func preflightCgroupsDisabled() bool {
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
