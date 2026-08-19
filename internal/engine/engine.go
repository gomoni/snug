// Package engine computes the paths and launch spec for a container engine
// that belongs to one sandbox, and tears it down again.
//
// It is never the host's podman. A sandbox gets its own store, its own runroot
// and its own service process, so:
//
//   - the host's images, containers, volumes and networks are untouched, and
//     the sandbox cannot list or delete them
//   - two projects cannot see each other's containers
//   - a more privileged profile set never inherits a store built under a less
//     privileged one, because the store key includes the profile set
//
// # The engine runs in the sandbox's own network namespace (issue #63, Tier B)
//
// It used to be a plain host process, on the host's own network namespace,
// meaning a container it started reached the internet even from an offline
// sandbox (ENGINE-NETNS.md §0, the finding this tier closes). The engine is
// now forked by internal/stage, EAGERLY, as a second long-lived child of the
// stage (P1) alongside bwrap — this package no longer starts it directly. It
// computes the paths (Engine.New), builds the stage.EngineSpec the stage's
// StartEngine consumes (Engine.Spec), and tears the result down again
// (Engine.Stop) — the fork, the setns into N, the private mount-namespace
// copy and the capability drop all live in internal/stage (EnterEngine,
// __inengine) because they need the stage's own raw-fork machinery and its
// membership in the sandbox's user namespace U.
//
// # Teardown, and why it is not just a kill
//
// The engine process itself dies WITH the stage: it is Pdeathsig'd to P1,
// which is itself Pdeathsig'd (and lifeline-held) to P0, so engine ⊂ P1 ⊂ P0
// and any death of snug cascades down to it. That REPLACES this package's old
// job of killing the engine process directly — Stop below no longer signals
// it at all. What Stop still owns:
//
//  1. lifeline.go — the engine runs with a finite idle timeout and snug holds
//     one streaming request open, dialled at its (now /tmp) socket. This is
//     what keeps a live run's engine up through idle stretches; its old
//     "keep a wrapper engine alive long enough to reap it" role is gone now
//     that preflight P1 refuses a wrapper outright and the engine is always a
//     real stage child.
//  2. reaper.go — a pipe-triggered helper stops this run's CONTAINERS (never
//     the engine process) when snug dies without cleaning up. Read the note
//     below on what issue #125's C0 did to the fact this helper was built
//     for: it is now REDUNDANT on every measured path, and it stays.
//  3. reap.go — Stop's own ordinary-path teardown: stop containers by label
//     while the engine is still live, THEN verify by sweeping for processes
//     that still name this run's socket path. "The kill returned no error" is
//     not evidence anything died; the sweep is.
//
// # Where containers live now, and what that did to the reaper (issue #125, C0)
//
// This package's teardown was designed around one sentence, and C0 falsified
// it: "containers are not the engine's children — conmon double-forks and its
// grandchild reparents in the HOST pid namespace, because the engine does not
// unshare pid — so they outlive the engine". C0 gave the engine CLONE_NEWPID
// at its own clone (internal/stage/enginefork.go) and a fresh procfs
// (internal/stage/inengine.go), which changed all three clauses. MEASURED on
// this host, A/B against C0's own parent commit, with a real pinned podman
// bundle and a long-running container (test/integration/testdata/holder):
//
//	                         pre-C0 (HEAD)              with C0
//	engine /proc/<p>/ns/pid  the HOST's own inode       its own, distinct
//	conmon's PPid (host      an ancestor init in the    the ENGINE itself,
//	  procfs)                  HOST pid namespace         which is pid 1 there
//	container init           a descendant pidns of      a descendant pidns of
//	                           the HOST's                 the ENGINE's
//	SIGKILL the engine,      container STILL RUNNING    container gone within
//	  nothing else             10s later                  one 250ms poll tick
//	recorded conmon.pid /    host pids, matching        SMALL numbers, valid
//	  pidfile in the runroot   /proc exactly              only inside the engine
//
// conmon still double-forks; what changed is which init adopts the orphan.
// Pid 1 of the engine's pid namespace is podman itself (execve does not change
// pid), so the orphan reparents ONTO THE ENGINE, and the kernel's rule that
// destroying a pid namespace SIGKILLs every member and every member of its
// descendant namespaces now covers the containers too.
//
// Consequences, in the order they matter:
//
//   - The reaper is REDUNDANT on every path measured, not wrong. The engine is
//     Pdeathsig'd to P1 and P1 to P0, so any death of snug — SIGKILL included —
//     fells the engine, and the namespace collapse takes the containers with
//     it. Measured end to end: SIGKILL snug, and the engine, the container and
//     the socket-path sweep were all clean inside 70ms — far faster than the
//     reaper could fork a `podman stop` even if it were the mechanism. It is
//     LEFT IN PLACE deliberately: removing a teardown mechanism is a
//     maintainer's call, not a side effect of correcting a comment, and this
//     one costs nothing on the clean path (Stop tells it to stand down).
//   - reap.go's host-/proc sweep is UNAFFECTED and still correct. A nested pid
//     namespace does not hide its members from an ancestor's procfs: every
//     process in the engine's namespace is still enumerable under
//     /proc/<host-pid>/ with a readable cmdline, which is all the sweep needs.
//     Measured: one process named this run's socket path while the engine was
//     live, zero after it died.
//   - The ORDERING in Stop is still right, for a NEW reason. Containers no
//     longer outlive the engine, so stopping them first is no longer about
//     reaching something that would otherwise be orphaned — it is the
//     difference between a graceful `podman stop` and the kernel SIGKILLing
//     them when the namespace collapses.
//   - NOT fixed here, and a finding rather than a comment: the runroot's
//     recorded conmon.pid and pidfile are now pids in the ENGINE's pid
//     namespace. Measured on the same container in both eras — pre-C0 they
//     read 1954739/1954741 and matched /proc exactly; with C0 they read
//     168/170 while the host pids were seven digits. So the HOST-side `podman
//     stop` in stopLocked below, and the identical command in reaperScript,
//     are reading pid numbers that mean nothing in their own numbering. See
//     stopLocked's own comment on step 1.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
)

// idleTimeout is how long the engine outlives its last client. Never
// `--time 0`, which would disable the timeout and make the engine the daemon
// this project says it does not run. Short enough that a hard kill is cleaned
// up while the human is still looking at the terminal; long enough that a
// slow re-dial of the lifeline cannot expire it.
const idleTimeout = 10 * time.Second

// quietBudget bounds how long Stop waits for this run's containers to go away
// before it gives up and says so. It exceeds idleTimeout so that the
// lifeline alone is enough to reach a verified-clean state even when the
// direct filtered stop below could not land.
const quietBudget = idleTimeout + 5*time.Second

// RunLabelKey is the container label snug stamps every container it creates
// with, so that teardown can reach this run's containers and only those.
//
// A dotted, namespaced key rather than a bare word: labels are a flat namespace
// shared with whatever the image and the user set, and `run` alone would be a
// plausible thing for someone else to mean.
const RunLabelKey = "snug.run"

type Engine struct {
	sock     string
	runroot  string
	store    string
	runDir   string
	runLabel string

	// podman and env are what Stop needs to run a HOST-SIDE `podman stop`
	// against this run's store — set once, from the same values Spec() puts
	// into the stage.EngineSpec, so the two never diverge (invariant 6's
	// spirit applied within this package: one source of the engine's own
	// identity).
	podman string
	env    []string

	mu   sync.Mutex
	life *lifeline
	reap *reaper
	once sync.Once
}

// New computes the paths for a sandbox's engine but starts nothing.
//
// The STORE key is derived from the profile set AND the target, so the same
// project with the same profiles reuses its images across runs (a warm
// start) while a different project — or the same project with wider profiles
// — gets a different store. It stays under XDG_DATA_HOME, unaffected by
// issue #63 Tier B: nothing about WHERE the engine runs changes what should
// persist across runs.
//
// The SOCKET lives under /tmp/snug-<uid>-<pid>/ (issue #63, Tier B,
// ENGINE-WIRING.md §3.1), hardened and unique to THIS run — createRunDir
// refuses to reuse an existing entry at that path, the same discipline
// commit dfe6ac8 (#61, #85) applied to snug's own runtime directory. That is
// what teardown matches on (see reap.go): the store is shared with every
// past and concurrent sandbox that resolved to the same key, so killing
// "whatever names the store" would reach into a sibling sandbox that is
// still working.
//
// The RUNROOT, MEASURED, must NOT be pid-unique the way the socket is, and
// that is a correction of what ENGINE-WIRING.md §3.1 assumed: podman's own
// libpod database, which lives IN the persisted store, records the runroot
// path a run used and REFUSES a later run against the same store with a
// DIFFERENT one ("database run root ... does not match"). A store that
// persists across runs (by design, for a warm start) needs a runroot that is
// STABLE across those same runs — exactly like ordinary rootless podman's
// own default ($XDG_RUNTIME_DIR/containers, stable for a login session) — so
// it is keyed by the SAME profiles+target key as the store, not by pid, and
// created with the SAME shared, first-writer-wins MkdirAll the store already
// uses. It still lives under /tmp, not $XDG_RUNTIME_DIR — that half of §3.1's
// reasoning (a root-in-userns podman masks $XDG_RUNTIME_DIR with its own
// tmpfs on /run) is unaffected by this correction.
func New(profiles []policy.ProfileName, target string) (*Engine, error) {
	sorted := policy.NameStrings(profiles)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, ",") + "\x00" + target))
	key := hex.EncodeToString(sum[:])[:16]

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}

	pid := os.Getpid()
	runDir := filepath.Join(os.TempDir(), runDirName(os.Getuid(), pid))
	if err := createRunDir(runDir); err != nil {
		return nil, err
	}

	e := &Engine{
		// runLabel is what teardown stops, and it identifies THIS RUN rather
		// than the store. The store is shared on purpose — that is what makes
		// a warm start warm — so `stop --all` scoped to it stopped a
		// concurrent sibling's containers as collateral. The proxy stamps
		// this label on every container it creates; Stop and the reaper both
		// filter on it, so a teardown reaches exactly the containers this run
		// started.
		runLabel: fmt.Sprintf("%s=%d", RunLabelKey, pid),

		store:   filepath.Join(dataHome, "snug", "engines", key, "storage"),
		runDir:  runDir,
		runroot: filepath.Join(os.TempDir(), fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key), "rr"),
		sock:    filepath.Join(runDir, fmt.Sprintf("podman-%d.sock", pid)),
	}
	for _, d := range []string{e.store, e.runroot} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			_ = os.RemoveAll(runDir)
			return nil, err
		}
	}
	return e, nil
}

func (e *Engine) Socket() string { return e.sock }

// RunLabel is the `key=value` this run's containers are stamped with. The proxy
// applies it at create; teardown filters on it.
func (e *Engine) RunLabel() string { return e.runLabel }

// Spec builds the stage.EngineSpec that Stage.StartEngine consumes: exactly
// what this run's engine execs into, chosen entirely by P0. podman is the
// preflight-checked path to a real binary; baseEnv is the explicit, minimal
// environment the caller built (PATH, and anything a pinned podman bundle
// needs, e.g. CONTAINERS_STORAGE_CONF) — XDG_RUNTIME_DIR is added here,
// pointing at this run's own runroot, so the caller never has to know that
// path.
//
// HOME is Spec's, not the caller's, and so are CONTAINERS_REGISTRIES_CONF and
// REGISTRY_AUTH_FILE: everything podman reads out of a home directory is a
// second author of what a container IS or what it may authenticate as
// (issues #137, #142), and the files those variables point at are generated
// here beside the containers.conf below. Every one of them is SET rather than
// appended (see setEnv), because a duplicate loses to the caller's entry and
// the only symptom would be the feature not being there.
//
// cgroupsDisabled is preflight P5's own
// measured selection (ENGINE-WIRING.md §4): when this host's cgroup
// delegation does not survive even the private cgroup namespace __inengine's
// own fork creates, podman needs `cgroups = "disabled"` as its DEFAULT for
// every container it creates. That is a containers.conf setting, not an argv
// flag on `system service` — so it is GENERATED into a file under this run's
// own /tmp directory and pointed at by CONTAINERS_CONF, never handed over
// inline (the same "pointer, not inline value" rule CLAUDE.md states for
// GIT_CONFIG_GLOBAL, PIP_CONFIG_FILE and friends).
//
// Spec also remembers podman and the final env on the Engine itself, so
// Stop's own host-side `podman stop` (reap.go) uses the IDENTICAL values
// rather than a second, potentially-diverging computation.
//
// resolvConf is the generated /etc/resolv.conf content the caller's resolved
// Policy already produced for the sandbox payload (policy.NetPolicy.ResolvConf)
// — the SAME bytes, not a second computation of them. Spec writes it to a
// file under this run's own hardened /tmp directory and returns its path in
// EngineSpec.ResolvConfPath; EnterEngine bind-mounts that path over the
// engine's own /etc/resolv.conf so a container never learns the host's real
// DNS config (issue #126).
func (e *Engine) Spec(podman string, baseEnv []string, cgroupsDisabled bool, net policy.NetPolicy) (stage.EngineSpec, error) {
	finalEnv := setEnv(append([]string{}, baseEnv...), "XDG_RUNTIME_DIR", e.runroot)

	// HOME is snug's, not the host user's (issues #137, #142). Everything
	// podman reads out of a home directory — registries.conf, policy.json,
	// storage.conf, auth.json — is then a file this run authored or a file
	// that does not exist. The two channels that have an environment
	// variable of their own are ALSO pointed at explicitly below, because
	// which home a rootless podman believes in is a version-dependent
	// question (see writeEngineHome) and an environment variable is not.
	engineHome, err := e.writeEngineHome()
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "HOME", engineHome)

	registriesPath, err := e.writeRegistriesConf()
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "CONTAINERS_REGISTRIES_CONF", registriesPath)

	authPath, err := e.writeAuthFile()
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "REGISTRY_AUTH_FILE", authPath)

	confPath, err := e.writeContainersConf(cgroupsDisabled, net.Resolver())
	if err != nil {
		return stage.EngineSpec{}, err
	}
	// BOTH variables, and they are not redundant. CONTAINERS_CONF REPLACES
	// the host's /etc/containers/containers.conf and
	// $HOME/.config/containers/containers.conf, which is the structural half:
	// keys snug never thought to name cannot reach the engine at all.
	// CONTAINERS_CONF_OVERRIDE is loaded LAST, after everything else, which is
	// the half that survives a later export of CONTAINERS_CONF by something
	// between here and the engine (issue #133 is exactly that, in the test
	// wrapper). Setting only the first is defeated by such an export; setting
	// only the second leaves the host's files loaded underneath and reduces
	// the guarantee to "every key snug remembered to enumerate".
	finalEnv = setEnv(finalEnv, "CONTAINERS_CONF", confPath)
	finalEnv = setEnv(finalEnv, "CONTAINERS_CONF_OVERRIDE", confPath)

	resolvConfPath, err := e.writeResolvConf(net.ResolvConf())
	if err != nil {
		return stage.EngineSpec{}, err
	}

	e.podman = podman
	e.env = finalEnv

	argv := []string{
		"--root", e.store,
		"--runroot", e.runroot,
		// NOT --time 0. The idle timeout is the engine's own "my client went
		// away", and the lifeline (lifeline.go) is what keeps it from firing
		// while the sandbox lives.
		"system", "service", "--time", strconv.Itoa(int(idleTimeout.Seconds())),
		"unix://" + e.sock,
	}

	return stage.EngineSpec{
		Podman: podman, Argv: argv, Env: finalEnv, Sock: e.sock, ResolvConfPath: resolvConfPath,
	}, nil
}

// writeContainersConf generates THE containers.conf this run's engine reads —
// the only one, because Spec points both CONTAINERS_CONF and
// CONTAINERS_CONF_OVERRIDE at it. It lives under this run's own (already
// hardened, 0700, host-uid-owned) /tmp directory, and it is a POINTER handed
// over as an environment variable, never an inline value: the same rule
// CLAUDE.md states for GIT_CONFIG_GLOBAL, PIP_CONFIG_FILE and friends.
//
// Three separate jobs, in one file because podman gives us one file:
//
//  1. cgroupsDisabled — preflight P5's measured selection (ENGINE-WIRING.md
//     §4). A containers.conf setting, not an argv flag on `system service`,
//     which is why this file existed before the other two jobs did.
//
//  2. DNS and hosts (issue #126). podman generates every container's
//     /etc/resolv.conf FROM the engine's own unless containers.conf names DNS
//     explicitly, and its /etc/hosts from the host's /etc/hosts unless
//     base_hosts_file says otherwise — so without these keys an OFFLINE
//     sandbox's container still learned the host LAN's nameservers, search
//     domain and hostname table. Neither is a client-requested mount, so the
//     proxy's bind filter (internal/dockerproxy/create.go) never sees them
//     and --dry-run never mentions them. Configuration rather than the
//     resolv.conf bind alone because the bind is best-effort: it needs a
//     mount over the engine's /etc/resolv.conf to succeed, which issue #128
//     measured can fail on a perfectly ordinary host, and a container must
//     not learn host DNS just because a mount did not take.
//
//  3. The keys a host containers.conf would otherwise have supplied (issue
//     #132) — mounts/volumes inject host PATHS, devices injects a host device
//     NODE, env injects variables and env_host passes the engine's whole
//     environment, hooks_dir names PROGRAMS run on every container's
//     lifecycle. All of them on EVERY container and none of them
//     client-requested. CONTAINERS_CONF already stops those files being read
//     at all; naming the keys anyway is CLAUDE.md's "never trust a helper's
//     default, in either direction".
//
//     BE PRECISE ABOUT WHAT THAT SECOND LINE OF DEFENCE COVERS, because the
//     first version of this comment claimed more than the code delivered and
//     a red-team pass measured the gap. The enumeration is NOT the complete
//     set of containers.conf keys that reach a container. It is the set that
//     can be closed WITHOUT choosing a value on podman's behalf.
//     default_capabilities, default_sysctls, default_ulimits, seccomp_profile
//     and userns are deliberately absent: emptying or pinning any of them
//     overrides podman's own default for every container, which is a policy
//     decision this file must not make silently. For those keys the guarantee
//     is CONTAINERS_CONF's replacement and nothing else — issue #136 carries
//     the residual and the measurement.
//
//     What the enumeration IS worth was measured, against a hostile
//     containers.conf on CONTAINERS_CONF and this file on
//     CONTAINERS_CONF_OVERRIDE: `env = ["INJECTED_BY_CONF=leaked"]` reaches a
//     container when nothing closes it, and does not when `env = []` is
//     written here. That is the merge-future this list exists for, and it is
//     also the shape the test wrapper already produces today (issue #133).
//
// res is policy.NetPolicy.Resolver() — the SAME derivation the sandbox
// payload's own /etc/resolv.conf comes from, taken as VALUES rather than by
// parsing the rendered file back, so the two cannot diverge (invariant 6).
func (e *Engine) writeContainersConf(cgroupsDisabled bool, res policy.ResolverConfig) (string, error) {
	path := filepath.Join(e.runDir, "containers.conf")

	var b strings.Builder
	b.WriteString("# snug: generated for this run. Pointed at by both CONTAINERS_CONF and\n" +
		"# CONTAINERS_CONF_OVERRIDE, so this is the ONLY containers.conf the engine reads:\n" +
		"# the host's /etc/containers/containers.conf and ~/.config/containers/containers.conf\n" +
		"# are not merged in (issue #132).\n" +
		"[containers]\n")

	if cgroupsDisabled {
		b.WriteString("\n# preflight P5 measured that this host's cgroup delegation does not survive\n" +
			"# even the engine's own private cgroup namespace.\n" +
			"cgroups = \"disabled\"\n")
	}

	// dns_servers is never written EMPTY: podman reads an empty list as "not
	// configured" and falls back to the engine's own /etc/resolv.conf, which
	// is precisely the leak this closes. Offline therefore names a server
	// that cannot resolve anything instead of naming none — measured against
	// podman 5.8.4, which writes it through literally, so the container's
	// resolver has an unusable nameserver and fails fast rather than
	// inheriting the host's. Assert the EFFECT (no host resolver reaches a
	// container) rather than this file's bytes: a podman that starts treating
	// "none" as "no nameservers at all" satisfies the same requirement.
	servers := res.Servers
	if len(servers) == 0 {
		servers = []string{"none"}
	}
	b.WriteString("\n# DNS, from the resolved policy (issue #126) — the same derivation the\n" +
		"# sandbox payload's own /etc/resolv.conf comes from.\n")
	fmt.Fprintf(&b, "dns_servers = %s\n", tomlStringList(servers))
	// All three keys, as a set. dns_servers alone still leaked the host's
	// search domain, measured: podman copies `search` from the engine's own
	// resolv.conf when dns_searches does not name one.
	fmt.Fprintf(&b, "dns_searches = %s\n", tomlStringList(res.Searches))
	fmt.Fprintf(&b, "dns_options = %s\n", tomlStringList(res.Options))

	b.WriteString("\n# The host's /etc/hosts is a hostname table for the host's networks, and\n" +
		"# podman copies it into every container by default (issue #126).\n" +
		"base_hosts_file = \"none\"\n")

	b.WriteString("\n# Nothing is mounted, no device is passed, no environment is inherited or\n" +
		"# injected, and no lifecycle hook runs, except what a client asks for and the\n" +
		"# proxy's own filter then allows (issue #132).\n" +
		"mounts = []\n" +
		"volumes = []\n" +
		"devices = []\n" +
		"env = []\n" +
		"env_host = false\n" +
		"http_proxy = false\n" +
		"annotations = []\n" +
		"privileged = false\n")

	// hooks_dir is an [engine] key, NOT a [containers] one, and it spent one
	// commit in the wrong table where podman silently ignored it — an unknown
	// key in containers.conf is not an error, so the only symptom of writing
	// it in the wrong place is the feature not being there. It names
	// DIRECTORIES OF PROGRAMS the OCI runtime executes for every container,
	// which is a command table rather than data, so it is the one key in this
	// file whose misplacement would have mattered most.
	b.WriteString("\n[engine]\n" +
		"# Directories of programs run for every container. A command table,\n" +
		"# not data (issue #132).\n" +
		"hooks_dir = []\n")

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// tomlStringList renders a TOML array of basic strings. The values it is given
// are addresses, `.` and resolver options that policy.NetPolicy produced, none
// of which can contain a quote or a backslash; it refuses rather than escaping
// so that a future caller with untrusted values does not get a silently
// mangled config file.
func tomlStringList(vs []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range vs {
		if i > 0 {
			b.WriteString(", ")
		}
		if strings.ContainsAny(v, "\"\\\n\r\x00") {
			// Unreachable from policy.NetPolicy today; see the doc comment.
			v = "snug-refused-unquotable-value"
		}
		fmt.Fprintf(&b, "%q", v)
	}
	b.WriteByte(']')
	return b.String()
}

// setEnv sets one variable in a `KEY=VALUE` environment, REPLACING an
// existing entry rather than appending a second one.
//
// Appending is what this used to do, and it is wrong for a variable a caller
// might also have set: execve preserves duplicates in order and glibc's
// getenv returns the FIRST match, so an appended override is silently the
// loser. The failure mode is the one CLAUDE.md warns about — the flag is
// present in the argv (here: the variable is present in the environment) and
// the feature is not there.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// writeEngineHome creates the home directory this run's engine is given
// INSTEAD of the host user's, and returns its path.
//
// The host's home is a second author of what a container IS (issue #137).
// CONTAINERS_CONF closed containers.conf outright, but podman reads more than
// one file out of a home directory and the rest have no such variable:
//
//   - $HOME/.config/containers/policy.json — the signature policy. It decides
//     whether an image may be used at all, it is REQUIRED (podman refuses to
//     pull without one), and it is the one file here with NO environment
//     variable and no flag: podman 5.8.4 has no --signature-policy at all,
//     and a per-command flag would not reach an API-driven pull anyway. A
//     home of our own is the only lever, which is the same conclusion
//     PODMAN-STATIC.md §5 reached for the research bundle.
//   - $HOME/.config/containers/registries.conf — where an image comes from.
//     Also closed by CONTAINERS_REGISTRIES_CONF below; both, for the reason
//     the next paragraph gives.
//   - $HOME/.config/containers/auth.json and $HOME/.docker/config.json — the
//     host user's REGISTRY CREDENTIALS (issue #142). Also closed by
//     REGISTRY_AUTH_FILE below.
//   - $HOME/.config/containers/storage.conf — where the store is. Already
//     overridden by the explicit --root/--runroot in the argv.
//
// BE PRECISE ABOUT WHAT THIS LEVER IS WORTH, because it is the weakest of the
// three used here. MEASURED against podman 5.8.4 (the pinned bundle this
// host gives snug through $SNUG_PODMAN): with the host's HOME the engine
// resolved a live credential out of ~/.docker/config.json, and with a home of
// its own it resolved none. But a rootless podman is free to derive "the
// user's home" from the passwd entry rather than from $HOME, in which case
// this closes nothing on that version — which is exactly why policy.json's
// two neighbours are ALSO pointed at by their own environment variables. The
// residual, stated plainly: on such a podman the host's policy.json is still
// read, so signature policy stays host-authored. Nothing else does.
func (e *Engine) writeEngineHome() (string, error) {
	home := filepath.Join(e.runDir, "home")
	confDir := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", confDir, err)
	}
	path := filepath.Join(confDir, "policy.json")
	if err := os.WriteFile(path, []byte(SignaturePolicyJSON), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return home, nil
}

// SignaturePolicyJSON is the signature policy this run's engine reads.
//
// Exported for ONE reader: containerpreflight.go's P8, which compares the
// host's own policy against it. A second copy of "what snug considers
// permissive" living in the preflight would be a fact stored twice, and the
// half that drifts would be the one that decides whether a downgrade is
// announced.
//
// It is podman's own shipped default, verbatim in meaning: accept any image,
// verify no signature. Choosing it is not a hardening decision and must not
// be read as one — a stricter policy (requiring a signature) would refuse
// every image on Docker Hub and make the container profiles unusable, and
// snug has no vocabulary in which a user could say which keys they trust.
// What this file buys is that the ANSWER IS SNUG'S: today the answer is
// whatever the host happens to have, or on a host with no policy.json at all
// (measured: openSUSE ships only /usr/share/containers/policy.json, which
// podman 5.8.4 does not look at) the answer is "no pull works", which is a
// host-dependent failure a sandbox should not inherit.
//
// The downgrade case — a host that configured a STRICTER policy than this —
// is not silently accepted: containerpreflight.go's P8 reads the host's own
// policy.json and says so before the run (CLAUDE.md invariant 5).
const SignaturePolicyJSON = `{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ]
}
`

// writeRegistriesConf generates the registries.conf this run's engine reads,
// and returns its path for CONTAINERS_REGISTRIES_CONF.
//
// What a host registries.conf authors is IMAGE PROVENANCE, which is a
// different question from every other key snug has taken over so far:
// `unqualified-search-registries` decides what a bare `alpine:3.20` resolves
// to, and `[[registry]]` + `[[registry.mirror]]` redirect a FULLY QUALIFIED
// pull somewhere else entirely. So a file snug did not write decided which
// bytes became the image a container ran, and neither --dry-run nor the
// proxy's bind filter said a word about it (issue #137).
//
// The value is podman's own upstream default and nothing else. That is a
// deliberate choice between two defensible ones:
//
//   - EMPTY (no search registry) is the deny-by-default reading: a bare name
//     resolves to nothing, every image must be named in full. It is more in
//     keeping with the guiding principle, and it breaks `FROM alpine` in
//     every Dockerfile the sandbox builds.
//   - docker.io, written here, reproduces what a stock podman on a stock host
//     does. It is not a widening of anything: the alternative to snug naming
//     docker.io is the HOST file naming docker.io, which is what happens
//     today.
//
// The second was chosen because the security difference between them is
// small — either way the answer is deterministic and no longer the host's —
// while the ergonomic difference is not. It is one line to change, and
// --dry-run states the value, so nobody has to read this file to find out
// what a short name means inside.
//
// No [[registry]] block is written at all, so no mirror, no rewrite and no
// insecure (non-TLS) registry can be reached through configuration this run
// authored.
func (e *Engine) writeRegistriesConf() (string, error) {
	path := filepath.Join(e.runDir, "registries.conf")
	const content = `# snug: generated for this run. Pointed at by CONTAINERS_REGISTRIES_CONF, so
# the host's /etc/containers/registries.conf and
# ~/.config/containers/registries.conf are not read (issue #137).
#
# podman's own default, chosen so that a short image name means the same thing
# inside the sandbox as it does on a stock host — with snug as the author of
# that fact rather than a file snug does not control. No [[registry]] block:
# no mirror, no rewrite, no insecure registry.
unqualified-search-registries = ["docker.io"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// writeAuthFile generates the EMPTY registry authentication file this run's
// engine reads, and returns its path for REGISTRY_AUTH_FILE.
//
// Without it, containers/image walks its ordinary search order and lands on
// the host user's own credentials — $XDG_RUNTIME_DIR/containers/auth.json is
// absent by construction (snug points XDG_RUNTIME_DIR at this run's runroot),
// so the fall-through reaches $HOME/.config/containers/auth.json and then
// $HOME/.docker/config.json. MEASURED on this host: a live credential for a
// private registry resolved out of the latter (issue #142).
//
// That is not a configuration leak, it is a CREDENTIAL one, and it is
// payload-reachable: the proxy allows the images tree, so a payload with
// @net can make the engine pull — and PUSH — as the host user. It cannot read
// the credential's bytes, which is why #142 is medium rather than high; what
// it gets is use of the host user's identity against a system outside the
// sandbox.
//
// Empty rather than projected, deliberately. A subset would need a rule for
// WHICH registries a sandbox may authenticate to, and snug has no vocabulary
// for that; inventing one in order to hand over a credential is the wrong
// direction. The cost is stated plainly instead: no registry login is
// possible from inside, so a private image cannot be pulled.
func (e *Engine) writeAuthFile() (string, error) {
	path := filepath.Join(e.runDir, "auth.json")
	if err := os.WriteFile(path, []byte("{\n    \"auths\": {}\n}\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// writeResolvConf writes resolvConf (the caller's already-resolved
// policy.NetPolicy.ResolvConf() bytes) to this run's own hardened /tmp
// directory, so EnterEngine can bind-mount it over the engine's own
// /etc/resolv.conf (issue #126) — a pointer, never the content itself,
// crossing the same startengine request the cgroups-disabled config does.
func (e *Engine) writeResolvConf(resolvConf []byte) (string, error) {
	path := filepath.Join(e.runDir, "resolv.conf")
	if err := os.WriteFile(path, resolvConf, 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// ArmReaper starts the pipe-triggered teardown helper (reaper.go) that stops
// this run's containers if snug dies without cleaning up.
//
// Called by the caller BEFORE sandbox.Run even begins — deliberately not
// tied to whether the engine has actually started yet, unlike DialLifeline
// below, because arming it early is what covers a snug killed during the
// stage's own startup window (creating U+N, waiting for the network), before
// the engine has been forked at all. It needs only paths and the podman
// binary, all of which Spec has already fixed on the Engine by the time this
// is called; it does not need the engine's socket to exist yet.
func (e *Engine) ArmReaper() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := startReaper(e.podman, e.store, e.runroot, e.sock, e.runLabel)
	if err != nil {
		return err
	}
	e.reap = r
	return nil
}

// ReaperPIDs names the reaper process, if one is armed, for the ONE caller
// entitled to know: whatever is about to hand sandbox.Options a list of pids
// the signalled-teardown sweep must not kill (issue #113).
//
// A slice rather than an int because the answer is genuinely "zero or one" and
// a zero pid is a dangerous thing to pass to something that signals — see
// sandbox.Options.excludeSet, which drops it again as a second defence.
//
// The reaper is the only process snug starts that the sweep must spare, and
// the reason is the same one reaper.go gives for its missing Pdeathsig: its
// whole job is to outlive snug and stop this run's containers when snug did
// not get to. A guard that killed it would be killing the thing that exists
// because the guard might not run.
func (e *Engine) ReaperPIDs() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reap == nil || e.reap.cmd == nil || e.reap.cmd.Process == nil {
		return nil
	}
	return []int{e.reap.cmd.Process.Pid}
}

// DialLifeline opens the keepalive stream (lifeline.go) that ties the
// engine's lifetime to this sandbox. Unlike ArmReaper, this NEEDS the
// engine's socket to already exist, so the caller runs it from
// sandbox.Options.OnEngineReady — after Stage.StartEngine has confirmed the
// socket is there, before the payload is forked. A failure here is fatal to
// the whole run (invariant 5): without the lifeline a hard-killed snug would
// leave a finite-timeout-but-not-yet-expired engine running for up to
// idleTimeout with nothing to shorten it, so snug refuses to hand the
// sandbox an engine it cannot guarantee to reap promptly.
func (e *Engine) DialLifeline() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	life, err := dialLifeline(e.sock)
	if err != nil {
		if e.reap != nil {
			e.reap.standDown()
			e.reap = nil
		}
		return fmt.Errorf("the container engine came up but would not accept the keepalive\n"+
			"      stream that ties its lifetime to this sandbox (%v).\n"+
			"      Without it a hard-killed snug would leave the engine running, so snug\n"+
			"      refuses to hand the sandbox an engine it cannot guarantee to reap", err)
	}
	e.life = life
	return nil
}

// Stop tears the engine's CONTAINERS down and verifies. The engine PROCESS
// itself is not signalled here at all: it is Pdeathsig'd to the stage (P1),
// which is Pdeathsig'd (and lifeline-held) to P0, so it dies with the stage
// on every path — clean exit, panic, SIGKILL. What is left for this to do is
// exactly what Pdeathsig cannot reach: containers are not the engine's
// children, so they outlive it whatever kills it.
func (e *Engine) Stop() {
	e.once.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopLocked()
	})
}

func (e *Engine) stopLocked() {
	// Everything snug runs itself is excluded from the sweep, or teardown
	// would find its own cleanup and call it a leak.
	exclude := map[int]bool{os.Getpid(): true}
	if e.reap != nil && e.reap.cmd.Process != nil {
		exclude[e.reap.cmd.Process.Pid] = true
	}

	// 1. Containers, FIRST — and the reason changed under issue #125's C0
	//    without the ordering changing. It used to read "not the engine's
	//    children, and they outlive it": true pre-C0, false now (see the
	//    package comment's measurement). Containers are inside the engine's
	//    own pid namespace since C0, so the engine's death already fells
	//    them. What this step still buys is that they get a GRACEFUL stop
	//    while the engine is live, instead of the kernel's SIGKILL when that
	//    pid namespace collapses — so it still has to run before anything
	//    touches the engine.
	//
	//    KNOWN GAP, tracked as a finding rather than fixed here: the runroot's
	//    recorded conmon.pid/pidfile are pids in the ENGINE's pid namespace
	//    now, not host pids, so this HOST-side invocation is reading numbers
	//    that mean nothing in its own numbering. On this development host it
	//    never got that far in either era — it exits 125 with "creating events
	//    dirs: mkdir /run/libpod: permission denied", measured identically
	//    pre- and post-C0, so that failure is environmental and not C0's. The
	//    outcome the run promises is unaffected: step 3's sweep is what
	//    verifies, and the namespace collapse is what actually delivers.
	if e.podman != "" {
		// --filter, not just --all: the store is shared with any concurrent
		// sandbox that resolved to the same key, and stopping ITS containers
		// because this one is going away is collateral a user cannot predict.
		//
		// Run on the HOST here, unconfined — this is P0 itself, not the
		// engine, invoking podman's CLI directly against the shared store's
		// path (which is host-uid-owned, exactly like every other file this
		// process writes) to STOP, never to run anything new. It needs no
		// network and no namespace of its own.
		stop := exec.Command(e.podman, "--root", e.store, "--runroot", e.runroot,
			"stop", "--all", "--filter", "label="+e.runLabel, "--time", "5")
		stop.Env = e.env
		_ = stop.Run()
	}

	// 2. Drop the keepalive. From here the engine is on its own idle timeout
	//    even if it somehow outlives the stage.
	e.life.Close()
	e.life = nil

	// 3. Verify. "The stop command returned no error" is not evidence anything
	//    died — that assumption is what let a wrapper-engine case leak
	//    silently in the pre-Tier-B design. The sweep is by SOCKET PATH, never
	//    by comm and never by the shared store path (which would reach a
	//    concurrent sibling).
	if left := waitQuiet(e.paths(), exclude, quietBudget); len(left) > 0 {
		signalOwned(e.paths(), exclude, syscall.SIGKILL)
		if left = waitQuiet(e.paths(), exclude, 3*time.Second); len(left) > 0 {
			fmt.Fprintf(os.Stderr,
				"snug: WARNING — this sandbox's containers did not die with it.\n"+
					"      Still running:\n%s"+
					"      Reap them with:\n"+
					"        kill -9 %s\n"+
					"      and check the store with:\n"+
					"        podman --root %s --runroot %s ps\n",
				describe(left), joinPIDs(left), e.store, e.runroot)
		}
	}

	// 4. The reaper's job is done; tell it so and wait, so that snug
	//    returning means teardown has finished.
	e.reap.standDown()
	e.reap = nil

	_ = os.RemoveAll(e.runDir)
}

func joinPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, p := range pids {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, " ")
}
