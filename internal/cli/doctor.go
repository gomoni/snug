package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/internal/stage"
)

// doctorNetnsOKMessage is a named constant rather than an inline fmt.Println
// sequence so a test can assert its wording WITHOUT running the userns/netns
// probes above it, which need real unprivileged-userns support and so cannot
// be part of Layer 1/2. Issue #288: this used to attribute X11/D-Bus/Wayland's
// absence to the netns (they are pathname sockets on a typical desktop and are
// closed by the MOUNT POLICY, by absence — see CLAUDE.md). The netns closes the
// ABSTRACT instance only. Kept in step with dryrun.go's two describeNetwork
// arms and config.go's networkConsequence by
// TestTheNetworkBlockDoesNotClaimPathnameSocketsAreNetnsScoped, which drives
// all four and applies one shared predicate rather than one test per site.
const doctorNetnsOKMessage = "" +
	"  ✅ private network namespace — loopback only\n" +
	"     🔒 no egress, no host loopback, no abstract unix sockets (netns-scoped)\n" +
	"     ℹ️  X11/D-Bus/Wayland are pathname sockets — a mount question, not this probe's\n"

// doctor reports whether this host can run snug, so a user diagnoses a machine
// before their first run rather than during it.
//
// The messages name the exact sysctl or package to change. snug runs in odd
// environments — distrobox, CI containers, hardened kernels — and a vague error
// there costs an hour.
func doctor(argv []string) int {
	// argv was DROPPED here until issue #52, which made `snug doctor --json`
	// exit 0 with the human report and the flag silently ignored. That is the
	// worst of the three possible answers: a consumer that asked for a machine
	// format got prose on a stream it is about to parse, and a zero exit code
	// saying it worked.
	//
	// doctor has no flags and no positional argument at all, so the refusal is
	// "any argument", not a list of known ones — a list is the catalogue shape
	// that goes stale the moment a flag is added elsewhere.
	if len(argv) > 0 {
		fmt.Fprintf(os.Stderr, "snug: doctor takes no arguments (got %s)\n",
			visibleValue(argv[0]))
		fmt.Fprintln(os.Stderr, "      there is no machine-readable doctor; --json belongs to --dry-run")
		return exitUsage
	}

	ok := true

	fmt.Println("🩺 snug doctor")
	fmt.Println()

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		fmt.Println("  ❌ bubblewrap (bwrap) not found on PATH")
		fmt.Println("     📦 zypper in bubblewrap  |  apt install bubblewrap  |  dnf install bubblewrap")
		ok = false
	} else {
		fmt.Printf("  ✅ %s\n     📍 %s\n", firstLine(capture(bwrap, "--version")), bwrap)
	}

	// The real test is not a sysctl read but whether a sandbox actually starts:
	// AppArmor on Ubuntu 24.04+, seccomp policy in CI containers, and nested
	// userns limits all fail in different places.
	usernsWorks := false
	if ok {
		verdict, detail := probeUserns(bwrap)
		switch verdict {
		case usernsFailed:
			fmt.Println("  ❌ cannot create a user namespace here")
			fmt.Printf("     💬 bwrap said: %s\n", detail)
			fmt.Println("     🔧 sysctl kernel.unprivileged_userns_clone           must be 1")
			fmt.Println("     🔧 sysctl user.max_user_namespaces                   must be > 0")
			fmt.Println("     🔧 Ubuntu 24.04+: kernel.apparmor_restrict_unprivileged_userns=0")
			ok = false
		case usernsSilentlySkipped:
			// The reason this probe reads a namespace id at all (issue #98).
			// bwrap exited 0 having created NO user namespace, so the old
			// exit-code check printed a green tick for a host where the
			// sandbox has none.
			fmt.Println("  ❌ bwrap reported success but created NO user namespace")
			fmt.Printf("     💬 inside the probe, /proc/self/ns/user is %s — the same one this\n", detail)
			fmt.Println("        process is already in, so nothing was unshared")
			fmt.Println("     🔧 sysctl user.max_user_namespaces                   must be > 0")
			fmt.Println("        (this is what an exhausted ucount looks like: --unshare-all decodes")
			fmt.Println("         to bwrap's own -try spellings, which skip silently and exit 0)")
			ok = false
		case usernsInconclusive:
			// NOT fatal, and NOT a tick. A host where the probe cannot read a
			// namespace id still runs snug; what it must not do is produce the
			// affirmative answer this command exists to give.
			fmt.Println("  ⚠️  could not verify the user namespace — probe inconclusive")
			fmt.Printf("     💬 %s\n", detail)
			usernsWorks = true
		default:
			fmt.Println("  ✅ unprivileged user namespaces work")
			usernsWorks = true
		}
	}

	// Prove the netns is real and empty rather than asserting it: list the
	// interfaces inside and expect nothing but loopback.
	//
	// Guarded on the probe ABOVE having worked, and the error checked, because
	// otherwise this misreports spectacularly: when bwrap cannot start, its
	// error text goes to the same combined output, gets split into fields, and
	// is printed as though those words were interface names — "network
	// namespace has more than loopback: bwrap: No permissions to create a new
	// namespace…", followed by "the sandbox may not be isolated". Measured, by
	// running doctor inside a snug sandbox. A false alarm is expensive in the
	// one command whose entire job is telling a human what is wrong.
	if usernsWorks {
		// `cat` and nothing else. The parsing happens HERE, in Go.
		//
		// This used to pipe through awk, and awk is not reliably present in the
		// probe sandbox: probeBase binds /usr but not /etc, and on a Debian-family
		// host /usr/bin/awk is a symlink into /etc/alternatives, so it dangles.
		// The runner then produced "/bin/sh: 1: awk: not found", which the field
		// split turned into three interface names and doctor reported the sandbox
		// as possibly not isolated. Every tool this probe needs is one more way
		// for it to be wrong about the thing it is measuring.
		ifaces := exec.Command(bwrap, append(probeBase(), "--", "/bin/cat", "/proc/net/dev")...)
		out, err := ifaces.CombinedOutput()
		got := parseNetDev(string(out))
		switch {
		case err != nil || len(got) == 0:
			// NOT fatal: this is the probe failing, not the sandbox. A host that
			// cannot run `cat` inside the probe base still runs snug fine.
			fmt.Println("  ⚠️  could not list the sandbox's interfaces — probe inconclusive")
			fmt.Printf("     💬 %s\n", firstLine(strings.TrimSpace(string(out))))
		case len(got) == 1 && got[0] == "lo":
			fmt.Print(doctorNetnsOKMessage)
		default:
			// Fatal, and this one has earned it: the interfaces parsed cleanly
			// and there is something in the namespace that should not be there.
			fmt.Printf("  ❌ network namespace has more than loopback: %s\n", strings.Join(got, " "))
			fmt.Println("     this should not happen — the sandbox may not be isolated")
			ok = false
		}
	}

	// The stage is a SECOND set of namespaces, created by snug itself with its
	// own clone(2) rather than by bwrap, so nothing above covers it — and the
	// reason has changed, so read this one rather than the version you may
	// remember. It used to say the probe above asks for --unshare-user-TRY,
	// which succeeds where the stage's strict clone fails; that stopped being
	// true when issue #98 made the probe strict, and the sentence survived its
	// own fix for one commit (issue #159).
	//
	// What still makes this block necessary: bwrap's userns creation and snug's
	// own clone(CLONE_NEWUSER|CLONE_NEWNET) from a MULTITHREADED Go process are
	// different code paths with different failure modes, and the stage does
	// four more things bwrap never attempts — writes the uid map, brings lo up
	// from inside N, pins N with a descriptor and then LEAVES it, and survives
	// a re-exec across all of that. A host where doctor was entirely green and
	// every `-p @net` run died was constructible until this block existed.
	//
	// It calls stage.Start rather than re-typing the clone flags, for the same
	// reason the golden spec test reads the real constant: a probe that
	// approximates the code path can pass while the code path fails. This runs
	// the real one — the clone, the uid map, bringing lo up inside N, pinning
	// N, leaving it, and the re-exec that has to survive all of that — and then
	// tears it straight down again. No sandbox is started.
	// The info pipe is real, and dangling on purpose. Since issue #125's C2-gate
	// the stage requires it at Start — its child asserts fd 5 exists before it
	// will serve anything (serve.go's requireFD) — and it is only ever READ on
	// a `start` request, which this probe never sends. So a pipe whose write end
	// nothing holds is exactly right here: it exercises the descriptor plumbing
	// the real path uses without pretending a sandbox exists.
	//
	// Supplying it, rather than relaxing stage.Start's check for callers who say
	// they will not start a sandbox, is deliberate. This block's whole argument
	// is that a probe approximating the code path can pass while the code path
	// fails — an exemption for doctor would be exactly that approximation, and
	// it is how this probe came to be missing a required field in the first
	// place (caught by CI running `snug doctor`, which the integration suite
	// does not).
	infoR, infoW, pipeErr := os.Pipe()
	if pipeErr != nil {
		fmt.Println("  ❌ cannot create the stage that `-p @net` needs")
		fmt.Printf("     💬 creating the bwrap info pipe for the probe: %v\n", pipeErr)
		return exitUnavail
	}
	defer infoR.Close()
	defer infoW.Close()
	if st, err := stage.Start(stage.Config{
		Topology:  policy.Topology{Netns: policy.NetnsStage},
		BwrapInfo: infoR,
	}); err != nil {
		fmt.Println("  ❌ cannot create the stage that `-p @net` needs")
		fmt.Printf("     💬 %v\n", err)
		ok = false
	} else {
		_ = st.Close()
		fmt.Println("  ✅ the stage starts — clone, uid map, loopback, and the netns move")
		fmt.Println("     🔒 offline sandboxes do not use it and are unaffected either way")
	}

	if pasta, err := exec.LookPath("pasta"); err != nil {
		fmt.Println("  ⚠️  pasta not found — the 'net' profile will refuse to run")
		fmt.Println("     📦 zypper in passt  |  apt install passt  |  dnf install passt")
		fmt.Println("     🔒 offline sandboxes work fine without it")
	} else {
		fmt.Printf("  ✅ %s\n     📍 %s\n", firstLine(capture(pasta, "--version")), pasta)
	}

	if ok, detail := podmanClientUsable(); ok {
		fmt.Println("  ✅ podman client is usable inside a sandbox")
	} else {
		fmt.Printf("  ⚠️  podman CLI will not work inside a sandbox — %s\n", detail)
		fmt.Println("     🔒 snug's engine and proxy still work; drive the API at $CONTAINER_HOST")
	}

	reportPodmanHelpers()

	if legacyTIOCSTI() {
		fmt.Println("  ⚠️  this kernel still allows the TIOCSTI ioctl")
		fmt.Println("     🛡️  snug will add --new-session to stop the sandbox typing into your")
		fmt.Println("        terminal. Cost: no job control inside an interactive sandbox shell.")
	} else {
		fmt.Println("  ✅ TIOCSTI disabled kernel-wide — job control works inside the sandbox")
	}

	if _, err := os.Stat("/run/.containerenv"); err == nil {
		fmt.Println("  📦 running inside a container (distrobox/podman) — supported")
	} else if _, err := os.Stat("/.dockerenv"); err == nil {
		fmt.Println("  📦 running inside a docker container — supported")
	}

	// A host can be perfectly capable and snug still refuse to start because the
	// profile set will not load. doctor is what someone runs to find out why, so
	// it must say so rather than reporting a clean bill of health.
	_, bad, err := profile.Load()
	switch {
	case err != nil:
		fmt.Printf("  ❌ the profile set will not load\n     %v\n", err)
		ok = false
	case len(bad) > 0:
		// Named, not counted, and not fatal: doctor is the command someone runs
		// to find out WHY, so it has to name the file rather than report a clean
		// bill of health or die on the way to printing one.
		fmt.Printf("  ❌ %d profile file(s) did not load; snug will refuse to start a sandbox\n", len(bad))
		for _, f := range bad {
			fmt.Printf("     %s\n       %v\n", f.Path, f.Err)
		}
		ok = false
	default:
		fmt.Println("  ✅ profiles load cleanly")
	}

	fmt.Println()
	if !ok {
		fmt.Println("🚫 snug cannot run on this host as configured.")
		return exitUnavail
	}
	fmt.Println("🎉 This host can run snug.")
	return 0
}

// The four outcomes of the user-namespace probe. Three of them are not "it
// worked", and the whole point of issue #98 is that the previous version could
// only tell one of them apart.
type usernsVerdict int

const (
	usernsCreated         usernsVerdict = iota
	usernsFailed                        // bwrap could not start at all
	usernsSilentlySkipped               // bwrap exited 0 and unshared nothing
	usernsInconclusive                  // the probe could not measure; do NOT claim success
)

// String exists so a failing test names the verdict instead of printing an
// integer — three of the four values are ways of NOT succeeding, and telling
// them apart is the whole point of issue #98.
func (v usernsVerdict) String() string {
	switch v {
	case usernsFailed:
		return "failed"
	case usernsSilentlySkipped:
		return "silently-skipped"
	case usernsInconclusive:
		return "inconclusive"
	default:
		return "created"
	}
}

// probeUserns answers "does a sandbox on this host get its own user namespace"
// by MEASURING it, not by reading bwrap's exit status.
//
// Issue #98: `probeBase()` passes `--unshare-all`, which bwrap decodes to its
// own `-try` spellings, so an exhausted `user.max_user_namespaces` makes bwrap
// skip the unshare and exit **0**. The old check was `cmd.CombinedOutput()`
// plus `err != nil`, which cannot tell "created a namespace" from "silently did
// not", and printed `✅ unprivileged user namespaces work` for the second.
// Measured, reproducing the issue on this host: inside `unshare --user
// --map-root-user` with `max_user_namespaces` set to 0, a plain `unshare --user
// --map-root-user -- /bin/true` fails ENOSPC (the positive control) while the
// probe above exits 0 and reports the CALLER'S OWN namespace id.
//
// So the id is what gets compared. A namespace id is a global inode number, so
// reading it from inside a different pid namespace is still meaningful — the
// same value means the same namespace, whatever /proc it was read through.
//
// Not bwrap's --info-fd, and that is measured too rather than assumed: its JSON
// carries child-pid and the cgroup/ipc/mnt/net/pid/uts namespaces and **no user
// namespace at all**, so the one namespace this probe is about is the one it
// cannot report.
//
// Not /proc/self/uid_map either. In the silent-skip case the map inside is
// byte-identical to the caller's, so it answers the wrong question.
//
// This is the general rule the project already writes down — verify a security
// feature is ACTIVE, not merely requested — which bit `--seccomp` in exactly
// this shape: a flag that was passed, accepted, and never installed, with a
// zero exit code and no warning.
func probeUserns(bwrap string) (usernsVerdict, string) {
	// /bin/readlink, not a shell: probeBase binds /usr and symlinks /bin to
	// usr/bin, and the netns probe below already depends on /bin/cat being
	// reachable the same way. Every extra tool is one more way for a probe to
	// be wrong about the thing it measures, so this uses exactly one.
	cmd := exec.Command(bwrap, append(probeBase(), "--", "/bin/readlink", "/proc/self/ns/user")...)
	out, err := cmd.CombinedOutput()
	got := strings.TrimSpace(string(out))
	if err != nil {
		// Ambiguous on its own: bwrap failing to create the namespace and
		// /bin/readlink being absent both land here. Re-ask with the original
		// /bin/true payload, which needs no tool beyond the loader — if THAT
		// starts, the namespace is fine and it was the probe tool that was
		// missing.
		if plain := exec.Command(bwrap, append(probeBase(), "--", "/bin/true")...); plain.Run() == nil {
			return usernsInconclusive, "/bin/readlink is not usable inside the probe sandbox"
		}
		return usernsFailed, firstLine(got)
	}

	mine, rerr := os.Readlink("/proc/self/ns/user")
	if rerr != nil {
		return usernsInconclusive, fmt.Sprintf("cannot read this process's own namespace id (%v)", rerr)
	}
	return classifyUserns(got, mine)
}

// classifyUserns is the decision, separated from the two syscalls that feed it
// so it can be tested on any host — including one where the failure it exists
// to catch cannot be constructed. The rule is one line, and stating it as data
// rather than as control flow inside probeUserns is what lets a test assert the
// SET of outcomes rather than the one that happens to be reachable in CI.
func classifyUserns(inside, mine string) (usernsVerdict, string) {
	switch {
	case inside == "" || !strings.HasPrefix(inside, "user:["):
		return usernsInconclusive, fmt.Sprintf("the probe returned %q, which is not a namespace id", inside)
	case !strings.HasPrefix(mine, "user:["):
		return usernsInconclusive, fmt.Sprintf("this process's own namespace id reads %q", mine)
	case inside == mine:
		return usernsSilentlySkipped, inside
	default:
		return usernsCreated, inside
	}
}

// probeBase is a minimal runnable sandbox. The lib/lib64 symlinks are not
// optional garnish: without them the dynamic loader is absent and execvp fails
// with a misleading "No such file or directory" that looks like a namespace
// problem. That misdiagnosis is exactly what doctor exists to prevent.
func probeBase() []string {
	// The namespaces the real sandbox creates, READ FROM THE POLICY rather than
	// re-typed here (issue #159). This probe's output is a claim that snug will
	// run on this host, so a probe demanding less of the kernel than the run
	// demands produces a false green — invariant 5's silent downgrade arriving
	// through a diagnostic instead of through the sandbox, which is issue #98.
	// It got that way by passing `--unshare-all`, which decodes to bwrap's own
	// `-try` spellings (bubblewrap.c:1894-1903) and skips a namespace it cannot
	// create while exiting 0. The first fix re-typed the strict list here; a
	// hand-typed copy checked by nothing is one edit from the same false green,
	// which is what the call below removes.
	//
	// NetnsSandbox is named explicitly rather than taken as the zero value,
	// because it is the topology that demands the MOST of the kernel: the stage
	// topology asks bwrap for fewer namespaces (the stage already made the
	// netns) and NetnsHost asks for the same set and then relaxes it with
	// --share-net. A host that passes this probe satisfies all three.
	//
	// probeUserns compares namespace ids on top of this rather than trusting it,
	// because "strict flag" and "namespace actually created" are the two things
	// the --seccomp bug taught this project not to conflate.
	flags := policy.Topology{Netns: policy.NetnsSandbox}.UnshareFlags()

	return append(flags,
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc",
		"--dev", "/dev",
		"--die-with-parent",
	)
}

func capture(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

// parseNetDev extracts interface names from /proc/net/dev, which has two header
// lines and then "  name: <counters>". Parsing here rather than shelling out to
// awk is deliberate: every tool the probe needs inside the sandbox is one more
// way for it to report a wrong answer about the thing it is measuring, and awk
// on a Debian-family host is a symlink into /etc/alternatives that probeBase
// does not bind.
//
// Returns nil when nothing parses, which the caller treats as "probe
// inconclusive" rather than as a finding — the difference between the sandbox
// being wrong and the probe being unable to look.
func parseNetDev(out string) []string {
	var names []string
	for i, line := range strings.Split(out, "\n") {
		if i < 2 { // "Inter-|   Receive ..." and the column headings
			continue
		}
		name, _, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found || name == "" || strings.ContainsAny(name, " \t/") {
			continue
		}
		names = append(names, name)
	}
	return names
}

// ── podman's helper binaries ────────────────────────────────────────────────
//
// A host can have `podman`, pass every other check here, and still fail at the
// FIRST container because one helper is missing. Measured on this host, twice in
// a row — which is the point, because fixing the first only reveals the second:
//
//	Error: could not find a working conmon binary (configured options: [...]:
//	       invalid argument)
//	Error: could not find "netavark" in one of [/snug/engine/toolchain/usr/local/bin
//	       /usr/libexec/podman /usr/lib/podman /usr/bin]
//
// podman resolves a helper by looking in ABSOLUTE DIRECTORIES. It never walks a
// prefix, so a relocated bundle's helpers are invisible unless
// helper_binaries_dir names the directory they are in — and a relocated engine
// splits them across usr/local/bin (crun, runc, pasta, podman) and
// usr/local/lib/podman (conmon, netavark, aardvark-dns, catatonit,
// rootlessport), of which snug's generated config names only the first.
//
// doctor exists so a user diagnoses that before their first run rather than
// during it, which is why this is a check and not a paragraph in the README.

// podmanHelperDirs are the absolute directories podman searches. Taken from
// libpod's own two error messages above rather than from memory, so the list a
// user is checked against is the list podman actually used.
func podmanHelperDirs() []string {
	return []string{
		"/usr/libexec/podman",
		"/usr/local/libexec/podman",
		"/usr/local/lib/podman",
		"/usr/lib/podman",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/run/current-system/sw/bin",
	}
}

// findPodmanHelper returns the full path of the first executable named name in
// podmanHelperDirs, or "" when no directory podman searches holds one.
//
// NOT exec.LookPath: that answers "is it on MY $PATH", which is a different and
// misleading question here — a helper on the user's PATH but in none of the
// directories above is one podman will not find, and reporting it as present is
// exactly the false green this check exists to remove.
func findPodmanHelper(name string) string {
	return findPodmanHelperIn(podmanHelperDirs(), name)
}

// findPodmanHelperIn is findPodmanHelper with the directory list injected, so a
// test can point it at a temp tree and assert BOTH arms. Without the seam the
// only reachable assertion would be "this host happens to have conmon", which
// passes or fails for reasons that have nothing to do with the code — the "test
// that cannot fail" shape.
func findPodmanHelperIn(dirs []string, name string) string {
	for _, d := range dirs {
		p := filepath.Join(d, name)
		fi, err := os.Stat(p)
		if err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// requiredPodmanHelpers are the helpers a container run needs unconditionally.
//
// rootlessport is deliberately absent, and the exclusion is MEASURED rather
// than only reasoned. The reasoning: snug publishes no ports (the engine holds
// no CAP_NET_ADMIN — INDEX §4.6), so a missing rootlessport changes nothing
// this tool can do, and warning about it would be a warning nobody can act on.
// The measurement: two independent hosts running the container tests GREEN with
// no rootlessport anywhere in podmanHelperDirs — this one, and a second
// development host checked for exactly this question. A required-set entry that
// is absent on every host where the feature works is a false alarm, not a check.
// TestRequiredPodmanHelpersExcludesRootlessport holds it out.
//
// crun/runc are absent too — they are an either/or, checked separately, because
// requiring one would report a working host as broken.
func requiredPodmanHelpers() []string {
	return []string{"conmon", "netavark", "aardvark-dns", "catatonit"}
}

// reportPodmanHelpers prints one line per missing helper and one summary line
// when nothing is missing. Named the way the other checks here are: the message
// carries the package to install, because a vague answer in an odd environment
// costs an hour.
func reportPodmanHelpers() {
	missing := []string{}
	for _, h := range requiredPodmanHelpers() {
		if findPodmanHelper(h) == "" {
			missing = append(missing, h)
		}
	}
	// One OCI runtime is enough. podman needs crun OR runc, so neither is
	// "missing" while the other is present, and reporting both would tell a
	// working host it is broken.
	crun, runc := findPodmanHelper("crun"), findPodmanHelper("runc")
	if crun == "" && runc == "" {
		missing = append(missing, "crun or runc")
	}

	if len(missing) == 0 {
		fmt.Println("  ✅ podman's helper binaries are all findable")
		return
	}
	fmt.Printf("  ⚠️  podman helper binaries not found: %s\n", strings.Join(missing, ", "))
	fmt.Println("     📦 zypper in conmon netavark aardvark-dns catatonit crun  |  apt install")
	fmt.Println("        conmon netavark aardvark-dns catatonit crun  |  dnf install conmon")
	fmt.Println("        netavark aardvark-dns catatonit crun")
	fmt.Println("     🔒 only the container profiles need these; every other sandbox is unaffected")
	fmt.Println("     📍 podman searches these directories and does NOT walk a bundle prefix:")
	fmt.Printf("        %s\n", strings.Join(podmanHelperDirs(), " "))
}
