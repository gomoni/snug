package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
	"github.com/gomoni/snug/internal/stage"
)

// doctor reports whether this host can run snug, so a user diagnoses a machine
// before their first run rather than during it.
//
// The messages name the exact sysctl or package to change. snug runs in odd
// environments — distrobox, CI containers, hardened kernels — and a vague error
// there costs an hour.
func doctor() int {
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
		cmd := exec.Command(bwrap, append(probeBase(), "--", "/bin/true")...)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Println("  ❌ cannot create a user namespace here")
			fmt.Printf("     💬 bwrap said: %s\n", strings.TrimSpace(string(out)))
			fmt.Println("     🔧 sysctl kernel.unprivileged_userns_clone           must be 1")
			fmt.Println("     🔧 sysctl user.max_user_namespaces                   must be > 0")
			fmt.Println("     🔧 Ubuntu 24.04+: kernel.apparmor_restrict_unprivileged_userns=0")
			ok = false
		} else {
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
			fmt.Println("  ✅ private network namespace — loopback only")
			fmt.Println("     🔒 no egress, no host loopback, no abstract sockets (X11/D-Bus)")
		default:
			// Fatal, and this one has earned it: the interfaces parsed cleanly
			// and there is something in the namespace that should not be there.
			fmt.Printf("  ❌ network namespace has more than loopback: %s\n", strings.Join(got, " "))
			fmt.Println("     this should not happen — the sandbox may not be isolated")
			ok = false
		}
	}

	// The stage is a SECOND set of namespaces, created by snug itself with its
	// own clone(2) rather than by bwrap, so nothing above covers it: the probe
	// two blocks up asks bwrap to make a user namespace, and bwrap's own
	// spelling is --unshare-user-TRY, which succeeds on a host where the stage's
	// strict clone fails. A host where doctor was entirely green and every
	// `-p @net` run died was constructible until this block existed.
	//
	// It calls stage.Start rather than re-typing the clone flags, for the same
	// reason the golden spec test reads the real constant: a probe that
	// approximates the code path can pass while the code path fails. This runs
	// the real one — the clone, the uid map, bringing lo up inside N, pinning
	// N, leaving it, and the re-exec that has to survive all of that — and then
	// tears it straight down again. No sandbox is started.
	if st, err := stage.Start(stage.Config{Netns: policy.NetnsStage}); err != nil {
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

// probeBase is a minimal runnable sandbox. The lib/lib64 symlinks are not
// optional garnish: without them the dynamic loader is absent and execvp fails
// with a misleading "No such file or directory" that looks like a namespace
// problem. That misdiagnosis is exactly what doctor exists to prevent.
func probeBase() []string {
	return []string{
		"--unshare-all",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc",
		"--dev", "/dev",
		"--die-with-parent",
	}
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
