package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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
		}

		// Prove the netns is real and empty rather than asserting it: list the
		// interfaces inside and expect nothing but loopback.
		ifaces := exec.Command(bwrap, append(probeBase(), "--", "/bin/sh", "-c",
			"cat /proc/net/dev | awk 'NR>2{print $1}' | tr -d ' :'")...)
		out, _ := ifaces.CombinedOutput()
		got := strings.Fields(strings.TrimSpace(string(out)))
		if len(got) == 1 && got[0] == "lo" {
			fmt.Println("  ✅ private network namespace — loopback only")
			fmt.Println("     🔒 no egress, no host loopback, no abstract sockets (X11/D-Bus)")
		} else if len(got) > 0 {
			fmt.Printf("  ⚠️  network namespace has more than loopback: %s\n", strings.Join(got, " "))
			fmt.Println("     this should not happen — the sandbox may not be isolated")
		}
	}

	if pasta, err := exec.LookPath("pasta"); err != nil {
		fmt.Println("  ⚠️  pasta not found — the 'net' profile will refuse to run")
		fmt.Println("     📦 zypper in passt  |  apt install passt  |  dnf install passt")
		fmt.Println("     🔒 offline sandboxes work fine without it")
	} else {
		fmt.Printf("  ✅ %s\n     📍 %s\n", firstLine(capture(pasta, "--version")), pasta)
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
