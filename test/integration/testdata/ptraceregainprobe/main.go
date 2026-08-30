// Command ptraceregainprobe measures what CAP_SYS_PTRACE regained inside a
// SELF-MADE user namespace is worth against a real process living in a
// different one — the negative half of issue #61 part (a)'s gate, and the
// argument internal/policy/stagecaps.go's own "SCOPE THIS SENTENCE" section
// makes: a nested user namespace resets the bounding set to full, and that
// regained bit "reaches nothing in U" because it holds only in the namespace
// that regained it and its descendants, never in an ancestor or a sibling.
//
// It takes ONE argument: the pid of a real process living in a namespace
// this probe's own nested one is neither an ancestor nor a descendant of
// (the test drives it against P1, the stage, found from outside any
// sandbox). Deliberately run OUTSIDE bwrap's own pid-namespace isolation —
// unlike capregainprobe (which attacks the NETWORK namespace N and needs no
// pid visibility at all), a ptrace attempt needs the target's pid to
// resolve via /proc in the first place, and a process inside a
// bwrap-sandboxed pid namespace cannot even NAME an ancestor pid, let alone
// ptrace it (ENOENT, not EPERM — a weaker, differently-shaped negative than
// the one this probe measures). Running here, in the same pid namespace as
// the target, isolates the USER NAMESPACE boundary as the only thing being
// asked about, which is exactly what stagecaps.go's own claim is about.
//
// Same shape as capregainprobe: a single-threaded clone is required for
// CLONE_NEWUSER, which the Go runtime is not, so the nested half is a
// re-exec of this same binary via SysProcAttr.Cloneflags.
//
// This directory is named testdata, so the Go toolchain ignores it
// everywhere else in the module; only the integration test compiles it.
//
// Output is one "name=RESULT" line per step (RESULT is "OK" or an errno's
// short name) plus "name=VALUE" lines for values the test reads back. The
// test asserts exact tokens rather than matching prose.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func report(name string, err error) {
	if err == nil {
		fmt.Printf("%s=OK\n", name)
		return
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		fmt.Printf("%s=%s\n", name, errno.Error())
		return
	}
	fmt.Printf("%s=OTHER:%v\n", name, err)
}

func value(name, v string) { fmt.Printf("%s=%s\n", name, v) }

// capMasks mirrors capregainprobe's own helper: CapEff/CapBnd out of
// /proc/self/status, as the kernel spells them.
func capMasks() (eff, bnd string) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "READ-ERROR", "READ-ERROR"
	}
	eff, bnd = "ABSENT", "ABSENT"
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "CapEff:":
			eff = f[1]
		case "CapBnd:":
			bnd = f[1]
		}
	}
	return eff, bnd
}

// firstMappedAddress returns the low end of a process's first /proc/<pid>/maps
// entry — an address known to be mapped and readable in ITS OWN address
// space, so a successful process_vm_readv against it is a real read of real
// bytes rather than a coincidence. The exact address a real target (P1) maps
// there is not needed for the attack half: the permission check in
// process_vm_readv and mm_access happens before any address is validated
// (measured directly on this host: an arbitrary, almost certainly-unmapped
// address against a real process still returns EPERM, not EFAULT), so the
// attack half below uses a fixed guess and only the CONTROL half — reading
// the peer, which must demonstrate an actual successful cross-process read —
// needs a real one.
func firstMappedAddress(pid int) (uint64, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
		if err == nil && len(data) > 0 {
			line, _, _ := strings.Cut(string(data), "\n")
			if addrPart, _, ok := strings.Cut(line, "-"); ok {
				if a, err := strconv.ParseUint(addrPart, 16, 64); err == nil && a != 0 {
					return a, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("no mapping appeared in /proc/%d/maps before the deadline", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func vmReadv(pid int, addr uint64) error {
	local := make([]byte, 8)
	liov := unix.Iovec{Base: &local[0]}
	liov.SetLen(len(local))
	riov := unix.RemoteIovec{Base: uintptr(addr), Len: 8}
	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	return err
}

func openMem(pid int) error {
	f, err := os.OpenFile("/proc/"+strconv.Itoa(pid)+"/mem", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "nested" {
		nested(os.Args[2])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "peer" {
		peer()
		return
	}
	outer()
}

// outer takes the real target pid on argv[1] and re-execs itself into a
// user namespace of its own making — the same `unshare -U -r` shape
// internal/policy/stagecaps.go's own doc comment measured by hand.
func outer() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ptraceregainprobe <target-pid>")
		os.Exit(2)
	}
	target := os.Args[1]
	cmd := exec.Command("/proc/self/exe", "nested", target)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	err := cmd.Run()
	report("nested-userns", err)
}

// nested runs as root in a user namespace it created itself, holding the
// full capability set (including CAP_SYS_PTRACE) in that namespace and
// nothing more. It attacks the real target, then a peer it forks into the
// SAME nested namespace, as the positive control.
func nested(targetStr string) {
	target, err := strconv.Atoi(targetStr)
	if err != nil {
		report("parse-target", err)
		return
	}
	value("target-pid", targetStr)

	// The fact stated plainly, not hidden: this namespace DID regain
	// CAP_SYS_PTRACE. What stops it reaching U is namespace ownership, not
	// the bit's absence.
	eff, bnd := capMasks()
	value("nested-capeff", eff)
	value("nested-capbnd", bnd)

	// A peer inside the SAME nested user namespace: a plain child (no
	// SysProcAttr, so it inherits the caller's namespaces exactly), which is
	// the positive control's whole point — same capability regime as the
	// attacker, unlike the real target.
	peerCmd := exec.Command("/proc/self/exe", "peer")
	if err := peerCmd.Start(); err != nil {
		report("start-peer", err)
		return
	}
	defer func() {
		peerCmd.Process.Kill()
		peerCmd.Wait()
	}()
	peerPid := peerCmd.Process.Pid
	value("peer-pid", strconv.Itoa(peerPid))

	peerAddr, err := firstMappedAddress(peerPid)
	if err != nil {
		report("peer-maps", err)
		return
	}

	// ── the attack: a process in U ──────────────────────────────────────
	report("vm-readv-target", vmReadv(target, 0x400000))
	report("open-mem-target", openMem(target))

	// ── the control: a peer in the attacker's OWN namespace ─────────────
	report("vm-readv-peer", vmReadv(peerPid, peerAddr))
	report("open-mem-peer", openMem(peerPid))
}

// peer does nothing but stay alive long enough to be attacked/read — a
// real, mapped, readable address is all the control half needs from it.
func peer() {
	time.Sleep(5 * time.Second)
}
