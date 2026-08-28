// Command capregainprobe measures what a user namespace the PAYLOAD creates
// for itself is worth against the namespaces snug created for it.
//
// It is the mechanised form of the argument internal/policy/enginecaps.go
// makes for excluding CAP_NET_ADMIN from EngineCapBounding: a nested user
// namespace hands its creator the full capability set, and every bit of it is
// namespace-relative, so none of it reaches a namespace owned further up. The
// probe therefore prints BOTH halves — the caps it regained, and each
// privileged operation those caps did not buy — because the second half alone
// would pass on a run that regained nothing.
//
// Creating a user namespace needs a single-threaded process, which the Go
// runtime is not, so the nested half runs as a re-exec of this same binary
// with the "nested" argument, via SysProcAttr.Cloneflags — the same shape
// `unshare -U -r` has. The nested half then LockOSThread()s for its whole
// life: unshare(CLONE_NEWNET) and unshare(CLONE_NEWNS) act on the calling
// THREAD, so every syscall that depends on them has to stay on it.
//
// This directory is named testdata, so the Go toolchain ignores it everywhere
// else in the module; only the integration test compiles it.
//
// Output is one "name=RESULT" line per step, RESULT being "OK" or an errno's
// short name, plus "name=VALUE" lines for the things the test has to read back
// out (capability masks, namespace identities, interface flags). The test
// asserts exact tokens rather than matching prose.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// report prints "name=RESULT": OK, or the errno's short name, unwrapped
// through whatever the standard library wrapped it in (os/exec hands back an
// *os.PathError around the clone failure; the raw unix.* wrappers return
// unix.Errno directly).
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

// capMasks reads CapEff and CapBnd out of /proc/self/status, as the kernel
// spells them (16 hex digits, no 0x).
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

// netns is /proc/self/ns/net's symlink target — "net:[<inode>]" — which names
// the same namespace whoever reads it, so two readings are comparable text.
func netns() string {
	s, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "READLINK-ERROR"
	}
	return s
}

// loFlags returns the SIOCGIFFLAGS word for "lo" in the CALLING THREAD's
// network namespace. The socket is opened per call so it belongs to whichever
// namespace the thread is in at the time.
func loFlags() (uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return 0, err
	}
	return ifr.Uint16(), nil
}

// setLoFlags is the write half, SIOCSIFFLAGS — the privileged operation this
// whole probe is about. It needs CAP_NET_ADMIN in the user namespace that OWNS
// the network namespace being written to, which is not the same thing as
// holding CAP_NET_ADMIN.
func setLoFlags(flags uint16) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	ifr.SetUint16(flags)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "nested" {
		nested()
		return
	}
	outer()
}

// outer runs as the payload snug started: no capabilities, in snug's network
// namespace N. It records what it can see and then re-execs itself in a user
// namespace of its own making.
func outer() {
	eff, bnd := capMasks()
	value("outer-capeff", eff)
	value("outer-capbnd", bnd)
	value("outer-netns", netns())

	cmd := exec.Command("/proc/self/exe", "nested")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		// The mapping `unshare -r` makes: this uid alone, as root inside.
		// Mapping only one's own uid needs no privilege, and setgroups is
		// denied (GidMappingsEnableSetgroups false) because the kernel
		// requires that of an unprivileged gid_map writer.
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	err := cmd.Run()
	report("nested-userns", err)
}

// nested runs as root in a user namespace it created itself, holding the full
// capability set in that namespace and nothing more.
func nested() {
	runtime.LockOSThread()

	eff, bnd := capMasks()
	value("nested-capeff", eff)
	value("nested-capbnd", bnd)
	value("nested-uid", fmt.Sprint(os.Getuid()))

	// N, remembered as a descriptor before leaving it — the fd a nested
	// namespace's occupant would use to come back.
	saved, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY, 0)
	report("open-saved-netns", err)
	if err != nil {
		return
	}
	value("nested-netns", netns())

	// N's lo, read then written. The read is the control that says lo is
	// there and this thread is talking to a real namespace, so the write's
	// refusal is about privilege over N and not about a missing interface.
	flags, err := loFlags()
	report("in-N-getflags", err)
	if err == nil {
		value("in-N-lo-flags", fmt.Sprintf("0x%x", flags))
		report("in-N-setflags", setLoFlags(flags^unix.IFF_UP))
		after, err2 := loFlags()
		if err2 == nil {
			value("in-N-lo-flags-after", fmt.Sprintf("0x%x", after))
		}
	}

	// A network namespace of its OWN, which the nested user namespace does
	// own — the positive control for both the ioctl and the setns below.
	report("unshare-netns", unix.Unshare(unix.CLONE_NEWNET))
	own, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY, 0)
	report("open-own-netns", err)
	value("own-netns", netns())

	if f, err := loFlags(); err != nil {
		report("in-own-getflags", err)
	} else {
		value("in-own-lo-flags", fmt.Sprintf("0x%x", f))
		report("in-own-setflags", setLoFlags(f|unix.IFF_UP))
		if after, err := loFlags(); err == nil {
			value("in-own-lo-flags-after", fmt.Sprintf("0x%x", after))
			value("in-own-lo-changed", fmt.Sprint(after != f))
		}
	}

	// One more fresh namespace, so the setns pair below is measured from a
	// namespace that is neither N nor the one it owns.
	report("unshare-netns-again", unix.Unshare(unix.CLONE_NEWNET))
	if own >= 0 {
		report("setns-into-own", unix.Setns(own, unix.CLONE_NEWNET))
	}
	report("setns-into-N", unix.Setns(saved, unix.CLONE_NEWNET))
	value("final-netns", netns())

	mounts()
}

// mounts is the same measurement one layer over: a mount namespace the nested
// user namespace owns, full CAP_SYS_ADMIN in it, and the mounts bwrap made in
// snug's user namespace still not writable.
func mounts() {
	dir, err := filepath.Abs("capregain-mnt")
	if err != nil {
		report("mount-dir", err)
		return
	}
	// Created before the mount namespace exists, so it is a real directory in
	// the target rather than something only this thread can see.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		report("mount-dir", err)
		return
	}
	report("unshare-mountns", unix.Unshare(unix.CLONE_NEWNS))

	// Positive control: CAP_SYS_ADMIN in this mount namespace is real, so a
	// tmpfs of its own mounts. Without it, every refusal below would also be
	// satisfied by a nested namespace that got no privilege at all.
	report("mount-own-tmpfs", unix.Mount("tmpfs", dir, "tmpfs", 0, ""))

	for _, path := range []string{"/usr", "/", "/etc"} {
		name := "remount-rw-" + path
		err := unix.Mount("", path, "", unix.MS_REMOUNT|unix.MS_BIND, "")
		report(name, err)
		if err != nil {
			continue
		}
		// It said yes. Whether the write lands is the question that matters,
		// so ask it rather than reporting the remount and stopping.
		probe := filepath.Join(path, ".snug-capregain-write-probe")
		f, werr := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE, 0o644)
		report("write-after-"+name, werr)
		if werr == nil {
			f.Close()
			os.Remove(probe)
		}
	}
}
