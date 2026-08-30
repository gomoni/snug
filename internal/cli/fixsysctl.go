package cli

// fixsysctl.go is `snug fix sysctl`, the second noun under `snug fix` and
// the acting half of issue #526: `snug doctor` reports the kernel knobs
// snug's threat model inherits (hostsysctl.go), and this applies them.
//
// It follows `snug fix subuid` exactly, because the contract there was
// argued for and holds here unchanged: stdout is the CONTENT and a caller
// may pipe it, stderr is the commentary, nothing changes without -w, and
// NOTHING TO DO PRINTS NOTHING AND EXITS 0 — which is what makes it safe in
// a distrobox init_hook running under `set -o errexit`.
//
// Two rules that are this noun's own, and neither is decoration:
//
//   - ONLY THE WEAK ROWS ARE WRITTEN. Emitting the whole table would set
//     knobs that are already satisfied, and a host stricter than snug asks
//     for — kptr_restrict=2, say — would be WEAKENED to 1 at the next boot
//     by a file snug wrote to harden it. A fix that can lower a hardening
//     knob is not a fix.
//   - AN UNREADABLE KNOB IS NEVER FIXED. kernel.yama.ptrace_scope does not
//     exist without the Yama LSM and unprivileged_bpf_disabled is absent on
//     a kernel built without BPF; a line for either would name a sysctl the
//     machine refuses to set, and `sysctl --system` would then fail on every
//     boot because of a file snug left behind.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/hostread"
	"golang.org/x/sys/unix"
)

// maxDropInBytes bounds the read of snug's own drop-in, which exists only to
// answer "is this already what I would write". The file snug writes is under
// 400 bytes; 64 KiB is far past any honest one and far below anything that
// hurts.
const maxDropInBytes = 64 << 10

// snugSysctlDropIn is where -w persists the settings.
//
// 00-, and the number is the whole point: sysctl.d applies its files in
// lexicographic order and the LAST one to set a knob wins. snug's file is
// therefore read FIRST, so any deliberate host file — 50-hardening.conf,
// a distro drop-in, anything an admin put there — overrides it. That is the
// direction this has to go: snug's job is to raise a floor, never to overrule
// what the machine's owner decided.
//
// A redteam round measured the other direction and it is a real defect, not a
// theoretical one: at 99- a host whose admin had persisted
// kernel.kptr_restrict = 2 in 50-hardening.conf, and whose RUNTIME was still
// at the distro's value because the machine had not rebooted, got 1 from the
// next boot onward — lowered by the file snug wrote to harden it.
//
// The cost, stated rather than hidden: a later file that sets one of these
// knobs WEAKER also wins. `snug doctor` reports that on the next run, which
// is the difference between a cost and a hole.
const snugSysctlDropIn = "/etc/sysctl.d/00-snug.conf"

// sysctlWeakLines is what this host is MISSING RIGHT NOW: the knobs below
// their want, at their want, in the table's order. This is what gets applied
// to the running kernel and what the commentary talks about. Empty means the
// running kernel needs nothing.
func sysctlWeakLines(readings []sysctlReading) []string {
	var lines []string
	for _, r := range readings {
		if !r.readable() || r.ok() {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s = %d", r.sysctl.knob, r.sysctl.want))
	}
	return lines
}

// sysctlDropInLines is what the PERSISTENT file should contain, and it is a
// different question from sysctlWeakLines with a different answer.
//
// THE FILE IS A FUNCTION OF THE TABLE, NOT OF THIS BOOT. Deriving its content
// from the weak rows was measured to destroy hardening it had itself
// persisted: a drop-in holding all five settings, on a host where a developer
// had loosened ONE knob at runtime to profile something, was truncated to
// that one line — four persistent settings deleted by the command whose only
// purpose is to add them, exit 0, and `snug doctor` answering ✅ for all five
// because doctor reads the RUNNING kernel. Both halves were honest; together
// they asserted a hardening that would not survive a reboot.
//
// Every READABLE row is written, at desired() — max(want, current) — so the
// file can never lower a knob this kernel is already running stricter. A
// faulted row is written NEVER: a sysctl.d line naming a knob the kernel does
// not have fails on every boot, in a file snug left behind.
func sysctlDropInLines(readings []sysctlReading) []string {
	var lines []string
	for _, r := range readings {
		if !r.readable() {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s = %d", r.sysctl.knob, r.desired()))
	}
	return lines
}

// sysctlDropInBody wraps those lines in the file -w writes. The header names
// the command that wrote it, so a human who finds this file on a machine
// learns what to run to change it rather than guessing.
//
// Byte-for-byte identical to what the preview arm prints, which is what lets
// `snug fix sysctl > 00-snug.conf` be an honest instruction and what lets -w
// decide "already current" by comparing the file to this string.
func sysctlDropInBody(lines []string) string {
	var b strings.Builder
	b.WriteString("# Written by `snug fix sysctl -w`.\n")
	b.WriteString("# The kernel hardening snug's threat model inherits from this host;\n")
	b.WriteString("# `snug doctor` reports it. 00- so a deliberate host file later in\n")
	b.WriteString("# sysctl.d's order overrides this one; snug raises a floor.\n")
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

func fixSysctlCmd(argv []string) int {
	write := false
	for _, a := range argv {
		switch a {
		case "-w", "--write":
			write = true
		default:
			fmt.Fprintf(os.Stderr, "snug: `snug fix sysctl` takes no arguments and one flag, -w/--write (got %s)\n",
				visibleValue(a))
			return exitUsage
		}
	}

	readings := readHostSysctls(readProcSysFile)

	// Named before anything else that could look like the real problem: a
	// faulted knob is not a weak one, and a user about to be told four things
	// are missing should know first that a fifth could not be read at all.
	for _, r := range readings {
		if !r.readable() {
			fmt.Fprintf(os.Stderr, "snug: %s %s — not fixable, and no line for it will be written\n",
				r.sysctl.knob, r.faultClause())
		}
	}

	weak := sysctlWeakLines(readings)
	body := sysctlDropInBody(sysctlDropInLines(readings))

	if !write {
		return printSysctlFixPreview(readings, weak, body)
	}

	return applySysctlFix(readings, body, os.Geteuid(), containerMarker(), snugSysctlDropIn, writeProcSys)
}

// applySysctlFix is -w's whole effect, with every host fact injected: the
// euid, the container marker, where the drop-in lives, and how a knob is set.
//
// Injected for the reason doctorsubuid.go states for its own report — a
// function that reads the machine can only be tested against whatever machine
// runs the test, and the arms that matter here (running as root, running in a
// container, a drop-in that has been deleted) are all arms this development
// host is not in.
func applySysctlFix(
	readings []sysctlReading,
	body string,
	euid int,
	marker, dropIn string,
	apply func(path string, value int) error,
) int {
	if euid != 0 {
		fmt.Fprintf(os.Stderr, "snug: -w writes %s and /proc/sys and this process is not root; "+
			"run `sudo snug fix sysctl -w`\n", dropIn)
		return exitUnavail
	}

	// The container case, said plainly rather than left to five identical
	// EACCES lines: /proc/sys is mounted read-only in a container and these
	// knobs belong to the host kernel anyway, which the container shares.
	// Setting them from inside is not a thing that can work.
	//
	// EXIT 0, and the code is the finding rather than the message: `snug fix`
	// states in capitals that nothing-to-do exits 0 BECAUSE the namespace is
	// meant to be callable from a distrobox init_hook, where distrobox-init
	// runs hooks under `set -o errexit` and a nonzero exit stops the box from
	// coming up at all. Inside a container there is, by this very refusal,
	// nothing that can be done — which is the definition of nothing to do.
	// Measured at exit 69 before this: a hook that aborted box startup with a
	// message about sysctls.
	if marker != "" {
		fmt.Fprintf(os.Stderr, "snug: %s — these are the HOST kernel's knobs and /proc/sys is read-only "+
			"here; run `sudo snug fix sysctl -w` on the host instead\n", marker)
		return 0
	}

	// TWO INDEPENDENT JOBS, and running the second only when the first had
	// work is the defect a redteam round measured: once the runtime was
	// strict, -w said "nothing to do" and exited 0 even with the drop-in
	// DELETED — an image rebuild, an ansible run, a package upgrade — so the
	// persistence could never be restored until a reboot made the knobs weak
	// again. `snug fix` names that exact failure mode for the sibling noun
	// ("/etc/subuid is part of this container's image, so it goes away on
	// every rebuild"); this one had it with no recovery.
	failed := false
	weak := sysctlWeakLines(readings)
	if len(weak) == 0 {
		fmt.Fprintln(os.Stderr, "snug: the running kernel already has every knob this kernel provides")
	}
	for _, r := range readings {
		if !r.readable() || r.ok() {
			continue
		}
		if err := apply(r.sysctl.path(), r.sysctl.want); err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			failed = true
			continue
		}
		fmt.Fprintf(os.Stderr, "snug: %s = %d (was %d)\n", r.sysctl.knob, r.sysctl.want, r.value)
	}

	// The drop-in is written even if a runtime write above failed: the two
	// answer different questions, and a host where the running kernel refused
	// the value may still be one where the next boot takes it.
	settings := len(sysctlDropInLines(readings))
	if settings == 0 {
		fmt.Fprintln(os.Stderr, "snug: this kernel provides none of these knobs; there is nothing to persist")
		return exitOf(failed)
	}
	if _, err := os.Stat(filepath.Dir(dropIn)); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %s does not exist here (%v) — anything applied above is on the "+
			"RUNNING kernel only and will NOT survive a reboot\n", filepath.Dir(dropIn), err)
		return exitOf(failed)
	}
	// hostread, not os.ReadFile: /etc/sysctl.d is a directory snug does not
	// own, and a FIFO at this path would turn the comparison into an open(2)
	// that never returns (issue #337). An error here is simply "not current"
	// — writeDropIn below refuses anything that is not an ordinary file, in
	// its own words.
	if current, err := hostread.Required(dropIn, maxDropInBytes); err == nil && string(current) == body {
		fmt.Fprintf(os.Stderr, "snug: %s is already current (%d setting(s))\n", dropIn, settings)
		return exitOf(failed)
	}
	if err := writeDropIn(dropIn, body); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v — anything applied above is on the RUNNING kernel only "+
			"and will NOT survive a reboot\n", err)
		return exitUnavail
	}
	fmt.Fprintf(os.Stderr, "snug: wrote %s (%d setting(s)) — `snug doctor` to confirm\n", dropIn, settings)
	return exitOf(failed)
}

// exitOf is the one place -w decides its status, so a return added later
// cannot forget that a failed /proc/sys write is still a failure even when
// the drop-in went in cleanly.
func exitOf(failed bool) int {
	if failed {
		return exitUnavail
	}
	return 0
}

// printSysctlFixPreview is the arm with no -w. Stdout is the COMPLETE file
// body, byte for byte what -w would write; stderr is every word of
// explanation.
//
// It prints that body even when the running kernel needs nothing, and that is
// the fix for a measured defect rather than a style choice. The instruction
// this command inherited from `snug fix subuid` — "nothing to do prints
// nothing" — is correct for a noun whose content is a LINE TO APPEND and
// wrong for one whose content is a WHOLE FILE: with the redirect this
// command's own comment recommended, a host that needed nothing truncated the
// target to zero bytes (measured: 148 bytes before, 0 after, exit 0), which
// is the drop-in deleted by the command that maintains it.
//
// So the promise is made TRUE rather than withdrawn: stdout is always the
// file, `snug fix sysctl > /etc/sysctl.d/00-snug.conf` always leaves a valid
// one, and the only host where stdout is bare is one whose kernel has none of
// these knobs — where an empty drop-in is the correct file.
func printSysctlFixPreview(readings []sysctlReading, weak []string, body string) int {
	fmt.Print(body)
	if len(weak) == 0 {
		fmt.Fprintln(os.Stderr, "snug: the running kernel already has every knob this kernel provides; "+
			"the file above is what makes that survive a reboot")
		fmt.Fprintf(os.Stderr, "snug: nothing was changed — `sudo snug fix sysctl -w` writes %s\n",
			snugSysctlDropIn)
		return 0
	}
	fmt.Fprintf(os.Stderr, "snug: nothing was changed — `sudo snug fix sysctl -w` applies the %d setting(s) "+
		"below to the running kernel and writes %s\n", len(weak), snugSysctlDropIn)
	for _, r := range readings {
		if r.readable() && !r.ok() {
			fmt.Fprintf(os.Stderr, "snug: %s = %d — %s\n", r.sysctl.knob, r.value, r.sysctl.what)
		}
	}
	return 0
}

// writeDropIn writes the sysctl.d file, and it does three things os.WriteFile
// does not. This runs as ROOT, under the user's sudo, so each of the three is
// a file on the machine that is not overwritten.
//
//  1. It REFUSES anything at the path that is not an ordinary, single-linked
//     regular file, and says so in its own words. O_NOFOLLOW alone covered
//     the symlink and a redteam round walked straight past it with a HARD
//     LINK: `ln victim.conf /etc/sysctl.d/00-snug.conf` and the victim's
//     content was gone, replaced by the drop-in. O_NOFOLLOW has nothing to
//     say about a second name for the same inode; st_nlink does.
//  2. It writes a TEMPORARY file in the same directory and rename(2)s it into
//     place, so a concurrent `sysctl --system` reads either the old file or
//     the new one and never a half-written one.
//  3. Its refusal NAMES THE FIX. The bare O_NOFOLLOW error surfaced as `too
//     many levels of symbolic links`, which a human reads as a symlink loop
//     rather than as snug declining to follow one.
//
// The precondition for planting either link is write access to
// /etc/sysctl.d, which is root-owned — the same precondition the symlink case
// had. That is not a reason to skip it: "the attacker would already be root"
// is exactly the argument this discipline exists to stop being made file by
// file, and appendLine (fixcmd.go) states the same for /etc/subuid.
func writeDropIn(path, body string) error {
	// Lstat, not Stat: the question is what is AT the path, not what it
	// points to.
	switch fi, err := os.Lstat(path); {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is a symlink; snug will not write through one — remove it, or "+
			"write the settings into the file it points at by hand", path)
	case err == nil && !fi.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (%s); snug will not write over it — remove it "+
			"and run this again", path, fi.Mode().Type())
	case err == nil && hardLinked(fi):
		return fmt.Errorf("%s is a hard link to another file on this filesystem; snug will not "+
			"write through one, because the write would land in that file too — remove it and "+
			"run this again", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("cannot examine %s before writing it: %w", path, err)
	}

	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".snug-tmp")
	// O_EXCL: the temporary name must not exist, so nothing can have planted
	// a link at it either.
	// HOSTREAD-EXEMPT: this is a WRITE, and hostread is a reader.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("creating %s to write %s: %w", tmp, path, err)
	}
	if _, err := f.WriteString(body); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("closing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming %s into place as %s: %w", tmp, path, err)
	}
	return nil
}

// hardLinked reports whether this directory entry is one of several names for
// the same inode. Split out because the syscall-level type assertion is the
// part a reader stumbles on, and because a filesystem that does not report
// links must answer NO rather than panicking — being unable to tell is not
// evidence of an attack.
func hardLinked(fi os.FileInfo) bool {
	// *syscall.Stat_t, which is what os.FileInfo.Sys() carries on Linux —
	// NOT *unix.Stat_t, the identically-shaped type from x/sys/unix. The
	// assertion against the wrong one fails silently and returns false, so
	// the refusal simply never fires: measured, the hard-link case wrote
	// straight through until the test above named it.
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

// writeProcSys sets one knob on the RUNNING kernel.
//
// A /proc/sys write, not `sysctl -w`: the binary is one more thing to find,
// and doctor's own history (the awk that dangled through
// /etc/alternatives inside the probe sandbox) is what an external tool costs
// a command whose job is to be right about the machine.
func writeProcSys(path string, value int) error {
	// HOSTREAD-EXEMPT: this is a WRITE, and hostread is a reader. path comes
	// from the constant table, and O_NOFOLLOW is the half that does apply —
	// procfs has no symlink here, and refusing one costs nothing.
	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening %s to set %d: %w", path, value, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%d\n", value); err != nil {
		return fmt.Errorf("setting %s to %d: %w", path, value, err)
	}
	return nil
}
