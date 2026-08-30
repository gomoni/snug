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
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// snugSysctlDropIn is where -w persists the settings. 99- so it is read last
// and a deliberate host file earlier in the sequence does not lose to it by
// accident of naming; .conf because that is what sysctl.d(5) reads.
const snugSysctlDropIn = "/etc/sysctl.d/99-snug.conf"

// sysctlFixLines is the decision, with no IO in it: which knobs this host is
// missing, rendered in sysctl.conf(5) syntax, in the table's order. Empty
// means there is nothing to do, which is the contract's most important case.
func sysctlFixLines(readings []sysctlReading) []string {
	var lines []string
	for _, r := range readings {
		if !r.readable() || r.ok() {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s = %d", r.sysctl.knob, r.sysctl.want))
	}
	return lines
}

// sysctlDropInBody wraps those lines in the file -w writes. The header names
// the command that wrote it, so a human who finds this file on a machine
// learns what to run to change it rather than guessing.
func sysctlDropInBody(lines []string) string {
	var b strings.Builder
	b.WriteString("# Written by `snug fix sysctl -w`.\n")
	b.WriteString("# The kernel hardening snug's threat model inherits from this host;\n")
	b.WriteString("# `snug doctor` reports it. Only the knobs this host was missing are here.\n")
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

	// Named before anything else that could look like the real problem: an
	// unreadable knob is not a weak one, and a user who is about to be told
	// four things are missing should know first that a fifth could not be
	// read at all.
	unreadable := 0
	for _, r := range readings {
		if !r.readable() {
			unreadable++
			fmt.Fprintf(os.Stderr, "snug: %s is not readable on this host (%v) — not fixable, and no line "+
				"for it will be written\n", r.sysctl.knob, r.err)
		}
	}

	lines := sysctlFixLines(readings)
	if len(lines) == 0 {
		// Two different sentences, because "already set" is FALSE on a host
		// where a knob could not be read at all — and that is exactly the
		// host where a reader most needs to be told which one it was.
		if unreadable > 0 {
			fmt.Fprintf(os.Stderr, "snug: nothing here is fixable — every knob this kernel has is set, "+
				"and the %d it does not have cannot be\n", unreadable)
		} else {
			fmt.Fprintln(os.Stderr, "snug: this host already sets every kernel knob snug's threat model "+
				"inherits; nothing to do")
		}
		return 0
	}

	if !write {
		return printSysctlFixPreview(readings, lines)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "snug: -w writes %s and /proc/sys and this process is not root; "+
			"run `sudo snug fix sysctl -w`\n", snugSysctlDropIn)
		return exitUnavail
	}

	// The container case, said plainly rather than left to five identical
	// EACCES lines: /proc/sys is mounted read-only in a container and these
	// knobs belong to the host kernel anyway, which the container shares.
	// Setting them from inside is not a thing that can work.
	if marker := containerMarker(); marker != "" {
		fmt.Fprintf(os.Stderr, "snug: %s — these are the HOST kernel's knobs and /proc/sys is read-only "+
			"here; run `sudo snug fix sysctl -w` on the host instead\n", marker)
		return exitUnavail
	}

	failed := false
	for _, r := range readings {
		if !r.readable() || r.ok() {
			continue
		}
		if err := writeProcSys(r.sysctl.path(), r.sysctl.want); err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			failed = true
			continue
		}
		fmt.Fprintf(os.Stderr, "snug: %s = %d (was %d)\n", r.sysctl.knob, r.sysctl.want, r.value)
	}

	// The drop-in is what makes it survive a reboot, and it is written even
	// if a runtime write above failed: the two answer different questions,
	// and a host where the running kernel refused the value may still be one
	// where the next boot takes it.
	if _, err := os.Stat("/etc/sysctl.d"); err != nil {
		fmt.Fprintf(os.Stderr, "snug: /etc/sysctl.d does not exist here (%v) — the settings above are "+
			"applied to the RUNNING kernel and will NOT survive a reboot\n", err)
		if failed {
			return exitUnavail
		}
		return 0
	}
	if err := writeDropIn(snugSysctlDropIn, sysctlDropInBody(lines)); err != nil {
		fmt.Fprintf(os.Stderr, "snug: writing %s: %v — the settings above are applied to the RUNNING "+
			"kernel and will NOT survive a reboot\n", snugSysctlDropIn, err)
		return exitUnavail
	}
	fmt.Fprintf(os.Stderr, "snug: wrote %s (%d setting(s)) — `snug doctor` to confirm\n",
		snugSysctlDropIn, len(lines))
	if failed {
		return exitUnavail
	}
	return 0
}

// printSysctlFixPreview is the arm with no -w, and the split between the two
// streams is the contract rather than a formatting choice: stdout carries
// ONLY the sysctl.conf(5) lines, so `snug fix sysctl > /etc/sysctl.d/99-snug.conf`
// does exactly what it looks like it does, and every word of explanation is
// on stderr where a redirect cannot corrupt the file.
func printSysctlFixPreview(readings []sysctlReading, lines []string) int {
	for _, l := range lines {
		fmt.Println(l)
	}
	fmt.Fprintf(os.Stderr, "snug: nothing was changed — run `sudo snug fix sysctl -w` to apply this "+
		"and write %s\n", snugSysctlDropIn)
	for _, r := range readings {
		if r.readable() && !r.ok() {
			fmt.Fprintf(os.Stderr, "snug: %s = %d — %s\n", r.sysctl.knob, r.value, r.sysctl.what)
		}
	}
	return 0
}

// writeDropIn writes the sysctl.d file, and O_NOFOLLOW is the whole reason
// it is not os.WriteFile: this runs as ROOT, and os.WriteFile follows a
// symlink at the target — a planted /etc/sysctl.d/99-snug.conf pointing at
// any file on the machine would have snug truncate and rewrite it under the
// user's sudo. /etc/sysctl.d is root-owned, so planting one is not a step an
// unprivileged attacker has; appendLine (fixcmd.go) states the same refusal
// for /etc/subuid on the same reasoning, and "the attacker would already be
// root" is exactly the argument that discipline exists to stop being made
// file by file.
//
// O_TRUNC, not append: this file is snug's own by name, its whole content is
// derived from the table, and appending would grow a duplicate stanza on
// every run.
func writeDropIn(path, body string) error {
	// HOSTREAD-EXEMPT: a WRITE; hostread is a reader.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(body)
	return err
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
