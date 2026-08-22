package engine

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Identity by PATH, not by process tree.
//
// That is what makes teardown work when /usr/bin/podman is a WRAPPER. Inside
// distrobox it is a symlink to distrobox-host-exec, which forwards the call
// over D-Bus to the real podman on the host: snug's child is the shim, the
// engine is in a process tree parented to the host's systemd, and both a
// process-group kill and Pdeathsig miss it entirely. The process tree is a lie
// there; the socket the engine is serving is not.
//
// The mark is the SOCKET path, not the store, and the difference is the whole
// design of this file. The socket carries snug's pid, so it names exactly one
// run. The store is deliberately SHARED — that is what makes a warm start
// possible — so two sandboxes with the same profiles on the same directory
// have the same store, and "kill whatever names the store" would reach into a
// sibling sandbox that is still working. It was written that way first, and it
// killed a concurrent sandbox's engine mid-run.
//
// The accident sentence, which matters more here than an abuse sentence
// because this kills things: the ONLY way this reaps something that is not
// this run's engine is if a foreign command line contains the literal string
// $XDG_RUNTIME_DIR/snug/engines/<key>/podman-<our pid>.sock. The user's own
// rootless podman — eleven images and several containers on the host this was
// developed on — serves $XDG_RUNTIME_DIR/podman/podman.sock and can never
// match. Tests assert both halves.
//
// It is best-effort by construction: in a container without the host PID
// namespace the engine simply is not in /proc, so this finds nothing. That is
// why it is a fast path plus a verification, never the only mechanism — the
// engine's own idle timeout (see lifeline.go) is what holds when this is blind.

// paths returns the strings that identify this run's engine processes.
func (e *Engine) paths() []string { return []string{e.sock} }

// ownedPIDs lists every visible process whose command line names one of paths.
// Processes in exclude (snug itself, and the podman clients snug is running
// right now) are never returned.
func ownedPIDs(paths []string, exclude map[int]bool) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, ent := range ents {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || exclude[pid] {
			continue
		}
		if cmdlineNamesPath(pid, paths) {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

// cmdlineNamesPath reports whether pid's command line contains one of paths.
// Reading /proc/<pid>/cmdline for DATA by numeric pid is reuse-safe — the worst
// a recycled number does is answer for the wrong process, and the caller that
// SIGNALS re-checks this through a pidfd (see signalPinned). A read error (pid
// gone, another user's) is "does not name us".
func cmdlineNamesPath(pid int, paths []string) bool {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(raw) == 0 {
		return false
	}
	cmdline := strings.ReplaceAll(string(raw), "\x00", " ")
	for _, p := range paths {
		if p != "" && strings.Contains(cmdline, p) {
			return true
		}
	}
	return false
}

// signalOwned sends sig to every process that owns one of paths, pinning each
// with a pidfd and re-verifying identity through the pin before it signals.
// It returns the pids it actually signalled.
//
// The pin is the point, not decoration. ownedPIDs learned each pid by scanning
// /proc; between that scan and the kill the pid can be reaped and its number
// handed to an unrelated process, and a bare syscall.Kill(pid) would then
// SIGKILL that innocent process — the exact reuse TOCTOU #294 removed from the
// orphan sweep. pidfd_open pins the task the number named AT OPEN TIME, so
// pidfd_send_signal can never land on a later reuse; and re-reading the cmdline
// after the open drops a number the scan matched but that no longer names us
// (recycled, or an engine that exited between scan and signal).
//
// These pids are HOST-namespace: ownedPIDs reads the host /proc and matches the
// socket path in a host command line, so pidfd_open — which takes a pid in the
// caller's namespace — refers to the same task. This never sees the engine's
// OWN pids, which are numbered in its own namespace (#167) and are not what this
// matches; it matches the host-visible process serving the socket.
func signalOwned(paths []string, exclude map[int]bool, sig syscall.Signal) []int {
	var signalled []int
	for _, pid := range ownedPIDs(paths, exclude) {
		if signalPinned(pid, paths, sig) {
			signalled = append(signalled, pid)
		}
	}
	return signalled
}

// signalPinned pins pid with a pidfd, confirms the pinned process still names
// one of paths, and only then sends sig. It reports whether it signalled.
func signalPinned(pid int, paths []string, sig syscall.Signal) bool {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		// ESRCH: reaped between the scan and here. Nothing to signal, and
		// crucially nothing to signal BY NUMBER — the number may already be
		// someone else's.
		return false
	}
	defer unix.Close(pidfd)
	if !cmdlineNamesPath(pid, paths) {
		// The number was recycled to a process that is not this run's engine.
		// The pidfd pins that innocent process; do not signal it.
		return false
	}
	return unix.PidfdSendSignal(pidfd, sig, nil, 0) == nil
}

// waitQuiet polls until nothing owns paths any more, or the budget runs out.
// It returns what is still there, which is [] on success.
//
// Polling rather than waiting on a pid is deliberate: these are not our
// children, so there is no wait(2) to call on them.
func waitQuiet(paths []string, exclude map[int]bool, budget time.Duration) []int {
	deadline := time.Now().Add(budget)
	for {
		left := ownedPIDs(paths, exclude)
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return left
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// describe renders a pid list with its command lines, for a message a human can
// act on.
func describe(pids []int) string {
	var b strings.Builder
	for _, pid := range pids {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		cmd := "(exited)"
		if err == nil {
			cmd = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		}
		if len(cmd) > 120 {
			cmd = cmd[:120] + "…"
		}
		fmt.Fprintf(&b, "        %d  %s\n", pid, cmd)
	}
	return b.String()
}
