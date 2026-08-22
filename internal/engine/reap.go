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

	"github.com/gomoni/snug/internal/policy"
)

// Identity by PATH, not by process tree — and since Tier C the reason is
// VERIFICATION, not reach.
//
// The wrapper case this was written for is closed. A `podman` that forwards to
// the host — distrobox's distrobox-host-exec shim is the live spelling — put
// the engine in a process tree parented to the host's systemd, where a
// process-group kill and Pdeathsig both missed it, and the socket path was the
// only true thing about it. It cannot happen now, for two independent reasons:
//
//   - The engine's argv names GUEST paths only. Spec resolves --root, --runroot
//     and the socket through Engine.guestPath, which refuses a path no graft
//     exposes, so the argv is entirely under /snug (asserted by
//     TestEngineArgvNamesOnlyGuestPaths). Those paths resolve only inside the
//     engine's derived mount namespace, so an engine that exec'd on the host
//     could not open its own store or bind its own socket — it cannot start.
//   - Preflight P1 refuses the shim before that, by name. Measured on the
//     development host: "podman resolves to /usr/bin/podman, a host-escape
//     helper (distrobox-host-exec) ... snug will not run the container engine
//     through it."
//
// What kills the engine now is the CASCADE: it is pid 1 of its own pid
// namespace (Tier C's C0), so the namespace collapsing takes it and every
// container with it. This file is what checks the cascade worked.
//
// Path identity is still the right mechanism for that check, and the reason is
// not the wrapper: a RECORDED PID is not an option. libpod's recorded pids are
// numbered in the engine's own namespace and mean nothing to a host-side reader
// (#167, which cost a caller its existence), and the engine's own host-side pid
// would still have to be re-verified before any signal — which is what a pidfd
// and a cmdline re-read already do here, without a second thing to keep in
// step. Cheap, and a verification rather than the mechanism.
//
// A wrapper that re-execs INSIDE the derived view is still possible and is not
// this paragraph's case: whatever it execs is a descendant in the engine's pid
// namespace, so the cascade already covers it.
//
// The mark is the SOCKET path, not the store, and the difference is the whole
// design of this file. The socket carries snug's pid, so it names exactly one
// run. The store is deliberately SHARED — that is what makes a warm start
// possible — so two sandboxes on the same target directory, whatever profiles
// either one selected (issue #276), have the same store, and "kill whatever
// names the store" would reach into a sibling sandbox that is still working.
// It was written that way first, and it killed a concurrent sandbox's engine
// mid-run.
//
// The accident sentence, which matters more here than an abuse sentence
// because this kills things: the ONLY way this reaps something that is not
// this run's engine is if a foreign command line contains the literal string
// paths() returns. Note what #344 measured about which string that is —
// paths() returns the HOST socket path while the engine's own cmdline names the
// GUEST one, so today a foreign process naming the host path is the only thing
// this can reap at all, and the verification leg cannot fail. The matcher is
// not corrected here; #344 carries it, because correcting it changes what
// stopLocked's step 3 verifies and when.
//
// The host spelling is
// /tmp/snug-<uid>-<our pid>/sock/podman-<our pid>.sock — NOT under
// $XDG_RUNTIME_DIR, which is where an earlier design put it before issue #63
// Tier B moved the engine's own run directory to /tmp (see engine.go's own
// doc comment on New). The user's own rootless podman — eleven images and
// several containers on the host this was developed on — serves
// $XDG_RUNTIME_DIR/podman/podman.sock and can never match. Tests assert both
// halves.
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
//
// A pid whose /proc/<pid>/cmdline reads back EMPTY means "cannot tell yet", NOT
// "not ours" — issue #318, and the distinction is the point. The kernel sets
// mm->arg_start only after close-on-exec fires, so for a real window after
// execve a live process reads back zero bytes: measured empty 2965/3000
// immediately after exec.Cmd.Start (#317). Rootless podman re-execs itself with
// the same argv, so the one process this sweep looks for is exactly the kind
// that passes through that window, and while it does it is invisible here.
//
// Deliberately not retried, and cmdlineNamesPath is deliberately unchanged.
// Retrying is not cheap: a zero-byte cmdline is not only mid-exec — every
// kernel thread reads zero bytes forever, and so does a zombie — so telling
// mid-exec apart from those needs /proc/<pid>/stat parsing (state Z, PF_KTHREAD)
// on the teardown path. That is new machinery in the file that most needs to
// stay simple, to shorten a miss that is already fail-safe and already bounded;
// waitQuiet names what bounds it.
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
//
// So is an EMPTY read, and that answer is right for this predicate and wrong
// for one of its callers. The predicate asked here is "does this command line
// name us", and a command line nobody can read does not name us. What differs
// is the question the caller is asking it: signalPinned asks "may I KILL this
// pid", where false must mean no; ownedPIDs/waitQuiet ask "is anything of mine
// still ALIVE", where false is not an answer at all. See both (#318).
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
		//
		// An unreadable or EMPTY cmdline lands here too, and that is correct
		// and deliberate — unlike ownedPIDs, this caller is asking "may I kill
		// this", so "cannot tell" must answer no. Do NOT make this one retry
		// (#318): retrying here is signalling a process snug could not
		// identify, which is the reuse TOCTOU #298 exists to prevent wearing a
		// different hat. Whatever the liveness side ever does, this stays.
		return false
	}
	return unix.PidfdSendSignal(pidfd, sig, nil, 0) == nil
}

// waitQuiet polls until nothing owns paths any more, or the budget runs out.
// It returns what is still there, which is [] on success.
//
// Polling rather than waiting on a pid is deliberate: these are not our
// children, so there is no wait(2) to call on them.
//
// Read the empty return as "nothing I could IDENTIFY", never as "nothing
// alive". ownedPIDs cannot see a pid that is mid-execve (#318), and this loop
// returns on its first quiet observation, so a poll landing in that window
// reports a clean teardown while the engine is live — Stop then skips its
// SIGKILL and removes the run directory under it.
//
// What holds instead is named, because "best effort" without a named backstop
// is the kind of prose that rots: the engine is started with --time
// idleTimeout (engine.go), so an engine this sweep missed exits by itself
// within that, and quietBudget is idleTimeout + 5s. Same category as the other
// blindness this file already accepts — in a container without the host PID
// namespace the engine is not in /proc at all — and the same backstop covers
// both.
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
//
// Through policy.VisibleText, because a command line is not snug's text: any
// process on the host can put anything in its own argv, so an ESC here erases
// the line snug printed above it and a bidi override reverses the order the
// rest reads in. Same hazard and same answer as every other host string on a
// snug screen — and TestNoSnugScreenEmitsARawControlCharacter drives the
// --dry-run screen, so it does not reach this sink;
// TestDescribeSanitisesACommandLine does.
func describe(pids []int) string {
	var b strings.Builder
	for _, pid := range pids {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		cmd := "(exited)"
		if err == nil {
			cmd = policy.VisibleText(strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " ")))
		}
		if len(cmd) > 120 {
			cmd = cmd[:120] + "…"
		}
		fmt.Fprintf(&b, "        %d  %s\n", pid, cmd)
	}
	return b.String()
}
