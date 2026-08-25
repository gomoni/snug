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
// THE MARK IS THE SPELLING THE ENGINE'S OWN ARGV CARRIES, which since Tier C is
// the GUEST path — engine.go's Spec builds "unix://" + guestSock, and its
// comment there says the host and guest names must not be tidied into one. This
// file was not told for a milestone, and matched the HOST spelling: a string no
// process on the machine ever carries, so the sweep answered "nothing of mine is
// running" on its first poll of every run (issue #344, sev:medium). A matcher
// that names a string nobody produces is not a strict matcher, it is a check
// that cannot fail.
//
// The accident sentence, which matters more here than an abuse sentence
// because this kills things: the ONLY way this reaps something that is not
// this run's engine is if a foreign command line contains the literal string
// /snug/engine/sock/podman-<our pid>.sock. That names a path which exists only
// inside the engine's derived view and carries snug's own pid, unique among
// live processes, so nothing produces it by accident. The user's own rootless
// podman — eleven images and several containers on the host this was developed
// on — serves $XDG_RUNTIME_DIR/podman/podman.sock and can never match, and a
// concurrent snug on the same (deliberately shared) store carries a different
// pid. Tests assert both halves.
//
// FOR CONTRAST, THE SPELLING THIS DELIBERATELY DOES NOT MATCH (kept from #362,
// because paths() returning nil rather than falling back to it is a decision a
// reader needs the other half of): e.sock is
// /tmp/snug-<uid>-<our pid>/sock/podman-<our pid>.sock — NOT under
// $XDG_RUNTIME_DIR, which is where an earlier design put it before issue #63
// Tier B moved the engine's own run directory to /tmp (see engine.go's own doc
// comment on New). No process on the machine carries that string, which is
// exactly why falling back to it would be indistinguishable from not sweeping.
//
// IT IS A STRING THE PAYLOAD CAN AUTHOR, and what stops that is CONFINEMENT
// PLUS AN UNBLOCKABLE KILL PLUS A FIXED BUDGET — not the wall-clock ordering an
// earlier version of this comment named. A payload can put candidate pids on its
// own argv, and payload processes are visible in the host /proc.
//
// The old sentence read: Stop sweeps only after the stage has been reaped, so
// there is nothing of the payload's left to match. That is slightly stronger
// than the timing guarantees — a poll can land while the cascade completes and
// momentarily match a dying, payload-argv'd process. What carries the property
// instead, measured (issue #369 row 1, 2ms poll on host /proc against 1500
// forged engine-ns processes under load): the payload has its own pid namespace
// and no route to a host-namespace process, so every process it can create lives
// under a pid 1 that is Pdeathsig-chained and reaped before this runs, pid 1's
// SIGKILL and zap_pid_ns_processes are unblockable, and the fixed budget
// outlasts any collapse the machine can hold. Observed there: 1500 forgeries
// gone 0.76s before the sweep's first poll.
//
// The wrong version is left visible because a future reader quoting "the sweep
// runs later" would be leaning on the one part that is only usually true. Moving
// this sweep before the collapse still re-opens it, and the symptom would be
// snug naming a payload-chosen command line in the warning that tells a human
// what to kill -9.
//
// It is best-effort by construction: in a container without the host PID
// namespace the engine simply is not in /proc, so this finds nothing. That is
// why it is a fast path plus a verification, never the only mechanism — the
// engine's own idle timeout (see lifeline.go) is what holds when this is blind.

// paths returns the strings that identify this run's engine processes: the
// socket path the engine's argv carries, recorded by Spec when it built that
// argv rather than recomputed here (invariant 6 — one author for the host->guest
// mapping; a second derivation would agree until the day it did not).
//
// EMPTY means Spec never ran, which means no engine was ever exec'd and there is
// nothing to sweep for. Deliberately NOT a fallback to e.sock: that spelling
// appears in no command line on this machine, so falling back to it is
// indistinguishable from not sweeping while looking like a sweep — which is
// precisely the defect issue #344 was. Emptiness has its own failure mode,
// silent vacuity, so stopLocked reconciles it against the lifeline rather than
// trusting it.
func (e *Engine) paths() []string {
	if e.guestSock == "" {
		return nil
	}
	return []string{e.guestSock}
}

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
// within that. quietBudget is no longer tied to idleTimeout and must not be
// read as covering it (issue #344) — Stop runs after the cascade has already
// SIGKILLed the engine, so the budget covers scheduling, not a timeout snug
// would otherwise be standing there waiting out. Same category as the other
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
// EVERY COMMAND LINE HERE IS TEXT SNUG DID NOT WRITE, so it goes through
// policy.VisibleText — the same render-half predicate the dry-run screen and the
// container audit line use. Before the matcher was fixed this was theoretical,
// because the string being matched was one only snug could produce; the match is
// now on the GUEST socket path, which is a string a PAYLOAD can put in its own
// argv, and payload processes are visible in the host /proc. A process that
// wants a human to misread the line telling them what to `kill -9` is not an
// edge case, it is the threat model — and this warning is a screen a human reads
// especially carefully, since it is the one that stopped them.
//
// WHICH TEST COVERS THIS SINK (kept from #362, and the distinction is the point):
// TestNoSnugScreenEmitsARawControlCharacter drives the --dry-run screen and does
// NOT reach internal/engine, which is why this could print a raw command line
// for as long as it did. TestDescribeSanitisesACommandLine is the one that
// reaches it, with a live decoy.
//
// Escaped BEFORE the length clamp: truncating first could cut a multi-byte rune
// and leave a raw 0x9b behind, which is the CSI introducer on a terminal in
// 8-bit mode. Cutting inside %q output is only ever harmless text.
//
// The cmdline is re-read by NUMBER after waitQuiet returned, so on a recycled
// pid this prints an unrelated process's line. Harmless — this only describes,
// it does not signal, and signalPinned is where reuse matters — but it is why
// the escaping is not optional: the line may be some other process's text.
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
