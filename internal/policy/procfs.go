package policy

// The read side of /proc, closed where it can be closed at all.
//
// bwrap's `--proc DEST` takes NO mount options — no `hidepid=`, no
// `subset=pid`, no read-only procfs (measured; .claude/design/PSEUDOFS-AUDIT.md
// §"What bwrap can and cannot do"). A curated procfs is therefore impossible:
// procfs is one mount, all or nothing, and no subtraction primitive exists in
// bwrap at all. **Any closure of a /proc leak is necessarily a REPLACEMENT**,
// which is exactly the case CLAUDE.md's author distinction licenses — snug puts
// its own truthful (here: empty) node at a path, rather than a profile hiding
// what another profile granted.
//
// That authorship is not editorial. Each mount below goes through
// Policy.yieldTo, which sets Mount.Authored, and `rejectMasking` exempts
// Authored mounts and NOTHING else (validate.go RULE 3). A profile cannot
// reach these paths: RULE 2's KindProc row refuses any profile grant strictly
// beneath /proc — asked over the REGION since #29, not over the nearest
// covering mount — and RULE 4 refuses one AT /proc. So this file adds mounts
// inside a region profiles cannot express a grant in, which is what keeps
// invariant 1 literally true while snug carves.
//
// WHY THESE THREE, and not a longer list. The audit ranks the procfs leaks and
// splits them: this is its Tier 1 — the entries with no compat cost, where
// something else in snug has already decided the question.
//
//   - /proc/config.gz  the complete host kernel config: an exploit-selection
//     oracle, and the audit's only High in this group.
//   - /proc/keys, /proc/key-users  the host user's live keyring, Kerberos
//     ccache included. snug ALREADY seccomp-denies add_key/keyctl/request_key,
//     so key USE is dead and this is enumeration of a door that is shut; crun
//     and runc mask the same two.
//
// Tier 2 (kallsyms, modules, interrupts, timer_list, sysrq-trigger) is
// deliberately NOT here: each has a real reader (lsmod, perf, an operator
// debugging), and the audit calls it a judgement rather than a freebie.
// /proc/cpuinfo, /proc/meminfo and /proc/stat are explicitly out — build and
// test runners parse them, which is the payload snug exists to run.
//
// AN EMPTY REGULAR FILE, NOT /dev/null: measured, a bind of /dev/null yields
// EACCES to a reader rather than empty content, and a payload that gets EACCES
// where it expected data behaves differently from one that gets nothing. Empty
// is the honest answer to "what does this sandbox know about the host kernel".
//
// CONDITIONAL ON THE HOST HAVING THE ENTRY, and that is load-bearing rather
// than defensive: `--ro-bind-data` has no `-try` spelling, so naming a path
// this kernel does not publish (no CONFIG_IKCONFIG_PROC, no CONFIG_KEYS) would
// fail the whole run at bwrap. The Stat goes through the injected Environ, so
// internal/policy stays pure and the decision is testable without a kernel
// that has any particular option set.
var maskedProcEntries = []struct{ path, why string }{
	{"/proc/config.gz", "the complete host kernel config — an exploit-selection oracle"},
	{"/proc/keys", "the host user's live keyring (keyctl is already seccomp-denied)"},
	{"/proc/key-users", "the host user's keyring accounting"},
}

// ProcfsNote is the one line --dry-run puts under one of these rows, and it is
// why the table above carries a `why` at all.
//
// The audit's R3 says every replacement must be PRINTED, and a `data
// /proc/config.gz (snug)` row satisfies the letter of that while telling a
// reader nothing: on that screen it looks exactly like a generated config file,
// which is the one thing it is not. What a human needs is which host fact this
// sandbox no longer carries.
//
// Returns "" for every other path, so the renderer can call it per row.
func ProcfsNote(guest string) string {
	if guest == "/proc/sys" {
		return "read-only: the write side is snug's own mount now, not a capability check " +
			"snug does not own. Reads are unchanged, and namespace-scoped values are still " +
			"this sandbox's"
	}
	for _, e := range maskedProcEntries {
		if e.path == guest {
			return "replaced with an EMPTY file — the host's copy is " + e.why
		}
	}
	return ""
}

// installProcfsReplacements is issue #29 / the audit's R3 and R4, and it runs
// AFTER the profile fold: everything here is snug's own, and nothing a profile
// wrote can appear at these paths (validate.go RULES 2 and 4).
//
// R4 first — `--ro-bind /proc/sys /proc/sys` — because it is the one with a
// counter-intuitive measurement behind it. The obvious objection is that
// binding the HOST's /proc/sys over the sandbox's would import the host's
// netns-scoped sysctls, and it does not: /proc/sys/net entries resolve through
// the READING TASK's network namespace, not through the procfs superblock the
// path went via. Measured, inside a private netns:
//
//	--proc /proc                            ls /proc/sys/net/ipv4/conf -> all default lo
//	--proc /proc --ro-bind /proc/sys /proc/sys -> all default lo   (host: + enp2s0f0 wlp3s0 wwan0)
//
// so the sandbox keeps its own view and gains EROFS on the write side. That
// matters because what refuses those writes today is a capability check
// (CAP_NET_ADMIN) or file ownership — the audit's P10a/P10b/P11 — i.e. things
// snug does not own. After this the refusal is snug's own mount, and it stays
// true whatever a future uid mapping does. crun does the same.
// ProcfsClosuresSkipped answers "does this run get the closures", and it is
// the ONE place that decides. --dry-run asks it to disclose the exemption and
// installProcfsReplacements asks it to apply one; two spellings of this
// condition would be a screen that disagrees with the run.
//
// It keys on the RESOLVED Podman mode, not on what the user typed, which is
// deliberate and is the half a reader is most likely to get wrong: a profile
// that INCLUDES @podman-socket takes the closures away from every selection
// that includes it, without the word "podman" appearing on anyone's command
// line. That is why the disclosure is a line on the screen rather than a note
// in the profile's own description.
func ProcfsClosuresSkipped(p *Policy) bool { return p.Podman != PodmanOff }

// IsProcfsClosurePath answers "is this one of the mounts the closures install",
// for the two places that have to name the set without copying it: --dry-run's
// disclosure and TestResolveIsMonotone's named exception. A second literal list
// of these four paths would be the drift this file exists to avoid.
func IsProcfsClosurePath(guest string) bool {
	if guest == "/proc/sys" {
		return true
	}
	for _, e := range maskedProcEntries {
		if e.path == guest {
			return true
		}
	}
	return false
}

// ProcfsClosureExemptionNote is what --dry-run says when they are skipped. It
// lives here, next to the condition and the list, so the screen cannot drift
// from either.
const ProcfsClosureExemptionNote = "the /proc closures are NOT applied on this run: this " +
	"sandbox starts a container engine, and the engine mounts its own procfs for its own pid " +
	"namespace — which the kernel refuses while any mount covers part of the procfs it can " +
	"see (issue #29). So config.gz, keys and key-users read the HOST's values here, and " +
	"/proc/sys is writable-by-capability rather than read-only. Selecting a profile that " +
	"INCLUDES a container profile does this too, whether or not you named one."

func installProcfsReplacements(p *Policy, env Environ) {
	// THE EXEMPTION, and it is a named exception to invariant 1 rather than an
	// implementation detail: selecting a container profile makes this run less
	// protected than the same run without it.
	//
	// Measured, and both ways of having both are closed. A mask has to live in
	// the namespace the PAYLOAD sees — bwrap's, owned by the nested userns —
	// and any mount covering part of a procfs makes that procfs not "fully
	// visible", which is the kernel's precondition for mounting a fresh one in
	// a nested user namespace. So the engine's own `mount("proc", …)` returns
	// EPERM:
	//
	//	snug: __inengine: mounting a fresh /proc for this engine's own pid
	//	namespace: operation not permitted
	//
	// Bisected: the three empty files alone do it, and the read-only bind of
	// /proc/sys alone does it. Unmounting them in the engine's own namespace
	// first is refused by MNT_LOCKED; putting them somewhere the engine
	// tolerates puts them where the payload never sees them, which is not a
	// closure at all.
	//
	// The cost is real and is stated on screen rather than absorbed:
	// ProcfsClosureExemptionNote, printed by --dry-run for exactly the runs
	// this branch takes.
	if ProcfsClosuresSkipped(p) {
		return
	}

	// A read-only bind rather than a KindData replacement: /proc/sys is a
	// directory tree the payload legitimately READS (a build reading
	// /proc/sys/kernel/pid_max, say). This closes the write side and changes
	// nothing about the read side.
	//
	// yieldTo, NOT Replace, and the difference is a silent displacement.
	// Replace overwrites whatever is at the guest path, so a profile's own
	// `ro = ["/proc/sys"]` would VANISH from the policy and Validate would
	// never see it — the sandbox would be correct and the refusal a human
	// depends on would be gone. Measured while writing this: with Replace,
	// TestGrantStrictlyInsideProcIsFatal went green for the wrong reason.
	// Yielding leaves the profile's grant in place for rejectMasking to refuse
	// by name, exactly as /proc and /dev do one level up.
	p.yieldTo(Mount{
		Guest: "/proc/sys", Host: "/proc/sys", Kind: KindBind, Access: AccessRO,
		From: []string{"(snug)"},
	})

	for _, e := range maskedProcEntries {
		if _, err := env.Stat(e.path); err != nil {
			// This kernel does not publish it, so there is nothing to close and
			// naming it would fail the run rather than harden it.
			continue
		}
		p.yieldTo(Mount{
			Guest: e.path, Kind: KindData, Access: AccessRO,
			Content: []byte{}, From: []string{"(snug)"},
		})
	}
}
