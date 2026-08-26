package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// dryRun is not a debugging convenience. It is the mechanism by which a human
// can trust snug at all: a sandbox you cannot read is a sandbox you are
// guessing about. It starts no process and creates no file.
//
// refusedBy is nil for a policy that can actually run. When it is not nil, p
// is a policy Validate refused (see policy.Resolve's doc comment for the
// contract) — dryRun renders it anyway, so a human can see exactly what was
// refused, but says so at the top and bottom instead of implying this is a
// runnable sandbox.
//
// out is an io.Writer rather than the *os.File this took until issue #52,
// because the human screen is no longer the only renderer of this policy:
// renderJSON (dryrunjson.go) writes the same facts to the same stream. Every
// describe* helper below takes the same type for the same reason — a second
// renderer that cannot attach to the block helpers would have to re-derive
// what they know, which is the copy-with-no-link-back shape this repo keeps
// paying for.
func dryRun(env policy.Environ, out io.Writer, p *policy.Policy, args []string, cfg config, refusedBy error) error {
	// ONE Report, then ONE renderer. --json REPLACES the human form; it never
	// adds to it, because the document is the whole of stdout (renderJSON's
	// doc comment says why that matters on a refusal).
	// The one call site with a real host behind it. Everywhere else — every
	// golden, every unit test — pins the summary, so no fixture's verdict
	// depends on what this machine has in /etc/containers.
	rep := buildReport(env, p, args, cfg, refusedBy, func() engine.SignaturePolicySummary {
		return engine.SummariseSignaturePolicy(p.Home)
	})
	if cfg.json {
		return renderJSON(out, rep)
	}
	renderHuman(out, rep, p, args, cfg, refusedBy)
	return nil
}

// renderHuman is the screen this file has always printed. It takes the Report
// as well as the Policy because the facts both renderers state must come from
// ONE derivation — see Report's doc comment for where the sharing is
// structural (Mounts) and where it is only parallel.
func renderHuman(out io.Writer, rep Report, p *policy.Policy, args []string, cfg config, refusedBy error) {
	if refusedBy != nil {
		fmt.Fprintln(out, "snug — dry run of a REFUSED policy (nothing below can run; nothing was started)")
	} else {
		fmt.Fprintln(out, "snug — dry run, nothing was started")
	}
	fmt.Fprintln(out)
	// TARGET and HOME are HOST paths, and a host path is not snug's to refuse —
	// the attacker controls only a directory name, and `mkdir` is not a grant.
	// So rendering is the only guard these two have, exactly as it is for the
	// host path in a masking refusal (policy's describeNode). These two rows sat
	// four lines above a block that had been escaping since the value class was
	// found, which is the shape CLAUDE.md records: a guard added to one block
	// and not the one above it (issue #65).
	fmt.Fprintf(out, "TARGET   %s  %s\n", visibleValue(p.Target), targetAnnotation(p))
	fmt.Fprintf(out, "HOME     %s  %s\n", visibleValue(p.Home), homeAnnotation(p))
	fmt.Fprintf(out, "PROFILES %s\n", visibleValue(policy.JoinNames(p.Selected, " ")))
	if implied := p.Implied(); len(implied) > 0 {
		fmt.Fprintf(out, "         + %s  (pulled in by include; see: snug profile tree)\n",
			visibleValue(policy.JoinNames(implied, " ")))
	}
	describeNetwork(out, p)
	describeTopology(out, p)
	describeGrafts(out, p)
	describeContainers(out, p, rep.Containers)
	describeGit(out, p)
	describeSSH(out, p)
	describeCommands(out, p)
	describeClaude(out, p)
	if rep.NewSession {
		fmt.Fprintf(out, "TTY      --new-session (this kernel allows TIOCSTI, so the sandbox is kept\n")
		fmt.Fprintf(out, "         out of your terminal — the cost is no job control inside)\n")
	} else {
		fmt.Fprintf(out, "TTY      shared session — job control works (TIOCSTI is disabled kernel-wide)\n")
	}
	describeSeccomp(out, rep.Seccomp)
	describeAttach(out)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "FILESYSTEM  (deny-by-default; every line is a grant, there are no deny rules)")
	// rep.Mounts, NOT p.SortedMounts(): this is the ONE place the two
	// renderers share a derivation structurally rather than in parallel, so
	// the FILESYSTEM block and the JSON `mounts` array cannot list different
	// grants. TestHumanAndJSONFilesystemBlocksAgree drives both and compares
	// the sets.
	for _, m := range rep.Mounts {
		kind := m.Kind.String()
		if m.Kind == policy.KindBind {
			kind = m.Access.String()
		}
		// A KindData file with an executable permission bit is CODE, not
		// config — the podman stub is the one case of this today (see
		// podmanstub.go). Kind.String() itself stays "data" for every other
		// caller; this is a dry-run-only rendering so a human scanning the
		// FILESYSTEM block sees "this one runs" at a glance rather than
		// having to notice a permission column.
		if m.Kind == policy.KindData && m.Perms != nil && *m.Perms&0o111 != 0 {
			kind = "exec"
		}
		opt := ""
		if m.Optional {
			opt = " (optional)"
		}
		// Escaped for the same reason the ENVIRONMENT block escapes values, and
		// this block is the one where a forged line reads as a GRANT. A newline
		// survives filepath.Clean, so a profile could write
		//
		//	tmpfs = ["/a\n  ro     /etc/shadow      @sys"]
		//
		// and get a correctly-columned row for a mount that does not exist —
		// while the sandbox really had one directory whose name contained a
		// newline. Validate now refuses a control character in a GUEST path
		// outright, which closes the profile-written half; the escaping stays
		// because a HOST path is not snug's to refuse (a real file may legally
		// be named with a newline) and it still renders here.
		detail := visibleValue(m.Guest)
		if m.Kind == policy.KindSymlink {
			detail = fmt.Sprintf("%s -> %s", visibleValue(m.Guest), visibleValue(m.Host))
		} else if m.Kind == policy.KindBind && m.Host != m.Guest {
			detail = fmt.Sprintf("%s (from %s)", visibleValue(m.Guest), visibleValue(m.Host))
		} else if m.Kind == policy.KindTmpfs {
			// The bound goes on the FILESYSTEM picture, not just in accessWord's
			// "ephemeral" note, because --dry-run is the mechanism by which a
			// human can trust snug and a size a payload could fill the host's
			// RAM with is exactly what this screen exists to disclose (#281).
			detail = fmt.Sprintf("%s (max %s)", visibleValue(m.Guest), policy.FormatBytes(p.TmpfsSizeBytes))
		}
		fmt.Fprintf(out, "  %-6s %-46s %s%s\n", kind, detail, visibleValue(strings.Join(m.From, "+")), opt)
		for _, frag := range wrapMark(yieldedMark(p, m)) {
			fmt.Fprintln(out, frag)
		}
		// The procfs closures (issue #29). Only for snug's OWN mount at that
		// path: a row there that is not Authored is a profile grant, which
		// Validate refuses — and if that ever changes, this must not describe
		// someone else's mount with snug's reasoning.
		//
		// THE EXEMPTION IS DISCLOSED ON THE /proc ROW, which is the one row
		// that is always there. The closures themselves are absent on an
		// engine run, so a note attached to them would be a note nobody sees
		// — the missing rows are exactly what has to be explained. This is
		// invariant 1's named exception reaching the screen it has to reach:
		// a profile that INCLUDES a container profile removes the closures
		// from every selection carrying it, and the command line need never
		// say "podman".
		if m.Authored && m.Guest == "/proc" && policy.ProcfsClosuresSkipped(p) {
			for _, frag := range wrapMark("  ← " + policy.ProcfsClosureExemptionNote) {
				fmt.Fprintln(out, frag)
			}
		}
		if m.Authored {
			if note := policy.ProcfsNote(m.Guest); note != "" {
				for _, frag := range wrapMark("  ← " + note) {
					fmt.Fprintln(out, frag)
				}
			}
		}
	}
	fmt.Fprintf(out, "  %-6s %s\n", "ro-/", "everything else is a read-only skeleton (--remount-ro /)")

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  NOT GRANTED (never mounted — these read as absent, they are not hidden;")
	fmt.Fprintln(out, "  where it says \"host's\", snug generates its own file at that path instead):")
	for _, line := range rep.NotGranted {
		fmt.Fprintf(out, "    %s\n", line)
	}

	fmt.Fprintln(out)
	describeEnvironment(out, p)

	if p.Net.Mode == policy.NetEgress {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "── pasta ─────────────────────────────────────────────────────────────────")
		// The placeholder must name the same KIND of reference the real run
		// uses, or this screen stops being the thing a human can trust: under
		// NetnsSandbox that is bwrap's child pid (ns/net and ns/user together);
		// under NetnsStage no single pid can produce both (policy.PastaTarget's
		// doc comment), so pasta is aimed at a DESCRIPTOR the stage pinned,
		// named from outside as /proc/<stage>/fd/<n>.
		pastaExec := execResolution("pasta")
		if p.Topology.Netns == policy.NetnsStage {
			fmt.Fprintln(out, pastaExec.Argv0+" "+visibleArgs(p.PastaArgs(policy.PastaTargetStage(0, 63))))
			fmt.Fprintln(out, "  (/proc/0/fd/63 is a placeholder; the real pid is the stage's, "+
				"and 63 is fdNetnsN)")
		} else {
			fmt.Fprintln(out, pastaExec.Argv0+" "+visibleArgs(p.PastaArgs(policy.PastaTargetChild(0))))
			fmt.Fprintln(out, "  (/proc/0/... is a placeholder; the real pid is bwrap's child)")
		}
		describeArgv0(out, pastaExec)
	}

	fmt.Fprintln(out)
	describeBwrap(out, p, args, refusedBy)

	if refusedBy != nil {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "REFUSED: %v\n", refusedBy)
	}
}

// describeSeccomp is the review artifact for the filter internal/sandbox
// installs — issue #23's fix. Before this, `snug --dry-run` contained zero
// matches for seccomp|ptrace|filter, in EITHER mode: the flag is appended in
// sandbox.Run after the argv this screen prints, so the bwrap block could not
// show it either, and a run with the hardening deliberately switched off was
// indistinguishable on screen from one with it on. That is invariant 5's
// shape — a guarantee a human cannot check is not one they can trust.
//
// It must read DIFFERENTLY under --no-seccomp; that is the load-bearing half
// of this line, not the summary of what is denied.
//
// What this line must NOT be read to say: that co-resident payloads inside one
// sandbox are isolated from each other. They are not, and the "active" branch
// names BOTH residuals rather than one — a red-team review found that naming
// only the weaker one reads as a complete list and is worse than naming
// neither:
//
//   - /proc/<pid>/fd/N reopen (PTRACE_MODE_READ, which Yama does not gate)
//     lets a sibling read another payload's regular files.
//   - /proc/<pid>/mem — open(2) + pread/pwrite(2) — is the SAME residual
//     process_vm_readv/writev denies, reached without any denied syscall:
//     full read AND write of a sibling's memory, i.e. code injection.
//     Measured, with this filter active and Yama's PR_SET_PTRACER_ANY waived:
//     PROCMEM_READ=OK, PROCMEM_WRITE=OK, victim overwritten. Strictly worse
//     than the fd residual, and the one most worth saying out loud.
//
// Neither is a syscall snug can single out (see the deniedSyscalls doc comment
// in internal/sandbox/seccomp.go, and issues #23 and #47).
// This filter is defence in depth on top of the namespace boundary, scoped to
// the bwrap payload tree; it says nothing about payload-vs-payload isolation.
//
// Three further review findings, each fixed here rather than only noted:
//
//  1. The syscall names below are DERIVED from internal/sandbox's
//     deniedSyscalls (sandbox.DeniedSyscallNames), not typed out a second
//     time. A hand-written copy is exactly the "count in prose is a copy of
//     state held somewhere else" hazard, and it drifted within this same
//     session — the row named one residual and silently omitted a worse one
//     two comments away. Deriving it means the next syscall added to
//     deniedSyscalls either appears here automatically or panics loudly in
//     DeniedSyscallNames — never goes quietly stale.
//  2. BuildFilter's error is no longer discarded. `ok == false` covers two
//     different failures with different fixes: an unsupported GOARCH (err ==
//     nil, nothing wrong, just no syscall table for this arch) and an
//     ASSEMBLY failure (err != nil, asm.offset's jump-range check — a bug in
//     snug's own filter construction). Collapsing both into "UNAVAILABLE for
//     this architecture" would print that sentence on a fully supported
//     amd64 host with a broken filter, naming the wrong fix on the one
//     screen that exists so a human can trust what snug tells them.
//  3. The "active" branch states a KNOWN GAP that BuildFilter's own doc
//     comment already carries twelve lines up: on x86_64, a 32-bit (i386
//     compat) payload runs under a different audit arch and this filter
//     denies it NOTHING. Saying "active" with no qualifier on such a host is
//     the unqualified-guarantee shape this whole block exists to avoid.
//
// describeAttach is §9 of the attach design, rendered rather than paraphrased
// because the honesty requirements are load-bearing: --dry-run starts
// nothing, so it must not create the run directory, and the path it prints
// is the PATTERN (run-<pid>), never a fabricated pid — this run's own pid is
// not the pid a real run would use for its directory name (the pid in the
// name is a human-readable label only; nothing parses it back out), and
// inventing one would be the kind of small lie CLAUDE.md says makes the
// whole artifact untrustworthy.
func describeAttach(out io.Writer) {
	base, snugName := runtimeBase()
	pattern := filepath.Join(base, snugName, "run-<pid>", "state.json")
	fmt.Fprintf(out, "ATTACH   this run publishes %s (0600,\n", pattern)
	fmt.Fprintln(out, "         in a 0700 directory snug owns), so `snug attach <dir>` can join it.")
	fmt.Fprintln(out, "         The file names the sandbox's init pid, its start time and its six")
	fmt.Fprintln(out, "         namespace ids. It carries no command, no argv and no secret.")
	fmt.Fprintln(out, "         Attach is NOT a permission: any process with your uid can join these")
	fmt.Fprintln(out, "         namespaces without snug. What attach adds is the run's own seccomp")
	fmt.Fprintln(out, "         filter, an empty capability set and this policy's environment — a")
	fmt.Fprintln(out, "         plain nsenter has none of the three.")
}

func describeSeccomp(out io.Writer, sc reportSeccomp) {
	// The facts arrive from buildSeccompReport, which is the ONLY caller of
	// sandbox.BuildFilter on this path. Deriving them here as well would be
	// two opinions about whether the filter assembles on this host, on the one
	// screen whose job is saying whether it is actually installed.
	listLines := wrapList(sc.Denied, 64)

	if !sc.Requested {
		fmt.Fprintln(out, "SECCOMP  DISABLED (--no-seccomp) — every syscall below runs UNFILTERED:")
		for _, l := range listLines {
			fmt.Fprintf(out, "           %s\n", l)
		}
		fmt.Fprintln(out, "         — plus clone3 (ENOSYS), ioctl(_, TIOCSTI, _), and")
		fmt.Fprintln(out, "         clone/unshare(CLONE_NEWUSER). The namespace boundary is")
		fmt.Fprintln(out, "         unaffected; this is defence in depth, not the boundary.")
		return
	}

	switch sc.Reason {
	case "assembly-error":
		// An ASSEMBLY failure, not an unsupported architecture: BuildFilter
		// returns (nil, false, err) only when asm.offset's jump-range check
		// trips, on a host whose GOARCH is otherwise fully supported. This is
		// the exact message sandbox.Run's warn would print at run time — show
		// it here rather than the "no syscall table" sentence below, which
		// would name the wrong fix (there is nothing to fix on this host; the
		// bug is in snug's own filter construction).
		fmt.Fprintf(out, "SECCOMP  BROKEN — %s\n", sc.Error)
		fmt.Fprintln(out, "         This is a bug in snug's filter assembly, not a property of this")
		fmt.Fprintln(out, "         host. sandbox.Run will warn and continue WITHOUT the filter. The")
		fmt.Fprintln(out, "         namespace boundary is unaffected; this filter is defence in depth,")
		fmt.Fprintln(out, "         not the boundary.")
		return
	case "unsupported-arch":
		fmt.Fprintf(out, "SECCOMP  UNAVAILABLE for GOARCH=%s (no syscall table) — sandbox.Run will\n", sc.Arch)
		fmt.Fprintln(out, "         warn and continue WITHOUT it. The namespace boundary is unaffected;")
		fmt.Fprintln(out, "         this filter is defence in depth, not the boundary.")
		return
	}

	fmt.Fprintln(out, "SECCOMP  active — denies (EPERM), derived from deniedSyscalls in")
	fmt.Fprintln(out, "         internal/sandbox/seccomp.go:")
	for _, l := range listLines {
		fmt.Fprintf(out, "           %s\n", l)
	}
	fmt.Fprintln(out, "         — plus clone3 (ENOSYS), ioctl(_, TIOCSTI, _), and")
	fmt.Fprintln(out, "         clone/unshare(CLONE_NEWUSER).")
	if sc.CompatArchGap {
		fmt.Fprintln(out, "         KNOWN GAP on this architecture: a 32-bit (i386 compat) payload runs")
		fmt.Fprintln(out, "         under a DIFFERENT audit arch, and this filter denies it NOTHING —")
		fmt.Fprintln(out, "         see BuildFilter's doc comment in internal/sandbox/seccomp.go.")
	}
	fmt.Fprintln(out, "         Defence in depth on the payload tree, not a guarantee that")
	fmt.Fprintln(out, "         co-resident payloads are isolated from each other: a sibling still")
	fmt.Fprintln(out, "         reaches another payload's files through /proc/<pid>/fd/N, and —")
	fmt.Fprintln(out, "         strictly worse — its MEMORY (read and write) through")
	fmt.Fprintln(out, "         /proc/<pid>/mem. Neither is a syscall seccomp can single out.")
}

// wrapList joins items with ", " and wraps to width VISIBLE runes per line —
// used because the syscall list is DERIVED (sandbox.DeniedSyscallNames) and
// therefore variable-length: a hand-wrapped literal string cannot track a
// list whose length changes when a future syscall is added or removed.
func wrapList(items []string, width int) []string {
	var lines []string
	cur := ""
	for _, it := range items {
		switch {
		case cur == "":
			cur = it
		case utf8.RuneCountInString(cur)+2+utf8.RuneCountInString(it) > width:
			lines = append(lines, cur+",")
			cur = it
		default:
			cur = cur + ", " + it
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// describeEnvironment renders what the sandbox's environment will be. bwrap
// --clearenv discards the host's, so nothing of the HOST's environment appears
// inside that is not on this block — with two caveats, and the second one used
// to be missing, which is the reason this comment now enumerates rather than
// asserts.
//
// CAVEAT 1, long recorded: a bound /etc means /etc/profile.d can still put
// variables back (CLAUDE.md).
//
// CAVEAT 2, and it is the one that made this comment false: BWRAP AUTHORS `PWD`
// ITSELF, from --chdir. This block used to say "this block is the WHOLE of it —
// there is nothing inherited that does not appear here", and it was measured
// wrong in a live sandbox (redteam host round 2, F5 — the measurements in this
// paragraph are that round's; the bwrap-binary corroboration below is not).
// Across five selections, the block's names, the argv's --setenv names
// and `env` INSIDE agreed byte for byte except for exactly one name:
//
//	block 16 / argv 16 / inside 17   (@sys @home @cwd-rw @parent-ro)
//	block 18 / argv 18 / inside 19   (@claude)
//	…and PWD is the difference every time
//
// isolated with no shell anywhere — the payload was `env`, exec'd directly:
//
//	bwrap --ro-bind /usr /usr … --clearenv --chdir /usr /usr/bin/env
//	  PWD=/usr
//
// Corroborated here against bwrap 0.11.2's own binary, and the way it was
// corroborated is worth keeping: `strings /usr/bin/bwrap | grep -i pwd` finds
// NOTHING and reads as a refutation, because strings(1) defaults to -n 4 and
// "PWD" is three characters. `strings -n 3` finds it. A check that cannot
// produce the answer it is looking for is this project's named failure mode, and
// it nearly retracted a true finding here.
//
// AND THE EVIDENCE WAS ALREADY IN THE REPOSITORY, which is the part worth
// keeping: ENVIRONMENT-VARIABLES.md §4.1 lists what `snug <dir> -- env` printed
// — "HOME LANG LOGNAME PATH PS1 PWD SHELL SNUG …", PWD among them — measured, in
// a document, while this comment two directories away said the block was the
// whole of it. Nobody read the two together. A measurement filed under one
// question does not answer another one on its own.
//
// So PWD is rendered as its own row, in bwrap's provenance rather than snug's.
// The content is harmless — it is the target, already on this screen twice — and
// that is exactly why it is worth a row: what invariant 5 forbids is an artifact
// claiming a completeness it does not have. Note what this says about the check
// that passed while the claim was false: round 1 compared "18 variables, byte for
// byte" between the block and the argv, and BOTH are generated from p.Env. An
// equivalence between two things snug generates cannot see a third party adding
// to the result.
//
// It is a function of its own, rather than eight lines inside dryRun, because
// it is the review artifact for the environment the same way the .bwrap.txt
// goldens are for the argv: internal/cli/testdata/env.*.txt is exactly this block,
// resolved against the REAL builtin profiles rather than a fake registry.
// The layout is §2.8's, and the PATH bands read top to bottom in RESOLUTION
// ORDER — so the rendering IS the §2.4 band diagram. If the two ever disagree,
// the renderer is lying, and a flat NAME=value list (which this replaced) could
// not disagree because it said nothing: not which verb produced a value, not
// which profile, and not what a filter dropped on the way.
func describeEnvironment(out io.Writer, p *policy.Policy) {
	fmt.Fprintln(out, "ENVIRONMENT  (--clearenv, then:)")
	for _, name := range p.EnvNames() {
		v := p.Env[name]
		lines := envLines(p, v)
		if len(lines) == 0 && len(v.Dropped) == 0 {
			continue
		}
		label := name
		if len(lines) == 0 {
			// Nothing survived the filter, so the variable is UNSET rather than
			// set empty (§4.3). Say so on the screen: a variable that vanished
			// silently is exactly the failure §2.8 exists to prevent, and the
			// drops below are the whole explanation.
			fmt.Fprintf(out, "  %-16s %s\n", label, "(unset — nothing survived)")
		}
		for _, l := range lines {
			fmt.Fprintln(out, strings.TrimRight("  "+pad(label, 16)+" "+
				pad(strings.Join(l.values, " "), 31)+" "+pad(l.verb, 9)+" "+l.from, " "))
			label = ""
			// EACH MARK ON ITS OWN INDENTED LINE, never appended to the row.
			// See markIndent for why, and for why the indent is 21 rather than
			// the 19 the drop lines below use.
			for _, m := range l.marks {
				for _, frag := range wrapMark(m) {
					fmt.Fprintln(out, frag)
				}
			}
		}
		// Dropped elements are NAMED, not counted. "1 of 3 kept" does not let
		// anyone check a filter, and a filter nobody can check is the exact shape
		// of failure this whole model exists to avoid.
		//
		// Grouped by REASON, one line per group, because "nothing grants that
		// path" and "only a tmpfs grants it" are materially different facts: the
		// second means the directory IS inside, is empty, and is writable, and
		// snug removed the element because keeping it would ship that shadow slot
		// pre-installed. Conflating the two into one ungrouped line is exactly
		// the ambiguity the drop's own Reason field exists to remove.
		//
		// Iterates a FIXED slice, never map order, so the rendering does not vary
		// run to run for the identical policy.
		// EVERY reason must be listed here. A drop whose reason is missing from
		// this slice is removed from the value and rendered nowhere — a silent
		// removal, which is the exact failure EnvDrop.Reason exists to prevent.
		// Adding a reason to policy.EnvDropReason means adding it here.
		for _, reason := range []policy.EnvDropReason{
			policy.DropNoGrant, policy.DropTmpfsOnly, policy.DropPseudoOnly,
			policy.DropReplaceable,
		} {
			var vals []string
			for _, d := range v.Dropped {
				if d.Reason == reason {
					vals = append(vals, visibleValue(d.Value))
				}
			}
			if len(vals) == 0 {
				continue
			}
			word := "entries"
			if len(vals) == 1 {
				word = "entry"
			}
			fmt.Fprintf(out, "  %-16s (%d host %s dropped — %s: %s)\n",
				"", len(vals), word, reason.String(), strings.Join(vals, ", "))
		}
	}
	describeBwrapAuthoredEnv(out, p)
}

// describeBwrapAuthoredEnv renders the one variable inside the sandbox that snug
// does not write: PWD, which bwrap sets from --chdir. See describeEnvironment's
// comment for the measurement.
//
// It is rendered AFTER the sorted rows rather than in its sorted place, and that
// is the honest layout rather than the tidy one: the block above is snug's
// resolved environment, in name order, and this row is not part of it. Its verb
// column says `(bwrap)` — a provenance no policy can produce, since EnvVerb has
// no such value — so the row cannot be mistaken for something a profile asked
// for.
func describeBwrapAuthoredEnv(out io.Writer, p *policy.Policy) {
	if p.Chdir == "" {
		return
	}
	fmt.Fprintln(out, strings.TrimRight("  "+pad("PWD", 16)+" "+
		pad(visibleValue(p.Chdir), 31)+" "+pad("(bwrap)", 9)+" --chdir", " "))
	// ONE LINE, deliberately. This row is on every --dry-run, including the
	// default one, and internal/cli/testdata/env.defaults.txt staying quiet is the
	// review artifact for issue #84's deferral — three lines of explanation about
	// a harmless variable would be exactly the "teaches the reader to skip marks"
	// noise that decision was avoiding.
	for _, frag := range wrapMark("  ← bwrap sets this from --chdir; snug does not") {
		fmt.Fprintln(out, frag)
	}
}

// pad is %-Ns counted in RUNES rather than bytes. PS1 is snug's own and carries
// a lock emoji, so byte padding shifted every column on that one line — in the
// file a human reads to check the environment.
func pad(s string, n int) string {
	if w := utf8.RuneCountInString(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

// The geometry of a mark line, and both numbers are load-bearing.
//
// WIDTH. A row can carry three marks at once — `← unchecked` about the NAME, the
// annotation about what the tool DOES, and `← not granted` about the VALUE — and
// concatenating all three onto one line of a fixed-column table produced, measured
// on this host before this change:
//
//	277  GIT_CONFIG_KEY_0 …  ← unchecked …  ← GIT_CONFIG_*: git reads this at the …
//	272  NPM_CONFIG_SCRIPT_SHELL …
//	264  GIT_SSH  /var/lib/toolchain/ssh  set  worst  ← unchecked …  ← git runs this …  ← not granted
//
// At 80 columns that is 3–4 UNINDENTED wrapped fragments in the middle of a
// 20-row aligned table, with `← not granted` — the one verdict about that value —
// landing at the end of the third fragment, typographically indistinguishable
// from snug's prose. Every other --dry-run block already fits 80 (the seccomp
// list wraps at 64, the bwrap notes reach 78, the topology block 81), so 80 is
// the house width and this block was the outlier.
//
// INDENT, and this is a security property rather than taste. Column 19 is
// TAKEN: a continuation BAND of a list variable renders pad("",16) — exactly 19
// spaces — and so does a drop line. A mark starting there would be told apart
// from a value only by the `←` glyph, and visibleValue does not escape that
// glyph (it is not a control character), so a value could render a line that
// reads as snug's own verdict. That is the §2.3 class — a profile's text
// authoring a LIE on the screen a human trusts — one layer down from the
// newline case. At 21 no data line can reach the column, and the rule
// "a line indented 20 or more is snug's own mark" is structural.
// TestNoEnvironmentLineCanBeMistakenForAMark asserts it.
const (
	markIndent  = 21
	markWrapPad = 2 // hanging indent for the wrapped remainder of one mark
	screenWidth = 80
)

// wrapMark renders one mark as its own indented line, or several if it does not
// fit. It breaks on spaces ONLY and never splits a token: a path cut in half is
// a lie about a path, and these lines carry paths. Widths are counted in RUNES
// for the reason pad is — the block already carries an emoji and a `←` per mark.
//
// The caller hands over the mark exactly as internal/policy rendered it, leading
// spaces and all: that "  ← " prefix is `snug profile show`'s business (it
// concatenates), so this sink trims rather than asking policy for a second
// spelling. One wording, two screens — see policy.UncheckedEnvNote.
func wrapMark(mark string) []string {
	s := strings.TrimLeft(mark, " ")
	if s == "" {
		return nil
	}
	head := strings.Repeat(" ", markIndent)
	cont := strings.Repeat(" ", markIndent+markWrapPad)

	var out []string
	prefix, cur := head, ""
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case utf8.RuneCountInString(prefix)+utf8.RuneCountInString(cur)+1+
			utf8.RuneCountInString(word) > screenWidth:
			out = append(out, prefix+cur)
			prefix, cur = cont, word
		default:
			cur += " " + word
		}
	}
	if cur != "" {
		out = append(out, prefix+cur)
	}
	return out
}

// envLine is one rendered row: consecutive entries that agree on verb, marks and
// provenance are one line, which is what makes a band read as a band rather than
// as four unrelated rows.
//
// marks is a SLICE and not a concatenated string, which is the whole of the
// rendering fix: the three statements a row can carry are three statements, and
// they render as three lines. The order is fixed by envLines and asserted by
// TestUncheckedMarkJoinsRatherThanReplacesTheGrantMark.
type envLine struct {
	values []string
	verb   string
	from   string
	marks  []string
}

func envLines(p *policy.Policy, v policy.EnvVar) []envLine {
	var out []envLine
	for _, e := range v.Entries {
		verb, from := e.Verb.String(), strings.Join(e.From, "+")
		if e.Verb == policy.VerbSnug {
			from = e.Note
		}
		var marks []string
		add := func(s string) {
			if s != "" {
				marks = append(marks, s)
			}
		}
		// THE UNCHECKED MARK JOINS THE GRANT MARK; it does not replace it, and
		// the first draft of this change had it the other way round.
		//
		// The argument for replacing was that `← not granted` is a claim about a
		// PATH, and for an unrostered name snug does not know the value is one —
		// the same reason the coupling rule leaves such a value alone
		// (envcoupling.go's isPathValued). Two independent reviews measured what
		// that actually did, and it removed information the screen had on the
		// base commit: the identical profile text rendered `← not granted`
		// before the flip and only `← unchecked` after it, so a human reading
		// --dry-run stopped being told that the path a profile just handed the
		// sandbox does not exist inside it. It also inverted the pair — a
		// ROSTERED code-carrying scalar (`set BASH_ENV = "/var/lib/x"`) kept the
		// verdict while the UNROSTERED one lost it.
		//
		// The two marks are two different statements and both are true
		// independently. `unchecked` is about the NAME: snug has no roster row,
		// so nothing about this variable's meaning was checked. `not granted` is
		// about this VALUE as a string: it is spelled like an absolute path and
		// no mount covers it. grantMark presumes no type it did not already
		// presume for every rostered scalar — its whole test is HasPrefix(value,
		// "/") and a lookup in p.Mounts — and it is exactly as approximate for
		// BASH_ENV, whose value is a path, as for LESSOPEN, whose value is a
		// command line. Suppressing it for one of those and not the other was
		// the difference this branch introduced, not a difference in what snug
		// knows.
		//
		// THREE STATEMENTS, ONE ORDER, and none of them replaces another. The
		// third arrived with the annotation table (issue #44's second pass), and
		// it is inserted between the other two rather than beside them:
		//
		//   unchecked   about the NAME — snug has no roster row, so no type
		//   EnvNote     about what the tool DOES with the value
		//   grantMark   about the VALUE as a path — nothing inside covers it
		//
		// The order is narrowest-scope-last and is fixed by
		// TestUncheckedMarkJoinsRatherThanReplacesTheGrantMark. `unchecked` comes
		// first because it qualifies everything after it. The note comes before
		// grantMark because it is about the variable's MEANING, while grantMark
		// is about this one string.
		//
		// They ARE THREE LINES rather than one, and that is the second half of the
		// same argument: three statements concatenated onto one row of an aligned
		// table produced a 277-column line whose last mark — the verdict about this
		// very value — was unreadable (see markIndent). The ORDER is unchanged; only
		// the geometry is.
		//
		// The two can co-occur, and that is not a contradiction: `set
		// PIP_INDEX_URL` has no roster row (unchecked — snug has no type for it)
		// and matches an annotated family (PIP_*: outranks the config file pip
		// reads). Both sentences are true and they answer different questions.
		//
		// Both strings come from internal/policy, so `snug profile show` renders
		// the identical text: one property, one wording, two screens. That was
		// claimed here while this sink still held its own copy of the unchecked
		// string and the other sink held a second — see policy.UncheckedEnvNote.
		add(policy.UncheckedEnvNote(v.Name, e.Verb))
		add(policy.EnvNote(v.Name, e.Verb))
		add(grantMark(p, v.Name, e.Value))
		// The collapse key is unchanged in MEANING — it was the concatenated mark
		// string and is now the same statements compared elementwise. A band of
		// several values that all carry the identical marks stays one row with one
		// set of marks under it.
		if n := len(out); n > 0 && out[n-1].verb == verb && out[n-1].from == from &&
			slices.Equal(out[n-1].marks, marks) {
			out[n-1].values = append(out[n-1].values, elementValue(v.Name, e.Value))
			continue
		}
		out = append(out, envLine{values: []string{elementValue(v.Name, e.Value)},
			verb: verb, from: from, marks: marks})
	}
	return out
}

// elementValue is visibleValue for one element of a LIST, and it adds the one
// thing a list needs: an element containing a space is quoted.
//
// Consecutive entries from the same verb and the same profiles are collapsed
// onto one line and joined with a space, so `/srv/a /srv/b` on the screen could
// be two elements or one element with a space in it — and those are different
// policies. The same ambiguity in `checkPrependAgreement`'s KEY made two
// disagreeing profiles compare equal and silently deleted one's entry (seqKey,
// envresolve.go); this is the display half of it. Fixing only the key would
// leave the screen unable to show what the key now distinguishes.
func elementValue(name, s string) string {
	if policy.IsEnvList(name) && strings.ContainsAny(s, " \t") {
		return fmt.Sprintf("%q", s)
	}
	return visibleValue(s)
}

// visibleValue renders a value so it cannot forge a line in this block.
//
// A sanitised element is HOST text — snug copies the host's value and filters
// it — and the drop line printed it verbatim. The red team put a newline in a
// host PATH element and the drop line split, the injected second line reading as
// a legitimate ENVIRONMENT row:
//
//	(2 host entries dropped — only an empty writable tmpfs is mounted there: /tmp/x/bin
//	  FORGED_VAR       fake-value                    forged-provenance, /tmp/y)
//
// --dry-run is the mechanism by which a human trusts snug, so a value that can
// author a row in it is a hole in the trust artifact even though it escapes
// nothing. internal/policy already applies exactly this guard to variable NAMES
// in its error messages (quoteVisible); the values had no equivalent.
//
// Applied to kept entries as well as dropped ones: a host element under a bind
// survives the filter, and it can carry a newline just as easily.
//
// A value with no control characters renders unchanged, so the ordinary screen —
// and every golden — is untouched.
//
// THE TRIGGER WAS ASCII-ONLY AND THAT LEFT THE C1 CONTROLS RAW (redteam host
// round 2, F6). `r < 0x20 || r == 0x7f` misses U+0085 (NEL) and U+009B (CSI —
// the single-character form of ESC-[), which are neither below 0x20 nor DEL, so
// a profile description containing ONLY C1 characters reached every sink
// verbatim:
//
//	$ snug profile list | grep c1 | cat -A
//	  c1   harmlessM-BM-^[1AM-BM-^[1G@sys   shipped by snugM-BM-^Esneaky$
//
// Note the asymmetry that hid it, because it is the reusable half: mix ONE ASCII
// control into the same value and %q escapes the C1 characters too — Go's
// strconv quotes anything unicode.IsPrint rejects — so the guard LOOKS like it
// covers them. Only a pure-C1 value shows that the TRIGGER, not the escaper, was
// the narrow half.
//
// Latent rather than live on this box: tmux 3.7b does not interpret C1 decoded
// from UTF-8 (measured with `tmux capture-pane` — the bytes sit in the cell, no
// line was overwritten). It becomes live on a terminal in 8-bit C1 mode.
//
// WHAT COUNTS AS FORGING IS NOT DECIDED HERE. It is policy.IsForgingRune, which
// this file's isForgingRune wraps and does not extend: C0/DEL/C1 through
// unicode.IsControl, U+2028/U+2029 by name, and the nine UAX #9 explicit
// directional formatting characters — the last group added after a red team
// rendered U+202E raw into this very block, the --setenv argv line, `profile
// show` and `profile list`, in a value, a description and a mount path. The
// argument for the edge of that set, including the characters deliberately left
// out of it, is at the predicate.
//
// AND INVALID UTF-8 IS ESCAPED WHOLESALE, which is the live half of the same
// finding. A raw 0x9b byte is not valid UTF-8, so it decodes to RuneError and no
// rune predicate can see it — while on a terminal in 8-bit mode it IS the CSI
// introducer. The values that can carry one are the HOST's (`inherit`,
// `sanitise`, a host path in a bind): checkEnvValue cannot reach those, and TOML
// cannot produce them, so this is the only guard that can.
// It is policy.VisibleText, not a copy of it, for the reason isForgingRune below
// gives: this file held one of the copies that agreed with each other and not
// with the two in internal/policy, and the sink that was still rendering raw was
// a REFUSAL — the screen a human reads most carefully, since it is the one that
// stopped them.
// visibleArgs escapes EVERY element of a rendered command line, not the joined
// string, and the difference is the defect it was written for.
//
// The bwrap argv four lines above this went through formatArgs/visibleValue
// from the beginning; the pasta argv did not, and a red team round put an ESC
// payload through a profile's `address` key straight onto the screen — the
// "fixed one block, left the block below it broken" shape this file's own
// comments warn about. Escaping per element rather than after the join is what
// keeps the separator snug's: an element cannot contribute a space that reads
// as an argument boundary, and cannot contribute a newline that reads as the
// end of the command.
func visibleArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = visibleValue(a)
	}
	return strings.Join(out, " ")
}

func visibleValue(s string) string {
	return policy.VisibleText(s)
}

// isForgingRune is "this rune can author a line snug did not write", and it is
// now literally the same predicate policy.checkEnvValue refuses at parse time
// rather than a second spelling of it.
//
// IT WAS A COPY, AND THE COPY IS WHAT LET U+202E THROUGH. The two spellings were
// widened together when the ASCII-only trigger was found, which read as evidence
// that "kept in step by TestNoSnugScreenEmitsARawControlCharacter" was working \u2014
// and it was, for the two sites that test drives. It never covered
// policy.Validate's guest-path check or Identity.CheckText, which stayed
// ASCII-only through the whole of that round, and when round 3 arrived with a
// category-Cf character it walked past all four at once. A test that keeps N
// copies in step is worth less than not having N copies: the argument for the
// SET, including which characters are deliberately not in it, lives at
// policy.IsForgingRune (internal/policy/forging.go).
//
// This wrapper stays because visibleValue needs a func(rune) bool and because
// the name is what the tests here read; it must never grow a case of its own.
func isForgingRune(r rune) bool {
	return policy.IsForgingRune(r)
}

// grantMark is §4.2's repair, and it is a MARK rather than a refusal on purpose.
//
// snug authors HOME, PATH and SHELL unconditionally, and must keep doing so:
// there is no safe absent state for any of them (§4.3 — unset PATH and bash
// substitutes a compiled-in default ending in ".", which inside snug is the
// target). An earlier draft concluded the opposite and would have converted
// twenty minutes of confusion into a reachable hole. So the repair is to say
// which authored values name a path that is not inside this sandbox:
//
//	snug --dry-run --no-defaults -p @parent-ro .
//	  HOME, SHELL and all four PATH entries name directories that do not exist
//	  inside, and until now the screen said nothing about it.
//
// Computed against the RESOLVED MOUNTS, unlike the coupling rule in
// envcoupling.go, which is deliberately text-only. The asymmetry is the point:
// REFUSING must not depend on the host, or the same profile passes review on one
// machine and fails on another — but MARKING may, and here it must, or the mark
// is not about the sandbox that is actually going to run.
// The count of grants INSIDE an unmarked path is not decoration either. The
// predicate is "does a grant cover this path", and it must stay the one the
// sanitise filter uses (policy.GrantsGuestPath) — two implementations of "is
// this granted" eventually disagree, and the one on screen is the one a human
// trusts. But that predicate alone says "not granted" about policy.StagedBinDir,
// the directory snug creates to hold every executable it stages: true in the
// policy's own vocabulary, and misleading on a line whose whole point is that a
// binary WILL be found there. Naming what is mounted inside keeps one predicate and
// stops the mark reading as a bug report — the difference between "$HOME is not
// yours to write" and "this directory holds exactly one generated file" is then
// visible without a second rule.
//
// THE SECOND MARK, and why it is scoped to PATH rather than to every path-valued
// name. The screen used to render two entries with the IDENTICAL property in
// opposite ways, four lines apart:
//
//	PATH  /opt/scratch/bin   merge   both      <- kept, unmarked
//	      (1 host entry dropped — only an empty writable tmpfs is mounted
//	       there: /tmp/attacker/bin)
//
// Both are empty writable tmpfs directories. The filter dropped one and named
// its reason; the other is a profile's own `merge`, which `sanitise` structurally
// cannot reach (it only ever judges the HOST's value for a variable a profile
// imported). Correct in every particular, and it reads as a bug in the filter —
// or worse, does not read at all, which is how @claude's {home}/.local/bin
// survived a milestone on screen in front of everybody.
//
// So the mark answers policy.IsShadowSlot's question — "can the payload write
// here" — and only for PATH, because PATH is the variable whose entries are
// searched for COMMANDS. A writable CARGO_HOME or XDG_CACHE_HOME is not a defect,
// it is the point of those variables, and marking them would train the reader to
// ignore the mark on the one line where it matters.
//
// THE SHADOW MARK IS TESTED FIRST, and it used to be nested inside the "granted"
// branch under the argument that the two "cannot collide: IsShadowSlot needs a
// covering mount to return true, and GrantsGuestPath returning false means there
// is none". That was true while both predicates stopped AT a symlink. They now
// follow one, and the two answers came apart in the one direction that loses a
// warning: a DANGLING link standing on writable ground is not granted (the chain
// resolves to nothing) and IS a shadow slot (the payload unlinks it and mkdirs
// its own directory at that name). Nested, that renders as a bare "not granted"
// and the writable mark disappears — the screen omitting the more dangerous of
// two true facts. Hoisted, the warning wins, which is the right precedence: "you
// can be given a command you did not install" outranks "this names nothing".
//
// For every case reachable before the symlink work the two orderings agree, so
// this is a reorder rather than a behaviour change wherever it can be compared.
func grantMark(p *policy.Policy, name, value string) string {
	grant, inside := envGrantVerdict(p, name, value)
	switch grant {
	case grantShadowSlot:
		return "  ← writable from inside"
	case grantNotGranted:
		switch inside {
		case 0:
			return "  ← not granted"
		case 1:
			return "  ← not granted (1 grant inside)"
		}
		return fmt.Sprintf("  ← not granted (%d grants inside)", inside)
	}
	return ""
}

// The three CODES envGrantVerdict returns. jsonEnvEntry.Grant carries these
// spellings verbatim (dryrunjson.go), so a consumer can assert `grant !=
// "shadow_slot"` without reimplementing IsShadowSlot over mounts[] — the thing
// grantMark's own history above warns against.
const (
	grantOK         = ""
	grantShadowSlot = "shadow_slot"
	grantNotGranted = "not_granted"
)

// envGrantVerdict is grantMark's FACT, split from its SENTENCE, so both
// renderers derive one answer rather than the human screen owning the only
// copy. insideCount is meaningful only when grant is grantNotGranted; it is
// the same count grantMark's parenthetical reports.
//
// See grantMark's own comment for why the shadow-slot check runs before
// GrantsGuestPath and why it is scoped to PATH alone.
func envGrantVerdict(p *policy.Policy, name, value string) (grant string, insideCount int) {
	if !strings.HasPrefix(value, "/") {
		return grantOK, 0
	}
	if name == "PATH" && p.IsShadowSlot(value) {
		return grantShadowSlot, 0
	}
	if p.GrantsGuestPath(value) {
		return grantOK, 0
	}
	inside := 0
	for _, m := range p.Mounts {
		if strings.HasPrefix(m.Guest, value+"/") {
			inside++
		}
	}
	return grantNotGranted, inside
}

// mountedAt finds the mount that determines what is visible at path — the
// deepest KindBind or KindTmpfs mount whose Guest is path itself or an
// ancestor of it. This mirrors the "deepest mount wins" rule Resolve itself
// applies (CLAUDE.md invariant 1): effective access at a path is a property of
// the covering set, not of any one grant, so --dry-run must compute it the
// same way rather than assuming which profile was selected.
//
// see policy.coveringMount — different question (the TARGET/HOME headline
// here vs. "is the host's content really at this path").
func mountedAt(p *policy.Policy, path string) (policy.Mount, bool) {
	var best policy.Mount
	found := false
	for _, m := range p.Mounts {
		if m.Kind != policy.KindBind && m.Kind != policy.KindTmpfs {
			continue
		}
		if m.Guest != path && !strings.HasPrefix(path, m.Guest+"/") {
			continue
		}
		if !found || len(m.Guest) > len(best.Guest) {
			best = m
			found = true
		}
	}
	return best, found
}

// targetAnnotation and homeAnnotation replace two claims that used to be
// hard-coded true — "(writable)" and "(tmpfs, ephemeral)" — and were false
// for any selection that did not include @cwd-rw / @home, the floor (no
// profile at all) most of all: neither path is mounted, so the honest
// annotation is "never granted", not "writable".
func targetAnnotation(p *policy.Policy) string {
	return pathAnnotation(p, p.Target)
}

func homeAnnotation(p *policy.Policy) string {
	return pathAnnotation(p, p.Home)
}

func pathAnnotation(p *policy.Policy, path string) string {
	m, ok := mountedAt(p, path)
	if !ok {
		return "(not mounted — never granted)"
	}
	word := accessWord(m)
	where := ""
	if m.Guest != path {
		where = fmt.Sprintf(", via %s covering %s", visibleValue(strings.Join(m.From, "+")), m.Guest)
	}
	return fmt.Sprintf("(%s%s%s)", word, where, writableBelow(p, path, m))
}

// writableBelow names the writable grants STRICTLY INSIDE path, so a read-only
// headline cannot hide them.
//
// REGRESSION (redteam). The annotation above reports the DEEPEST mount
// covering the path, which is the right answer for "what is this path itself",
// and the wrong answer for "what can the sandbox write in here". Grants below it
// are invisible to that walk — and those are exactly the ones that RAISE the
// write surface. The result was `TARGET <dir>  (read-only)`, bare and
// unqualified, for the arrangement CLAUDE.md invariant 2 explicitly recommends:
//
//	ro = ["{target}"]        # grant the tree read-only...
//	rw = ["{target}/src"]    # ...and the part you want to write separately
//
// A write inside {target}/src then persisted to the host while the trust
// artifact said read-only. That is worse than the hard-coded "(writable)" this
// replaced: over-warning is a nuisance, under-warning is invariant 5.
//
// The information was never missing — the FILESYSTEM block lists every grant.
// Only the headline discarded it, and the headline is the line people read.
func writableBelow(p *policy.Policy, path string, covering policy.Mount) string {
	var inside []string
	for _, m := range p.SortedMounts() {
		// KindBind only, and that is the whole point rather than a shortcut. A
		// tmpfs below a tmpfs is not a surprise — it is ephemeral either way, and
		// listing @home's .cache/.config/.local/state/.local/share under HOME
		// would be noise
		// that trains the reader to skip the line. What must never hide is a
		// grant that PERSISTS TO THE HOST underneath a headline saying read-only
		// or ephemeral, and that is exactly a writable bind.
		if m.Kind != policy.KindBind || m.Access != policy.AccessRW {
			continue
		}
		if m.Guest == covering.Guest || !strings.HasPrefix(m.Guest, path+"/") {
			continue
		}
		inside = append(inside, m.Guest)
	}
	if len(inside) == 0 {
		return ""
	}
	// Named, not counted: "1 writable grant below" would still leave the reader
	// guessing which one, and the whole point is that they can see it.
	return fmt.Sprintf("; WRITABLE and PERSISTS below: %s", strings.Join(inside, " "))
}

func accessWord(m policy.Mount) string {
	if m.Kind == policy.KindTmpfs {
		return "tmpfs, ephemeral"
	}
	if m.Access == policy.AccessRW {
		return "writable"
	}
	return "read-only"
}

// describeContainers states where a container's network and mounts come
// from, because it is worth restating even once it agrees with the NETWORK
// block above: a reader should not have to infer it from the topology block.
//
// The engine runs in THIS sandbox's own network namespace (issue #63; see the
// TOPOLOGY block's engine line for the capability set it runs with), so the
// pasta guarantees above cover containers too and `@podman-socket` alone
// really is offline. That is what makes this block honest: a container's
// network IS the sandbox's (.claude/design/ENGINE-NETNS.md §0).
func describeContainers(out io.Writer, p *policy.Policy, c *reportContainers) {
	if p.Podman == policy.PodmanOff {
		return
	}
	fmt.Fprintf(out, "CONTAINERS  a per-sandbox engine behind a filtering proxy at %s\n",
		containerSocketGuest)
	describeEngineSource(out, c)
	fmt.Fprintf(out, "         Containers run in THIS sandbox's own network namespace: with no\n")
	fmt.Fprintf(out, "         '@net', a container has no egress either; with '@net', full egress\n")
	fmt.Fprintf(out, "         via the sandbox's pasta, exactly as the NETWORK block above states.\n")
	fmt.Fprintf(out, "         A container has the sandbox's own network with NO port mapping:\n")
	fmt.Fprintf(out, "         'podman run -p N:80' is not supported — the engine holds no\n")
	fmt.Fprintf(out, "         CAP_NET_ADMIN, so it cannot reconfigure this namespace to publish one.\n")
	fmt.Fprintf(out, "         A container gets its own pid namespace and may not join another:\n")
	fmt.Fprintf(out, "         'podman run --pid=host' is refused. Inside the sandbox 'host' would\n")
	fmt.Fprintf(out, "         mean the ENGINE, and /proc/<pid>/root in a shared pid namespace\n")
	fmt.Fprintf(out, "         reaches that process's entire filesystem view.\n")
	fmt.Fprintf(out, "         A container may mount only a path the sandbox can already see,\n")
	fmt.Fprintf(out, "         enforced by the proxy's bind filter, which reads this same resolved\n")
	fmt.Fprintf(out, "         policy — and the engine's own mount namespace is DERIVED from the\n")
	fmt.Fprintf(out, "         sandbox's view rather than being a copy of the host tree, so the\n")
	fmt.Fprintf(out, "         filter now refuses by name what the namespace does not contain\n")
	fmt.Fprintf(out, "         anyway (see the TOPOLOGY and ENGINE VIEW blocks).\n")
	describeImageProvenance(out, c)
}

// describeEngineSource names WHICH engine binary this run will start, and which
// of the three sources answered — $SNUG_PODMAN, $SNUG_PODMAN_ROOT, or PATH.
//
// Why it matters: a host with a host-escape shim on PATH and $SNUG_PODMAN
// exported starts a DIFFERENT binary from one without, and the resolution
// deliberately trusts those two env vars (preflightPodmanBinary trusts
// $SNUG_PODMAN for WHICH binary, checking only that it is not itself a shim
// (#396); $SNUG_PODMAN_ROOT names a toolchain root that is not recoverable from
// the binary path). --dry-run is the
// screen a human trusts, so it must not be silent about which engine it is
// about to run (issue #278).
//
// It reports the SOURCE rather than a verified binary for the PATH case, and
// that limit is unchanged: --dry-run runs no preflight, so it does not search
// PATH and does not follow the shim readlink chain. What it DOES do since issue
// #422 is judge the two paths a human NAMED, by calling the functions the run
// judges with (report.go) — the two most security-relevant paths on this screen
// used to be the only ones judged without looking at the host.
//
// THREE STATES per path, and the order is the safety argument: a refusal wins;
// otherwise a clearance requires an object of the right KIND to exist; otherwise
// NOT JUDGED. Existence can only downgrade a clearance, never manufacture or
// soften a refusal (report.go's own comment on why that cannot become a lie).
//
// Values are host-controlled, so every one goes through visibleValue — the
// refusal text included, which is what describeSignaturePolicy already does
// with the host's own decoder output.
func describeEngineSource(out io.Writer, c *reportContainers) {
	if c.EngineSource == "SNUG_PODMAN" {
		fmt.Fprintf(out, "         engine      binary %s ($SNUG_PODMAN) — trusted outright, PATH\n",
			visibleValue(c.EngineBinary))
		fmt.Fprintf(out, "                     resolution bypassed on purpose; refused if it is\n")
		fmt.Fprintf(out, "                     itself a host-escape shim (a testing seam, not a\n")
		fmt.Fprintf(out, "                     supported way to install an engine)\n")
		switch {
		case c.EngineBinaryRefusal != "":
			describeEngineRefusal(out, c.EngineBinaryRefusal)
		case !c.EngineBinaryIsRegularFile:
			fmt.Fprintf(out, "                     NOT JUDGED: no regular file at that path on this host, so\n")
			fmt.Fprintf(out, "                     the writability question has no object — preflight P1\n")
			fmt.Fprintf(out, "                     stats it and refuses a run whose engine is missing or a\n")
			fmt.Fprintf(out, "                     directory\n")
		default:
			fmt.Fprintf(out, "                     no grant of this sandbox makes that path, or any name on\n")
			fmt.Fprintf(out, "                     the way to it, writable — the engine is not\n")
			fmt.Fprintf(out, "                     payload-controlled (issue #405)\n")
			describeEngineResolution(out, c.EngineBinary, c.EngineBinaryResolved)
		}
	} else {
		fmt.Fprintf(out, "         engine      binary resolved from PATH when the run starts — preflight\n")
		fmt.Fprintf(out, "                     P1 refuses a host-escape shim there; --dry-run does not\n")
		fmt.Fprintf(out, "                     probe PATH, so it names the source, not the binary\n")
		fmt.Fprintf(out, "                     the run also refuses it if any grant of this sandbox makes it\n")
		fmt.Fprintf(out, "                     WRITABLE — snug execs it as uid 0, pid 1 of the engine's own\n")
		fmt.Fprintf(out, "                     pid namespace (issue #405). Not checkable here: that needs\n")
		fmt.Fprintf(out, "                     the resolved binary, and this screen has only the source\n")
	}
	if c.ToolchainRoot != "" {
		fmt.Fprintf(out, "                     toolchain root %s ($SNUG_PODMAN_ROOT) — named, not\n",
			visibleValue(c.ToolchainRoot))
		fmt.Fprintf(out, "                     derived from the binary path, and must contain it\n")
		switch {
		case c.ToolchainRootRefusal != "":
			describeEngineRefusal(out, c.ToolchainRootRefusal)
		case !c.ToolchainRootIsDir:
			fmt.Fprintf(out, "                     NOT JUDGED: no directory at that path on this host, so\n")
			fmt.Fprintf(out, "                     there is no tree to walk — preflight P9 stats it and\n")
			fmt.Fprintf(out, "                     refuses the run\n")
		default:
			fmt.Fprintf(out, "                     no grant makes the root, the tree below it, or any name\n")
			fmt.Fprintf(out, "                     on the way to it, writable (issue #405)\n")
			describeEngineResolution(out, c.ToolchainRoot, c.ToolchainRootResolved)
		}
	}
	if c.EngineSource == "SNUG_PODMAN" || c.ToolchainRoot != "" {
		fmt.Fprintf(out, "                     judged by the functions the run judges with, against this\n")
		fmt.Fprintf(out, "                     host as it is NOW: snug resolves each path above and every\n")
		fmt.Fprintf(out, "                     name on the way to it, so a symlink rewritten after this\n")
		fmt.Fprintf(out, "                     screen is judged again — and refused again — when the run\n")
		fmt.Fprintf(out, "                     starts\n")
	}
}

// describeEngineRefusal prints the RUN's own refusal text rather than a
// paraphrase of it.
//
// The paraphrase is what shipped false: it asserted "a grant of this sandbox
// makes that path WRITABLE" for what is now one of four refusals
// ResolveEngineBinary and JudgeEngineToolchain can return — not absolute, a
// control character in the value, writable bytes, a writable NAME on the
// resolution chain. Re-indented to this block's continuation column, exactly as
// describeSignaturePolicy does with the host decoder's own output, and through
// visibleValue for the same reason: the text carries a host-controlled path.
func describeEngineRefusal(out io.Writer, refusal string) {
	fmt.Fprintf(out, "                     THIS RUN WILL REFUSE:\n")
	for _, line := range strings.Split(strings.TrimRight(refusal, "\n"), "\n") {
		fmt.Fprintf(out, "                     %s\n", visibleValue(strings.TrimSpace(line)))
	}
}

// describeEngineResolution states where a CLEARED path resolves to, and only
// when that differs from the spelling.
//
// Cleared only, deliberately. On a refusal the resolved path is "" by contract,
// and the refusal itself names what was judged; on NOT JUDGED the "resolved"
// value is a lexical rejoin of a name with nothing behind it, so printing it as
// "resolves to" would be the prettier lie in miniature.
func describeEngineResolution(out io.Writer, spelled, resolved string) {
	if resolved == "" || resolved == spelled {
		return
	}
	fmt.Fprintf(out, "                     resolves to %s, which is what was judged\n",
		visibleValue(resolved))
}

// describeImageProvenance states who decides which bytes become an image, for
// the same reason describeGit states who wrote the sandbox's git config: the
// answer used to be "a file on this host that snug does not control", and a
// screen that says nothing about it reads as though the resolved policy
// covered it (issue #137).
//
// It is unconditional within the CONTAINERS block — no `if` on anything —
// because every one of these files is written for every run that has an
// engine. There is no host-dependent branch to render, and a line that
// appears only sometimes would invite the reader to conclude something from
// its absence.
//
// The SIGNATURES line is the exception, and it is host-dependent because the
// fact is (issue #307). snug projects this host's own policy.json into the
// engine's rather than writing a permissive one over it, so the line has four
// answers and the reader needs to know which: no host policy at all, a host
// policy that accepts anything, a host policy that demands something, and a
// host policy snug cannot reproduce — which is a run that will REFUSE, stated
// here because a dry run describing a run that cannot start is worse than no
// dry run.
//
// The credential line is the one worth reading twice: it is a CAPABILITY the
// sandbox does not have (issue #142), stated plainly rather than apologised
// for, and it is what makes "a private image cannot be pulled from inside"
// a documented property rather than a bug report.
func describeImageProvenance(out io.Writer, c *reportContainers) {
	fmt.Fprintf(out, "IMAGES   provenance is snug's, not this host's (issue #137)\n")
	fmt.Fprintf(out, "         search      docker.io and nothing else — no mirror, no rewrite, no\n")
	fmt.Fprintf(out, "                     insecure registry. A generated registries.conf, pointed\n")
	fmt.Fprintf(out, "                     at by CONTAINERS_REGISTRIES_CONF\n")
	describeSignaturePolicy(out, c)
	fmt.Fprintf(out, "         logins      NONE. REGISTRY_AUTH_FILE points at an empty file, so the\n")
	fmt.Fprintf(out, "                     host's ~/.docker/config.json and auth.json are not read,\n")
	fmt.Fprintf(out, "                     and no private image can be pulled (issue #142)\n")
	fmt.Fprintf(out, "         home        the engine gets a HOME of its own for the same reason —\n")
	fmt.Fprintf(out, "                     everything podman reads out of one is snug's or absent\n")
}

// describeSignaturePolicy renders the four answers.
//
// BOTH HOST-TEXT FIELDS GO THROUGH visibleValue. The source is a path out of
// $HOME and the refusal carries a decoder's rendering of the host's own file —
// the sink class issue #58's red-team round found, where a crafted value erases
// the lines above it and writes a reassuring one in their place. Not
// payload-reachable (it is the host user's own file), so this is screen
// integrity rather than an escape; asserted anyway, because the rule is to name
// every sink a value reaches rather than the site where it was noticed.
func describeSignaturePolicy(out io.Writer, c *reportContainers) {
	switch {
	case c.SignaturePolicyRefusal != "":
		fmt.Fprintf(out, "         signatures  THIS RUN WILL REFUSE. The engine's policy.json is a\n")
		fmt.Fprintf(out, "                     projection of your host's, and this host configured one\n")
		fmt.Fprintf(out, "                     snug cannot reproduce. Accepting any image instead would\n")
		fmt.Fprintf(out, "                     drop exactly the check you configured:\n")
		for _, line := range strings.Split(strings.TrimRight(c.SignaturePolicyRefusal, "\n"), "\n") {
			fmt.Fprintf(out, "                     %s\n", visibleValue(strings.TrimSpace(line)))
		}
	case c.SignaturePolicySource == "":
		fmt.Fprintf(out, "         signatures  NOT verified, and that is snug's decision, not your\n")
		fmt.Fprintf(out, "                     host's: this host has no policy.json where podman looks,\n")
		fmt.Fprintf(out, "                     so a podman here refuses every pull outright and snug\n")
		fmt.Fprintf(out, "                     generates an accept-anything one so the sandbox can pull\n")
		fmt.Fprintf(out, "                     at all. Nothing you configured was weakened — you\n")
		fmt.Fprintf(out, "                     configured nothing — but the sandbox verifies LESS than\n")
		fmt.Fprintf(out, "                     the bare host. Write ~/.config/containers/policy.json and\n")
		fmt.Fprintf(out, "                     snug projects it\n")
	case !c.SignaturesVerified:
		fmt.Fprintf(out, "         signatures  NOT verified, because your host does not verify them\n")
		fmt.Fprintf(out, "                     either: %s accepts\n",
			visibleValue(c.SignaturePolicySource))
		fmt.Fprintf(out, "                     any image, and snug reproduces it rather than deciding\n")
	default:
		fmt.Fprintf(out, "         signatures  as %s requires.\n",
			visibleValue(c.SignaturePolicySource))
		fmt.Fprintf(out, "                     snug projects that file into the engine's own\n")
		fmt.Fprintf(out, "                     policy.json — the keys it names are copies snug makes,\n")
		fmt.Fprintf(out, "                     because a host path resolves to nothing in the engine's\n")
		fmt.Fprintf(out, "                     derived view. A requirement snug cannot reproduce\n")
		fmt.Fprintf(out, "                     refuses the run rather than being dropped\n")
		fmt.Fprintf(out, "                     It binds PULLS, not the warm store: an image already in\n")
		fmt.Fprintf(out, "                     this target's store runs without a second policy check,\n")
		fmt.Fprintf(out, "                     whatever admitted it. See the store graft above\n")
	}
}

// describeGit states that the sandbox's git config was RECONSTRUCTED, and from
// what.
//
// A `data ~/.gitconfig` row on its own says a file was generated; it does not say
// that the host's was read to build it, nor that most of the host's file was
// deliberately left behind. Both are decisions a human is entitled to see before
// they run something — the first is host IO, the second is why their aliases are
// missing inside.
//
// It also gives Policy.Git a reader. A field that is written and never read is a
// field nobody notices going wrong.
func describeGit(out io.Writer, p *policy.Policy) {
	if p.Git != policy.GitExtract {
		return
	}
	fmt.Fprintf(out, "GIT      config RECONSTRUCTED from the host's, never bound\n")
	fmt.Fprintf(out, "         carried    %s\n", strings.Join(policy.SortedGitKeys(), " "))
	fmt.Fprintf(out, "         left out   everything that names a program — credential.helper,\n")
	fmt.Fprintf(out, "                    alias = !cmd, core.pager, core.sshCommand, textconv\n")
	fmt.Fprintf(out, "         includeIf  \"gitdir:\" evaluated against this target; \"hasconfig:\"\n")
	fmt.Fprintf(out, "                    and \"onbranch:\" ignored — the repository decides those\n")
}

// describeSSH states that snug replaced this host's system-wide ssh_config,
// and why — modelled directly on describeGit, because both are the same
// disclosure ("we generated this file instead of trusting the host's") and
// both need to say what triggered it and what it costs.
//
// It reads p.SystemSSHConfigs — the record Resolve wrote — rather than
// re-deriving the coverage predicate: the screen must describe what Resolve
// actually decided, not recompute a second opinion that could disagree with
// it. A host where nothing was replaced gets nothing here, silently and
// correctly — the same as a host with no [identity] getting nothing from
// describeGit.
//
// It used to walk policy.SystemSSHConfigPaths itself, and that stopped being
// the whole set when discovery landed (issue #42): the paths a run may
// replace are now the fixed list PLUS whatever this host's ssh named, so a
// sandbox on a host with a third spelling would have had its system ssh_config
// replaced with nothing on screen saying so. A screen that recomputes a
// predicate is a copy of state held somewhere else.
//
// The PATH line is per replaced mount — a host can have both spellings
// covered at once (openSUSE's /usr/etc/ssh plus a human profile binding
// /etc) and each is a distinct fact the reader needs. The mechanism and
// cost paragraph is the same explanation regardless of which path it is, so
// it is printed ONCE, after the loop, gated on whether anything matched —
// not once per path, which would repeat six identical lines for a
// coincidence of two paths sharing one cause.
func describeSSH(out io.Writer, p *policy.Policy) {
	if len(p.SystemSSHConfigs) == 0 {
		return
	}
	for _, guest := range p.SystemSSHConfigs {
		fmt.Fprintf(out, "SSH      system-wide ssh_config REPLACED at %s\n", guest)
	}
	fmt.Fprintf(out, "         the host's is root-owned and reads as 65534 inside (one uid is\n")
	fmt.Fprintf(out, "         mapped); OpenSSH refuses such a file, so ssh, git-over-ssh, scp\n")
	fmt.Fprintf(out, "         and rsync -e ssh all die without this\n")
	if len(p.SystemSSHCarried) == 0 {
		fmt.Fprintf(out, "         cost       the host's system-wide defaults do not apply — this host\n")
		fmt.Fprintf(out, "                    resolves the algorithm lists and RequiredRSASize to\n")
		fmt.Fprintf(out, "                    OpenSSH's compiled-in values anyway, so nothing was lost\n")
		return
	}
	var spelled []string
	for _, k := range p.SystemSSHCarried {
		spelled = append(spelled, policy.SSHKeySpelling(k))
	}
	// The list is DERIVED from what this host's ssh actually said, so its
	// length varies per host and a hand-wrapped literal cannot track it — the
	// same reason the syscall list is wrapped rather than written out.
	for i, line := range wrapList(spelled, 56) {
		label := "carried   "
		if i > 0 {
			label = "          "
		}
		fmt.Fprintf(out, "         %s %s\n", label, line)
	}
	fmt.Fprintf(out, "                    — this host's own values, read with `ssh -G`, kept because\n")
	fmt.Fprintf(out, "                    they name algorithms and nothing else\n")
	fmt.Fprintf(out, "         left out   everything that names a program, a file or a socket —\n")
	fmt.Fprintf(out, "                    ProxyCommand, Match exec, KnownHostsCommand, PKCS11Provider,\n")
	fmt.Fprintf(out, "                    IdentityFile, IdentityAgent, ControlPath\n")
	fmt.Fprintf(out, "         cost       anything else the host's file said is gone, and a key not\n")
	fmt.Fprintf(out, "                    named above — RequiredRSASize included, when it is absent —\n")
	fmt.Fprintf(out, "                    falls back to OpenSSH's compiled-in value (1024 for that\n")
	fmt.Fprintf(out, "                    one). An algorithm name this sandbox's ssh does not know is\n")
	fmt.Fprintf(out, "                    a loud failure (`Bad SSH2 cipher spec`), never a silent one\n")
}

// describeCommands names EVERY executable staged in policy.StagedBinDir, which
// is every command snug puts on PATH ahead of the distro's.
//
// It exists because "there is a new executable running before the tool you
// typed" is exactly the kind of thing --dry-run exists to make legible, rather
// than a human having to notice that one FILESYSTEM line reads "exec" instead of
// "data". The block used to hard-code the podman stub, which was true while the
// stub was the only thing ever staged and became a silent omission the moment
// @claude's binary moved here — so it now enumerates the directory and cannot
// fall behind whatever staged next.
//
// The paragraph under a name is per-command and only the stub has one. A staged
// bind gets the one-line form: what it is and where it came from is a profile's
// grant, already on the FILESYSTEM lines above, and repeating it here would be
// two places to keep true.
func describeCommands(out io.Writer, p *policy.Policy) {
	var staged []string
	for guest := range p.Mounts {
		if strings.HasPrefix(guest, policy.StagedBinDir+"/") {
			staged = append(staged, guest)
		}
	}
	if len(staged) == 0 {
		return
	}
	sort.Strings(staged)

	for _, guest := range staged {
		fmt.Fprintf(out, "COMMANDS  %s\n", guest)
		m := p.Mounts[guest]
		switch {
		case guest == policy.StagedBinDir+"/podman" && m.Authored:
			fmt.Fprintf(out, "         podman on this host resolves to a shim that cannot reach the host from\n")
			fmt.Fprintf(out, "         inside a sandbox (distrobox-host-exec, host-spawn or flatpak-spawn), so\n")
			fmt.Fprintf(out, "         snug staged a dispatcher ahead of it on PATH: it forwards a fixed\n")
			fmt.Fprintf(out, "         allowlist of docker subcommands to 'docker', byte for byte, and refuses\n")
			fmt.Fprintf(out, "         everything else by name — never a flag rewrite, never a translation.\n")
			fmt.Fprintf(out, "         It is read-only (see the FILESYSTEM line above: 'exec', not writable),\n")
			fmt.Fprintf(out, "         and /usr/bin/podman is UNTOUCHED — still reachable by its absolute path,\n")
			fmt.Fprintf(out, "         just no longer first on PATH. See .claude/design/CONTAINER-CLIENT.md §8.\n")
		case m.Host != "":
			// Read m.Access rather than asserting it. This line said "and
			// read-only" unconditionally, and a profile staging a `rw` bind got
			// that sentence while the payload overwrote the command and the
			// overwrite persisted to the HOST file. A staged command that can be
			// rewritten is the worst line on this screen to be wrong about, so it
			// is the one that has to come from the policy.
			how := "read-only"
			if m.Access == policy.AccessRW {
				how = "WRITABLE from inside — anything running here can rewrite this " +
					"command, and the rewrite persists to the host file"
			}
			fmt.Fprintf(out, "         %s, staged here from %s and %s.\n",
				filepath.Base(guest), m.Host, how)
		}
	}
	// The closing paragraph is a CLAIM about the directory, so it is gated on the
	// same predicate the PATH mark uses rather than being printed unconditionally.
	//
	// It used to be unconditional, and with a profile grant at StagedBinDir the
	// screen contradicted itself four lines apart: this paragraph said "NOT
	// writable from inside" while the ENVIRONMENT block below rendered
	// `PATH  /snug/bin  (snug) staged bin  ← writable from inside`. Validate
	// refuses that arrangement outright — at the directory since the tmpfs-at-it
	// finding, and at any ANCESTOR of it since issue #22.
	//
	// THIS BRANCH IS STILL REACHED, and an earlier version of this comment
	// guessed otherwise ("should be unreachable"). Measured: under --dry-run,
	// main.go renders the whole policy AND THEN prints the Validate error, so a
	// refused `tmpfs = ["/snug"]` + @podman-socket selection prints these three
	// lines above its own refusal. (It said `/run` until issue #206 moved
	// snug's paths into their own namespace; `/run` is now an ordinary path
	// that nothing refuses, so the example no longer produced a refusal at
	// all.) That is the diagnostic doing its job — it is
	// the picture behind the error, on the same screen. Do not delete it on a
	// reachability argument, and do not weaken it on one either: it is also the
	// backstop for an AUTHORED mount, which Validate's refusal exempts by design,
	// and for any future renderer that shows a policy Validate never saw.
	if p.IsShadowSlot(policy.StagedBinDir) {
		fmt.Fprintf(out, "         %s IS WRITABLE from inside, which it must never be: it is first on\n", policy.StagedBinDir)
		fmt.Fprintf(out, "         PATH, so anything running here can drop a file called 'git' or 'ssh'\n")
		fmt.Fprintf(out, "         into it and the next one a human runs is that file. Report this.\n")
		return
	}
	fmt.Fprintf(out, "         %s is snug's own and is NOT writable from inside, so nothing running\n", policy.StagedBinDir)
	fmt.Fprintf(out, "         here can add a command to it — the directory ahead of /usr/bin on PATH is\n")
	fmt.Fprintf(out, "         not a slot the payload can fill.\n")
}

// describeClaude states that ~/.claude.json was GENERATED rather than copied,
// which of Claude Code's prompts snug therefore pre-answers, and what the host's
// file carried that is now absent.
//
// It exists because the FILESYSTEM block cannot say any of it. That block prints
//
//	data   /home/u/.claude.json                  @claude
//
// for the 62 KB verbatim copy and for a three-key generated file alike, and
// Mount.Content is a policy.Secret that renders as "<redacted N bytes>"
// everywhere by design (internal/policy/secret.go argues why classifying per
// instance is the judgement that was wrong about ~/.gitconfig — do not
// special-case this one to print in the clear). So without this block a human
// reading --dry-run cannot see WHETHER Claude Code's safety prompt was
// pre-answered for this run, which is the residual of issue #19's fix and the
// reason the block is mandatory rather than nice to have.
//
// The trust line has two arms and must keep both. snug writes the trust entry
// only when the HOST's ~/.claude.json already records this exact path as
// trusted (claudeStateJSON), so on an unfamiliar repository there is no entry
// and Claude Code prompts — and a block that printed the pre-answered sentence
// unconditionally would be describing a decision snug did not make. What must
// NOT be written here is the retired reassurance that the entry is "strictly
// narrower than the seven paths the copied file answered for": measured, the old
// set was the host's seven paths and the new one is at most {target}, neither
// contains the other, and the seven were inert inside the sandbox while {target}
// is the one live entry. State the measurement; invariant 5 is what makes saying
// it out loud the difference between a scoped decision and a silent downgrade.
//
// Modelled on describeGit and describeSSH, and gated the same way: on the
// AUTHORED KindData mount actually being in the resolved policy, so the screen
// describes what Resolve decided rather than recomputing a second opinion that
// could disagree with it. The trust arm and the settings.json sentence are gated
// the same way, off the staged CONTENT and off the resolved mounts respectively
// — never off a re-read of the host.
func describeClaude(out io.Writer, p *policy.Policy) {
	m, ok := claudeStateMount(p)
	if !ok {
		return
	}
	trusted := claudeTrustCarried(p, m)
	keys := "two keys"
	if trusted {
		keys = "three keys"
	}
	fmt.Fprintf(out, "CLAUDE   ~/.claude.json is GENERATED, not copied — %s, no host bytes\n", keys)
	fmt.Fprintf(out, "         hasCompletedOnboarding  skips the theme picker, whose answer could not\n")
	// UNCONDITIONAL, unlike the two-arm parenthesis this replaces: issue #17
	// removed the last profile grant at ~/.claude/settings.json (base.toml's
	// [profile.claude] no longer names it under `ro` or `optional`), so
	// stageClaudeSettings now writes this mount on every host regardless of
	// whether one has ever run Claude Code, and there is exactly one true
	// sentence about it rather than a claim gated on host state.
	fmt.Fprintf(out, "                    persist anyway (~/.claude/settings.json is GENERATED by\n")
	fmt.Fprintf(out, "                    snug from an allowlist of the host's, and it is writable —\n")
	fmt.Fprintf(out, "                    a private tmpfs copy that dies with this session)\n")
	fmt.Fprintf(out, "         autoUpdates=false       the binary is a read-only bind; a self-update\n")
	fmt.Fprintf(out, "                    inside can only fail\n")
	// %q rather than the bare path: it is the JSON key this file actually
	// contains, and quoting escapes a control character in a directory name for
	// free — a host path is not snug's to refuse (a real directory may legally be
	// named with a newline), so every screen that renders one has to escape it
	// (see visibleValue, and TestNoSnugScreenEmitsARawControlCharacter, which
	// asserts the SET of sinks rather than any one of them).
	if trusted {
		fmt.Fprintf(out, "         trust      CARRIED from your host ~/.claude.json, which already\n")
		fmt.Fprintf(out, "                    records this exact path as trusted:\n")
		fmt.Fprintf(out, "                    projects.%q.hasTrustDialogAccepted = true\n", p.Target)
		fmt.Fprintf(out, "                    One boolean about the ONE directory you named on the\n")
		fmt.Fprintf(out, "                    command line; no other directory appears in the file, and\n")
		fmt.Fprintf(out, "                    snug decides nothing here — it carries your answer\n")
	} else {
		fmt.Fprintf(out, "         trust      NOT pre-answered — your host ~/.claude.json does not\n")
		fmt.Fprintf(out, "                    record this exact path as trusted:\n")
		fmt.Fprintf(out, "                    projects.%q\n", p.Target)
		fmt.Fprintf(out, "                    is absent, and so is the whole projects key, so Claude\n")
		fmt.Fprintf(out, "                    Code asks \"Quick safety check\" for it once per run —\n")
		fmt.Fprintf(out, "                    the prompt that stops a repository's own\n")
		fmt.Fprintf(out, "                    .claude/settings.json hooks running at startup\n")
	}
	fmt.Fprintf(out, "         not here   the host file's 62 KB: every project path on this machine,\n")
	fmt.Fprintf(out, "                    org, email, account UUIDs, machine ID, MCP servers, and the\n")
	fmt.Fprintf(out, "                    host's per-project tool approvals — so tools you approved on\n")
	fmt.Fprintf(out, "                    the host are asked again in here\n")

	// The credentials disclosure (issue #58), and it belongs on this screen
	// more than anything else here: --dry-run is the artifact a human uses to
	// decide whether to trust snug, and "which of my credentials does the
	// sandbox get" is the sharpest form of that question. The names are
	// snug's own fixed lists, not host-controlled, so they need no
	// visibleValue — and unlike the settings block there is no per-run
	// variation to render, because the allowlist IS the answer.
	if m, ok := claudeCredentialsMount(p); ok {
		fmt.Fprintf(out, "         creds      ~/.claude/.credentials.json is PROJECTED from the host's —\n")
		fmt.Fprintf(out, "                    a generated file, not a copy\n")
		fmt.Fprintf(out, "                    carried: %s\n", strings.Join(claudeCredentialNames(), " "))
		fmt.Fprintf(out, "                    NOT carried: refreshToken refreshTokenExpiresAt\n")
		// THE NUMBER, not just the adjective. The whole security argument of
		// issue #58 is a TIME BOUND, snug already has the value in hand
		// (ProjectClaudeCredentials returns it), and an earlier version of this
		// block stated the bound only qualitatively — "dies with the access
		// token" — which asks the reader to take the bound on trust on the one
		// screen whose job is to replace trust with measurement.
		if when, ok := claudeCredentialExpiry(m, screenNow()); ok {
			fmt.Fprintf(out, "                    expires:  %s\n", when)
		}
		// Deliberately NOT "dies with the access token instead of outliving
		// it". A red-team pass pushed back on that sentence and was right: it
		// invites the reading "does not outlive the sandbox", which is false.
		// Expiry is a TIMER, not a kill switch — there is no revocation faster
		// than it — so a stolen token still buys its remaining life, which is
		// hours against a sandbox that often lives for minutes. What is true is
		// the comparison with what shipped before, and that is what this says.
		fmt.Fprintf(out, "                    Nothing in here can mint a NEW token, so a stolen copy is\n")
		fmt.Fprintf(out, "                    bounded by the expiry above — hours — rather than by the\n")
		fmt.Fprintf(out, "                    refresh token's, which is weeks. It is a timer, not a\n")
		fmt.Fprintf(out, "                    kill switch: it can still outlive this sandbox\n")
	} else {
		// "snug staged nothing at this path", NOT "Claude Code will start
		// LOGGED OUT". The second is a claim about the SANDBOX where this code
		// only checked snug's OWN staging: a user profile binding the host's
		// file at this guest path is a named hole the human selected, and on
		// the projection-failure arm that bind survives — so the sandbox would
		// read the host's full file, refresh token included, under a line
		// claiming it was logged out. The FILESYSTEM block above shows the
		// bind; this line no longer contradicts it.
		fmt.Fprintf(out, "         creds      snug staged NOTHING at ~/.claude/.credentials.json — this\n")
		fmt.Fprintf(out, "                    host has no such file, or it could not be projected. snug\n")
		fmt.Fprintf(out, "                    does not fall back to copying a file it could not read.\n")
		fmt.Fprintf(out, "                    Unless a profile above binds one, Claude Code starts\n")
		fmt.Fprintf(out, "                    LOGGED OUT in here\n")
	}

	// The settings.json disclosure. Mount.Content is redacted (policy.Secret)
	// everywhere else on this screen by design (see the doc comment above and
	// secret.go's "why every value" section) — printing the CARRIED key names
	// here is not an exception to that, it is the mechanism the redaction
	// exists to be replaced by for exactly this one generated file, the same
	// way the trust/not-here lines above replace it for ~/.claude.json.
	if sm, ok := claudeSettingsMount(p); ok {
		fmt.Fprintf(out, "         settings   ~/.claude/settings.json is GENERATED from an allowlist of\n")
		fmt.Fprintf(out, "                    the host's — not bound, never read-only\n")
		if names := claudeSettingsCarriedNames(sm); len(names) > 0 {
			fmt.Fprintf(out, "                    carried: %s\n", visibleValue(strings.Join(names, " ")))
		} else {
			fmt.Fprintf(out, "                    carried: (none of the allowlisted keys were present)\n")
		}
		// AUTHORED, not carried — snug writes both regardless of what the
		// host's file said. The pairs render from policy.ClaudeAuthoredSettings
		// (claudeAuthoredPairs, shared with stageClaudeSettings' stderr lines)
		// rather than being typed here, so this line cannot state a value the
		// generated file does not actually contain.
		fmt.Fprintf(out, "         snug set   %s\n", strings.Join(claudeAuthoredPairs(), "  "))
		// "these" and not "these two": the line above is rendered from
		// policy.ClaudeAuthoredSettings, so a counted word here would be a copy
		// of that table's length and would go quietly false on the third key.
		fmt.Fprintf(out, "                    snug AUTHORS these; your host's values for them are\n")
		fmt.Fprintf(out, "                    dropped like every other remote-surface key. Inbound peer\n")
		fmt.Fprintf(out, "                    messages are refused, and SendMessage/SendFile to a session\n")
		fmt.Fprintf(out, "                    on ANOTHER machine needs explicit approval (bypassImmune in\n")
		fmt.Fprintf(out, "                    claude 2.1.246 — bypassPermissions does not lift it)\n")
		fmt.Fprintf(out, "                    CLIENT-SIDE: a DEFAULT, not a boundary. The payload holds\n")
		fmt.Fprintf(out, "                    the credential, controls its own argv, and this file is\n")
		fmt.Fprintf(out, "                    writable — THREAT-MODEL.md 3.1\n")
		// Overridden names are HOST-CONTROLLED in WHICH they name (the host's
		// file chose to set one), so this goes through visibleValue the same
		// way `unknown` below does — even though FilterClaudeSettings only
		// ever populates p.ClaudeSettingsOverridden with snug's own authored
		// key spellings, never a byte the host's file supplied.
		if len(p.ClaudeSettingsOverridden) > 0 {
			fmt.Fprintf(out, "         overridden %s\n",
				visibleValue(strings.Join(p.ClaudeSettingsOverridden, " ")))
			fmt.Fprintf(out, "                    the one class where both happen: your host's value dropped\n")
			fmt.Fprintf(out, "                    AND snug's own written\n")
		}
		// The unknown-key disclosure. UNCONDITIONAL — unlike the -v-gated stderr
		// line in stageClaudeSettings — because this screen IS the trust
		// artifact and has no volume problem a human can opt out of: "what did
		// snug not carry" is exactly what --dry-run exists to answer, so it
		// cannot be silent here even where it may be quiet on an ordinary run's
		// stderr. p.ClaudeSettingsUnknown is set by stageClaudeSettings
		// regardless of -v for exactly this reason (see its own doc comment).
		//
		// The names are HOST-CONTROLLED, so each goes through visibleValue —
		// same reason every other value on this screen does (see visibleValue's
		// doc comment): a key name from a crafted settings.json must not be
		// able to forge a line on the one screen a human is meant to trust.
		if len(p.ClaudeSettingsUnknown) > 0 {
			fmt.Fprintf(out, "         unknown    %s\n",
				visibleValue(strings.Join(p.ClaudeSettingsUnknown, " ")))
			fmt.Fprintf(out, "                    on NEITHER list above (not the allowlist, not\n")
			fmt.Fprintf(out, "                    ClaudeExecutingKeys) — not carried, and not otherwise\n")
			fmt.Fprintf(out, "                    classified; most likely an ordinary preference upstream\n")
			fmt.Fprintf(out, "                    added since this catalogue was written, but if one of\n")
			fmt.Fprintf(out, "                    these matters to you, it is a snug change to make\n")
		}
		// A fixed, host-independent list rather than a per-run diff: which NAMES
		// the host's file happened to use this run is not the disclosure that
		// matters — what matters is which CLASSES of key never cross regardless
		// of what the host has. Mirrors the "not here" line above for the same
		// reason: a category a human can check against base.toml's abuse block,
		// not a value that could itself be forged by a crafted host file (it
		// cannot be — see visibleValue — but the category is also just the more
		// stable thing to pin in a golden).
		fmt.Fprintf(out, "         never      hooks, apiKeyHelper, statusLine, env, mcpServers,\n")
		fmt.Fprintf(out, "                    enabledPlugins, extraKnownMarketplaces, permissions — each\n")
		fmt.Fprintf(out, "                    names a program, selects/fetches code, or sets env; see\n")
		fmt.Fprintf(out, "                    policy.ClaudeExecutingKeys for the full catalogue\n")

		// Project scope (issue #73), and the two states MUST read differently
		// here: a run that projects the target's settings and a run whose target
		// has no such file look identical in the reject-list above, so this line
		// names which project-scope files are actually reinterpreted. Read from
		// the resolved mount set, so it says what snug did, not what it might.
		projected := projectedTargetSettings(p)
		if len(projected) > 0 {
			fmt.Fprintf(out, "         project    the TARGET's own %s reinterpreted read-only:\n",
				strings.Join(projected, " and "))
			fmt.Fprintf(out, "                    a hostile repo's hooks do not run inside, and the\n")
			fmt.Fprintf(out, "                    payload cannot write one that runs on your host later\n")
		} else {
			fmt.Fprintf(out, "         project    the target ships no .claude/settings.json or\n")
			fmt.Fprintf(out, "                    settings.local.json, so none is projected — a NEW one\n")
			fmt.Fprintf(out, "                    the payload writes there is NOT closed (issue #73)\n")
		}
	}
}

// projectedTargetSettings returns the target-scope settings files snug is
// projecting read-only this run (issue #73), read from the resolved mounts so
// --dry-run states what happened rather than re-deriving it. Empty when the
// target ships neither file — the state --dry-run must not let read the same as
// the projecting one.
func projectedTargetSettings(p *policy.Policy) []string {
	var out []string
	for _, name := range projectClaudeSettingsFiles {
		guest := filepath.Join(p.Target, ".claude", name)
		if m, ok := p.Mounts[guest]; ok && m.Kind == policy.KindData && m.HostDestExists {
			out = append(out, ".claude/"+name)
		}
	}
	return out
}

// claudeTrustCarried reports whether the GENERATED ~/.claude.json actually
// carries the trust entry for this target.
//
// It reads the staged CONTENT rather than re-reading the host, for the reason
// describeGit and describeSSH exist in their present shape: the screen must
// describe what snug decided, not recompute a second opinion that could
// disagree. Mount.Content is a policy.Secret and stays one — what leaves this
// function is a bool, and the only thing the caller prints is p.Target, which is
// already on the screen twice.
//
// Unparseable content is "not carried", which matches what Claude Code will do
// with a file it cannot parse.
func claudeTrustCarried(p *policy.Policy, m policy.Mount) bool {
	var doc struct {
		Projects map[string]struct {
			HasTrustDialogAccepted bool `json:"hasTrustDialogAccepted"`
		} `json:"projects"`
	}
	if err := json.Unmarshal([]byte(m.Content), &doc); err != nil {
		return false
	}
	return doc.Projects[p.Target].HasTrustDialogAccepted
}

// claudeStateMount returns the ~/.claude.json this block describes, if snug
// authored one.
//
// It returns the MOUNT rather than a bool because the block now reads the staged
// content to decide which trust arm to print, and a second lookup written next
// to this one is a second answer to "which file are we describing" — the exact
// shape that lets a screen describe one mount while a sibling function describes
// another.
//
// The obvious spelling — p.Mounts[filepath.Join(p.Home, ".claude.json")] — is
// the primary lookup and is not sufficient on its own. Resolve canonicalises
// $HOME (EvalSymlinks), while claudeFiles is handed main.go's raw
// os.UserHomeDir() value, so on a host whose home is a symlink the two paths
// differ and the exact-match lookup misses. That mismatch is worth fixing where
// it lives rather than here, but its failure mode HERE is the one this whole
// block exists to prevent: the mount is still in the policy, snug still
// pre-answers the trust prompt, and the only line on screen that says so
// silently disappears. So the fallback names the file rather than the path.
//
// It cannot misfire on a profile's grant: Mount.Authored is set by
// Policy.Replace and nothing else, i.e. only by snug's own post-resolution
// writers.
func claudeStateMount(p *policy.Policy) (policy.Mount, bool) {
	if m, ok := p.Mounts[filepath.Join(p.Home, ".claude.json")]; ok {
		return m, m.Authored && m.Kind == policy.KindData
	}
	for _, m := range p.Mounts {
		if m.Authored && m.Kind == policy.KindData && filepath.Base(m.Guest) == ".claude.json" {
			return m, true
		}
	}
	return policy.Mount{}, false
}

// claudeSettingsMount returns the ~/.claude/settings.json mount this block
// describes, if snug authored one.
//
// Same two-step lookup as claudeStateMount, for the identical measured reason:
// Resolve canonicalises $HOME (EvalSymlinks) while claudeFiles is handed
// main.go's raw os.UserHomeDir() value, so on a host whose home is a symlink
// the exact-match lookup on p.Home can miss even though stageClaudeSettings put
// the mount in the policy under a different, equally valid key. The basename
// fallback matches on BOTH path components (".claude" and "settings.json"),
// not just the leaf, because "settings.json" alone is not a distinctive enough
// name to trust as a fallback the way ".claude.json" is.
func claudeSettingsMount(p *policy.Policy) (policy.Mount, bool) {
	if m, ok := p.Mounts[filepath.Join(p.Home, ".claude", "settings.json")]; ok {
		return m, m.Authored && m.Kind == policy.KindData
	}
	for _, m := range p.Mounts {
		if m.Authored && m.Kind == policy.KindData &&
			filepath.Base(m.Guest) == "settings.json" &&
			filepath.Base(filepath.Dir(m.Guest)) == ".claude" {
			return m, true
		}
	}
	return policy.Mount{}, false
}

// claudeSettingsCarriedNames decodes the GENERATED settings.json content to
// list which allowlisted keys survived for THIS run.
//
// It reads the CONTENT snug already staged, never the host, for the same
// reason claudeTrustCarried does: the screen must describe what was already
// DECIDED, not recompute a second opinion — from a second read of the host's
// file — that could disagree with the one the sandbox is actually running
// with.
//
// policy.ClaudeAuthoredNames() is subtracted from the decoded key set: the
// mount's content is policy.ClaudeUserSettingsJSON's output, which now
// contains the two authored keys alongside the allowlisted ones, and this
// function's own contract is CARRIED keys — the `snug set` line, not this
// one, is where an authored key belongs.
func claudeSettingsCarriedNames(m policy.Mount) []string {
	var doc map[string]any
	if err := json.Unmarshal([]byte(m.Content), &doc); err != nil {
		return nil
	}
	authored := make(map[string]bool, len(policy.ClaudeAuthoredSettings))
	for _, a := range policy.ClaudeAuthoredSettings {
		authored[a.Name] = true
	}
	names := make([]string, 0, len(doc))
	for k := range doc {
		if authored[k] {
			continue
		}
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// describeNetwork spells out what the sandbox can and cannot reach. The
// negative half matters more than the positive half and is stated first.
func describeNetwork(out io.Writer, p *policy.Policy) {
	switch p.Net.Mode {
	case policy.NetIsolated:
		fmt.Fprintf(out, "NETWORK  isolated — private netns, loopback only, no helper process.\n")
		fmt.Fprintf(out, "         No egress. No host loopback. No abstract unix sockets (netns-scoped).\n")
		fmt.Fprintf(out, "         Pathname sockets (X11, D-Bus, Wayland, ssh-agent) are a MOUNT\n")
		fmt.Fprintf(out, "         question, not a network one — see FILESYSTEM for what is granted.\n")
		fmt.Fprintf(out, "         Add the '@net' profile for egress.\n")
	case policy.NetEgress:
		fmt.Fprintf(out, "NETWORK  egress — private netns (one per sandbox) with a pasta helper.\n")
		fmt.Fprintf(out, "         host loopback   UNREACHABLE (--map-host-loopback none, -T none, -U none)\n")
		fmt.Fprintf(out, "         abstract unix   UNREACHABLE (netns-scoped)\n")
		fmt.Fprintf(out, "         pathname sockets (X11, D-Bus, Wayland, ssh-agent) — see FILESYSTEM,\n")
		fmt.Fprintf(out, "                         not this block; a directory grant can expose one\n")
		fmt.Fprintf(out, "         egress          full, IPv4 + IPv6\n")
		// RENDERED FROM THE RESOLVED POLICY, never from a literal (issue
		// #28), and printed UNCONDITIONALLY in this arm rather than gated on
		// p.Net.DNS (issue #166). This line was a hardcoded string printed
		// whenever DNS was on, so on an ordinary LAN host it claimed pasta
		// intercepted while the sandbox was actually handed `nameserver
		// 192.168.1.1` — a false fact about DNS on the screen whose entire job
		// is letting a human decide whether a sandbox leaks its network
		// position, four lines above an offer of '@net-anon' because "the
		// host's LAN address is hidden".
		//
		// The gate went for the same reason the literal did: it made the SCREEN
		// consult a field the file's own author does not, so a profile writing
		// `network = "egress"` with no `dns = true` printed nothing here while
		// the sandbox still got a resolv.conf. A block that is SILENT about DNS
		// is not the same as a sandbox that HAS no DNS, and only one of those
		// was ever true at a time.
		//
		// Every arm names the addresses the sandbox will really read out of
		// /etc/resolv.conf and says WHO answers, because "which address" and
		// "which party" are two different questions and the old line answered
		// the second one wrongly while looking like it answered both.
		switch servers := p.Net.Resolver().Servers; {
		case len(servers) == 0:
			fmt.Fprintf(out, "         dns             NONE — no resolver is named inside; lookups fail fast\n")
			fmt.Fprintf(out, "                         (this profile grants egress but never asked for DNS)\n")
		case p.Net.NeedsDNSForward():
			fmt.Fprintf(out, "         dns             %s -> pasta -> %s\n",
				strings.Join(servers, " "), dnsHostLabel(p))
			fmt.Fprintf(out, "                         (pasta answers here from the host side; no host resolver\n")
			fmt.Fprintf(out, "                         address is named inside the sandbox)\n")
		default:
			fmt.Fprintf(out, "         dns             %s\n", strings.Join(servers, " "))
			fmt.Fprintf(out, "                         (the HOST's own resolvers, named inside the sandbox and\n")
			fmt.Fprintf(out, "                         reached through ordinary egress — a LAN resolver address\n")
			fmt.Fprintf(out, "                         discloses the network the host sits on)\n")
		}
		if len(p.Net.Publish) > 0 {
			fmt.Fprintf(out, "         host -> sandbox ports %v, on the host's 127.0.0.1 only\n", p.Net.Publish)
		} else {
			fmt.Fprintf(out, "         host -> sandbox CLOSED (publish = [3000] in a profile opens one)\n")
		}
		// THIS BLOCK USED TO SAY "the host's LAN address is hidden", full
		// stop, and that was false on any dual-stack host: `address` named
		// only an IPv4 value, and pasta's IPv6 default — copy the addresses
		// from the interface with the default route — still applied.
		// Measured on this host: snug0 inside @net-anon carried the host's
		// two GLOBAL v6 addresses verbatim, geolocatable and
		// ISP-attributable, while the v4 address it hid was RFC1918 (issue
		// #165). Fixed by naming BOTH families — see net.go's checkAddressPair
		// (V6: all four keys, or none) — so this block now renders whichever
		// of the two is set rather than assuming v4 alone.
		//
		// Anonymised(), not p.Net.Address.IsValid() alone: a hand-built Policy
		// (a test, or a future caller) that skipped Resolve's V6 refusal can
		// carry Address6 without Address, and this renderer must not lie about
		// it just because the ordinary case pairs them.
		//
		// Both address rows go through visibleValue as well as Validate's
		// refusal, and deliberately both: Validate says what a profile may
		// CONTAIN, this says what this screen may SHOW. A Policy can be
		// hand-built in a test or by a future caller without passing through
		// Validate, and the rule this file follows is that no screen renders
		// unescaped text it did not author. netip.Prefix.String() is snug's
		// own rendering already for the PREFIX half — it cannot carry a
		// forging rune, ParsePrefix refuses one — but visibleValue costs
		// nothing here and is the one place this belt-and-braces rule is
		// written down; the next author who adds a GATEWAY row will copy this
		// one.
		if p.Net.Anonymised() {
			if p.Net.Address.IsValid() {
				fmt.Fprintf(out, "         address v4      %s (synthetic; the host's IPv4 address is hidden)\n",
					visibleValue(p.Net.Address.String()))
			}
			if p.Net.Address6.IsValid() {
				fmt.Fprintf(out, "         address v6      %s (synthetic; the host's own IPv6 addresses are\n",
					visibleValue(p.Net.Address6.String()))
				fmt.Fprintf(out, "                         hidden -- those are globally routable and\n")
				fmt.Fprintf(out, "                         ISP-attributable, unlike the RFC1918 v4 one)\n")
			} else {
				fmt.Fprintf(out, "         address v6      NOT anonymised — the sandbox keeps the host's own v6\n")
				fmt.Fprintf(out, "                         addresses, which are globally routable and\n")
				fmt.Fprintf(out, "                         ISP-attributable (half-anonymised policy; issue #165)\n")
			}
			fmt.Fprintf(out, "         routes          synthetic (default via the gateway above). Under '@net' the\n")
			fmt.Fprintf(out, "                         sandbox inherits the host's default route, whose IPv6 form\n")
			fmt.Fprintf(out, "                         is the router's link-local address and carries its MAC.\n")
			fmt.Fprintf(out, "         host's own IPs  REACHABLE. A service the host binds on its OWN address,\n")
			fmt.Fprintf(out, "                         or on 0.0.0.0 / ::, is reachable from here, because that\n")
			fmt.Fprintf(out, "                         address is no longer the sandbox's own. Host LOOPBACK is\n")
			fmt.Fprintf(out, "                         not (row above). Under '@net' neither is (issue #176).\n")
		} else {
			fmt.Fprintf(out, "         address         copied from the host — add '@net-anon' to hide it\n")
			fmt.Fprintf(out, "         host's own IPs  unreachable, incidentally rather than by design: they are\n")
			fmt.Fprintf(out, "                         on the sandbox's own interface, so a connection to one\n")
			fmt.Fprintf(out, "                         never leaves the netns. '@net-anon' removes that.\n")
		}
	}
}

// dnsHostLabel names WHERE pasta sends an intercepted query, for the dns line.
//
// The screen used to end that sentence at "host resolver", which is the one
// part of it a reader cannot check — and until issue #166 snug did not know
// either, because the address was pasta's own default rather than a value the
// policy chose. Now it is chosen, so it can be said.
func dnsHostLabel(p *policy.Policy) string {
	if h := p.Net.DNSHost(); h != "" {
		return h
	}
	return "host resolver (pasta's default; this host names none)"
}

// describeTopology is not a debugging convenience either — it is the one place
// a human learns that snug started a SECOND long-lived process ahead of the
// sandbox, what that process holds, and when it dies. "No daemon, no service
// files" is a claim the README already makes; a process that outlives the
// command belongs on screen with its lifetime rule, printed always — including
// the one-process case, where saying so plainly is the point (Phase 1 adds no
// user-visible capability, and this block is how that claim stays checkable
// rather than merely asserted).
// longLivedProcess is one entry in the TOPOLOGY block's process list: what it
// is called and what it is for. Both are shown, because a count on its own
// answers "how many" and a reader's actual question is "which".
type longLivedProcess struct {
	name string
	role string
}

// longLivedProcesses derives the list from the SAME predicates
// internal/sandbox/exec.go's Run and runStaged branch on, in the order those
// processes come into existence:
//
//	snug     always — this process
//	stage    Topology.NeedsStage()          (exec.go: Run's runStaged arm)
//	pasta    Net.Mode == NetEgress          (runStaged: `if p.Net.Mode == policy.NetEgress`)
//	engine   Podman != PodmanOff            (runStaged: `if opts.EngineSpec != nil`)
//	bwrap    always — the sandbox itself
//
// The engine's own predicate is spelled from the POLICY (p.Podman) rather than
// from Options.EngineSpec, because --dry-run has no Options: internal/cli's
// startContainers sets EngineSpec exactly when p.Podman != PodmanOff, so the
// two agree by construction. If that ever stops being true, this comment is
// the thing to fix, not the count.
//
// bwrap is listed LAST on the staged arm on purpose: it is the last thing
// created, after the network is confirmed up, which is the ordering property
// INDEX §4.3 exists to state. __innetns is deliberately absent — it execve's
// into bwrap rather than running beside it, so counting it would inflate the
// number a human uses to check `ps`.
func longLivedProcesses(p *policy.Policy) []longLivedProcess {
	procs := []longLivedProcess{{"snug", "this process — resolves the policy and supervises"}}
	if p.Topology.NeedsStage() {
		role := "creates the sandbox's network namespace, pins it, leaves it"
		if p.Topology.Netns != policy.NetnsStage {
			// Unreachable today: the podman branch of deriveTopology is the
			// only producer of SubuidFull and it raises Netns to at least
			// NetnsStage in the same breath, so NeedsStage() cannot be true
			// without NetnsStage. Rendered honestly rather than asserted, so a
			// future second producer of SubuidFull cannot make this line claim
			// a namespace it did not make.
			role = "holds the delegated subuid range"
		}
		procs = append(procs, longLivedProcess{"stage (P1)", role})
	}
	if p.Net.Mode == policy.NetEgress {
		procs = append(procs, longLivedProcess{"pasta", "attached to that namespace — the only egress path"})
	}
	if p.Podman != policy.PodmanOff {
		procs = append(procs, longLivedProcess{"engine", "the container engine, forked into the same namespace"})
	}
	return append(procs, longLivedProcess{"bwrap", "the sandbox itself, and the payload inside it"})
}

func describeTopology(out io.Writer, p *policy.Policy) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "TOPOLOGY")
	// One denominator, counted the same way in every arm: every long-lived
	// process snug will run, snug itself included.
	//
	// DERIVED, not written out, and that is the point of longLivedProcesses.
	// This line has now been wrong twice for the same reason. First the two
	// arms counted differently — "1 — bwrap only" excluded snug, "2 — snug,
	// and a stage" excluded bwrap, and neither mentioned pasta. The fix for
	// that was a second hand-written sentence, which Tier B (issue #63) then
	// falsified: it named pasta on an offline @podman-socket run that starts
	// none, omitted the container engine that run does start, and printed 4
	// for a `@net -p @podman-socket` run that starts five. A count in prose is
	// a copy of state held somewhere else — internal/sandbox/exec.go's
	// runStaged, here — so it is read off the same predicates runStaged
	// branches on rather than restated beside them. Adding a long-lived helper
	// without touching this block is now a golden diff rather than a silent
	// lie (TestGoldenTopology, TestTopologyProcessesMatchRunStagedsPredicates).
	procs := longLivedProcesses(p)
	fmt.Fprintf(out, "  processes       %d — every long-lived process this run starts, snug included:\n", len(procs))
	for _, pr := range procs {
		fmt.Fprintf(out, "                    %-11s %s\n", pr.name, pr.role)
	}
	if !p.Topology.NeedsStage() {
		fmt.Fprintf(out, "                  No stage, no privileged ancestor namespace.\n")
	} else {
		fmt.Fprintf(out, "                  (__innetns is a setns shim that BECOMES bwrap rather than\n")
		fmt.Fprintf(out, "                  running beside it, so it is not one of the %d.)\n", len(procs))
	}
	fmt.Fprintf(out, "  netns owner     %s\n", p.Topology.Netns)
	if p.Topology.NeedsStage() {
		fmt.Fprintf(out, "                  the sandbox's user namespace has a PRIVILEGED ANCESTOR: the\n")
		fmt.Fprintf(out, "                  stage is root in its own user namespace (U) for the whole run,\n")
		fmt.Fprintf(out, "                  holding CAP_SYS_ADMIN over the sandbox's network namespace (N)\n")
		fmt.Fprintf(out, "                  and over the sandbox's own mounts.\n")
	}
	fmt.Fprintf(out, "  subuid          %s", p.Topology.Subuid)
	if p.Topology.Subuid == policy.SubuidNone {
		fmt.Fprintf(out, " (no delegated range; nothing needs one yet)\n")
	} else {
		fmt.Fprintln(out)
	}
	if p.Podman != policy.PodmanOff {
		// The engine (issue #63, Tier B): a second process the stage forks
		// into its OWN user + network namespace, as a sibling of bwrap, so a
		// container it starts shares exactly the sandbox's own N. Its mount
		// namespace is DERIVED from the sandbox's view since Tier C (#245):
		// its root IS the sandbox's own root with the grafts under ENGINE VIEW
		// on top, so an ungranted path is not there to be named. The proxy's
		// bind filter still refuses one by name, reading this same resolved
		// policy — belt and braces now rather than the only barrier.
		//
		// This comment said the opposite for two tiers ("a private COPY of the
		// host tree … Tier C is what makes the VIEW itself structural"), which
		// is issue #252 one layer in: the screen was corrected there and the
		// comment above it would have kept telling the next reader that the
		// correction was wrong.
		//
		// Widening the capability set below is necessarily a diff to this
		// line, which is the point of keeping it a policy-owned constant
		// rather than a per-profile field. The pid namespace is its own from
		// the moment the engine exists (issue #125's C0): CLONE_NEWPID at the
		// engine's clone time plus a fresh procfs mount
		// (internal/stage/inengine.go).
		fmt.Fprintf(out, "  engine          joins THIS sandbox's own network namespace (N) — a container has\n")
		fmt.Fprintf(out, "                  exactly the sandbox's own network, nothing more.\n")
		fmt.Fprintf(out, "                  mount namespace: DERIVED from this sandbox's view — the\n")
		fmt.Fprintf(out, "                  engine's root IS the sandbox's own root, with the grafts\n")
		fmt.Fprintf(out, "                  listed under ENGINE VIEW below mounted on top of it. The host\n")
		fmt.Fprintf(out, "                  tree is not in it, and neither is your home directory.\n")
		fmt.Fprintf(out, "                  So a container may bind only what this policy already\n")
		fmt.Fprintf(out, "                  exposes, and that is now STRUCTURAL — the proxy's bind filter\n")
		fmt.Fprintf(out, "                  still refuses one by name, but a path the sandbox cannot see\n")
		fmt.Fprintf(out, "                  is not in the engine's namespace to be bound.\n")
		fmt.Fprintf(out, "                  pid namespace: its own, so the engine cannot see the host's\n")
		fmt.Fprintf(out, "                  process table and the sandbox cannot see the engine's. Each\n")
		fmt.Fprintf(out, "                  container gets its own too, and may not ask for anyone else's:\n")
		fmt.Fprintf(out, "                  '--pid=host' is REFUSED, because in a shared pid namespace\n")
		fmt.Fprintf(out, "                  /proc/<pid>/root reaches that process's whole mount namespace,\n")
		fmt.Fprintf(out, "                  and pid 1 here is the engine — whose mount namespace is the\n")
		fmt.Fprintf(out, "                  derived view named above, plus every graft on it.\n")
		fmt.Fprintf(out, "                  ipc + uts namespaces: the ENGINE's OWN (issue #182). A container\n")
		fmt.Fprintf(out, "                  may not ask for either — \"host\" would name the engine's, not the\n")
		fmt.Fprintf(out, "                  machine's; the payload has its own too (bwrap --unshare-ipc\n")
		fmt.Fprintf(out, "                  --unshare-uts).\n")
		fmt.Fprintf(out, "                  capability bounding set (%d): %s\n",
			len(policy.EngineCapBounding), strings.Join(policy.EngineCapBounding, " "))
		// The gate (issue #125), printed for exactly the selections that get
		// it. It changes the process shape of the run — there is an interval
		// with a fully built sandbox and no payload in it — and --dry-run is
		// where a human is entitled to learn that rather than from a comment
		// in exec.go. The residual is on screen for the same reason: a cost
		// that only appears in a design document is a cost nobody priced.
		fmt.Fprintf(out, "  payload gate    the payload is PARKED (bwrap --block-fd) from the moment its\n")
		fmt.Fprintf(out, "                  mount tree is built until this engine's socket answers, so a\n")
		fmt.Fprintf(out, "                  run whose engine never came up is a run whose payload never\n")
		fmt.Fprintf(out, "                  existed. The same pipe's write end is passed as --sync-fd and\n")
		fmt.Fprintf(out, "                  held by the sandbox's own pid 1, so snug being KILLED cannot\n")
		fmt.Fprintf(out, "                  release it either — only snug writing the byte can.\n")
		fmt.Fprintf(out, "                  Residual: a snug SIGKILLed inside that window is measured to\n")
		fmt.Fprintf(out, "                  leave nothing behind — the stage sees the lifeline close and\n")
		fmt.Fprintf(out, "                  kills the parked init first — but a stage that cannot run code\n")
		fmt.Fprintf(out, "                  at all (a SIGSTOPped tree) orphans that init, holding N and the\n")
		fmt.Fprintf(out, "                  mount tree with a payload that does not exist and never will.\n")
	}
	if !p.Topology.NeedsStage() {
		fmt.Fprintf(out, "  control         none — there is no stage to control.\n")
	} else {
		// Not "none". There IS a channel, and it is the most authority-bearing
		// object in the topology: one request on it makes the stage execve an
		// arbitrary path as root-in-U inside N. Saying "no socket" was the half
		// a reviewer would use to decide there was nothing here to audit.
		fmt.Fprintf(out, "  control         an anonymous SOCK_SEQPACKET socketpair, inherited, between snug\n")
		fmt.Fprintf(out, "                  and the stage. UNREACHABLE from the sandbox: no pathname, no\n")
		fmt.Fprintf(out, "                  listener, and no descriptor for it in the payload's table. It\n")
		fmt.Fprintf(out, "                  carries at most two requests — is the network up, then start\n")
		fmt.Fprintf(out, "                  the sandbox — and the stage exits after the second.\n")
	}
	if p.Topology.NeedsStage() {
		fmt.Fprintf(out, "  host-visible    the stage's namespaces are nameable from the host by a\n")
		fmt.Fprintf(out, "                  same-uid process, as /proc/<stage>/ns/user and its pinned\n")
		fmt.Fprintf(out, "                  /proc/<stage>/fd/<n> for N. Measured equivalent to what such a\n")
		fmt.Fprintf(out, "                  process can already reach without a stage, via NS_GET_USERNS on\n")
		fmt.Fprintf(out, "                  the sandbox's own namespace descriptors. Same-uid is outside\n")
		fmt.Fprintf(out, "                  the threat model either way; it is listed so it is not a\n")
		fmt.Fprintf(out, "                  surprise.\n")
		fmt.Fprintf(out, "  lifetime        the stage exits when its one payload does, whatever the\n")
		fmt.Fprintf(out, "                  outcome, and dies with snug even if snug is SIGKILLed. Two\n")
		fmt.Fprintf(out, "                  mechanisms, covering different failures: an inherited pipe (the\n")
		fmt.Fprintf(out, "                  lifeline) for a stage that can still run code, and Pdeathsig\n")
		fmt.Fprintf(out, "                  for one that is stopped and cannot.\n")
		fmt.Fprintf(out, "  abuse sentence  a hostile process inside the sandbox gains no new reach — the\n")
		fmt.Fprintf(out, "                  stage is in neither its network namespace nor its pid\n")
		fmt.Fprintf(out, "                  namespace, binds nothing it can name, and holds no descriptor\n")
		fmt.Fprintf(out, "                  it can open — but its user namespace now has a privileged\n")
		fmt.Fprintf(out, "                  ancestor that lives for the whole run, so a userns-escape bug\n")
		fmt.Fprintf(out, "                  is worth more here than it was.\n")
	}
}

// graftIndent is the column every wrapped graft field ("from", "abuse:")
// re-starts at, matching the "  graft-rw  " kind+path prefix's own width so
// the block reads as a paragraph per field rather than a hanging indent
// nobody asked for.
const graftIndent = 12

// wrapGraftField wraps one graft field's text to screenWidth, label first
// ("abuse: ", "note: ") on the opening line, every continuation line
// re-indented to graftIndent with no label repeated. It breaks on spaces
// only, the same rule wrapMark uses and for the same reason: these lines
// carry prose, and splitting a token mid-word is a lie about what it named.
//
// NEVER call this on a Guest or a Host. strings.Fields below collapses runs
// of whitespace and trims the ends — harmless for prose, but a host path may
// legally contain two spaces (nothing refuses U+0020 in a path, nor should
// it: a real file can be named that way), and this function silently
// rewrote it to one, a small lie in the one block whose entire job is not
// lying about what a graft names (issue #55, finding F9). Guest is already
// printed verbatim on the kind-column row; Host is printed verbatim on its
// own line by describeGrafts, through visibleValue only — never through
// this function.
func wrapGraftField(label, text string) []string {
	indent := strings.Repeat(" ", graftIndent)
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{indent + strings.TrimRight(label, " ")}
	}
	var out []string
	cur := label + words[0]
	for _, w := range words[1:] {
		candidate := cur + " " + w
		if utf8.RuneCountInString(indent)+utf8.RuneCountInString(candidate) > screenWidth {
			out = append(out, indent+cur)
			cur = w
			continue
		}
		cur = candidate
	}
	out = append(out, indent+cur)
	return out
}

// describeGrafts renders p.Grafts — mounts in the ENGINE's derived mount
// namespace, never the payload's (issue #55). It is its own block rather than
// rows in FILESYSTEM, because that block's header says "every line is a
// grant" of the PAYLOAD's view, and a graft row there would claim the payload
// can see the host's container store — the same class of lie, facing the
// other way, that ENGINE-NETNS.md §5.1's /run finding is about.
//
// Placed right after TOPOLOGY and before FILESYSTEM: a graft is a property of
// the engine TOPOLOGY already describes, not of the sandbox's own filesystem.
//
// Prints ONLY when len(p.Grafts) > 0, and since Tier C that is EVERY container
// run: startContainers calls installEngineViewGrafts before its --dry-run
// branch (four grafts — /proc, /sys/fs/cgroup, /var/tmp, /run: the mounts the
// stage really makes in the engine's own namespace), and the branch itself
// records the store, runroot, sock and conf grafts from engine.PlannedPaths.
// The silent case is a run with NO engine, not a shipping gap.
//
// This paragraph said the opposite for a tier — "every topology that ships
// today has none, Tier B's engine gets a private COPY of the host tree and
// makes no graft" — which was true when written and false from #245 onward.
// It mattered more than an ordinary stale comment because it was the standing
// JUSTIFICATION for topology.podman-*.txt carrying no graft rows: prose
// explaining why a golden is empty outlives the reason, and then the empty
// golden looks checked.
//
// topology.podman-*.txt still do not move, and that is a FIXTURE BOUNDARY
// rather than a hole — verified, not assumed. Those files are goldens of
// describeTopology ALONE (topologygolden_test.go captures that one call), and
// describeTopology never reads p.Grafts, so installing grafts in that fixture
// would produce no diff at all. One block, one golden, the same way FILESYSTEM
// lives in filesystem.defaults.txt. THIS block's own golden is
// engineview.enginemounts.txt — real installEngineViewGrafts output on the
// same @sys @cwd-rw @podman-socket selection the podman-offline topology case
// uses — plus the hand-built engineview.tierc.txt for the host-tree render
// path. The TOPOLOGY prose pointing at "ENGINE VIEW below" is true ON THE
// SCREEN, which is where a human reads it, and graft_test.go's
// blockBetween(t, got, "ENGINE VIEW", "FILESYSTEM") pins that ordering.
//
// THERE IS DELIBERATELY NO WHOLE-SCREEN PODMAN GOLDEN, and the reason is a
// constraint rather than a preference: engine.PlannedPaths keys this run's
// directory on fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()), so a screen
// golden would embed a live pid and fail on its second run and on every other
// machine. That much still holds.
//
// The residual it used to leave — the store/runroot/sock/conf rows having no
// golden that exercises the real PlannedPaths — is CLOSED, by
// engineview.planned.txt (TestGoldenEngineViewPlannedPaths). This paragraph
// used to say covering them "needs an injectable tag in place of
// snug-<uid>-<pid>"; that was wrong twice over, and the correction is worth
// carrying because a seam in this particular function is the tempting fix.
//
// It was wrong about the REMEDY. A settable tag fixes the pid and leaves
// os.Getuid(), which enters a SECOND time through the runroot's own name
// (snug-engines-<uid>-<key> in planPaths), so the output stays host-dependent
// and the golden stays unwritable. Making the uid injectable too is the worse
// half: the runroot sits under world-writable /tmp and engineKey's own doc
// comment names what protects it — VerifyOwnedAndPrivate's uid+mode check,
// which compares against os.Getuid() and would keep doing so. A seam bypasses
// no ownership check; what it breaks is the AGREEMENT between the name and the
// owner, and planPaths is the sole author of "which host directory is this
// run's own".
//
// And it was wrong about the DIFFICULTY. Two of the four host-dependent inputs
// are already injectable through the environment — dataHomeDir() reads
// $XDG_DATA_HOME, os.TempDir() re-reads $TMPDIR — and the other two are the
// process's identity, which a test can normalise to placeholders after
// capture. No production change at all. See that test's own comment for what
// the normalisation must preserve (the 16-hex engineKey is left intact, so the
// golden still shows on its face which rows are per-run and which are
// per-target-and-persistent).
//
// KIND-COLUMN DISTINCTION IS REQUIRED, NOT DECORATIVE: "graft-ro"/"graft-rw",
// never bare "ro"/"rw" — a reader must never have to know which block a row
// came from to know which mount namespace it is in, the exact confusion
// keeping this out of FILESYSTEM exists to prevent. Provenance renders
// whatever the graft's own From carries, which G5 requires be exactly
// "(snug)" — the same word /proc and /dev already carry on the FILESYSTEM
// block.
//
// THE DESTINATION NOTE IS PER-GRAFT, decided from the SANDBOX's own view
// (graftDestinationNote), not one fixed sentence printed once. The fixed
// sentence — "created on the sandbox's own root tmpfs … empty … unwritable
// once / is remounted read-only" — is true only for a destination G3 accepted
// through its FIRST/SECOND disjunct (no covering mount at all: an
// auto-created directory on bare tmpfs). It is false for the shape G3's
// THIRD disjunct accepts — a destination inside a writable grant, which is
// exactly what this file's own golden fixture uses — where the destination is
// the payload's own writable tree, not an empty tmpfs, and a write through it
// can reach the HOST. Printing the fixed sentence unconditionally was a
// screen lie pinned by the golden that exercises precisely the shape it was
// wrong about (issue #55, finding F4). Do not go back to one sentence for
// every graft; ask p.SandboxView().CoveringMount(gr.Guest) each time.
//
// A ROW ALSO SAYS WHEN ITS SOURCE CAME FROM EngineOwnedHostPaths RATHER THAN
// FROM HostPathVisible: G4 has two disjuncts and they answer different
// questions (see checkGraft's own comment) — a graft whose Host the sandbox's
// OWN grants do not expose is legal only because snug declared that host path
// its own for this run, and a human reading this screen is owed exactly which
// case they are looking at, not a single unqualified "from" line (finding
// F2). The full EngineOwnedHostPaths set — not just the paths a graft
// currently uses — is listed too, because it is a host path snug declares its
// own by fiat and had, before this fix, no line on --dry-run at all.
//
// Every string here — Guest, Host, HostAsked, Why, From, and every
// EngineOwnedHostPaths entry — goes through visibleValue, the same guard
// every other screen uses; this block is in
// TestNoSnugScreenEmitsARawControlCharacter's sink set for exactly that
// reason. Guest, Host and HostAsked print VERBATIM (never through
// wrapGraftField, see its own comment, finding F9); only prose (Why, the
// destination note, the "resolved:" line) is wrapped.
func describeGrafts(out io.Writer, p *policy.Policy) {
	if len(p.Grafts) == 0 {
		return
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "ENGINE VIEW  (grafts — mounts in the ENGINE's derived mount namespace, NOT the")
	fmt.Fprintln(out, "  payload's. The payload cannot see any of these; no profile can ask for one.)")

	// The one graft this screen CANNOT show, said here rather than left to be
	// discovered by diffing a dry run against a real one (issue #252). The
	// toolchain graft's source is a preflight answer — which host directory
	// this engine's own program files live in — and --dry-run runs no
	// preflight, so on a host that needs one this block is four grafts where
	// the run makes five. An absent row that nothing explains is the same
	// defect this issue was filed for, one graft smaller.
	//
	// Written as len(...) == 0 rather than == "": TestOnlyOneWriterOfEngine\
	// ToolchainRoot greps for `\.EngineToolchainRoot\s*=`, which a COMPARISON
	// against "" also matches, so the natural spelling trips a guard that
	// exists to catch assignments. Reported rather than loosened — the guard
	// is right about the field and wrong only about this read.
	//
	// AND THE ANSWER STAYS NO: this screen does not run the read-only preflight
	// probes either (subuid presence, ptrace_scope), asked and decided under
	// issue #422 when the block above started resolving $SNUG_PODMAN_ROOT. The
	// two are different questions. That one judges an INPUT — a path a human
	// named, judged by the function the run judges it with, over one sample of
	// the host. A probe answers whether this HOST can do something, which the
	// run's own preflight answers at the moment it matters; printing it here
	// invites the reader to treat a dry run's pass as the run's pass, and
	// invariant 5 is kept by the run refusing, not by the screen predicting.
	// Order makes a half-measure worse than none: runContainerPreflight runs P6
	// (ptrace_scope) before P1, so on a ptrace_scope=0 host the run refuses
	// before the engine binary is reached, and a screen probing some of
	// preflight would show the later judgement while hiding the earlier one. It
	// would also make every golden host-dependent — the trap buildReport's own
	// comment records for /etc/containers/policy.json. `snug doctor` is where
	// host-capability probes belong; it promises to start nothing.
	if p.Podman != policy.PodmanOff && len(p.EngineToolchainRoot) == 0 {
		fmt.Fprintln(out, "  (an engine outside every grant this sandbox makes adds a fifth graft at "+
			policy.EngineToolchainGuest+" — whether")
		fmt.Fprintln(out, "  this host needs one is a preflight answer, and --dry-run runs no preflight.)")
	}

	guests := make([]string, 0, len(p.Grafts))
	for g := range p.Grafts {
		guests = append(guests, g)
	}
	sort.Strings(guests)

	indent := strings.Repeat(" ", graftIndent)
	for _, guest := range guests {
		gr := p.Grafts[guest]
		// The kind's own word, not "graft" for everything: a fresh procfs and
		// an open_tree(2) clone of a host directory are different objects with
		// different rules, and a block that called both "graft" would make the
		// reader look at the `from` line to tell them apart — which is exactly
		// the line a fresh mount does not have. KindGraft still renders
		// byte-identically to what it always did (graft-ro / graft-rw).
		access := "ro"
		if gr.Access == policy.AccessRW {
			access = "rw"
		}
		// %-10s, not the %-8s this column used when "graft-ro" and "graft-rw"
		// were the only two words it could hold: "cgroup2-rw" is ten, and a
		// column that overflows shifts every field after it on that row only,
		// which is exactly the kind of ragged block a human stops reading.
		fmt.Fprintf(out, "  %-10s  %-44s  %s\n",
			gr.Kind.String()+"-"+access, visibleValue(gr.Guest),
			visibleValue(strings.Join(gr.From, "+")))
		// A HOST-shaped graft names the tree it clones; a fresh mount has no
		// host path at all, and printing "from " with nothing after it said
		// something false in the shape of something true. Host is EXACTLY
		// empty for those kinds rather than approximately so — checkGraft
		// refuses a non-empty Host on a kind the stage mounts itself — so this
		// is a fact about the graft, not a guess from an empty string.
		if gr.Host != "" {
			// Verbatim: Host may legally contain runs of whitespace, and
			// wrapGraftField's strings.Fields would collapse them (F9).
			fmt.Fprintf(out, "%sfrom %s\n", indent, visibleValue(gr.Host))
		} else {
			fmt.Fprintf(out, "%sfrom (nothing — the stage mounts a fresh %s here; no host path is opened)\n",
				indent, gr.Kind)
		}
		if gr.HostAsked != "" {
			// Verbatim, for F9's reason: a host path may legally contain runs
			// of whitespace and wrapGraftField's strings.Fields collapses them.
			fmt.Fprintf(out, "%sasked %s\n", indent, visibleValue(gr.HostAsked))
			for _, line := range wrapGraftField("resolved: ",
				"the path snug's own code named is a SYMLINK on the host; snug resolved it "+
					"before judging G4 and grafts the resolved path above. A source under any "+
					"path the payload can write is a path the payload chooses, so this is the "+
					"row to read twice") {
				fmt.Fprintln(out, line)
			}
		}
		// G4 asks about a SOURCE, so this whole block is about grafts that
		// have one. A fresh mount skips G4 entirely (graftKindRules'
		// hasHost=false), and the `owned:` line below claimed it "passed G4
		// only because snug declared it its own for this run" — a reason that
		// did not happen, printed next to a mount that has no source at all.
		// A screen that explains a check the code did not run is worse than a
		// screen that says nothing, because it reads as evidence.
		if gr.Host != "" && !p.HostPathVisible(gr.Host, gr.Access == policy.AccessRW) {
			// WHICH of G4's other two sources admitted it, named separately.
			// One sentence covering both would be false about whichever one
			// it did not describe, and these two have different owners: snug
			// authored the contents of an engine-owned path, while the
			// toolchain root is the host user's own installation that snug
			// only ever reads.
			if gr.Host == p.EngineToolchainRoot && gr.Access == policy.AccessRO {
				for _, line := range wrapGraftField("toolchain: ",
					"the sandbox's own grants do not expose this host path — it passed G4 as "+
						"this run's engine toolchain root ($SNUG_PODMAN_ROOT), read-only. It is "+
						"the engine's own program files, which it must be able to execute once "+
						"its view is derived from the sandbox's rather than copied from the "+
						"host's") {
					fmt.Fprintln(out, line)
				}
			} else {
				for _, line := range wrapGraftField("owned: ",
					"the sandbox's own grants do not expose this host path — it passed G4 only "+
						"because snug declared it its own for this run (EngineOwnedHostPaths)") {
					fmt.Fprintln(out, line)
				}
			}
		}
		for _, line := range wrapGraftField("abuse: ", visibleValue(gr.Why)) {
			fmt.Fprintln(out, line)
		}
		for _, line := range wrapGraftField("note: ", graftDestinationNote(p, gr)) {
			fmt.Fprintln(out, line)
		}
	}

	if p.EngineToolchainRoot != "" {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  engine toolchain root    the engine's own program files. A graft's Host may name")
		fmt.Fprintln(out, "                           EXACTLY this path, read-only, under G4 even though no")
		fmt.Fprintln(out, "                           sandbox grant exposes it — never a path under it:")
		fmt.Fprintf(out, "    %s\n", visibleValue(p.EngineToolchainRoot))
	}

	if len(p.EngineOwnedHostPaths) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  engine-owned host paths  snug created these for this run; a graft's Host may")
		fmt.Fprintln(out, "                           name one under G4 even though no sandbox grant")
		fmt.Fprintln(out, "                           exposes it (OwnEngineHostPath, the only writer):")
		paths := make([]string, 0, len(p.EngineOwnedHostPaths))
		for k := range p.EngineOwnedHostPaths {
			paths = append(paths, k)
		}
		sort.Strings(paths)
		for _, k := range paths {
			fmt.Fprintf(out, "    %s\n", visibleValue(k))
		}
	}
}

// graftDestinationNote decides, from the SANDBOX's own view, what is
// actually true about a graft's destination directory — see describeGrafts's
// own comment for why this must be per-graft rather than one fixed sentence
// (issue #55, finding F4).
//
// p.SandboxView().CoveringMount(gr.Guest) answers exactly the question G3
// itself asked when the graft was accepted:
//
//   - ok == false: nothing in the sandbox's own mount set covers this path at
//     all — G3's first/second disjunct, an auto-created directory sitting on
//     the bare root tmpfs. The original fixed sentence is true here.
//   - a writable BIND covers it: G3's third disjunct on a bind — the
//     destination is inside a host directory the payload can already write,
//     and any write through it reaches the HOST.
//   - a writable TMPFS covers it: G3's third disjunct on tmpfs (e.g. $HOME,
//     /tmp) — the payload can write there, but nothing written survives the
//     sandbox.
//   - a read-only grant covers it (G3's first disjunct at an exact,
//     read-only mountpoint): the payload can already read what is there and
//     cannot write to it.
func graftDestinationNote(p *policy.Policy, gr policy.Graft) string {
	m, ok := p.SandboxView().CoveringMount(gr.Guest)
	if !ok {
		return "this graft's destination is created on the sandbox's own root tmpfs and IS " +
			"visible to the payload — empty, and unwritable once / is remounted read-only. The " +
			"mount namespace is private; the tmpfs superblock is not (ENGINE-NETNS.md §5.1)."
	}
	switch {
	case m.Access == policy.AccessRW && m.Kind == policy.KindBind:
		return fmt.Sprintf("this graft's destination is inside a writable bind of a host directory "+
			"(%s) — the payload can create and write there directly, and any write on this path "+
			"reaches the HOST and persists after the sandbox exits.", visibleValue(m.Host))
	case m.Access == policy.AccessRW && m.Kind == policy.KindTmpfs:
		return "this graft's destination is inside a writable tmpfs grant — the payload can create " +
			"and write there, but nothing written survives: the tmpfs dies with the sandbox."
	case m.Access == policy.AccessRO:
		return fmt.Sprintf("this graft's destination coincides with a read-only %s grant already in "+
			"the sandbox's own view — the payload can already read whatever that grant exposes "+
			"there, and cannot write to it.", m.Kind)
	default:
		return fmt.Sprintf("this graft's destination coincides with an existing %s grant (access %s) "+
			"in the sandbox's own view.", m.Kind, m.Access)
	}
}

// describeBwrap prints the argv, framed by what the argv CANNOT say.
//
// Under NetnsStage the bwrap argv no longer determines the network posture.
// bwrap does not create the sandbox's network namespace on that path — the
// stage does, then a setns shim puts bwrap inside it — so --unshare-net is
// absent, and absence has no line. Run exactly as printed, the command lands in
// the HOST network namespace: MEASURED here, the payload's own
// readlink /proc/self/ns/net came back byte-identical to the host's and a live
// 127.0.0.1 listener answered from inside, while the real snug run of the same
// policy reported a different namespace id and a refused connection. Nothing on
// the screen said the command was incomplete.
//
// That is not a cosmetic defect, and the reader it costs is a specific one:
// VERIFY.md's whole style is "every line is a command with its expected
// output", so a reviewer checking the netns guarantee by hand reproduces this
// argv, gets host loopback and the host's abstract sockets, and concludes
// either that snug is broken or — worse — that the guarantee is weaker than it
// is, and writes that down.
//
// THREE OPTIONS, and they are not equivalent. The one chosen is prose at both
// ends of the argv, with the argv itself byte-faithful to what snug passes.
//
//   - Print a command that is complete on its own. MEASURED impossible: bwrap
//     0.11.2 takes --userns FD and --pidns FD and has NO --netns FD, so no
//     bwrap argv can name an existing network namespace. Making the printed
//     command self-contained would mean printing a different program (an
//     nsenter wrapper snug never runs) or adding --unshare-net for display
//     only — which is paste-safe by being false: an empty netns with no pasta
//     is a different sandbox, and a screen that lies to be tidy is the
//     engine-netns finding again.
//   - Print the stage invocation as well. Honest, and not runnable either (the
//     pinned descriptor and the hidden verbs do not exist in a shell), and it
//     duplicates the TOPOLOGY block above, which already says this and has its
//     own golden. Its one true sentence is adopted below instead.
//   - Put a marker INSIDE the argv where --unshare-net would be. The only
//     option a copied FRAGMENT carries with it, and rejected anyway. A '#'
//     comment line survives the obvious `tr '\n' ' '` join and comments out the
//     rest of the argv (MEASURED: bwrap then printed usage and exited 1 — fail
//     closed at this position, but only because the omission is near the top;
//     the same device further down truncates the mounts and still runs). A
//     fabricated --flag fails closed loudly but puts a flag in the block that
//     snug does not pass. Both make the block stop being a rendering of the
//     argv, and "a value that can author a row in --dry-run is a hole in the
//     trust artifact even though it escapes nothing" is this file's own rule
//     (visibleValue). A paste-safety device that corrupts the artifact defeats
//     the artifact.
//
// So the reader optimised for is the one who RUNS what is printed, subject to
// the block staying byte-faithful for the one who reads a golden diff. What is
// NOT solved: a human who copies one line out of the middle meets neither end.
// Nothing that keeps the argv byte-faithful can solve that, which is why the
// note names the by-hand check that DOES settle the question rather than only
// warning about the one that does not.
//
// The complete topologies get one line saying so, always. It is not decoration:
// it tells a reviewer that a hand-run IS valid there, and it makes the stage
// case's warning a contrast rather than an isolated scare. MEASURED, bwrap
// 0.11.2: --unshare-all yields a netns id different from the host's.
func describeBwrap(out io.Writer, p *policy.Policy, args []string, refusedBy error) {
	fmt.Fprintln(out, "── bwrap ─────────────────────────────────────────────────────────────────")
	if refusedBy != nil {
		fmt.Fprintln(out, "(this argv describes the REFUSED policy above; it is not a command you can")
		fmt.Fprintln(out, " paste and run — see the refusal below)")
	}
	switch p.Topology.Netns {
	case policy.NetnsStage:
		fmt.Fprintln(out, "INCOMPLETE ON ITS OWN — the network namespace is NOT in this argv.")
		fmt.Fprintln(out, "  The stage created it, pinned it, and a setns shim put bwrap inside it before")
		fmt.Fprintln(out, "  bwrap ran, so no --unshare-net appears below. Nothing could appear in its")
		fmt.Fprintln(out, "  place: bwrap takes --userns FD and --pidns FD, and has no --netns FD.")
		fmt.Fprintln(out, "  RUN AS PRINTED, this command lands in YOUR network namespace and starts no")
		fmt.Fprintln(out, "  pasta helper — host loopback and the host's abstract sockets (X11, D-Bus)")
		fmt.Fprintln(out, "  are both reachable, every line of the NETWORK block above is false of what")
		fmt.Fprintln(out, "  you ran, and what you measured is your own host network.")
	default:
		fmt.Fprintln(out, "(this argv determines the network posture on its own: --unshare-net creates")
		fmt.Fprintln(out, " the sandbox's own empty network namespace, so running it by hand reproduces")
		fmt.Fprintln(out, " it.)")
	}
	bwrapExec := execResolution("bwrap")
	fmt.Fprintln(out, formatArgs(bwrapExec.Argv0, args))
	describeArgv0(out, bwrapExec)
	if p.Topology.Netns == policy.NetnsStage {
		fmt.Fprintln(out, "(the argv ends here and the network namespace was never in it — see the note")
		fmt.Fprintln(out, " above it. To check the netns by hand, compare inside against outside:")
		fmt.Fprintln(out, "     readlink /proc/self/ns/net                        # on the host")
		fmt.Fprintln(out, "     snug -p @net <dir> -- readlink /proc/self/ns/net  # inside")
		fmt.Fprintln(out, " The two must DIFFER, and an empty answer from either side is a failed check")
		fmt.Fprintln(out, " rather than a pass: an empty string is != any real namespace id.)")
	}
}

// notGranted probes for paths a reasonable person would expect to be there and
// confirms they are absent from the grant set. This is the only advisory part
// of explain — but it is what makes deny-by-default legible rather than
// something you take on faith.
func notGranted(p *policy.Policy) []string {
	var lines []string

	candidates := []string{
		".ssh", ".gnupg", ".aws", ".config/gh", ".kube", ".docker", ".netrc",
		".claude", ".mozilla", ".local/share/keyrings",
	}
	var absent, partial []string
	for _, c := range candidates {
		full := filepath.Join(p.Home, c)
		if _, err := os.Stat(full); err != nil {
			continue // not on this host either; do not claim credit for it
		}
		cov, beneath := coverageOf(p, full)
		if cov == coverageFull {
			continue
		}
		// PARTIAL gets its own line rather than a place in the joined list. The
		// list is a run of bare names a reader skims as "none of these"; a
		// qualified entry buried in it is read as one more bare name, which is
		// the misreading issue #59 is about.
		if cov == coveragePartial {
			partial = append(partial, partialLines("~/"+c, beneath, authored(p, full))...)
			continue
		}
		// The host's copy is not granted — but if snug generates content at
		// that path, "reads as absent" is false and this block must not say it.
		// Qualified rather than deleted: suppressing the line entirely removed
		// the only sentence on the screen saying the host's ~/.ssh is not
		// mounted, leaving a reader to infer it from three `data` rows.
		if authored(p, full) {
			absent = append(absent, "~/"+c+" (host's; snug generates its own here)")
			continue
		}
		absent = append(absent, "~/"+c)
	}
	if len(absent) > 0 {
		lines = append(lines, strings.Join(absent, "  "))
	}
	lines = append(lines, partial...)

	// Siblings of the target, which is the property the parent-ro profile is
	// really about: the parent is readable, its other children are not.
	parent := filepath.Dir(p.Target)
	if entries, err := os.ReadDir(parent); err == nil {
		n, part := 0, 0
		for _, e := range entries {
			full := filepath.Join(parent, e.Name())
			if full == p.Target {
				continue
			}
			switch cov, _ := coverageOf(p, full); cov {
			case coverageFull:
			case coveragePartial:
				// Same blind spot as the candidate list, same fix: a sibling
				// with a bind strictly beneath it is not an entry that reads as
				// absent, and counting it as one overstates what is denied.
				part++
			default:
				n++
			}
		}
		if n > 0 {
			lines = append(lines, fmt.Sprintf("%d sibling entries under %s", n, parent))
		}
		if part > 0 {
			lines = append(lines, fmt.Sprintf("(%d further sibling entries under %s have "+
				"something bound BENEATH them — see FILESYSTEM)", part, parent))
		}
	}

	// The two STATIC host paths in this block now route through coverageOf like
	// every other candidate, which is issue #301's mechanical half (also #32's
	// R7 / PSEUDOFS-AUDIT.md Y5). Before this, the whole line was unconditional:
	// a run that bound the host's /tmp still printed /tmp/.X11-unix as NOT
	// GRANTED, asserting an absence with nothing behind it.
	//
	// NOT stat-gated, unlike the ~/ candidates above, and the reason is the
	// golden files. Those candidates sit under p.Home, which the golden fixtures
	// point at a directory that does not exist, so os.Stat skips them and the
	// golden is host-independent. /sys and /tmp/.X11-unix are absolute HOST
	// paths: a stat gate here would print one answer on a developer's box with a
	// display server and another on CI, which is the trap
	// TestGoldenContainers already had to sidestep for $SNUG_PODMAN — a golden
	// whose content depends on the host has a different correct value for every
	// developer. coverageOf reads only p.Mounts and is host-independent, so the
	// coverage half is safe and the existence half is not.
	//
	// The DESKTOP SOCKETS are no longer in this run of names at all — see the
	// claim appended after it. #301 asked whether to derive their paths from
	// host environment so they could be coverage-checked like everything else
	// here, and the answer is NO, ruled: the line was never a claim about two
	// host paths. It is a claim about snug's mount set, and a claim about the
	// mount set needs no host environment to be true.
	//
	// `partial` is NOT reused for these: it was appended to lines above, so a
	// later append to it would be silently dropped. Their PARTIAL lines follow
	// the joined line instead, which also reads better — the qualification sits
	// next to the run of bare names it qualifies.
	var static, staticPartial []string
	for _, c := range []string{"/sys", "/tmp/.X11-unix"} {
		cov, beneath := coverageOf(p, c)
		switch cov {
		case coverageFull:
			continue
		case coveragePartial:
			staticPartial = append(staticPartial, partialLines(c, beneath, authored(p, c))...)
			continue
		}
		static = append(static, c)
	}
	// The joined line is CONDITIONAL now, and it did not need to be before.
	// Until the desktop-socket names moved out of `static` below, two literals
	// were always appended, so the slice was never empty. It can be now — a run
	// binding the host's /sys and /tmp covers both — and joining an empty slice
	// would print a blank row under NOT GRANTED that reads as a missing entry.
	if len(static) > 0 {
		lines = append(lines, strings.Join(static, "  "))
	}
	lines = append(lines, staticPartial...)

	// The desktop-socket claim, stated as what it IS rather than left sitting in
	// the run of coverage-checked paths above, where it read as one more of them
	// (issue #301's residual).
	//
	// It is a claim about snug's MOUNT SET, not a probe of this host, and that
	// is what makes it host-independent: "snug mounts no desktop socket" is true
	// headless, true on a desktop, true on a CI runner. Deriving the paths
	// instead — $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY, and DBUS_SESSION_BUS_ADDRESS
	// which is a `unix:path=...,guid=...` string that also takes `abstract=`,
	// `tcp:` and a semicolon-separated list of alternatives — would convert a
	// true host-independent statement into a host-dependent approximation of the
	// same statement, and put a per-developer value into three golden fixtures
	// and VERIFY.md. That is the cost #320 refused when it declined to stat-gate
	// /sys and /tmp/.X11-unix, for a strictly stronger reason than this one.
	//
	// The residual is printed HERE, in plain words and without issue numbers,
	// because a human reading --dry-run has no issue tracker: a bare number
	// leads nowhere and dates the artifact. It is tracked as #292 (a grant of a
	// DIRECTORY is a grant of every socket in it) and #296 (the FIFO sibling) —
	// those numbers belong in this comment and in the test, not on the screen.
	//
	// What the claim actually rests on, none of which is a coverage check:
	// snug ships no profile naming a desktop socket, GUI/audio/D-Bus
	// passthrough being out of scope by construction; rejectEndpointSource
	// refuses a bind whose SOURCE is a socket; and the directory case is the
	// tracked, measured residual the second line states.
	lines = append(lines,
		"snug mounts no desktop socket — no Wayland, no session D-Bus.",
		"  (a claim about what snug mounts, not a probe of this host. A profile granting",
		"   the directory one of these sockets sits in would make it false, and nothing",
		"   here would notice.)")
	return lines
}

// authored reports whether snug generates content AT or BELOW a guest path.
//
// `covered` answers "is the HOST's copy reachable", which is the right question
// for a bind and the wrong one on its own for the NOT GRANTED block, whose
// claim is "these read as ABSENT". Both were true of `~/.config/gh` until
// identity staged a generated `hosts.yml` there — and then the same screen
// printed a `data ~/.config/gh/hosts.yml` row six lines above a line promising
// the directory was never mounted. The host's gh config is still not granted,
// which is why the mount is not a hole; the sentence was simply false, and this
// block is the artifact a human is supposed to be able to trust.
//
// Guest paths, not host paths: a generated file has no host side.
//
// Keyed on Mount.Authored, NOT on `Kind == KindData`. types.go records why that
// field exists: the KindData spelling is a PROXY for "snug wrote this" that had
// already drifted once, and a future TOML key producing KindData would inherit
// every exemption written against it. It also under-reports today — a socket
// staged by BindSocket is authored and is not KindData.
func authored(p *policy.Policy, guest string) bool {
	for _, m := range p.Mounts {
		if !m.Authored {
			continue
		}
		if guest == m.Guest || strings.HasPrefix(m.Guest, guest+"/") {
			return true
		}
	}
	return false
}

// covered reports whether a host path is reachable through some grant.
// coverage is how much of a candidate host path the grant set reaches. The
// distinction exists because `covered` used to walk UPWARD only —
//
//	host == m.Host || strings.HasPrefix(host, m.Host+"/")
//
// so a mount BENEATH a candidate never marked that candidate covered. `~/.claude`
// has no mount at or above it, so NOT GRANTED said it reads as absent, twelve
// rows below a FILESYSTEM block binding `~/.claude/plugins` and
// `~/.claude/settings.json` read-only (issue #59). Both statements were true
// about different things; together they read as a false one, on the screen
// CLAUDE.md calls the mechanism by which a human can trust snug at all.
//
// Three states rather than a wider `covered`, because "some of it is bound" is
// neither "granted" nor "absent" and saying either is a lie in one direction.
// Full wins over partial: a bind at or above the candidate reaches everything
// beneath it anyway.
type coverage int

const (
	coverageNone    coverage = iota // no bind at, above or below it
	coveragePartial                 // a bind lies strictly BENEATH it
	coverageFull                    // a bind lies AT or ABOVE it
)

func coverageOf(p *policy.Policy, host string) (coverage, int) {
	beneath := 0
	for _, m := range p.Mounts {
		if m.Kind != policy.KindBind {
			continue
		}
		if host == m.Host || strings.HasPrefix(host, m.Host+"/") {
			return coverageFull, 0
		}
		if strings.HasPrefix(m.Host, host+"/") {
			beneath++
		}
	}
	if beneath > 0 {
		return coveragePartial, beneath
	}
	return coverageNone, 0
}

func covered(p *policy.Policy, host string) bool {
	c, _ := coverageOf(p, host)
	return c == coverageFull
}

// formatArgs renders the argv block. argv0 is the producer's word (see
// reportExec) rather than a literal here, so this screen and the JSON document
// cannot name the binary differently.
func formatArgs(argv0 string, args []string) string {
	var b strings.Builder
	b.WriteString(argv0)
	for _, a := range args {
		if strings.HasPrefix(a, "--") || a == "--" {
			b.WriteString("\n  ")
		} else {
			b.WriteString(" ")
		}
		// visibleValue, for the same reason the ENVIRONMENT block uses it and
		// with a sharper consequence: this block starts every element that
		// begins with "--" on its own line, so a newline INSIDE an element is
		// indistinguishable from the start of a new flag. A host EDITOR of
		//
		//	vim\n  --ro-bind /home/u/.ssh /home/u/.ssh
		//
		// rendered, through @claude's shipped `inherit EDITOR`, as a --ro-bind
		// line in the argv block of a policy that has no such mount — no profile
		// file required. The ENVIRONMENT block on the SAME screen escaped the
		// same string correctly, which is exactly the failure mode its own
		// comment warns about: a fix at one site looks identical to a fix at all
		// of them.
		b.WriteString(visibleValue(a))
	}
	return b.String()
}

// describeArgv0 prints the one fact the argv block above it cannot carry: the
// word at index 0 is not the binary. The sentence is reportExec's, wrapped
// here and emitted verbatim in the JSON document, so the two renderers state
// one answer — the arrangement grantMark/envGrantVerdict already uses.
//
// argv0NoteWidth is 78 minus this block's two-space indent, the width the rest
// of the screen's wrapped prose uses.
func describeArgv0(out io.Writer, ex reportExec) {
	lines := wrapWords(ex.Note, argv0NoteWidth)
	for i, line := range lines {
		open, close := " ", ""
		if i == 0 {
			open = "("
		}
		if i == len(lines)-1 {
			close = ")"
		}
		fmt.Fprintf(out, "%s%s%s\n", open, line, close)
	}
}

// argv0NoteWidth is 78 minus the one column the "(" / " " prefix takes. The
// parenthesised shape is describeBwrap's own, and it is NOT the two-space
// indent this note first shipped with: the argv block indents every flag by
// two, so a two-space note directly beneath it reads as more argv.
const argv0NoteWidth = 78 - 1

// claudeCredentialsMount finds the staged ~/.claude/.credentials.json, which
// stageClaudeCredentials writes only when the host's file both exists and
// projects. Its ABSENCE is a fact --dry-run states rather than omits: "no
// credential is staged" and "a credential is staged" are different runs, and a
// human reading this screen is entitled to know which one they are about to
// start.
// The lookup is claudeSettingsMount's, verbatim in shape, and it was NOT that
// on first writing — the first version keyed on `m.Guest == want && m.Kind ==
// KindData` with neither an Authored check nor a fallback, four hundred lines
// below the sibling whose own comment states the measured hazard. A red-team
// pass found it, and the failure is the worst direction a trust screen can
// fail in: on a host whose $HOME is a symlink (the default on Silverblue- and
// MicroOS-shaped systems, /home -> /var/home), the screen printed "creds NOT
// staged ... Claude Code will start LOGGED OUT" while the SAME screen's mount
// table and bwrap argv showed the access token being handed over.
//
// Both guards therefore matter here, for the reasons their originals give:
// Resolve canonicalises $HOME while claudeFiles is handed main.go's raw
// os.UserHomeDir() value, so the exact-match key can miss; and `Authored`
// rather than `Kind == KindData` alone, because authored()'s own comment
// records that the KindData spelling is a PROXY for "snug wrote this" that has
// already drifted once.
func claudeCredentialsMount(p *policy.Policy) (policy.Mount, bool) {
	if m, ok := p.Mounts[filepath.Join(p.Home, ".claude", ".credentials.json")]; ok {
		return m, m.Authored && m.Kind == policy.KindData
	}
	for _, m := range p.Mounts {
		if m.Authored && m.Kind == policy.KindData &&
			filepath.Base(m.Guest) == ".credentials.json" &&
			filepath.Base(filepath.Dir(m.Guest)) == ".claude" {
			return m, true
		}
	}
	return policy.Mount{}, false
}

// claudeCredentialNames renders policy.ClaudeCredentialAllowlist for the
// screen. Derived from the allowlist rather than written out beside it, so a
// field added there cannot fail to appear here — the copy-of-state-held-
// elsewhere problem CLAUDE.md names about counts in prose.
func claudeCredentialNames() []string {
	names := make([]string, 0, len(policy.ClaudeCredentialAllowlist))
	for _, k := range policy.ClaudeCredentialAllowlist {
		names = append(names, k.Name)
	}
	return names
}

// claudeCredentialExpiry reads the expiry back out of the content snug already
// STAGED, never from a second read of the host — the same rule
// claudeSettingsCarriedNames follows: this screen describes what was decided,
// and a second opinion computed here could disagree with the file the sandbox
// gets.
//
// It renders the host's own value and computes no policy from it. An absent or
// unparseable expiry prints no line rather than a wrong one.
func claudeCredentialExpiry(m policy.Mount, now time.Time) (string, bool) {
	var envelope struct {
		OAuth struct {
			ExpiresAt int64 `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal([]byte(m.Content), &envelope); err != nil {
		return "", false
	}
	ms := envelope.OAuth.ExpiresAt
	if ms <= 0 {
		return "", false
	}
	at := time.UnixMilli(ms).UTC()
	left := at.Sub(now).Round(time.Minute)
	if left <= 0 {
		return at.Format(time.RFC3339) + " (ALREADY EXPIRED — run `claude` on the host)", true
	}
	return fmt.Sprintf("%s (in %dh%02dm)", at.Format(time.RFC3339),
		int(left.Hours()), int(left.Minutes())%60), true
}

// screenNow is the clock --dry-run reads, and it is a variable for ONE reason:
// the CLAUDE block now renders a duration, and a golden file containing "in
// 4h36m" would differ on every run. The golden test pins it; nothing else may.
//
// Deliberately not threaded through describeClaude's signature: the seam exists
// for a test, and widening a rendering function's parameters to advertise that
// would put the test's needs in the screen's API.
var screenNow = func() time.Time { return time.Now() }

// partialLine says what is bound and what is not, in that order. "Granted" would
// be a lie in the other direction — most of the tree is genuinely absent — and
// the word the row needs is one that is true for "some of it" (issue #59).
func partialLines(name string, beneath int, generated bool) []string {
	what, verb := "path", "is"
	if beneath != 1 {
		what, verb = "paths", "are"
	}
	head := fmt.Sprintf("%s  PARTIAL — %d host %s beneath it %s bound (see FILESYSTEM)",
		name, beneath, what, verb)
	tail := "the rest of it is not granted"
	if generated {
		tail += ", and snug generates its own content here"
	}
	// Two lines rather than one. The block prints each line at a fixed indent
	// with no wrapping of its own, and the single-line form ran past 150
	// columns — where a terminal breaks it mid-clause, in the middle of the
	// sentence that says what is NOT granted.
	return []string{head, "  " + tail}
}

// yieldedMark says when a profile has taken over one of the three paths snug
// would otherwise author itself — /proc, /dev and /tmp — and returns "" for
// every other row.
//
// WHY (issue #223). yieldTo() installs snug's own mount only if nothing already
// claims that guest path, and that is deliberate: it is how @tmp-shared works.
// What is NOT deliberate is @parent-ro reaching /tmp by accident of where the
// target sits. `snug /tmp/proj` makes the target's parent /tmp, so the private
// tmpfs never lands and the sandbox runs with the HOST's /tmp read-only, with
// TMPDIR pointing into it — no refusal, and nothing on screen saying so.
//
// Two things stop being true for that run, and the first is a documented count:
// CLAUDE.md says the writable surface is EIGHT paths with /tmp among them, and
// here it is seven. A user believing a guarantee that no longer holds is
// invariant 5's whole subject, and the guarantee changed silently.
//
// This says it rather than refusing it, which was a deliberate call: `snug
// /tmp/x` is ordinary — `mktemp -d` targets are how VERIFY.md and the whole
// integration suite build theirs — so a refusal would break snug's own workflow
// unless it could distinguish "the yield was asked for" from "the yield happened
// by accident", and this layer cannot. --dry-run being honest is the mechanism
// the project already relies on.
//
// Mount.Authored is what makes this cheap: yieldTo() sets it on snug's own
// mounts, so a row at one of these paths WITHOUT it is a profile that took over.
func yieldedMark(p *policy.Policy, m policy.Mount) string {
	if m.Authored {
		return ""
	}
	switch m.Guest {
	case "/tmp":
		note := "  ← this is the HOST's /tmp, not snug's private one — a profile claimed the " +
			"path, so the tmpfs snug would have put here never landed. $TMPDIR points inside it"
		if m.Access != policy.AccessRW {
			note += ", READ-ONLY, which most tooling breaks on"
		}
		return note
	case "/proc", "/dev":
		return fmt.Sprintf("  ← a profile claimed %s, so snug's own %s was not installed here",
			m.Guest, m.Guest)
	}
	return ""
}
