package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
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
func dryRun(p *policy.Policy, args []string, cfg config, refusedBy error) {
	out := os.Stdout
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
	describeContainers(out, p)
	describeGit(out, p)
	describeSSH(out, p)
	describeCommands(out, p)
	describeClaude(out, p)
	if p.NewSession {
		fmt.Fprintf(out, "TTY      --new-session (this kernel allows TIOCSTI, so the sandbox is kept\n")
		fmt.Fprintf(out, "         out of your terminal — the cost is no job control inside)\n")
	} else {
		fmt.Fprintf(out, "TTY      shared session — job control works (TIOCSTI is disabled kernel-wide)\n")
	}
	describeSeccomp(out, cfg)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "FILESYSTEM  (deny-by-default; every line is a grant, there are no deny rules)")
	for _, m := range p.SortedMounts() {
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
		}
		fmt.Fprintf(out, "  %-6s %-46s %s%s\n", kind, detail, visibleValue(strings.Join(m.From, "+")), opt)
	}
	fmt.Fprintf(out, "  %-6s %s\n", "ro-/", "everything else is a read-only skeleton (--remount-ro /)")

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  NOT GRANTED (never mounted — these read as absent, they are not hidden;")
	fmt.Fprintln(out, "  where it says \"host's\", snug generates its own file at that path instead):")
	for _, line := range notGranted(p) {
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
		if p.Topology.Netns == policy.NetnsStage {
			fmt.Fprintln(out, "pasta "+strings.Join(p.PastaArgs(policy.PastaTargetStage(0, 63)), " "))
			fmt.Fprintln(out, "  (/proc/0/fd/63 is a placeholder; the real pid is the stage's, "+
				"and 63 is fdNetnsN)")
		} else {
			fmt.Fprintln(out, "pasta "+strings.Join(p.PastaArgs(policy.PastaTargetChild(0)), " "))
			fmt.Fprintln(out, "  (/proc/0/... is a placeholder; the real pid is bwrap's child)")
		}
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
func describeSeccomp(out *os.File, cfg config) {
	// DeniedSyscallNames panics if internal/sandbox's own name table has
	// fallen behind deniedSyscalls — see its doc comment. That is deliberate:
	// failing this dry run loudly beats rendering a screen that no longer
	// matches the filter.
	names := sandbox.DeniedSyscallNames()
	listLines := wrapList(names, 64)

	if cfg.noSeccomp {
		fmt.Fprintln(out, "SECCOMP  DISABLED (--no-seccomp) — every syscall below runs UNFILTERED:")
		for _, l := range listLines {
			fmt.Fprintf(out, "           %s\n", l)
		}
		fmt.Fprintln(out, "         — plus clone3 (ENOSYS), ioctl(_, TIOCSTI, _), and")
		fmt.Fprintln(out, "         clone/unshare(CLONE_NEWUSER). The namespace boundary is")
		fmt.Fprintln(out, "         unaffected; this is defence in depth, not the boundary.")
		return
	}

	// BuildFilter is pure (no OS calls beyond reading runtime.GOARCH), so this
	// is safe to call from a dry run that starts nothing. It is the same
	// function sandbox.Run calls to build the real filter, so this line cannot
	// disagree with what actually gets installed — no second copy of "which
	// architectures are supported" to drift out of sync.
	prog, ok, err := sandbox.BuildFilter()
	if err != nil {
		// An ASSEMBLY failure, not an unsupported architecture: BuildFilter
		// returns (nil, false, err) only when asm.offset's jump-range check
		// trips, on a host whose GOARCH is otherwise fully supported. This is
		// the exact message sandbox.Run's warn would print at run time — show
		// it here rather than the "no syscall table" sentence below, which
		// would name the wrong fix (there is nothing to fix on this host; the
		// bug is in snug's own filter construction).
		fmt.Fprintf(out, "SECCOMP  BROKEN — %v\n", err)
		fmt.Fprintln(out, "         This is a bug in snug's filter assembly, not a property of this")
		fmt.Fprintln(out, "         host. sandbox.Run will warn and continue WITHOUT the filter. The")
		fmt.Fprintln(out, "         namespace boundary is unaffected; this filter is defence in depth,")
		fmt.Fprintln(out, "         not the boundary.")
		return
	}
	if !ok {
		fmt.Fprintf(out, "SECCOMP  UNAVAILABLE for GOARCH=%s (no syscall table) — sandbox.Run will\n", runtime.GOARCH)
		fmt.Fprintln(out, "         warn and continue WITHOUT it. The namespace boundary is unaffected;")
		fmt.Fprintln(out, "         this filter is defence in depth, not the boundary.")
		return
	}
	_ = prog // only the length/validity matters here; the argv carries the bytes

	fmt.Fprintln(out, "SECCOMP  active — denies (EPERM), derived from deniedSyscalls in")
	fmt.Fprintln(out, "         internal/sandbox/seccomp.go:")
	for _, l := range listLines {
		fmt.Fprintf(out, "           %s\n", l)
	}
	fmt.Fprintln(out, "         — plus clone3 (ENOSYS), ioctl(_, TIOCSTI, _), and")
	fmt.Fprintln(out, "         clone/unshare(CLONE_NEWUSER).")
	if runtime.GOARCH == "amd64" {
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
func describeEnvironment(out *os.File, p *policy.Policy) {
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
func describeBwrapAuthoredEnv(out *os.File, p *policy.Policy) {
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
	if !strings.HasPrefix(value, "/") {
		return ""
	}
	if name == "PATH" && p.IsShadowSlot(value) {
		return "  ← writable from inside"
	}
	if p.GrantsGuestPath(value) {
		return ""
	}
	inside := 0
	for _, m := range p.Mounts {
		if strings.HasPrefix(m.Guest, value+"/") {
			inside++
		}
	}
	switch inside {
	case 0:
		return "  ← not granted"
	case 1:
		return "  ← not granted (1 grant inside)"
	}
	return fmt.Sprintf("  ← not granted (%d grants inside)", inside)
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

// describeContainers states where a container's network comes from, because
// today it is NOT the sandbox's and the NETWORK block immediately above is
// therefore not the whole story.
//
// This exists because of the engine-netns finding
// (.claude/design/ENGINE-NETNS.md §0): `@podman-socket` granted full egress through a
// container while `--dry-run` printed "No egress. No host loopback." The
// profile now includes `net`, so the NETWORK block is no longer false — but a
// reader still has to be told that the container and the sandbox get their
// network from two different places, or they will read the pasta guarantees
// above as covering containers. They do not.
func describeContainers(out *os.File, p *policy.Policy) {
	if p.Podman == policy.PodmanOff {
		return
	}
	fmt.Fprintf(out, "CONTAINERS  a per-sandbox engine behind a filtering proxy at %s\n",
		containerSocketGuest)
	fmt.Fprintf(out, "         INTERIM: a container runs in the ENGINE's netns, not this sandbox's,\n")
	fmt.Fprintf(out, "         so it has the engine's network — which is why this profile includes\n")
	fmt.Fprintf(out, "         '@net' rather than pretending to be offline. The pasta\n")
	fmt.Fprintf(out, "         guarantees above cover the SANDBOX; they do not cover containers.\n")
	fmt.Fprintf(out, "         Consequence: '@podman-socket' cannot currently be offline, and\n")
	fmt.Fprintf(out, "         'podman run -p N:80' is not reachable from the sandbox.\n")
	fmt.Fprintf(out, "         Planned fix: engine inside the sandbox's netns, after which the\n")
	fmt.Fprintf(out, "         '@net' include goes away and both lines above stop being true.\n")
	fmt.Fprintf(out, "         Design and feasibility: .claude/design/ENGINE-NETNS.md\n")
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
func describeGit(out *os.File, p *policy.Policy) {
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
// It walks policy.SystemSSHConfigPaths and reads p.Mounts rather than
// re-deriving the coverage predicate: the screen must describe what
// Resolve actually decided, not recompute a second opinion that could
// disagree with it. A host with neither spelling present gets nothing here,
// silently and correctly — the same as a host with no [identity] getting
// nothing from describeGit.
//
// The PATH line is per replaced mount — a host can have both spellings
// covered at once (openSUSE's /usr/etc/ssh plus a human profile binding
// /etc) and each is a distinct fact the reader needs. The mechanism and
// cost paragraph is the same explanation regardless of which path it is, so
// it is printed ONCE, after the loop, gated on whether anything matched —
// not once per path, which would repeat six identical lines for a
// coincidence of two paths sharing one cause.
func describeSSH(out *os.File, p *policy.Policy) {
	var replaced []string
	for _, guest := range policy.SystemSSHConfigPaths {
		m, ok := p.Mounts[guest]
		if !ok || !m.Authored || m.Kind != policy.KindData {
			continue
		}
		replaced = append(replaced, guest)
	}
	if len(replaced) == 0 {
		return
	}
	for _, guest := range replaced {
		fmt.Fprintf(out, "SSH      system-wide ssh_config REPLACED at %s\n", guest)
	}
	fmt.Fprintf(out, "         the host's is root-owned and reads as 65534 inside (one uid is\n")
	fmt.Fprintf(out, "         mapped); OpenSSH refuses such a file, so ssh, git-over-ssh, scp\n")
	fmt.Fprintf(out, "         and rsync -e ssh all die without this\n")
	fmt.Fprintf(out, "         cost       the host's system-wide defaults do not apply — on a\n")
	fmt.Fprintf(out, "                    crypto-policy distro that is the policy's algorithm\n")
	fmt.Fprintf(out, "                    lists and RequiredRSASize (2048 -> OpenSSH's 1024)\n")
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
func describeCommands(out *os.File, p *policy.Policy) {
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
	// `PATH  /run/snug/bin  (snug) staged bin  ← writable from inside`. Validate
	// refuses that arrangement outright — at the directory since the tmpfs-at-it
	// finding, and at any ANCESTOR of it since issue #22.
	//
	// THIS BRANCH IS STILL REACHED, and an earlier version of this comment
	// guessed otherwise ("should be unreachable"). Measured: under --dry-run,
	// main.go renders the whole policy AND THEN prints the Validate error, so a
	// refused `tmpfs = ["/run"]` + @podman-socket selection prints these three
	// lines above its own refusal. That is the diagnostic doing its job — it is
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
func describeClaude(out *os.File, p *policy.Policy) {
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
	}
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
func claudeSettingsCarriedNames(m policy.Mount) []string {
	var doc map[string]any
	if err := json.Unmarshal([]byte(m.Content), &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc))
	for k := range doc {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// describeNetwork spells out what the sandbox can and cannot reach. The
// negative half matters more than the positive half and is stated first.
func describeNetwork(out *os.File, p *policy.Policy) {
	switch p.Net.Mode {
	case policy.NetIsolated:
		fmt.Fprintf(out, "NETWORK  isolated — private netns, loopback only, no helper process.\n")
		fmt.Fprintf(out, "         No egress. No host loopback. No abstract sockets (X11/D-Bus are\n")
		fmt.Fprintf(out, "         netns-scoped, so they are out too). Add the '@net' profile for egress.\n")
	case policy.NetEgress:
		fmt.Fprintf(out, "NETWORK  egress — private netns (one per sandbox) with a pasta helper.\n")
		fmt.Fprintf(out, "         host loopback   UNREACHABLE (--map-host-loopback none, -T none, -U none)\n")
		fmt.Fprintf(out, "         abstract unix   UNREACHABLE (netns-scoped: X11, D-Bus)\n")
		fmt.Fprintf(out, "         egress          full, IPv4 + IPv6\n")
		if p.Net.DNS {
			fmt.Fprintf(out, "         dns             169.254.1.1 -> pasta -> host resolver\n")
		}
		if len(p.Net.Publish) > 0 {
			fmt.Fprintf(out, "         host -> sandbox ports %v, on the host's 127.0.0.1 only\n", p.Net.Publish)
		} else {
			fmt.Fprintf(out, "         host -> sandbox CLOSED (publish = [3000] in a profile opens one)\n")
		}
		if p.Net.Address != "" {
			fmt.Fprintf(out, "         address         %s (synthetic; the host's LAN address is hidden)\n", p.Net.Address)
		} else {
			fmt.Fprintf(out, "         address         copied from the host — add '@net-anon' to hide it\n")
		}
	case policy.NetHost:
		fmt.Fprintf(out, "NETWORK  HOST — the sandbox SHARES your network namespace.\n")
		fmt.Fprintf(out, "         Every 127.0.0.1 service, every abstract socket (X11 keylogging and\n")
		fmt.Fprintf(out, "         screenshots included), and the LAN as you. Requires --i-know.\n")
	}
}

// describeTopology is not a debugging convenience either — it is the one place
// a human learns that snug started a SECOND long-lived process ahead of the
// sandbox, what that process holds, and when it dies. "No daemon, no service
// files" is a claim the README already makes; a process that outlives the
// command belongs on screen with its lifetime rule, printed always — including
// the one-process case, where saying so plainly is the point (Phase 1 adds no
// user-visible capability, and this block is how that claim stays checkable
// rather than merely asserted).
func describeTopology(out *os.File, p *policy.Policy) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "TOPOLOGY")
	// One denominator, counted the same way in both arms: every long-lived
	// process snug will run, snug itself included. The two arms used to count
	// differently — "1 — bwrap only" excluded snug, "2 — snug, and a stage"
	// excluded bwrap, and neither mentioned pasta — so the one line a human
	// reads to answer "how many processes" was wrong under either reading.
	if !p.Topology.NeedsStage() {
		fmt.Fprintf(out, "  processes       2 — snug and bwrap. No stage, no privileged ancestor namespace.\n")
	} else {
		fmt.Fprintf(out, "  processes       4 — snug, a stage (P1) that creates the sandbox's network\n")
		fmt.Fprintf(out, "                  namespace, pasta attached to that namespace, and bwrap, which\n")
		fmt.Fprintf(out, "                  the stage forks back into it. (A fifth, __innetns, is the\n")
		fmt.Fprintf(out, "                  setns shim that becomes bwrap; it never coexists with it.)\n")
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
// 0.11.2: --unshare-all yields a netns id different from the host's,
// --unshare-all --share-net yields the host's exactly.
func describeBwrap(out *os.File, p *policy.Policy, args []string, refusedBy error) {
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
	case policy.NetnsHost:
		fmt.Fprintln(out, "(this argv determines the network posture on its own: --share-net keeps the")
		fmt.Fprintln(out, " network namespace of whatever starts bwrap, and snug starts it directly, so")
		fmt.Fprintln(out, " running it by hand reproduces the HOST networking described above.)")
	default:
		fmt.Fprintln(out, "(this argv determines the network posture on its own: --unshare-net creates")
		fmt.Fprintln(out, " the sandbox's own empty network namespace, so running it by hand reproduces")
		fmt.Fprintln(out, " it.)")
	}
	fmt.Fprintln(out, formatArgs(args))
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
	var absent []string
	for _, c := range candidates {
		full := filepath.Join(p.Home, c)
		if _, err := os.Stat(full); err != nil {
			continue // not on this host either; do not claim credit for it
		}
		if covered(p, full) {
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

	// Siblings of the target, which is the property the parent-ro profile is
	// really about: the parent is readable, its other children are not.
	parent := filepath.Dir(p.Target)
	if entries, err := os.ReadDir(parent); err == nil {
		n := 0
		for _, e := range entries {
			full := filepath.Join(parent, e.Name())
			if full != p.Target && !covered(p, full) {
				n++
			}
		}
		if n > 0 {
			lines = append(lines, fmt.Sprintf("%d sibling entries under %s", n, parent))
		}
	}

	lines = append(lines, "/sys  /tmp/.X11-unix  the Wayland socket  the session D-Bus socket")
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
func covered(p *policy.Policy, host string) bool {
	for _, m := range p.Mounts {
		if m.Kind != policy.KindBind {
			continue
		}
		if host == m.Host || strings.HasPrefix(host, m.Host+"/") {
			return true
		}
	}
	return false
}

func formatArgs(args []string) string {
	var b strings.Builder
	b.WriteString("bwrap")
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
