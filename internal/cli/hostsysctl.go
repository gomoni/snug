package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// hostsysctl.go is issue #526 (R5 of .claude/design/PSEUDOFS-AUDIT.md): the
// kernel hardening snug's threat model INHERITS from the host and, until
// this file, never read.
//
// Invariant 5 is "no silent downgrade". Every other application of it is
// about a capability snug itself provides — if the netns cannot be created,
// snug refuses rather than running without one. These five knobs are the
// same guarantee coming from OUTSIDE: snug's seccomp filter denies bpf(2)
// and perf_event_open(2), and the sandbox's /proc/kallsyms is only harmless
// because the HOST zeroed it. On a host where those knobs are off, the
// sandbox is weaker than every document here describes, and nothing said so.
//
// REPORT, never refuse (the ticket's own scope, and it is the right call):
// key feature 3 says snug must work inside a container, and a container is
// exactly where these are least likely to be set — /proc/sys is read-only
// there and the values belong to the host anyway. Refusing would make snug
// unusable on the hosts the audit was written about. Disclosure is what
// invariant 5 asks for here, so `snug doctor` reads them and `snug fix
// sysctl` prints the settings that would close the gap.
//
// ptrace_scope is in the table but is NOT this file's rule: container
// preflight P6 (containerpreflight.go) REFUSES a container run at 0, and
// that refusal reads its threshold from the row below, so the report and the
// refusal cannot drift into disagreeing about the number.

// hostSysctl is one inherited knob.
//
// `want` is a MINIMUM and the direction is checked, not assumed: for all
// five, a larger value is at least as strict as `want` for the property snug
// depends on. The one that repays saying out loud is
// unprivileged_bpf_disabled, where the ordering is not simply "higher is
// stricter" — 1 disables unprivileged bpf(2) irreversibly until reboot and 2
// disables it while leaving it re-enablable by a privileged process. Both
// refuse the payload's bpf(2), which is the property here, so `>= 1` is the
// right test for what snug depends on and 1 is what the fix writes.
type hostSysctl struct {
	knob string // sysctl(8) spelling, e.g. "kernel.kptr_restrict"
	want int

	// what tells a human what the weak setting costs THEM, from inside the
	// sandbox, and every clause of it is traceable to a measurement in this
	// repo rather than to general hardening advice.
	what string

	// enforcedBy names the code that already refuses on this knob, empty
	// when nothing does. A row with it set is reported as enforced elsewhere
	// rather than as a fresh discovery, which is the ticket's "doctor should
	// say so rather than re-implement it".
	enforcedBy string
}

// inheritedSysctls is the audit's list, in the order doctor prints them.
var inheritedSysctls = []hostSysctl{
	{
		knob: "kernel.kptr_restrict", want: 1,
		what: "the sandbox's /proc/kallsyms and /proc/modules carry REAL kernel " +
			"symbol addresses — a KASLR base leak snug does not mask (audit P4). At 1 " +
			"they read as zeros for the payload.",
	},
	{
		knob: "kernel.dmesg_restrict", want: 1,
		what: "the payload can read the kernel ring buffer. syslog(2) is not in " +
			"snug's seccomp denial set, and this knob is the only thing that refuses it.",
	},
	{
		knob: "kernel.perf_event_paranoid", want: 2,
		what: "unprivileged perf_event_open(2) is permitted kernel-wide. snug's " +
			"seccomp filter denies that syscall, so this is the lock BEHIND the filter — " +
			"what remains on the one path snug warns about instead of refusing (--no-seccomp, " +
			"or a kernel that will not take the filter).",
	},
	{
		knob: "kernel.yama.ptrace_scope", want: 1,
		what: "any same-uid process can ptrace any other. ptrace(2) and " +
			"process_vm_readv/writev are seccomp-denied, but /proc/<pid>/mem is the same " +
			"effect through open(2)+pread/pwrite(2) and no classic-BPF filter can single it " +
			"out; Yama is its second lock (issue #47, seccomp.go's own measurement).",
		enforcedBy: "container preflight P6 refuses a container run at 0",
	},
	{
		knob: "kernel.unprivileged_bpf_disabled", want: 1,
		what: "an unprivileged process may load BPF programs. snug's seccomp " +
			"filter denies bpf(2), so this is again the lock behind the filter rather than " +
			"the only one. 2 also refuses the payload's bpf(2); 1 additionally cannot be " +
			"turned back on without a reboot.",
	},
}

// path is where the knob is read, and the mapping is sysctl(8)'s own: dots
// become slashes under /proc/sys. Written once here so no caller spells a
// /proc path by hand and gets kernel/yama/ptrace_scope subtly wrong.
func (s hostSysctl) path() string {
	return "/proc/sys/" + strings.ReplaceAll(s.knob, ".", "/")
}

// sysctlReading is one row's answer on this host. An unreadable knob is its
// own outcome and is NEVER folded into "weak": kernel.yama.ptrace_scope does
// not exist without the Yama LSM, and unprivileged_bpf_disabled is absent on
// kernels built without BPF — reporting either as "0, fix it" would name a
// sysctl the machine will refuse to set.
type sysctlReading struct {
	sysctl hostSysctl
	value  int
	err    error
}

func (r sysctlReading) readable() bool { return r.err == nil }

// ok is the whole rule: readable, and at least as strict as want.
func (r sysctlReading) ok() bool { return r.err == nil && r.value >= r.sysctl.want }

// readHostSysctls reads every row through the injected reader, which is what
// lets the report and the fix command be tested against a host that is not
// the one running the test — doctorsubuid.go's lesson, where the first
// version read os.Getuid() from inside the printer and its test asserted
// whatever machine ran it.
func readHostSysctls(read func(path string) (string, error)) []sysctlReading {
	out := make([]sysctlReading, 0, len(inheritedSysctls))
	for _, s := range inheritedSysctls {
		r := sysctlReading{sysctl: s}
		raw, err := read(s.path())
		switch {
		case err != nil:
			r.err = err
		default:
			n, cerr := strconv.Atoi(strings.TrimSpace(raw))
			if cerr != nil {
				r.err = fmt.Errorf("%s does not hold a number: %q", s.path(), strings.TrimSpace(raw))
			} else {
				r.value = n
			}
		}
		out = append(out, r)
	}
	return out
}

// readProcSysFile is the host reader readHostSysctls takes in production.
func readProcSysFile(path string) (string, error) {
	// HOSTREAD-EXEMPT: path is always one of inheritedSysctls' own
	// /proc/sys literals, joined by hostSysctl.path from a constant table —
	// a kernel pseudo-file, on a filesystem no host path snug reads can be
	// swapped for, the same exemption usernsSysctlsPermissive states one
	// file over.
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// reportHostSysctls is doctor's block. WARN only — it does not touch
// doctor's ok, for the reason at the top of this file.
func reportHostSysctls(readings []sysctlReading) {
	weak := 0
	unreadable := 0
	for _, r := range readings {
		if !r.readable() {
			unreadable++
			continue
		}
		if !r.ok() {
			weak++
		}
	}

	if weak == 0 && unreadable == 0 {
		fmt.Printf("  ✅ the %d kernel knobs snug's threat model inherits from this host are set\n",
			len(readings))
		return
	}

	// The headline distinguishes the two, because they need different things
	// from the reader: a weak knob is a decision they can make, an
	// unreadable one is a kernel that does not have it and nothing to do.
	if weak == 0 {
		fmt.Printf("  ⚠️  %d of the %d kernel knobs snug's threat model inherits could not be read here\n",
			unreadable, len(readings))
	} else {
		fmt.Println("  ⚠️  this host does not set every kernel knob snug's threat model inherits")
	}
	fmt.Println("     ℹ️  snug does not provide these and cannot: they are the host's, and the")
	fmt.Println("        sandbox is weaker than the design describes where they are off")
	for _, r := range readings {
		switch {
		case !r.readable():
			// Absent is not weak. Say which it is.
			fmt.Printf("     ❔ %s — not readable: %v\n", r.sysctl.knob, r.err)
		case r.ok():
			fmt.Printf("     ✅ %s = %d\n", r.sysctl.knob, r.value)
		default:
			fmt.Printf("     ⚠️  %s = %d, want %d or stricter\n", r.sysctl.knob, r.value, r.sysctl.want)
			fmt.Printf("        💬 %s\n", r.sysctl.what)
			if r.sysctl.enforcedBy != "" {
				fmt.Printf("        🛡️  %s\n", r.sysctl.enforcedBy)
			}
		}
	}
	if weak > 0 {
		fmt.Println("     🔧 `snug fix sysctl` prints what this host is missing and changes nothing;")
		fmt.Println("        `sudo snug fix sysctl -w` applies it and makes it survive a reboot")
	}
}

// inheritedSysctl returns the row for a knob and PANICS when there is none,
// for the reason sandbox.DeniedSyscallNames panics: the callers are
// hard-coded knob names in this package, and the failure this guards is a
// row RENAMED or dropped while a caller goes on reading its own idea of the
// threshold. A panic fails at test time — every caller has a test — instead
// of shipping a refusal and a report that quietly stopped meaning the same
// thing.
func inheritedSysctl(knob string) hostSysctl {
	for _, s := range inheritedSysctls {
		if s.knob == knob {
			return s
		}
	}
	panic("cli: no inherited sysctl named " + knob)
}
