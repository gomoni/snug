package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/hostread"
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
		enforcedBy: "container preflight P6 refuses a container run at anything weaker",
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

// sysctlFault is WHY a row has no usable value, and the three are not one
// state: "this kernel does not have the knob", "the knob is there and could
// not be read", and "it was read and holds something that is not a number"
// send a reader to three different places. A redteam round found all three
// printed as the single word "not readable".
type sysctlFault int

const (
	sysctlReadable   sysctlFault = iota // a number was read
	sysctlAbsent                        // ENOENT: this kernel has no such knob
	sysctlUnreadable                    // present, and the read failed
	sysctlNotANumber                    // read, and the content is not one
)

// sysctlReading is one row's answer on this host. A faulted knob is its own
// outcome and is NEVER folded into "weak": kernel.yama.ptrace_scope does not
// exist without the Yama LSM, and unprivileged_bpf_disabled is absent on
// kernels built without BPF — reporting either as "0, fix it" would name a
// sysctl the machine will refuse to set.
type sysctlReading struct {
	sysctl hostSysctl
	value  int
	raw    string // what the file held, for the not-a-number arm only
	fault  sysctlFault
	err    error
}

func (r sysctlReading) readable() bool { return r.fault == sysctlReadable }

// ok is the whole rule: readable, and at least as strict as want.
func (r sysctlReading) ok() bool { return r.readable() && r.value >= r.sysctl.want }

// desired is what the PERSISTENT file should carry for this row, and it is
// deliberately not `want`.
//
// A drop-in derived from the weak rows alone is a file that lowers hardening:
// a host running kptr_restrict=2 whose knob snug persists at 1 is weaker
// after the next boot than before the fix, because of the file written to
// harden it. max() makes the drop-in a FLOOR — it can never set a knob below
// what this kernel is already doing.
func (r sysctlReading) desired() int {
	if r.value > r.sysctl.want {
		return r.value
	}
	return r.sysctl.want
}

// fault renders the three not-a-value states as a clause with no subject, so
// the caller supplies "kernel.foo" and gets one sentence.
func (r sysctlReading) faultClause() string {
	switch r.fault {
	case sysctlAbsent:
		return "this kernel does not have it"
	case sysctlNotANumber:
		return fmt.Sprintf("holds %q, which is not a number", r.raw)
	default:
		return fmt.Sprintf("could not be read: %v", r.err)
	}
}

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
		case errors.Is(err, fs.ErrNotExist):
			r.fault, r.err = sysctlAbsent, err
		case err != nil:
			r.fault, r.err = sysctlUnreadable, err
		default:
			r.raw = strings.TrimSpace(raw)
			n, cerr := strconv.Atoi(r.raw)
			if cerr != nil {
				r.fault = sysctlNotANumber
			} else {
				r.value = n
			}
		}
		out = append(out, r)
	}
	return out
}

// readProcSysFile is the host reader readHostSysctls takes in production.
//
// hostread and NOT os.ReadFile, even for a /proc/sys literal, because the
// obvious exemption is FALSE here and a redteam round measured it: /proc/sys
// is exactly a path a container runtime bind-mounts over, key feature 3 says
// snug must run inside a container, and a FIFO at one of these five paths
// takes `snug doctor` to a read that never returns — issue #337's shape, rc
// 124 under `timeout 5`. hostread's O_NONBLOCK open and regular-file refusal
// cost nothing for five files read once.
func readProcSysFile(path string) (string, error) {
	data, err := hostread.Required(path, maxProcSysBytes)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// maxProcSysBytes bounds that read. Every one of these knobs holds a small
// integer and a newline; 64 bytes is far past any honest value and far below
// anything that hurts. The cap is the LimitReader rather than a size check —
// a /proc file stats as zero bytes, which is precisely why hostread does not
// bound on the stat.
const maxProcSysBytes = 64

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
		// "no usable value", not "could not be read": one of the three
		// faults is a knob that read perfectly well and holds something
		// that is not a number.
		fmt.Printf("  ⚠️  %d of the %d kernel knobs snug's threat model inherits have no usable value here\n",
			unreadable, len(readings))
	} else {
		fmt.Println("  ⚠️  this host does not set every kernel knob snug's threat model inherits")
	}
	fmt.Println("     ℹ️  snug does not provide these and cannot: they are the host's, and the")
	fmt.Println("        sandbox is weaker than the design describes where they are off")
	for _, r := range readings {
		switch {
		case !r.readable():
			// A fault is not weakness. Say WHICH fault it is.
			fmt.Printf("     ❔ %s — %s\n", r.sysctl.knob, r.faultClause())
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
