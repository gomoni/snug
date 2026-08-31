package policy

// NewSessionReason is the set of reasons a policy asks bwrap for
// --new-session, which calls setsid() so the sandbox leads a session of its
// own and has NO controlling terminal.
//
// TWO REASONS, HELD APART ON PURPOSE. They protect different things and they
// expire independently: the TIOCSTI reason disappears the day a host's kernel
// defaults legacy_tiocsti to 0, and folding the terminal reason into that
// condition would retire it on the same day, for an unrelated cause. A set,
// not a bool, is what makes that impossible to do by accident.
//
// WHAT setsid() CLOSES, AND WHAT IT DOES NOT (measured on this host, bwrap
// 0.11.2, with a controlling pty and pipes on stdio):
//
//   - /dev/tty is a bind of the host's magic 5,0 device, which resolves to the
//     CALLER's controlling terminal at open time. Without setsid a payload
//     writes through it to the terminal that launched snug — measured, the
//     operator's pty received the bytes. With setsid the open is ENXIO ("No
//     such device or address") and the write never happens.
//   - It does NOT take a terminal away from a payload that was handed one.
//     When snug's stdio is a pty, the payload holds that pty on fd 0/1/2 and
//     bwrap additionally binds the same device node as /dev/console (measured
//     `crw--w---- 1000 136,5` inside, the operator's own pts). Escape
//     sequences the payload writes there — OSC 52 clipboard among them — reach
//     the emulator whatever session the payload leads. setsid closes one
//     spelling of three, which is why NewSessionNoTerminal is a fact snug
//     OBSERVES rather than a switch a profile sets: in the shape where the
//     flag would be asked for and cannot work, asking would buy a lost job
//     control and nothing else.
type NewSessionReason uint8

const (
	// NewSessionTIOCSTI: this kernel still allows the TIOCSTI ioctl, so a
	// payload holding the controlling terminal can push characters into it as
	// though the operator had typed them. The ioctl is refused when the tty is
	// not the caller's controlling terminal, so setsid() is the whole defence.
	NewSessionTIOCSTI NewSessionReason = 1 << iota

	// NewSessionNoTerminal: no descriptor snug was started with (0, 1, 2) is a
	// terminal, so nothing inside needs one and the /dev/tty route to the
	// operator's terminal is the only one open. Cutting it costs no job
	// control, because there is no terminal to control the job from.
	NewSessionNoTerminal
)

// StdioSet is the subset of the descriptors snug ITSELF was started with (0, 1,
// 2) that refer to a terminal. It is a set and not a bool, and the reason is a
// measurement: what a payload can reach, and what --dry-run may claim about it,
// differs per descriptor.
//
//   - bwrap binds the operator's pty as /dev/console when, and only when, snug's
//     STDOUT is a terminal. Measured on this host, one pty on one descriptor at a
//     time: stdout-only gives `crw--w---- michal nobody 136,7 /dev/console`
//     inside; stdin-only and stderr-only give "No such file or directory".
//   - The channel to the operator is open in ALL of those shapes anyway, because
//     the pty is on a descriptor the payload holds — `snug ... > log` from a
//     terminal leaves it on stderr.
//
// A single bool collapsed those into one arm that named /dev/console and told
// the user to redirect snug's OUTPUT, which is false twice over in the
// stderr-only shape: there is no /dev/console, and redirecting stdout closes
// nothing. Carrying the set is what lets the screen say which descriptor it
// means.
type StdioSet uint8

const (
	// StdinTerminal: snug's fd 0 is a terminal.
	StdinTerminal StdioSet = 1 << iota
	// StdoutTerminal: snug's fd 1 is a terminal. This is the one bwrap keys
	// /dev/console on.
	StdoutTerminal
	// StderrTerminal: snug's fd 2 is a terminal.
	StderrTerminal
)

// Has reports whether every descriptor in x is in the set.
func (s StdioSet) Has(x StdioSet) bool { return s&x == x }

// Any reports whether any of the three is a terminal.
func (s StdioSet) Any() bool { return s != 0 }

// Names lists the descriptors in the set, in fd order, as the words a screen
// uses for them. Empty when none is a terminal.
func (s StdioSet) Names() []string {
	var out []string
	for _, e := range []struct {
		bit  StdioSet
		name string
	}{{StdinTerminal, "stdin"}, {StdoutTerminal, "stdout"}, {StderrTerminal, "stderr"}} {
		if s&e.bit != 0 {
			out = append(out, e.name)
		}
	}
	return out
}

// Has reports whether reason r is in the set.
func (r NewSessionReason) Has(x NewSessionReason) bool { return r&x != 0 }

// NewSession reports whether the sandbox is put in a session of its own. It is
// derived from NewSessionWhy rather than stored beside it, so a policy can
// never carry a flag and a reason set that disagree.
func (p *Policy) NewSession() bool { return p.NewSessionWhy != 0 }

// newSessionReasons collects the reasons that apply to one run. It is the ONE
// place the two conditions meet, and they meet as a union rather than as a
// condition with a second clause bolted on.
func newSessionReasons(ctx Context) NewSessionReason {
	var why NewSessionReason
	if ctx.LegacyTIOCSTI {
		why |= NewSessionTIOCSTI
	}
	if !ctx.StdioTerminals.Any() {
		why |= NewSessionNoTerminal
	}
	return why
}
