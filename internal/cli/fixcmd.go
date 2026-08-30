package cli

// fixcmd.go is `snug fix`, the namespace for restoring something the HOST is
// missing. `snug host` is RESERVED beside it for operating an integration the
// host provides, so a future command goes under whichever of the two it IS —
// a sharper test than which word reads better. Whether the surface as a whole
// should be flat or grouped is open and NOT settled here (issue #503); this
// file follows the shape `snug engine gc` already has.
//
// # Why this exists at all
//
// `snug doctor` used to tell a user to write a shell script and call it from a
// distrobox init_hook. That script had to re-derive the range from
// /proc/self/uid_map — a SECOND implementation of subuidSuggestion, living
// outside the repo, in a language with none of its tests. It drifts, it is
// untested, and it is not in CI (issue #502). The derivation belongs where the
// tests are.
//
// It also has to be here for a reason no script can meet: a verb whose meaning
// is "make the engine's id delegation work on this host" can one day answer
// "nothing to append, this host has systemd-nsresourced" (issue #482, kept
// deliberately distinct). A script that only knows how to append a line to
// /etc/subuid cannot say that, and every hook written against one would go on
// appending a range nobody needs.
//
// # The shape, and it is gofmt's
//
//	snug fix subuid       print what this host needs; change nothing
//	snug fix subuid -w    apply it
//	snug fix sysctl       print the kernel knobs this host is missing (issue #526)
//	snug fix sysctl -w    apply them, and write /etc/sysctl.d/99-snug.conf
//	snug fix              list the nouns; act on nothing
//
// MEASURED, `gofmt -h`: "-w  write result to (source) file instead of stdout".
// prettier is the same. So: stdout is the CONTENT, stderr is the commentary,
// and nothing to do prints nothing at all.
//
// EXIT 0 WHENEVER THERE IS NOTHING TO DO, and that is a contract rather than a
// convenience. This command's whole point is to be callable from a distrobox
// init_hook, and distrobox-init runs the hooks under `set -o errexit`: a
// nonzero exit there does not report a problem, it stops the box from coming
// up at all — a far worse symptom, pointing nowhere near the hook.
//
// THE NOUN IS MANDATORY. Bare `snug fix` never acts, the same rule `snug
// engine gc` states for itself ("nothing is ever reclaimed without a selector
// naming it"). There are two nouns and the namespace is expected to grow, so a
// "fix everything" default would now run something nobody asked for — and the
// two it would run are not comparable: one appends a line to /etc/subuid, the
// other rewrites kernel knobs on a running machine.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/hostread"
	"golang.org/x/sys/unix"
)

func fixUsage() {
	fmt.Fprint(os.Stderr, `snug fix — repair a host prerequisite snug needs

usage:
  snug fix subuid [USER]        print the delegated id range this host needs
  snug fix subuid [USER] -w     write it to /etc/subuid and /etc/subgid
  snug fix sysctl               print the kernel hardening this host is missing
  snug fix sysctl -w            apply it and write /etc/sysctl.d/99-snug.conf

Prints and changes NOTHING without -w. Printing nothing means there is nothing
to do, and the exit status is 0 either way, so this is safe to call from a
distrobox init_hook (distrobox-init runs hooks under `+"`set -o errexit`"+`).

USER defaults to the invoking user — $SUDO_USER under sudo, never "root",
because a range delegated to root is a line that looks right and does nothing.
`)
}

func fixCmd(argv []string) int {
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") {
		fmt.Fprintln(os.Stderr, "snug: `snug fix` takes one subject: subuid or sysctl")
		fixUsage()
		return exitUsage
	}
	switch argv[0] {
	case "subuid":
		return fixSubuidCmd(argv[1:])
	case "sysctl":
		return fixSysctlCmd(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "snug: `snug fix` has no subject %s (only: subuid, sysctl)\n", visibleValue(argv[0]))
		return exitUsage
	}
}

// fixSubuidCmd reads the same map and calls the same
// subuidSuggestion `snug doctor` does, which is the point: doctor is this
// command's dry run, so there is no second preview to keep in step.
func fixSubuidCmd(argv []string) int {
	write := false
	var who string
	for _, a := range argv {
		switch a {
		case "-w", "--write":
			write = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "snug: `snug fix subuid` has no flag %s (only: -w/--write)\n", visibleValue(a))
				return exitUsage
			}
			if who != "" {
				fmt.Fprintf(os.Stderr, "snug: `snug fix subuid` takes at most one user, got %s and %s\n",
					visibleValue(who), visibleValue(a))
				return exitUsage
			}
			who = a
		}
	}

	name, uid, err := subuidTargetUser(who)
	if err != nil {
		// REFUSES rather than guessing. The alternative is emitting a line for
		// the wrong account, which looks correct and delegates nothing.
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitUsage
	}

	idMap := readIDMap()
	base, size, ok := subuidSuggestion(idMap, uint64(uid))
	if !ok {
		fmt.Fprintf(os.Stderr, "snug: nothing in this namespace's /proc/self/uid_map can be delegated to %s "+
			"(id %d); rootless containers will not work here and no line would help\n", name, uid)
		return 0
	}

	line := fmt.Sprintf("%s:%d:%d", name, base, size)

	if present, perr := subuidLineAlreadyPresent(name); perr == nil && present {
		fmt.Fprintf(os.Stderr, "snug: %s already has a range in /etc/subuid and /etc/subgid; nothing to do\n", name)
		return 0
	}

	if !write {
		// stdout, alone, with no decoration: this is the content, and a
		// caller may reasonably pipe it. Everything explanatory is on stderr.
		fmt.Println(line)
		fmt.Fprintf(os.Stderr, "snug: nothing was changed — run `snug fix subuid%s -w` (as root) to append this "+
			"to /etc/subuid and /etc/subgid\n", subuidUserArg(who))
		if base != conventionalSubuidBase {
			fmt.Fprintf(os.Stderr, "snug: not the conventional %d — this namespace's uid_map cannot map it\n",
				conventionalSubuidBase)
		}
		return 0
	}

	if os.Geteuid() != 0 {
		// Refuse, name the fix, change nothing. Half-writing one of the two
		// files would leave a host that looks configured and is not.
		fmt.Fprintf(os.Stderr, "snug: -w writes /etc/subuid and /etc/subgid and this process is not root; "+
			"run `sudo snug fix subuid%s -w`\n", subuidUserArg(who))
		return exitUnavail
	}

	for _, path := range []string{"/etc/subuid", "/etc/subgid"} {
		if aerr := appendLine(path, line); aerr != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", aerr)
			return exitInternal
		}
	}
	fmt.Fprintf(os.Stderr, "snug: appended %s to /etc/subuid and /etc/subgid — `snug doctor` to confirm\n", line)
	return 0
}

// subuidUserArg renders the user back into the command a message names, so a
// copy-paste of that message does what the message described. Empty when the
// user was not named, because re-suggesting the default would be noise.
func subuidUserArg(who string) string {
	if who == "" {
		return ""
	}
	return " " + who
}

// subuidTargetUser answers WHOSE range this is, and it is the question that
// makes the difference between a working line and one that looks right.
//
// Under sudo, os.Getuid() is 0 and user.LookupId gives "root" — so the
// obvious implementation emits `root:1001:64535`, which delegates a range to
// an account no rootless container will ever run as. A distrobox init_hook is
// the same trap one level worse: root runs the hook and the BOX USER is the
// target, which is why an explicit argument exists at all.
//
// Order: an explicit argument, then $SUDO_USER, then the invoking user. Root
// with no argument and no $SUDO_USER is refused rather than served, because at
// that point nothing on the machine says who was meant.
func subuidTargetUser(explicit string) (name string, uid int, err error) {
	return resolveSubuidUser(explicit, os.Getenv("SUDO_USER"), os.Geteuid(), user.Lookup,
		func() (string, int) { return subuidEntryName(), os.Getuid() })
}

// resolveSubuidUser is the decision above with every host fact injected, for
// the same reason subuidHost exists one file over: the first version of THAT
// report read os.Getuid() from inside the printer, so its test asserted
// whatever machine ran it — green here at uid 1000 and red in CI at 1001.
// The root arm is the one that cannot be tested any other way at all.
func resolveSubuidUser(
	explicit, sudoUser string,
	euid int,
	lookup func(string) (*user.User, error),
	self func() (string, int),
) (name string, uid int, err error) {
	switch {
	case explicit != "":
		u, lerr := lookup(explicit)
		if lerr != nil {
			return "", 0, fmt.Errorf("no such user %s on this host: %w", visibleValue(explicit), lerr)
		}
		return u.Username, atoiOrNegative(u.Uid), nil
	case sudoUser != "":
		u, lerr := lookup(sudoUser)
		if lerr != nil {
			return "", 0, fmt.Errorf("$SUDO_USER names %s, which this host does not know: %w",
				visibleValue(sudoUser), lerr)
		}
		return u.Username, atoiOrNegative(u.Uid), nil
	case euid == 0:
		return "", 0, errors.New("running as root with no $SUDO_USER and no user named: say whose range " +
			"this is — `snug fix subuid <user>` — because a range delegated to root delegates nothing")
	default:
		n, i := self()
		return n, i, nil
	}
}

func atoiOrNegative(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// subuidLineAlreadyPresent is the idempotency check, and it is deliberately
// the same question `newusers`/`useradd` ask: does this owner have ANY line?
// Not "does it have exactly this line" — a host that delegated a different
// range on purpose must not have a second one appended under it.
func subuidLineAlreadyPresent(name string) (bool, error) {
	// hostread, not os.ReadFile, and the guard test that caught this is right
	// to: /etc/subuid is a file snug does not own, so a FIFO at that path
	// turns the read into an open(2) that never returns — issue #337, the
	// same lesson as ~/.claude/settings.json. Planting one needs root here,
	// but "the attacker would already be root" is exactly the reasoning the
	// discipline exists to stop being made file by file.
	blob, err := hostread.Required("/etc/subuid", subuidFileMaxBytes)
	if err != nil {
		return false, err
	}
	return subuidOwnerPresent(string(blob), name), nil
}

// subuidFileMaxBytes bounds that read. /etc/subuid is one short line per user
// and the biggest real one imaginable is a few hundred; a megabyte is far past
// any honest file and far below anything that hurts.
const subuidFileMaxBytes = 1 << 20

// subuidOwnerPresent is that question over the file's CONTENT, so the trap in
// it is testable: the owner is the field before the first colon, and matching
// on the bare name would make `michal` present because `michalx` is. The colon
// is load-bearing.
func subuidOwnerPresent(content, name string) bool {
	for _, l := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), name+":") {
			return true
		}
	}
	return false
}

// appendLine adds one line to path, creating nothing: /etc/subuid and
// /etc/subgid exist on every host that has shadow-utils, and creating one snug
// invented would be a bigger claim about the machine than this command makes.
func appendLine(path, line string) error {
	// HOSTREAD-EXEMPT: this is a WRITE, and hostread is a reader — its whole
	// discipline (stat, LimitReader, refuse anything not a regular file) is
	// about what comes back, and nothing comes back here. O_NOFOLLOW is the
	// half that does apply: it refuses a symlink at /etc/subuid rather than
	// appending through it, which is the shape issue #337's FIFO takes on the
	// writing side. O_APPEND makes the write atomic against a concurrent
	// useradd. No O_CREATE — see this function's doc comment.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("opening %s to append %q: %w", path, line, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		return fmt.Errorf("appending %q to %s: %w", line, path, err)
	}
	return nil
}
