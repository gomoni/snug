// Package getent is snug's ONE entrypoint for host account data: every user
// or group name, uid, home or shell snug learns about the host comes from
// glibc's getent(1), run on the host.
//
// getent resolves through NSS — files, sssd, LDAP, systemd userdb, nscd — the
// way the host's own `id` does. cgo-free Go's os/user can only parse
// /etc/passwd and /etc/group as text, so an sssd or LDAP account is invisible
// to it, and two sources would answer the same question two ways on such a
// host. test/guard's os/user sweep holds every other package to this one.
package getent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Timeout bounds each getent invocation the same way sshProbeTimeout bounds
// `ssh -G` (internal/cli/sshconfig.go): a stalled NSS backend — sssd waiting
// on a dead LDAP server, nscd wedged — must not hang snug forever, and a
// fixed ceiling turns that into a predictable refusal instead.
const Timeout = 5 * time.Second

// ErrNoEntry is wrapped by every error for getent's exit 2, the one code
// glibc's getent(1) documents: the key has no entry in that database. It is
// the only failure a caller may treat as an answer ("this uid has no name")
// rather than as a refusal.
var ErrNoEntry = errors.New("no entry")

// maxCapturedOutput bounds how much of getent's stdout or stderr Run holds
// onto. A well-formed line is at most a few hundred bytes; a getent that
// misbehaves and writes without bound (measured in the #612 reproduction at
// 400 MB to stderr, 1.8 GiB peak RSS to hold and re-quote it) must not turn
// one failed lookup into a memory problem for the whole process.
const maxCapturedOutput = 64 * 1024

// cappedWriter keeps only the first limit bytes written to it and silently
// drops the rest. Write always reports success for the FULL slice: cmd.Run
// must see getent's own exit status, not an I/O error this writer invented
// by refusing bytes past the cap.
type cappedWriter struct {
	limit int
	b     strings.Builder
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if room := w.limit - w.b.Len(); room > 0 {
		if room > len(p) {
			room = len(p)
		}
		w.b.Write(p[:room])
	}
	return len(p), nil
}

func (w *cappedWriter) String() string { return w.b.String() }

// LookPath resolves getent on $PATH. It is the ONE call, shared by every
// lookup below and `snug doctor`'s programs section, so a doctor report and
// an actual run's refusal can never disagree about whether getent is there.
// A variable so a test can simulate a host without getent.
var LookPath = func() (string, error) { return exec.LookPath("getent") }

// Passwd is one passwd(5) entry, as getent printed it.
type Passwd struct {
	Name  string
	UID   int
	GID   int
	Gecos string
	Home  string
	Shell string
}

// Group is one group(5) entry, as getent printed it. Members are not parsed:
// nothing in snug reads them, and a member list enumerates other accounts.
type Group struct {
	Name string
	GID  int
}

// PasswdByUID runs `getent passwd <uid>` and refuses a line whose uid field is
// not the one asked for.
func PasswdByUID(uid int) (Passwd, error) {
	pw, err := passwd(strconv.Itoa(uid))
	if err != nil {
		return Passwd{}, err
	}
	if pw.UID != uid {
		return Passwd{}, fmt.Errorf("getent passwd %d printed an entry for uid %d, not %d. "+
			"This is the host's own getent or NSS configuration disagreeing with itself, not "+
			"something snug can work around", uid, pw.UID, uid)
	}
	return pw, nil
}

// PasswdByName runs `getent passwd <name>` and refuses a line whose name field
// is not the one asked for. A name that is all digits is refused before
// getent runs, because getent reads it as a uid.
func PasswdByName(name string) (Passwd, error) {
	if name == "" {
		return Passwd{}, errors.New("getent passwd: empty account name")
	}
	if _, err := strconv.Atoi(name); err == nil {
		return Passwd{}, fmt.Errorf("getent passwd %q: a numeric name is read as a uid, "+
			"not as a name", name)
	}
	pw, err := passwd(name)
	if err != nil {
		return Passwd{}, err
	}
	if pw.Name != name {
		return Passwd{}, fmt.Errorf("getent passwd %s printed an entry for %q, not %q. "+
			"This is the host's own getent or NSS configuration disagreeing with itself, not "+
			"something snug can work around", name, pw.Name, name)
	}
	return pw, nil
}

// GroupByGID runs `getent group <gid>` and refuses a line whose gid field is
// not the one asked for.
func GroupByGID(gid int) (Group, error) {
	key := strconv.Itoa(gid)
	line, err := Run("group", key)
	if err != nil {
		return Group{}, err
	}
	f := strings.Split(line, ":")
	if len(f) != 4 {
		return Group{}, fmt.Errorf("getent group %s printed %d field(s), want exactly 4: "+
			"%q. Give gid %s an NSS entry, or install a getent that prints the standard "+
			"4-field group line", key, len(f), line, key)
	}
	got, err := strconv.Atoi(f[2])
	if err != nil || got != gid {
		return Group{}, fmt.Errorf("getent group %s printed a line for gid %s, not %s: %q. "+
			"This is the host's own getent or NSS configuration disagreeing with itself, not "+
			"something snug can work around", key, f[2], key, line)
	}
	if f[0] == "" {
		return Group{}, fmt.Errorf("getent group %s printed an empty group name: %q. "+
			"Give gid %s an NSS entry with a name", key, line, key)
	}
	return Group{Name: f[0], GID: gid}, nil
}

func passwd(key string) (Passwd, error) {
	line, err := Run("passwd", key)
	if err != nil {
		return Passwd{}, err
	}
	f := strings.Split(line, ":")
	if len(f) != 7 {
		return Passwd{}, fmt.Errorf("getent passwd %s printed %d field(s), want exactly 7: "+
			"%q. Give %s an NSS entry, or install a getent that prints the standard "+
			"7-field passwd line", key, len(f), line, key)
	}
	uid, uerr := strconv.Atoi(f[2])
	gid, gerr := strconv.Atoi(f[3])
	if uerr != nil || gerr != nil || uid < 0 || gid < 0 {
		return Passwd{}, fmt.Errorf("getent passwd %s printed a non-numeric uid or gid: %q",
			key, line)
	}
	if f[0] == "" {
		return Passwd{}, fmt.Errorf("getent passwd %s printed an empty account name: %q. "+
			"Give %s an NSS entry with a name", key, line, key)
	}
	return Passwd{Name: f[0], UID: uid, GID: gid, Gecos: f[4], Home: f[5], Shell: f[6]}, nil
}

// Run runs `getent database key` and returns its one line of output with the
// trailing newline stripped, refusing anything else: getent missing, a
// non-zero exit (2 wraps ErrNoEntry), a timeout, or output that is not
// EXACTLY one line ending in EXACTLY one '\n' — a second line, a missing
// newline, or a '\r' all mean the bytes are not the single line the caller's
// field split expects, and parsing past that would attribute a byte to the
// wrong field.
func Run(database, key string) (string, error) {
	getent, err := LookPath()
	if err != nil {
		return "", fmt.Errorf("snug takes host account data only from `getent`, and could "+
			"not find it on $PATH (%v). Install glibc's getent — package `glibc` on "+
			"openSUSE, `libc-bin` on Debian/Ubuntu, `glibc-common` on Fedora — or, on a "+
			"non-glibc host, provide a compact getent, as musl does", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, getent, database, key)
	// WaitDelay bounds the wait for cmd.Run's own internal goroutines, which
	// otherwise block on the stdout/stderr pipes staying open — not on getent
	// itself, which the context's kill already reached. A getent that forks a
	// child inheriting the pipe would
	// otherwise hold Run past Timeout for as long as that child lives.
	cmd.WaitDelay = time.Second
	stdout := &cappedWriter{limit: maxCapturedOutput}
	stderr := &cappedWriter{limit: maxCapturedOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()

	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("getent %s %s timed out after %s; snug refuses rather than hang "+
			"waiting for an NSS backend that may never answer", database, key, Timeout)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 2 {
			return "", fmt.Errorf("getent %s %s: %w (exit 2). Give %s an NSS entry",
				database, key, ErrNoEntry, key)
		}
		msg := fmt.Sprintf("getent %s %s failed: %v", database, key, runErr)
		// getent's stderr is the HOST's, not snug's: VisibleText escapes it the
		// same way a bind's host path is escaped in a refusal, so an ESC or a
		// bidi override in it cannot forge or erase a line of this message.
		if s := strings.TrimSpace(policy.VisibleText(stderr.String())); s != "" {
			msg += ": " + s
		}
		return "", errors.New(msg)
	}

	out := stdout.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") || strings.Contains(out, "\r") {
		return "", fmt.Errorf("getent %s %s printed output snug does not recognise — it must be "+
			"exactly one line ending in exactly one '\\n' and carry no '\\r': %q", database, key, out)
	}
	line := strings.TrimSuffix(out, "\n")
	// A NUL, a C0 control other than the line ending just trimmed, or DEL
	// would be authored verbatim into an environment variable or a generated
	// /etc/passwd or /etc/group line, and neither carries one as data: a NUL
	// truncates a C string's view of the value. Refused HERE, once, rather
	// than at every place downstream that authors a field from this line.
	if i := strings.IndexFunc(line, isForbiddenControlByte); i >= 0 {
		return "", fmt.Errorf("getent %s %s printed a control byte (0x%02x) snug will not carry "+
			"into an environment variable or a generated passwd/group line: %q. Give %s an NSS "+
			"entry whose fields contain no NUL, no C0 control and no DEL", database, key, line[i], out, key)
	}
	return line, nil
}

// isForbiddenControlByte reports whether r is a NUL, a C0 control byte
// (0x00-0x1F) or DEL (0x7F). It is a rune predicate rather than a byte loop so
// strings.IndexFunc can report the byte offset directly; every byte in this
// range is also a valid one-rune UTF-8 encoding of itself, so the two views
// agree everywhere the predicate can fire.
func isForbiddenControlByte(r rune) bool {
	return r < 0x20 || r == 0x7f
}
