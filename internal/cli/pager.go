package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
)

// The pager exists because --dry-run and --explain are the two screens a human
// reads to decide whether to trust this sandbox, and a screen that scrolls off
// the top has not been read (issue #541). git's shape is adopted wholesale
// rather than invented: $PAGER, and NOT a SNUG_PAGER, because a per-tool pager
// variable is one more thing to discover and nobody's terminal wants a
// different pager for snug than for git.
//
// What the pager is NOT: a sandbox surface. It runs on the HOST, as the user,
// before any namespace exists, and nothing sandboxed can influence which
// program it is. The abuse sentence is therefore empty by construction —
// "a hostile process inside the sandbox can use this to ___" has no completion,
// because the sandbox does not exist yet when this decision is made. The other
// direction, a hostile $PAGER, is not a downgrade either: whoever can set it
// can already run code as this user without going through snug.
//
// Nothing here uses golang.org/x/term. That would be a THIRD third-party
// dependency and CLAUDE.md ("Go, and it is not reopened") spends the whole
// budget on go-toml and golang.org/x/sys. The tty test is attachstdio.go's
// isTerminal, which already runs exactly the ioctl x/term would.

// pagerCmd decides which pager, if any, a human-readable screen goes through,
// and returns the argv to exec. nil means "write straight to the stream" —
// the answer for every non-interactive use, which is every pipe, every CI job
// and every test in this package.
//
// Pure, with lookup and look injected for the same reason internal/policy
// takes an Environ: the decision is the part worth pinning, and pinning it
// must not depend on this machine having a `less` — or, as the first version
// of this function did, on the developer's own $PAGER, which reached it
// through a fallback to the real environment and made four table rows pass
// for the wrong reason.
//
// lookup is os.LookupEnv's shape, not os.Getenv's, and the two-value form is
// load-bearing: "PAGER is unset, so fall back to less" and "PAGER is empty,
// so page nothing" are OPPOSITE answers that a bare getenv cannot tell apart.
func pagerCmd(lookup func(string) (string, bool), look func(string) (string, error), isTTY bool) []string {
	if !isTTY {
		return nil
	}
	// TERM=dumb is a terminal saying it cannot do the things a pager needs,
	// and an unset TERM is a terminal that never said anything. git treats
	// both as "no pager" and so does this.
	term, _ := lookup("TERM")
	switch term {
	case "", "dumb":
		return nil
	}
	// A set-but-empty PAGER is how a human turns paging off for one command
	// (`PAGER= snug --dry-run ...`), and `cat` is the other spelling of the
	// same wish. Neither is an instruction to exec something.
	if raw, ok := lookup("PAGER"); ok {
		p := strings.TrimSpace(raw)
		if p == "" || p == "cat" {
			return nil
		}
		// A $PAGER that is a plain command line is RESOLVED HERE rather than
		// handed to a shell, and that is what turns a typo into "no pager"
		// instead of into a lost screen. `PAGER=nonexistent-pager` under
		// `sh -c` starts successfully — /bin/sh exists — and the failure only
		// appears afterwards, as a broken pipe indistinguishable from a human
		// quitting `less` on page one. Resolving the name first means the
		// question is answered before anything is executed.
		//
		// Splitting on whitespace is safe for exactly this shape, which is the
		// shape $PAGER almost always has: `less`, `less -R`, `less -FRX`.
		if !hasShellMeta(p) {
			fields := strings.Fields(p)
			path, err := look(fields[0])
			if err != nil {
				// Named a pager this host does not have. Not an error — the
				// screen is what the human asked for, and it still gets
				// printed; the pager was the optional part.
				return nil
			}
			return append([]string{path}, fields[1:]...)
		}
		// A $PAGER carrying shell syntax (`less -R | tee /tmp/x`) really does
		// need a shell, and snug cannot resolve it in advance. The shell
		// reports its own failure, and writeThroughPager's exit-127 arm is
		// what keeps the screen from disappearing with it.
		return []string{"/bin/sh", "-c", p}
	}
	for _, name := range []string{"less", "more"} {
		if path, err := look(name); err == nil {
			return []string{path}
		}
	}
	// No pager on this host is not an error. It is a host with no pager.
	return nil
}

// hasShellMeta reports whether a $PAGER needs a shell to mean what it says.
// Conservative on purpose: anything in this set and snug stops trying to
// resolve the command itself, because guessing wrong there would run the wrong
// program rather than merely fail to page.
func hasShellMeta(s string) bool {
	return strings.ContainsAny(s, "|&;<>()$`\\\"'*?[]{}~!#\n")
}

// pagerEnv adds the LESS default git added for the same reason: without -F a
// twenty-line dry run still takes over the whole screen and has to be quit,
// and without -X quitting it wipes the screen the human was reading. FRX is a
// DEFAULT — a human who set LESS has already said what they want, and
// overriding that is the ergonomic shape of "no silent downgrade".
func pagerEnv(environ []string) []string {
	for _, kv := range environ {
		if strings.HasPrefix(kv, "LESS=") {
			return environ
		}
	}
	return append(environ, "LESS=FRX")
}

// writeThroughPager runs render, sending its bytes to the pager named by argv,
// or straight to out when argv is nil.
//
// THE RULE THAT OUTRANKS PAGING: a pager that does not work costs the human
// their paging, NEVER their screen. --dry-run is the artifact used to decide
// whether to trust snug at all, so losing it to a misconfigured $PAGER would
// be the worst trade available.
//
// The first version of this function believed cmd.Start was enough to enforce
// that, and it was wrong in the case that actually happens. MEASURED, with
// PAGER spelled as a command that does not exist:
//
//	writeThroughPager(&buf, []string{"/bin/sh", "-c", "exec nonexistent-pager-xyz"}, ...)
//	err=<nil>  bytes reaching out=0 (want 220000)
//
// cmd.Start succeeds — /bin/sh exists and starts fine — and it is the SHELL
// that then fails to exec, exits 127 and drops the read end. Every write to
// the pipe gets EPIPE, which this function deliberately swallows because it is
// also what a human quitting `less` on page one produces. The two are
// indistinguishable from the write side, so the entire screen vanished under a
// nil error. A typo in $PAGER made `snug --dry-run` print nothing at all.
//
// So the screen is rendered into memory FIRST and the pager is fed from that
// buffer. Buffering is free here — these screens are bounded and no human
// reads them incrementally — and it buys the one thing the streaming version
// could not have: something left to print when the pager turns out not to
// work.
//
// Counting what the pager consumed does NOT separate the two cases, which was
// the second wrong answer: bytes read out of the buffer are bytes the kernel
// put in a 64 KiB pipe, whether or not anything is on the other end. Testing
// for the shell's exit 127 was the third, and it caught only the typo it was
// written against — see the measurements on the wait arm below. The rule that
// works is the blunt one: any non-zero exit reprints, because a human quitting
// a pager early does not produce one.
func writeThroughPager(out io.Writer, argv []string, environ []string, render func(io.Writer) error) error {
	var screen bytes.Buffer
	if err := render(&screen); err != nil {
		return err
	}
	if len(argv) == 0 {
		_, err := out.Write(screen.Bytes())
		return err
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(screen.Bytes())
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	cmd.Env = pagerEnv(environ)
	if err := cmd.Start(); err != nil {
		_, werr := out.Write(screen.Bytes())
		return werr
	}
	// Wait before returning: the pager owns the terminal until it exits, and
	// returning early would let snug's next line race the screen.
	waitErr := cmd.Wait()
	// ANY non-zero exit reprints. The narrower rule this replaces — exit 127
	// only — was the third wrong answer to the same question, and it was wrong
	// because 127 detects "the shell could not exec it" while the property
	// being enforced is "the pager displayed nothing". MEASURED against a
	// 13847-byte --dry-run screen on a real terminal:
	//
	//	PAGER=nonexistent-pager-xyz   exit 0   13847 bytes   (127, caught)
	//	PAGER=false                   exit 0       0 bytes   (1, not caught)
	//	PAGER=<script that SEGVs>     exit 0       0 bytes   (-1, not caught)
	//
	// A wrapper script with a config error, a pager killed by a signal, a
	// `false` — each took the whole trust artifact and reported success.
	//
	// Reprinting on ANY failure is safe because quitting a pager early is not
	// a failure in the first place: `less` quit with `q` exits 0, `more` quit
	// exits 0, and `head -1` exits 0 after closing the pipe. So the "human
	// read some and quit" case never reaches this branch, and there is no
	// double-print to trade against.
	if waitErr != nil {
		_, werr := out.Write(screen.Bytes())
		return werr
	}
	return nil
}

// pageHuman is the one call the renderers make. It resolves the terminal
// question against the real stream and the real environment, then hands off.
//
// json is the one format that never pages: a JSON document is for a program,
// and a program's stdout is a pipe, which isTerminal already refuses — but
// stating it here means the guarantee does not depend on how snug was
// invoked.
func pageHuman(out *os.File, jsonOutput bool, render func(io.Writer) error) error {
	if jsonOutput {
		return render(out)
	}
	argv := pagerCmd(os.LookupEnv, exec.LookPath, isTerminal(int(out.Fd())))
	return writeThroughPager(out, argv, os.Environ(), render)
}
