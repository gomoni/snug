package cli

// hostcmd.go is `snug host`, the namespace for operating an integration the
// HOST provides. It is the other half of the split fixcmd.go states: `snug fix`
// restores something the host is MISSING, `snug host` operates something the
// host already has. Claude Code's ~/.claude.json is the host's, snug only ever
// READS it (hostTrustsTarget), and this is the one verb that writes to it.
//
// Shape, and it is `snug fix subuid`'s rather than a new one (issue #503 asks
// that the question be asked before the CLI grows, and the answer here is "the
// shape that exists"):
//
//	snug host trust DIR      print what trusting DIR would grant; change nothing
//	snug host trust DIR -w   write it into ~/.claude.json
//	snug host                list the subjects; act on nothing
//
// stdout is the CONTENT (the key that would be set), stderr is the commentary,
// and nothing to do prints nothing at all. Unlike `snug fix subuid` this is NOT
// safe to wire into a hook and is not meant to be: it grants something, so the
// noun and the directory are both mandatory and there is no default target. A
// grant that defaults to "wherever you happen to be" is the accident issue #460
// exists to refuse.
//
// OFF `--help`, like `engine` and `fix`, and discoverable from the screen where
// the friction is: --dry-run's CLAUDE block prints this command in the arm that
// says the target is not pre-answered. That is the same way `snug doctor` is
// what makes `snug fix subuid` findable.
//
// # The abuse sentence
//
// A hostile process inside the sandbox can use this to do NOTHING, and three
// measured facts are what make that true rather than hopeful:
//
//   - There is no snug inside. MEASURED in a real `-p @claude` run:
//     `command -v snug` prints nothing.
//   - The host's ~/.claude.json is never bound in. @claude GENERATES a
//     KindData file at that path; MEASURED in the same run, ~/.claude.json
//     inside is on a tmpfs and is 61 bytes. So a payload that did somehow run
//     this command would edit its own throwaway file and lose it at exit —
//     which is why runHostTrust refuses outright under $SNUG, rather than
//     reporting success for a write nobody will ever see.
//   - The sandbox has its own network namespace, so there is no host-local
//     socket to ask a host-side snug through.
//
// THE RESIDUAL IS SOCIAL, and it is the reason describeTrustGrant exists: a
// hostile repo (or an agent it has captured) can print "run `snug host trust .`
// on the host". Nothing stops a human typing that, so the command answers it by
// naming the file that gains the right to run, with its size and mode, before
// anything is written. For the same reason the command is NOT named on the
// guidance file the agent reads inside the sandbox — only on --dry-run, which
// only a human on the host sees.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func hostUsage() {
	fmt.Fprint(os.Stderr, `snug host — operate an integration the host already provides

usage:
  snug host trust DIR       print what recording trust for DIR would grant
  snug host trust DIR -w    record it in the host's ~/.claude.json

Prints and changes NOTHING without -w.

`+"`snug host trust`"+` answers Claude Code's "Quick safety check" for one exact
directory, on the host, so that a snug sandbox for that directory can carry the
answer. snug never records this by itself: the dialog is what stops a
repository's own .claude/settings.json hooks running at startup, and the
sandbox holds an Anthropic OAuth token.
`)
}

func hostCmd(argv []string) int {
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") {
		fmt.Fprintln(os.Stderr, "snug: `snug host` takes one subject: trust")
		hostUsage()
		return exitUsage
	}
	switch argv[0] {
	case "trust":
		return hostTrustCmd(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "snug: `snug host` has no subject %s (only: trust)\n", visibleValue(argv[0]))
		return exitUsage
	}
}

// hostTrustCmd parses argv and hands every host fact to runHostTrust, which is
// where the decision lives. $HOME is read HERE and passed down for the reason
// internal/policy is pure: the tests drive a fixture home through runHostTrust
// and so cannot touch the developer's own ~/.claude.json.
func hostTrustCmd(argv []string) int {
	write := false
	dir := ""
	for _, a := range argv {
		switch a {
		case "-w", "--write":
			write = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "snug: `snug host trust` has no flag %s (only: -w/--write)\n", visibleValue(a))
				return exitUsage
			}
			if dir != "" {
				fmt.Fprintf(os.Stderr, "snug: `snug host trust` takes one directory, got %s and %s\n",
					visibleValue(dir), visibleValue(a))
				return exitUsage
			}
			dir = a
		}
	}
	if dir == "" {
		// No default, and no cwd fallback: this command grants something, and
		// the directory it grants for is the whole decision. `snug host trust .`
		// is one keystroke and is still the human naming a directory.
		fmt.Fprintln(os.Stderr, "snug: `snug host trust` needs the directory to trust — "+
			"`snug host trust .` for the current one")
		return exitUsage
	}

	// Inside a sandbox this writes a tmpfs file that dies with the run, and
	// the agent that ran it reports the trust as recorded. Refuse instead. It
	// is not a boundary — a payload can unset $SNUG, and it gains nothing if it
	// does (see the abuse sentence above) — it is the difference between a
	// no-op and a no-op reported as a success.
	if os.Getenv("SNUG") == "1" {
		fmt.Fprintln(os.Stderr, "snug: `snug host trust` records a decision in the HOST's "+
			"~/.claude.json, and in here that path is a tmpfs file that dies with this "+
			"sandbox; run it on the host instead")
		return exitUnavail
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		fmt.Fprintln(os.Stderr, "snug: cannot determine $HOME, and ~/.claude.json is the file this "+
			"command writes; set $HOME and re-run")
		return exitUnavail
	}
	return runHostTrust(os.Stdout, os.Stderr, home, dir, write)
}

// runHostTrust is the whole command with the host injected. Order is
// deliberate: canonicalise, read and PARSE (so a malformed file refuses before
// anything is printed as if it were going to work), then print, then write.
func runHostTrust(out, errOut io.Writer, home, dir string, write bool) int {
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(errOut, "snug: %s is not a path this process can resolve: %v\n", visibleValue(dir), err)
		return exitUsage
	}
	// The SAME canonicalisation policy.Resolve does to pol.Target
	// (resolve.go's EvalSymlinks), because the key written here is looked up by
	// exact string match later. A key written under any other spelling of the
	// same directory is a key snug will never find, and the command would be
	// silently useless.
	key, err := filepath.EvalSymlinks(abs)
	if err != nil {
		fmt.Fprintf(errOut, "snug: %s: %v — trust is recorded for a directory that exists, "+
			"and snug records the path with its symlinks resolved because that is the spelling it "+
			"looks up later\n", visibleValue(abs), err)
		return exitUsage
	}
	if fi, serr := os.Stat(key); serr != nil {
		fmt.Fprintf(errOut, "snug: %s: %v\n", visibleValue(key), serr)
		return exitUsage
	} else if !fi.IsDir() {
		fmt.Fprintf(errOut, "snug: %s is not a directory — Claude Code keys trust per directory, "+
			"so there is nothing to record for a file\n", visibleValue(key))
		return exitUsage
	}

	plan, err := planClaudeTrust(home, key)
	if err != nil {
		fmt.Fprintf(errOut, "snug: %v\n", err)
		return exitUnavail
	}

	if plan.already {
		fmt.Fprintf(errOut, "snug: %s already records %s as trusted; nothing to do\n",
			visibleValue(plan.path), visibleValue(key))
		return 0
	}

	describeTrustGrant(errOut, plan, key)

	if !write {
		// stdout, alone: the key this would set. Everything explanatory is on
		// stderr, the same split `snug fix subuid` uses.
		// %q, the identical rendering --dry-run's CLAUDE block uses for this
		// key: it escapes a forging rune in a directory name (a host path is
		// not snug's to refuse, so every screen has to render one safely) and
		// the two screens then cannot disagree about the same string.
		fmt.Fprintf(out, "projects.%q.hasTrustDialogAccepted = true\n", key)
		fmt.Fprintf(errOut, "snug: nothing was changed — run `snug host trust %s -w` to record it\n",
			visibleValue(dir))
		return 0
	}

	if err := commitClaudeTrust(plan); err != nil {
		fmt.Fprintf(errOut, "snug: %v\n", err)
		return exitInternal
	}
	verb := "updated"
	if plan.created {
		verb = "created"
	}
	fmt.Fprintf(errOut, "snug: %s %s — Claude Code will not ask about %s again, on the host or in a "+
		"snug sandbox for it\n", verb, visibleValue(plan.path), visibleValue(key))
	return 0
}

// describeTrustGrant is the "print what it is granting rather than just doing
// it" half of issue #460, and it prints before the write rather than after so
// that the preview and the write read the same sentences.
//
// It names the file that gains the right to run, because that file IS the
// grant: the dialog's measured job is blocking repo-controlled startup config
// (claudeStateJSON's A/B), so a target that already ships one is the case where
// the human most needs to look before typing -w.
func describeTrustGrant(errOut io.Writer, plan claudeTrustPlan, key string) {
	if plan.created {
		fmt.Fprintf(errOut, "snug: %s does not exist; it would be CREATED, mode 0600, holding only this key\n",
			visibleValue(plan.path))
	} else if plan.write != plan.path {
		fmt.Fprintf(errOut, "snug: %s is a symlink; %s gains one key and every other byte of it "+
			"is preserved\n", visibleValue(plan.path), visibleValue(plan.write))
	} else {
		fmt.Fprintf(errOut, "snug: %s gains one key; every other byte of it is preserved\n",
			visibleValue(plan.path))
	}
	fmt.Fprintf(errOut, "snug: this ANSWERS Claude Code's \"Quick safety check\" for %s, for good, "+
		"on the host and inside every snug sandbox for that directory\n", visibleValue(key))
	fmt.Fprintf(errOut, "snug: from then on that directory's own .claude/settings.json runs at startup with "+
		"nothing asking first — a SessionStart hook there is what the dialog exists to stop, and a "+
		"@claude sandbox holds your Anthropic OAuth token\n")
	for _, name := range projectClaudeSettingsFiles {
		p := filepath.Join(key, ".claude", name)
		if fi, err := os.Lstat(p); err == nil {
			fmt.Fprintf(errOut, "snug: it already ships %s (%d bytes, %s) — read it before granting this\n",
				visibleValue(p), fi.Size(), fi.Mode())
		}
	}
	fmt.Fprintf(errOut, "snug: EXACTLY that path — a subdirectory of it is not trusted by this, and "+
		"neither is its parent\n")
}
