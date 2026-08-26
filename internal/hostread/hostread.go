// Package hostread is snug's one discipline for reading a file it does not
// own: bounded, non-blocking, and refusing anything that is not a regular
// file.
//
// "Does not own" covers three different owners, and the package is named for
// the discipline rather than for any one of them because a fourth is only a
// matter of time: the host user's own dotfiles (~/.claude.json, known_hosts),
// a file the user pointed snug at by name (identity.ssh_key), and a file a
// hostile REPO can influence the location or timing of ($XDG_CONFIG_HOME
// pointed into a checked-out tree, CLAUDE.md invariant 3; a target directory
// under @cwd-rw). A plain os.ReadFile trusts the node at that path to be an
// ordinary file that returns promptly and eventually ends. None of those
// three owners is obliged to honor that: `rm key.pub && mkfifo key.pub`
// (issue #337) turns the read into an open(2) that never returns — no
// output, no sandbox, no exit code — and a symlink to /dev/zero or a sparse
// file turns it into an unbounded host-side allocation. Both measured against
// ~/.claude/settings.json: /dev/zero stats as zero bytes, sailed past a size
// check on the PATH, and took the process to 3.1 GB resident in two seconds,
// still climbing; /proc/self/environ likewise stats as zero and had its
// contents read in full, stopped only by the JSON decode. Which is why the
// cap is the LimitReader and the stat is a cheap early exit for the honest
// case, never the bound.
//
// This package exists because that lesson was learned once, at
// internal/cli/claude.go's loadHostClaudeSettings, and then had to be
// re-learned by measurement at every sibling read before it moved here
// (CLAUDE.md: "a rule written once and applied to one of its two halves").
// The two things it is not: it is not a decision about what a MISSING file
// means — that is the caller's call, and Optional/Required below exist
// because the two answers are genuinely different — and it does not belong
// in internal/policy, which stays pure and touches no filesystem.
package hostread

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// MaxSSHPublicKeyBytes bounds identity.ssh_key. An OpenSSH public key line is
// `<type> <base64-blob> [comment]`; even an RSA-4096 key or an OpenSSH
// certificate (which embeds principals and a CA signature) runs to a few
// KiB. 64 KiB is two orders of magnitude of headroom without being a
// memory-exhaustion primitive on a file read on every agent-proxy run.
// Shared between internal/sshproxy (the proxy's own read)
// and internal/cli (the staged copy for ~/.ssh/config's IdentityFile) because
// both read the identical file for the identical reason.
const MaxSSHPublicKeyBytes = 64 << 10

// read is the shared mechanism: open without blocking on a FIFO, refuse
// anything that is not a regular file, and read at most maxBytes.
//
// Two kinds of failure come back distinctly, because Optional and Required
// below disagree about what to do with each:
//
//   - openErr is whatever os.OpenFile reported — absent (ENOENT), permission
//     denied, too many symlinks, and so on. It is returned RAW, unwrapped,
//     so a caller that wants to distinguish "does not exist" from "exists
//     but I may not read it" can still do so with errors.Is against it,
//     exactly as a caller of os.ReadFile could.
//   - problem is a human-readable reason for a failure that only becomes
//     visible once the file is OPEN: wrong type, oversized, a stat or read
//     that failed outright. It is never about whether the file exists.
//
// problem is a BARE CLAUSE with no subject of its own — "is not a regular
// file", not "it is not a regular file" — so a caller can put its own subject
// in front of it and get one sentence. Clause below hands it over unchanged;
// Optional and Required supply "it" so their existing callers read as before.
func read(path string, maxBytes int64) (data []byte, openErr error, problem string) {
	// O_NONBLOCK applies to the OPEN; for a regular file it has no further
	// effect on the read below. It exists solely so opening a FIFO returns
	// instead of blocking forever — the whole of issue #337.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err, ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Sprintf("could not be inspected (%v)", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Sprintf("is not a regular file (mode %s). snug reads that path as "+
			"data and will not read a FIFO, a device or a directory there", fi.Mode())
	}
	if fi.Size() > maxBytes {
		return nil, nil, fmt.Sprintf("is %d bytes, over the %d-byte cap snug reads for it",
			fi.Size(), maxBytes)
	}
	data, err = io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, fmt.Sprintf("could not be read (%v)", err)
	}
	// The real cap. A file whose st_size lied — /dev/zero through a symlink,
	// anything under /proc, a file that grew since the stat — lands here.
	if int64(len(data)) > maxBytes {
		return nil, nil, fmt.Sprintf("produced more than the %d-byte cap snug reads for it "+
			"(its reported size was %d)", maxBytes, fi.Size())
	}
	return data, nil, ""
}

// Optional reads path the way a file whose ABSENCE is an ordinary state must
// be read: ~/.claude.json (no Claude Code has ever run here), a host
// signature policy (nothing configured), known_hosts (a fresh machine).
// Three returns, and the distinction is load-bearing for every caller today:
//
//   - (nil, "")   ABSENT, or unreadable by permission — nothing to say,
//     nothing to stage or compare against.
//   - (nil, note) PRESENT and wrong — a FIFO, a device, a directory, or over
//     the cap. The caller must say so; this is never silent.
//   - (data, "")  the file, capped at maxBytes.
//
// Do not reach for this when the caller cannot tell "absent" apart from "the
// user explicitly asked for this file" — that is Required, below.
//
// note carries the subject "it", so every existing caller reads as it did.
// Clause is the same read with the subject left out, for a caller that has a
// better one — and at least one does: stageInstalledPlugins renders
// `the host's installed_plugins.json <note>`, which with the pronoun is
// "the host's installed_plugins.json it is not a regular file". That is a
// caller to move to Clause, not a reason to change this wording (issue #342).
func Optional(path string, maxBytes int64) (data []byte, note string) {
	data, clause := Clause(path, maxBytes)
	return data, itIs(clause)
}

// Clause is Optional with the SUBJECT left to the caller: the same three
// states, and a reason phrased as a bare clause — "is not a regular file",
// "is 9000 bytes, over the 4096-byte cap snug reads for it" — so that
// `<subject> <clause>` is one sentence and the caller decides what the
// subject is and what follows.
//
// It exists because a caller that renders onto a screen needs a label and a
// suffix of its own, and that requirement is what kept a second copy of this
// read sequence alive in internal/cli. One sequence, two renderings.
func Clause(path string, maxBytes int64) (data []byte, clause string) {
	data, openErr, problem := read(path, maxBytes)
	if openErr != nil {
		return nil, "" // absent, or unreadable by permission: nothing to stage
	}
	return data, problem
}

// itIs supplies the subject read() deliberately omits. Empty in, empty out:
// "no problem" must not become a sentence.
func itIs(clause string) string {
	if clause == "" {
		return ""
	}
	return "it " + clause
}

// Required reads path the way a file the user (or a profile) NAMED must be
// read: identity.ssh_key, snug's own config.toml, a profiles.d layer. There
// is no silent-skip state here — absent is itself the failure, because the
// caller asked for this specific file and has nothing to degrade to.
//
// err is nil only on success. Every other case names the path (openErr
// already does, via the underlying *fs.PathError; the wrong-type and
// oversized cases below prefix it themselves) and remains distinguishable
// with errors.Is(err, fs.ErrNotExist) exactly as a plain os.ReadFile's error
// would be — config.go depends on that to keep "no config file yet" from
// becoming a fatal error while "a config file that exists but will not read"
// stays one (invariant 5: no silent downgrade).
func Required(path string, maxBytes int64) ([]byte, error) {
	data, openErr, problem := read(path, maxBytes)
	if openErr != nil {
		return nil, openErr
	}
	if problem != "" {
		return nil, fmt.Errorf("%s: %s", path, itIs(problem))
	}
	return data, nil
}
