package engine

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// podmanpin.go pins the version of the podman bundle snug's own development
// and integration tests are measured against, and checks a binary against
// that pin.
//
// WHY THIS CONSTANT EXISTS (issue #384). The bundle at
// PinnedPodmanBundleBinary was pinned ON DISK — a tarball, a signature, a
// PROVENANCE file (.claude/design/PODMAN-STATIC.md) — but asserted NOWHERE IN
// CODE. Re-provisioning that directory at a different tag silently changed
// what every engine test measured, with nothing to notice: no failure, no
// diff, just a different podman answering every "does the engine start"
// question from then on. The constant below and the checks built on it are
// what make a mismatch a loud, named failure instead of a fact nobody wrote
// down.
//
// WHY 5.8.4 AND NOT 6.x, measured 2026-08-23. There is no 6.x STATIC
// LOCAL-ENGINE bundle to pin, from either supplier: mgoltzsche/podman-static's
// newest tag is v5.8.4, and its podman-6 pull request (#168, "feat: podman
// 6.0.0") is open and unmerged; upstream containers/podman does publish 6.x
// (v6.1.0) but its only linux assets are podman-remote-static-linux_* — the
// REMOTE CLIENT, with no conmon/crun/netavark, so it cannot serve this
// project's engine at all. A 6.x pin needs a new supplier, which is a
// maintainer's call, not a version bump — deferred. Bumping the pin, when it
// happens, is a one-line change to the constant below.
//
// THE `v` PREFIX TRAP. The GitHub release tag for this bundle is `v5.8.4`;
// `podman --version` prints the BARE form, "podman version 5.8.4". The
// constant below is the bare form on purpose — do not "correct" it to match
// the tag spelling, or every comparison against a real binary's output fails.
const PinnedPodmanBundleVersion = "5.8.4"

// PinnedPodmanBundleBinary is where the pinned bundle's own podman binary
// lives once extracted, per .claude/design/PODMAN-STATIC.md's layout
// (`tar -xzf … --strip-components=1`): the archive's own `usr/local/bin/podman`
// unpacks directly under root.
func PinnedPodmanBundleBinary(root string) string {
	return filepath.Join(root, "usr", "local", "bin", "podman")
}

// ParsePodmanVersion is the pure half: it turns `podman --version`'s stdout
// into the bare version string, or an error naming what it could not parse.
//
// EXACT, on purpose. Measured, `podman --version` on the pinned bundle prints
// exactly "podman version 5.8.4\n" — one line, stdout only, exit 0, ~10ms —
// so this splits on whitespace and requires precisely three fields with the
// first two fixed, rather than searching for a substring. A substring or
// prefix match would accept "5.8.40", "15.8.4" or "5.8.4-rc1" as if they were
// "5.8.4"; splitting into fields and comparing the whole third one with `==`
// (in CheckPodmanVersion, not here) is what rejects them.
func ParsePodmanVersion(output string) (string, error) {
	fields := strings.Fields(output)
	if len(fields) != 3 || fields[0] != "podman" || fields[1] != "version" {
		return "", fmt.Errorf("could not parse a podman version out of %q: expected exactly "+
			"\"podman version X.Y.Z\", got %d field(s)", strings.TrimSpace(output), len(fields))
	}
	return fields[2], nil
}

// CheckPodmanVersion is the pure half of the gate: it parses output (as
// ParsePodmanVersion does) and refuses unless the parsed version is EXACTLY
// want, compared with `==` — never strings.Contains, never a prefix, because
// both accept "5.8.40" or "5.8.4-rc1" as if they were "5.8.4".
//
// The two error messages below are worded to be textually distinguishable —
// "could not parse" versus "does not match" — so a test can assert which one
// fired without inspecting anything but the string.
func CheckPodmanVersion(output, want string) error {
	got, err := ParsePodmanVersion(output)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("podman version %s does not match the pinned %s", got, want)
	}
	return nil
}

// podmanVersionProbeTimeout bounds CheckPodmanBinaryVersion's exec. Measured,
// the real exec is ~10ms; 5s is slack for a loaded box, not a tight bound —
// the same precedent internal/cli/sshconfig.go's sshProbeTimeout sets.
const podmanVersionProbeTimeout = 5 * time.Second

// ProbePodmanBinaryVersion is the ONLY function in this file that execs
// anything, and it is the ONLY place the decisions below are made. Both
// callers — CheckPodmanBinaryVersion here, and internal/cli's preflight
// reporting — go through it, because they need the same three measured
// choices and a second copy of them would agree with this one right up until
// somebody changed one of them.
//
// THE FLAG, NEVER THE SUBCOMMAND. Measured: on a plainly-extracted bundle,
// `podman version` (the subcommand) fails with "Error: could not find a
// working conmon binary", because the subcommand queries the whole helper
// set, while `podman --version` (the flag) answers cleanly from the binary
// alone. A gate built on the subcommand would fail on exactly the minimal
// install .claude/design/PODMAN-STATIC.md §3 documents.
//
// cmd.Env is set to an empty slice, and the reason is NOT CLAUDE.md's PID-1
// rule (that rule is about a helper joining the SANDBOX's namespaces; this
// exec never enters a sandbox at all). The measured reason here is different:
// with a real, writable HOME, `podman --version` still creates
// $HOME/.config; with an empty environment it answers identically and writes
// nothing. Empty env is the only one of the three tried with no side effect
// on a real directory.
//
// Captures stdout only (cmd.Output()) and collects stderr separately for the
// error message, without requiring it to be empty — podman's own stderr
// chatter on a working binary is not this function's business.
//
// It returns the PARSED VERSION rather than a pass/fail, because its two
// callers want different things from the same measurement: the test gate
// compares against the pin and fails, while preflight only reports, since
// $SNUG_PODMAN may legitimately name a newer podman than the pinned bundle
// and newer is not a downgrade under invariant 5.
func ProbePodmanBinaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), podmanVersionProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("running %s --version: %s", path, detail)
	}
	return ParsePodmanVersion(string(out))
}

// CheckPodmanBinaryVersion execs path with --version through
// ProbePodmanBinaryVersion and refuses unless the answer is EXACTLY want.
//
// The exec discipline lives in ProbePodmanBinaryVersion, deliberately: this
// function exists so a caller that wants a gate rather than a reading does
// not restate the flag, the environment or the timeout.
func CheckPodmanBinaryVersion(path, want string) error {
	got, err := ProbePodmanBinaryVersion(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("podman version %s does not match the pinned %s", got, want)
	}
	return nil
}
