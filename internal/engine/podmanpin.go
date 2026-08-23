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

// podmanpin.go pins the podman bundle snug's own development and integration
// tests are measured against, and gates a binary against that pin (issue
// #384). Re-provisioning the bundle directory at a different tag with no
// check here would silently change what every engine test measures, with no
// failure and no diff.
//
// 5.8.4 is the supported version by maintainer's decision, 2026-08-23. No 6.x
// static local-engine bundle is published — mgoltzsche/podman-static has no
// 6.x tag, and upstream containers/podman's linux assets are the remote client
// only (no conmon/crun/netavark). A later version is a new member of the set
// below, not a rewrite.
//
// THE `v` PREFIX. The GitHub release tag is "v5.8.4"; `podman --version`
// prints the bare form, "podman version 5.8.4". PinnedPodmanBundle.Version
// is the bare form on purpose.

// PinnedPodmanBundle is one supported podman-static bundle.
type PinnedPodmanBundle struct {
	Tag           string // GitHub release tag, "v5.8.4" — note the v
	Version       string // what `podman --version` prints, "5.8.4" — no v
	TarballSHA256 string
	TarballSize   int64
}

// SupportedPodmanBundles is THE authority for which bundles exist: what
// snug's tests are measured against, and the identity the README install
// instructions and .claude/design/PODMAN-STATIC.md's PROVENANCE cross-check
// against. It is not consulted by the per-run gate below, which compares
// versions only — the tarball is ~34MB and re-hashing an installed BINARY on
// every run is out of scope; do not add that to the hot path.
//
// Ship with exactly one member. A second supported version is a maintainer's
// call, added as a second entry here — never as a second slice or constant
// beside it.
var SupportedPodmanBundles = []PinnedPodmanBundle{
	{
		Tag:           "v5.8.4",
		Version:       "5.8.4",
		TarballSHA256: "a58765fe8be6ab3fb79f892f1a027b4ce4a7e8eb589df1ef960c167cbde08d69",
		TarballSize:   33784113,
	},
}

// SupportedPodmanBundle looks up version (podman --version's bare form) in
// SupportedPodmanBundles.
func SupportedPodmanBundle(version string) (PinnedPodmanBundle, bool) {
	for _, b := range SupportedPodmanBundles {
		if b.Version == version {
			return b, true
		}
	}
	return PinnedPodmanBundle{}, false
}

// SupportedPodmanVersions lists every supported bundle's Version, for an
// error message that names the set rather than one member of it.
func SupportedPodmanVersions() []string {
	versions := make([]string, len(SupportedPodmanBundles))
	for i, b := range SupportedPodmanBundles {
		versions[i] = b.Version
	}
	return versions
}

// PinnedPodmanBundleBinary is where a pinned bundle's own podman binary lives
// once extracted, per .claude/design/PODMAN-STATIC.md's layout
// (`tar -xzf … --strip-components=1`): the archive's own `usr/local/bin/podman`
// unpacks directly under root.
func PinnedPodmanBundleBinary(root string) string {
	return filepath.Join(root, "usr", "local", "bin", "podman")
}

// ParsePodmanVersion turns `podman --version`'s stdout into the bare version
// string, or an error naming what it could not parse.
//
// EXACT, on purpose. Measured, `podman --version` on the pinned bundle prints
// exactly "podman version 5.8.4\n" — one line, stdout only, exit 0, ~10ms —
// so this requires precisely three whitespace-separated fields with the
// first two fixed, rather than searching for a substring: a substring match
// would accept "5.8.40", "15.8.4" or "5.8.4-rc1" as if they were "5.8.4".
func ParsePodmanVersion(output string) (string, error) {
	fields := strings.Fields(output)
	if len(fields) != 3 || fields[0] != "podman" || fields[1] != "version" {
		return "", fmt.Errorf("could not parse a podman version out of %q: expected exactly "+
			"\"podman version X.Y.Z\", got %d field(s)", strings.TrimSpace(output), len(fields))
	}
	return fields[2], nil
}

// CheckPodmanVersionSupported parses output (as ParsePodmanVersion does) and
// refuses unless the parsed version is a member of SupportedPodmanVersions(),
// compared with `==` — never strings.Contains, never a prefix, because both
// accept "5.8.40" or "5.8.4-rc1" as if they were "5.8.4".
//
// The two error messages are textually distinguishable — "could not parse"
// versus "is not supported" — so a caller can tell which one fired without
// inspecting anything but the string.
func CheckPodmanVersionSupported(output string) error {
	got, err := ParsePodmanVersion(output)
	if err != nil {
		return err
	}
	return checkVersionSupported(got)
}

// checkVersionSupported is the set-membership check and its message, written
// ONCE: both CheckPodmanVersionSupported and CheckPodmanBinaryVersionSupported
// need it, and a second copy would agree with this one right up until
// somebody changed one of them.
func checkVersionSupported(got string) error {
	if _, ok := SupportedPodmanBundle(got); ok {
		return nil
	}
	return fmt.Errorf("podman version %s is not supported (supported: %s)",
		got, strings.Join(SupportedPodmanVersions(), ", "))
}

// podmanVersionProbeTimeout bounds CheckPodmanBinaryVersionSupported's exec.
// Measured, the real exec is ~10ms; 5s is slack for a loaded box, not a tight
// bound — the same precedent internal/cli/sshconfig.go's sshProbeTimeout sets.
const podmanVersionProbeTimeout = 5 * time.Second

// ProbePodmanBinaryVersion is the ONLY function in this file that execs
// anything; CheckPodmanBinaryVersionSupported and internal/cli's preflight
// reporting both go through it.
//
// THE FLAG, NEVER THE SUBCOMMAND. Measured: on a plainly-extracted bundle,
// `podman version` (the subcommand) fails with "could not find a working
// conmon binary" — it queries the whole helper set — while `podman
// --version` (the flag) answers from the binary alone.
//
// cmd.Env is an empty slice: measured, with a real HOME `podman --version`
// still creates $HOME/.config, and with an empty environment it does not.
// (Not CLAUDE.md's PID-1 rule — this exec never enters a sandbox.) Stdout is
// captured via cmd.Output(); stderr is collected separately for the error
// message.
//
// Returns the parsed version, not pass/fail: preflight only reports it
// ($SNUG_PODMAN may legitimately name a podman newer than any pinned
// bundle — not invariant 5, which is about an unavailable capability, not a
// higher version number), while the test gate compares it against the
// supported set.
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

// CheckPodmanBinaryVersionSupported execs path with --version through
// ProbePodmanBinaryVersion and refuses unless the answer is a member of
// SupportedPodmanVersions().
func CheckPodmanBinaryVersionSupported(path string) error {
	got, err := ProbePodmanBinaryVersion(path)
	if err != nil {
		return err
	}
	return checkVersionSupported(got)
}
