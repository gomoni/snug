//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheWritableSurfaceIsExactlyTheseNinePaths enumerates every mount inside
// an ORDINARY default sandbox that carries the "rw" option, read from
// /proc/self/mounts, and requires the result to be exactly the writable
// surface a human deciding to trust snug is entitled to expect.
//
// NINE IS ITSELF THE FINDING. The document that counted this surface by hand,
// .claude/agents/sandbox-policy.md's shadow-slot rule, said EIGHT: {home},
// {home}/.cache, {home}/.config, {home}/.local/share, {home}/.local/state,
// the target, /dev/shm and /tmp — eight — and measured here, a ninth path,
// {home}/.local, is ALSO in the surface on every run that selects @home.
// @home's own tmpfs list (internal/profile/profiles/base.toml) never names
// {home}/.local itself, only its two children two levels down, but
// InstallAnchors (internal/policy/anchor.go, issue #553) mounts an empty,
// writable tmpfs at every ancestor of a mount whose deepest cover is itself a
// tmpfs, precisely so a payload cannot rename a granted path out from under
// its own mount — and {home}/.local is exactly such an ancestor. This is the
// SAME shape the doc comment on
// TestHomeTmpfsListIsPinnedToTheDocumentsQuotingIt already names happening
// once before ("said SEVEN for a milestone after @home grew
// {home}/.local/share"): a hand-count goes stale the moment the tree it
// describes grows a level, and nothing but eyes were checking it.
// sandbox-policy.md now says nine and names the anchor mechanism as the
// reason a list derived from base.toml will always be one short. This test
// is what replaces the eyes.
//
// THE TARGET IS ROOTED ONE os.MkdirTemp LEVEL DIRECTLY UNDER /tmp, not
// t.TempDir()'s own nested pair of directories and not target()'s deeper
// root/proj/sub shape. Both of those would add their OWN anchor rows for
// their own extra path depth — real per InstallAnchors' rule, but a property
// of the fixture rather than of the sandbox, which would make "exactly nine"
// false for a reason that has nothing to do with policy. Placing the target
// directly under /tmp means its own immediate parent is /tmp itself, already
// a mount, so InstallAnchors' "not itself a mount" condition excludes it and
// the target contributes no anchor of its own — measured directly before
// writing this assertion, both with and without the extra directory levels.
//
// /proc and bwrap's synthetic /dev device nodes (full, null, pts, random,
// tty, urandom, zero — individual rw binds of the host's own copies, not
// files a payload can put content into) are excluded deliberately. /dev
// itself does not appear at all: bwrap.go's KindDev arm remounts its root
// read-only immediately after creating it (issue #281), which is the half
// sandbox-policy.md got wrong in the other direction — it listed /dev as
// writable and omitted /dev/shm.
//
// PROBE-RAN is the positive control: without it, an enumeration that came back
// empty — because the sandbox never started, or the payload never reached the
// awk line — would read as a pass rather than as the vacuous non-result it is.
func TestTheWritableSurfaceIsExactlyTheseNinePaths(t *testing.T) {
	budget(t)
	requireSandbox(t)

	dir, err := os.MkdirTemp("/tmp", "snug-writable-surface-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	home, err := filepath.EvalSymlinks(os.Getenv("HOME"))
	if err != nil {
		t.Fatalf("resolving $HOME: %v", err)
	}

	r := run(t, nil, dir, `awk '$4 ~ /^rw(,|$)/ {print $2}' /proc/self/mounts | sort -u
echo PROBE-RAN`).mustRun(t)

	if !strings.Contains(r.out, "PROBE-RAN") {
		t.Fatalf("PROBE-RAN never printed, so an empty (or truncated) enumeration below would "+
			"read as a pass on a sandbox that never actually walked /proc/self/mounts:\n%s", r.out)
	}

	excludedDev := map[string]bool{
		"/dev/full": true, "/dev/null": true, "/dev/pts": true, "/dev/random": true,
		"/dev/tty": true, "/dev/urandom": true, "/dev/zero": true,
	}

	got := map[string]bool{}
	for _, line := range strings.Split(r.out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "", line == "PROBE-RAN", line == "/proc", excludedDev[line]:
			continue
		}
		got[line] = true
	}

	want := map[string]bool{
		home:                   true,
		home + "/.cache":       true,
		home + "/.config":      true,
		home + "/.local":       true, // the anchor — see the doc comment above
		home + "/.local/share": true,
		home + "/.local/state": true,
		dir:                    true,
		"/dev/shm":             true,
		"/tmp":                 true,
	}

	for p := range want {
		if !got[p] {
			t.Errorf("%s is not in the sandbox's writable surface; a grant went missing "+
				"or narrower than documented", p)
		}
	}
	for p := range got {
		if !want[p] {
			t.Errorf("%s IS writable inside the sandbox and is not one of the paths this test "+
				"knows to expect — either a grant went wider than .claude/agents/sandbox-policy.md's "+
				"writable-surface bullet documents, or this test's own expected set needs the "+
				"same kind of update {home}/.local just got", p)
		}
	}
}
