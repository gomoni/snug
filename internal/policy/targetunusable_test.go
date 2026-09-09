package policy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryTargetRejectionIsMarkedUnusable enumerates the four ways step 2 of
// Resolve can reject the target, rather than sampling one.
//
// The marker exists for exactly one consumer — internal/cli maps it to exit 64
// instead of 77 (issue #548) — and a consumer that reaches only three of the
// four classes is the failure this shape of bug always takes: `snug ""` and
// `snug /etc/passwd` would keep exiting 77, which tells a caller snug REFUSED A
// POLICY when it did no such thing. Nothing else in the tree names these four
// together, so the enumeration lives here.
func TestEveryTargetRejectionIsMarkedUnusable(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nope"), dangling); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		target string
		says   string
	}{
		{"no target named", "", "no target directory"},
		{"target does not exist", filepath.Join(dir, "missing"), "no such file"},
		{"target cannot be canonicalised", dangling, "no such file"},
		{"target is not a directory", file, "is not a directory"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := Context{Target: tc.target, Home: dir}
			pol, err := Resolve(map[ProfileName]*Profile{}, nil, ctx, OSEnviron{})
			if err == nil {
				t.Fatalf("Resolve accepted %q", tc.target)
			}
			// Resolve's contract: everything but a Validate failure returns a
			// nil policy. A target rejection is never a Validate failure, so a
			// policy coming back here would mean one was assembled over a
			// target snug had already refused.
			if pol != nil {
				t.Errorf("Resolve returned a policy alongside a target rejection")
			}
			if !errors.Is(err, ErrTargetUnusable) {
				t.Errorf("not marked ErrTargetUnusable, so the CLI will exit 77 for a usage error: %v", err)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("message does not say %q: %v", tc.says, err)
			}
		})
	}
}

// TestTheUnusableMarkerChangesNoMessageAndBreaksNoChain is the other half, and
// it is the half a marker gets wrong.
//
// Marking with `fmt.Errorf("%w: ...", ErrTargetUnusable, ...)` would have
// prefixed every one of these messages with "target unusable: ", turning an
// exit-code change into a change to what a user reads. And a marker that does
// not Unwrap would silently break `errors.Is(err, fs.ErrNotExist)` — a
// predicate internal/cli asks about paths, and the exact class of bug
// TestNoProductionCodeUsesANonUnwrappingErrorPredicate exists for (issue #124):
// no compiler error, no vet diagnostic, no test failure, just a wrong answer.
func TestTheUnusableMarkerChangesNoMessageAndBreaksNoChain(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")

	_, err := Resolve(map[ProfileName]*Profile{}, nil, Context{Target: missing, Home: dir}, OSEnviron{})
	if err == nil {
		t.Fatal("Resolve accepted a target that does not exist")
	}

	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the fs chain is broken — errors.Is(err, fs.ErrNotExist) is false: %v", err)
	}
	// The message opens with the target, exactly as it did before the marker.
	if got := err.Error(); !strings.HasPrefix(got, `target "`) {
		t.Errorf("the marker leaked into the message, which must still open with the target: %q", got)
	}
}
