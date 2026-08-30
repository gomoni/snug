package cli

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// fakeLook stands in for exec.LookPath so the table below does not depend on
// what this machine has in $PATH. A pager test that passes on a developer's
// box and fails in CI because the image ships no `less` is a test about the
// image, not about the decision.
func fakeLook(have ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		if slices.Contains(have, name) {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

// fakeLookup is os.LookupEnv's shape over a fixed map, so a row saying "PAGER
// unset" really means unset. The first draft injected os.Getenv's shape and
// fell back to the real environment for the empty case; on a developer box
// with PAGER=less in it, four rows of this table passed while asserting
// nothing.
func fakeLookup(kv map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := kv[k]
		return v, ok
	}
}

// TestPagerCmd pins the whole decision, because every arm of it is a place a
// human loses output they asked for. The two that matter most are the
// negatives: a non-tty and TERM=dumb must yield NO pager, or `snug --dry-run |
// grep` and every test in this package starts talking to `less`.
func TestPagerCmd(t *testing.T) {
	tests := []struct {
		name  string
		env   map[string]string
		have  []string
		isTTY bool
		want  []string
	}{
		{
			name:  "not a terminal: never a pager",
			env:   map[string]string{"TERM": "xterm-256color", "PAGER": "less"},
			have:  []string{"less", "more"},
			isTTY: false,
			want:  nil,
		},
		{
			name:  "TERM=dumb: no pager even on a tty",
			env:   map[string]string{"TERM": "dumb", "PAGER": "less"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  nil,
		},
		{
			name:  "TERM unset: no pager",
			env:   map[string]string{"PAGER": "less"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  nil,
		},
		{
			name:  "PAGER with arguments: resolved here, not handed to a shell",
			env:   map[string]string{"TERM": "xterm", "PAGER": "less -R"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  []string{"/usr/bin/less", "-R"},
		},
		{
			// The typo. Under `sh -c` this starts successfully and fails
			// afterwards as a broken pipe, which is indistinguishable from a
			// human quitting the pager — and cost the whole screen. Resolving
			// the name here answers it before anything runs.
			name:  "PAGER names a command this host does not have: no pager, not a lost screen",
			env:   map[string]string{"TERM": "xterm", "PAGER": "nonexistent-pager-xyz"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  nil,
		},
		{
			// Shell syntax really does need a shell, and snug does not try to
			// resolve it. writeThroughPager's exit-127 arm covers this path.
			name:  "PAGER carrying shell syntax still goes through sh",
			env:   map[string]string{"TERM": "xterm", "PAGER": "less -R | tee /tmp/x"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  []string{"/bin/sh", "-c", "less -R | tee /tmp/x"},
		},
		{
			name:  "PAGER empty: the documented way to turn paging off",
			env:   map[string]string{"TERM": "xterm", "PAGER": ""},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  nil,
		},
		{
			name:  "PAGER whitespace only: same as empty, not an sh -c of nothing",
			env:   map[string]string{"TERM": "xterm", "PAGER": "   "},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  nil,
		},
		{
			name:  "PAGER=cat: the other documented way off",
			env:   map[string]string{"TERM": "xterm", "PAGER": "cat"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  nil,
		},
		{
			name:  "no PAGER: less is preferred",
			env:   map[string]string{"TERM": "xterm"},
			have:  []string{"less", "more"},
			isTTY: true,
			want:  []string{"/usr/bin/less"},
		},
		{
			name:  "no PAGER, no less: more",
			env:   map[string]string{"TERM": "xterm"},
			have:  []string{"more"},
			isTTY: true,
			want:  []string{"/usr/bin/more"},
		},
		{
			name:  "no PAGER, neither on PATH: write direct rather than fail",
			env:   map[string]string{"TERM": "xterm"},
			have:  nil,
			isTTY: true,
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pagerCmd(fakeLookup(tt.env), fakeLook(tt.have...), tt.isTTY)
			if !slices.Equal(got, tt.want) {
				t.Errorf("pagerCmd() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPagerEnvKeepsLESSWhenSet is the half of git's rule that is easy to drop:
// FRX is a DEFAULT, not an override. A human who set LESS themselves has said
// what they want, and snug replacing it is the "no silent downgrade" shape
// aimed at ergonomics.
func TestPagerEnvKeepsLESSWhenSet(t *testing.T) {
	got := pagerEnv([]string{"TERM=xterm", "LESS=SR"})
	if slices.Contains(got, "LESS=FRX") {
		t.Errorf("pagerEnv overrode a LESS the human set: %q", got)
	}
	if !slices.Contains(got, "LESS=SR") {
		t.Errorf("pagerEnv dropped LESS=SR: %q", got)
	}
}

func TestPagerEnvAddsLESSWhenUnset(t *testing.T) {
	got := pagerEnv([]string{"TERM=xterm"})
	if !slices.Contains(got, "LESS=FRX") {
		t.Errorf("pagerEnv did not default LESS=FRX: %q", got)
	}
}

// TestWithPagerFallsBackWhenPagerCannotStart is the invariant that outranks
// paging itself: --dry-run is the artifact a human uses to decide whether to
// trust snug, so a pager that will not exec must cost them the paging, never
// the screen.
func TestWithPagerFallsBackWhenPagerCannotStart(t *testing.T) {
	var buf bytes.Buffer
	err := writeThroughPager(&buf, []string{"/nonexistent/pager/binary"}, nil, func(w io.Writer) error {
		_, werr := w.Write([]byte("the screen\n"))
		return werr
	})
	if err != nil {
		t.Fatalf("writeThroughPager returned %v; a dead pager must not fail the run", err)
	}
	if buf.String() != "the screen\n" {
		t.Errorf("output lost when the pager could not start: %q", buf.String())
	}
}

// TestAFailingPagerNeverCostsTheScreen is the permanent regression test for a
// defect this change shipped THREE broken fixes for, each narrower than the
// property it claimed to enforce.
//
//	cmd.Start only          — /bin/sh starts fine; the SHELL fails to exec.
//	counting consumed bytes — the 64 KiB pipe absorbs them either way.
//	exit == 127 only        — catches "could not exec", not "displayed nothing".
//
// MEASURED against a 13847-byte `--dry-run` screen on a real terminal, at the
// exit-127 revision: `PAGER=nonexistent-pager-xyz` delivered all 13847 bytes,
// and `PAGER=false` delivered 0 under exit 0 — the trust artifact silently
// replaced by an empty terminal.
//
// The sizes here are the ones the product actually produces (a real screen is
// 2-14 KiB, comfortably inside one pipe buffer). An earlier version of this
// test used a 220000-byte fixture reasoning that a smaller one "would pass
// against the broken code"; that reasoning fitted the byte-counting revision
// and not the product, so the test exercised a size no screen has while the
// real path stayed broken.
func TestAFailingPagerNeverCostsTheScreen(t *testing.T) {
	tests := []struct {
		name string
		argv []string
	}{
		{"a pager that cannot be exec'd at all", []string{"/nonexistent/pager/binary"}},
		{"a shell that cannot exec the pager (exit 127)", []string{"/bin/sh", "-c", "exec nonexistent-pager-xyz"}},
		{"a pager that just exits non-zero", []string{"/bin/false"}},
		{"a pager killed by a signal (ExitCode is -1)", []string{"/bin/sh", "-c", "kill -SEGV $$"}},
		{"a pager that fails after reading part of the screen", []string{"/bin/sh", "-c", "head -c 100 >/dev/null; exit 3"}},
	}
	// A realistic screen size, not a synthetic one.
	screen := strings.Repeat("FILESYSTEM  (deny-by-default; every line is a grant)\n", 200)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeThroughPager(&buf, tt.argv, nil, func(w io.Writer) error {
				_, werr := w.Write([]byte(screen))
				return werr
			})
			if err != nil {
				t.Fatalf("writeThroughPager returned %v; a pager that fails must not fail the run", err)
			}
			if !strings.HasSuffix(buf.String(), screen) {
				t.Errorf("a failing pager cost the human the screen: %d of %d bytes reached the "+
					"output. --dry-run is the artifact snug is trusted through; a pager that "+
					"does not work may cost the paging and never the screen",
					buf.Len(), len(screen))
			}
		})
	}
}

// TestPagerQuitEarlyIsNotAFailure is the other side of the same bit, and it is
// what stops the fix above from becoming "print the screen twice". A human who
// quits the pager after one page has READ something; reprinting the whole
// screen behind the pager they just closed is the annoyance the buffer exists
// to avoid. `head -1` is that shape: it consumes a little, then exits and
// drops the pipe.
func TestPagerQuitEarlyIsNotAFailure(t *testing.T) {
	var buf bytes.Buffer
	screen := strings.Repeat("the screen\n", 20000)
	err := writeThroughPager(&buf, []string{"/bin/sh", "-c", "head -1"}, nil,
		func(w io.Writer) error {
			_, werr := w.Write([]byte(screen))
			return werr
		})
	if err != nil {
		t.Fatalf("writeThroughPager returned %v for a pager the human quit early", err)
	}
	if buf.Len() >= len(screen) {
		t.Errorf("quitting the pager early reprinted the whole screen (%d bytes of %d). The "+
			"fallback is for a pager that consumed NOTHING, not for one the human closed",
			buf.Len(), len(screen))
	}
	if buf.Len() == 0 {
		t.Error("the pager consumed the screen but none of its output reached the stream")
	}
}

// TestWithPagerReportsRenderError keeps the OTHER direction honest: a renderer
// that fails is a real error and must not be swallowed by the pager plumbing.
func TestWithPagerReportsRenderError(t *testing.T) {
	var buf bytes.Buffer
	want := errors.New("renderer said no")
	err := writeThroughPager(&buf, nil, nil, func(w io.Writer) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Errorf("writeThroughPager() = %v, want %v", err, want)
	}
}
