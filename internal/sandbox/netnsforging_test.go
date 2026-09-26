package sandbox

// Issue #613: pasta's raw stderr is a subprocess output an attacker running
// inside a compromised or malicious pasta build controls, and both
// netHelper.failure (the "pasta exited before the network came up" sink) and
// netHelper.watch (the mid-run "network helper exited" warning) used to
// interpolate it unescaped, unlike every comparable subprocess-stderr site
// elsewhere in this tree.

import (
	"errors"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

func TestNetHelperFailureEscapesAForgingRuneInPastaStderr(t *testing.T) {
	const forged = "FORGED-PASTA-STDERR"
	h := &netHelper{stderr: &strings.Builder{}, done: make(chan struct{})}
	h.stderr.WriteString("bad\n          reclaimed  " + forged + "\x1b[2K")

	msg := h.failure()
	if !strings.Contains(msg, forged) {
		t.Fatalf("the fixture's forged text never reached failure() at all, so this test "+
			"measures nothing: %q", msg)
	}
	if i := strings.IndexFunc(msg, func(r rune) bool { return r != '\n' && policy.IsForgingRune(r) }); i >= 0 {
		t.Errorf("failure() returned a raw control character (%q) from pasta's own stderr:\n%s",
			[]rune(msg[i:])[0], strings.ReplaceAll(msg, "\x1b", "<ESC>"))
	}
	if !strings.Contains(msg, `\n`) {
		t.Errorf("the escaped form of the newline never reached failure(): %q", msg)
	}
}

func TestNetHelperWatchEscapesAForgingRuneInPastaStderr(t *testing.T) {
	const forged = "FORGED-PASTA-WATCH"
	h := &netHelper{stderr: &strings.Builder{}, done: make(chan struct{}), waitErr: errors.New("exit status 1")}
	h.stderr.WriteString("bad\n          reclaimed  " + forged + "\x1b[2K")

	warned := make(chan string, 1)
	h.watch(func(s string) { warned <- s })
	close(h.done)

	msg := <-warned
	if !strings.Contains(msg, forged) {
		t.Fatalf("the fixture's forged text never reached watch()'s warning at all, so this test "+
			"measures nothing: %q", msg)
	}
	if i := strings.IndexFunc(msg, func(r rune) bool { return r != '\n' && policy.IsForgingRune(r) }); i >= 0 {
		t.Errorf("watch()'s warning printed a raw control character (%q) from pasta's own "+
			"stderr:\n%s", []rune(msg[i:])[0], strings.ReplaceAll(msg, "\x1b", "<ESC>"))
	}
	if !strings.Contains(msg, `\n`) {
		t.Errorf("the escaped form of the newline never reached the warning: %q", msg)
	}
}
