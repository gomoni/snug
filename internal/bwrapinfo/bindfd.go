package bwrapinfo

import (
	"fmt"
	"os/exec"
	"strings"
)

// bindFDFlags are the two spellings snug emits for a grant opened by
// descriptor (policy.BwrapFlags).
var bindFDFlags = []string{"--ro-bind-fd", "--bind-fd"}

// RequireBindFD reports whether the bubblewrap at path lists --ro-bind-fd and
// --bind-fd in its --help. snug binds every grant outside /proc by descriptor,
// so a bwrap without them cannot run any sandbox, and the failure it would
// otherwise produce is an option-parse error from inside a run.
//
// A non-nil error is the refusal text: it names the missing flag and what to
// do. Failing to run bwrap --help at all is also an error, with bwrap's own
// output attached, never a pass.
func RequireBindFD(path string) error {
	out, err := exec.Command(path, "--help").CombinedOutput()
	if err != nil && len(out) == 0 {
		return fmt.Errorf("running `%s --help` to check for --ro-bind-fd: %w", path, err)
	}
	return checkBindFDHelp(string(out))
}

func checkBindFDHelp(help string) error {
	listed := map[string]bool{}
	for line := range strings.SplitSeq(help, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			listed[f[0]] = true
		}
	}
	for _, flag := range bindFDFlags {
		if !listed[flag] {
			return fmt.Errorf("this bubblewrap does not support %s; snug binds grants by "+
				"descriptor (issue #637); upgrade bubblewrap", flag)
		}
	}
	return nil
}
