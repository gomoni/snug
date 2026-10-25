// Package hostfacts reads what the host knows about identities: public ssh
// keys, which of them the ssh-agent holds, GitHub logins known to gh, and the
// global git author. It never reads a private key and never writes anything.
//
// Every command goes through a Runner, so tests supply canned output and
// nothing here needs gh, ssh-add or git to be installed.
package hostfacts

import (
	"bytes"
	"context"
	"os"
	"os/exec"
)

// Result is what a command printed.
type Result struct {
	Stdout, Stderr []byte
}

// Runner runs name with args and returns its output. env entries ("K=V") are
// added to the child's environment only. A non-zero exit is returned as an
// error alongside whatever the command printed; exec.ErrNotFound means the
// program is not installed.
type Runner func(ctx context.Context, env []string, name string, args ...string) (Result, error)

// ExecRunner is the Runner that executes the real program. The child has no
// stdin; env is appended to snug-setup's own environment for that child alone.
func ExecRunner(ctx context.Context, env []string, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return Result{Stdout: out.Bytes(), Stderr: errb.Bytes()}, err
}
