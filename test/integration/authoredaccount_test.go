//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// authoredAccount builds the root a harness needs when it runs snug inside a
// user namespace of its own making (a raw `bwrap` or `unshare`) to test
// something that is not the account lookup.
//
// snug reads the account's name and home directory from a root-owned getent on
// the host. In a user namespace the process's uid maps to one id and the host's
// root-owned files show as the overflow uid, so no getent there is trustworthy
// and snug only accepts the one other source it can verify: the single-line
// /etc/passwd and /etc/group that a snug sandbox itself has (the N2 rule in
// internal/getent: the files are regular, owned by the inner uid, on a
// read-only tmpfs mount on the same device as a tmpfs root, and hold exactly
// one line for this uid and gid). A harness that wraps snug in a bare
// namespace therefore gets "this is a user namespace but not a snug sandbox",
// which is the refusal working. This builds a root that really has that shape
// rather than teaching snug a way around it: the rest of the host is bound back
// in, /etc/passwd and /etc/group are bwrap data binds, and the root is
// remounted read-only.
//
// The account is named snugtest and its home is this process's $HOME, which
// stays the real directory the host binds back, so snug's check that $HOME is
// the account's home passes honestly rather than by a fixture.
//
// What it does NOT prove: that the inner snug took the authored source. Each
// caller asserts that itself from the inner snug's own account line
// (wantAuthoredSource), because a harness that silently fell back to getent
// would pass every other assertion unchanged.
type authoredAccount struct {
	// Root binds every top-level directory of the host back in, symlinks as
	// symlinks, except /proc and /dev, which the caller mounts to suit its own
	// pid namespace.
	Root []string
	// Account is the two data binds, the authored system ssh_config and the
	// read-only remount of the root. It must come after every other mount so
	// nothing is bound over the files.
	Account []string

	passwd, group string
}

// fromSnugAuthoredSource is the text of the inner snug's account line when it
// read the generated files.
const fromSnugAuthoredSource = "(from snug's generated /etc/passwd)"

func newAuthoredAccount(t *testing.T) authoredAccount {
	t.Helper()
	home := os.Getenv("HOME")
	if home == "" {
		t.Fatal("HOME is unset, so there is no account home directory to author")
	}
	dir := t.TempDir()
	a := authoredAccount{
		passwd: filepath.Join(dir, "passwd"),
		group:  filepath.Join(dir, "group"),
	}
	pw := fmt.Sprintf("snugtest:x:%d:%d:snugtest:%s:/bin/sh\n", os.Getuid(), os.Getgid(), home)
	gr := fmt.Sprintf("snugtest:x:%d:\n", os.Getgid())
	if err := os.WriteFile(a.passwd, []byte(pw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.group, []byte(gr), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := "/" + e.Name()
		if name == "/proc" || name == "/dev" {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(name)
			if err != nil {
				t.Fatal(err)
			}
			a.Root = append(a.Root, "--symlink", target, name)
			continue
		}
		if e.IsDir() {
			a.Root = append(a.Root, "--bind", name, name)
		}
	}
	a.Account = []string{
		"--ro-bind-data", "3", "/etc/passwd",
		"--ro-bind-data", "4", "/etc/group",
	}
	// A snug sandbox replaces the system-wide ssh_config with one it authors,
	// because the host's is root-owned and reads as 65534 here, where one uid
	// is mapped: the host's ssh then refuses it (measured: "Bad owner or
	// permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf", exit 255), and
	// the inner snug refuses the run when its ssh probe fails (#688). The
	// harness authors one too, owned by this uid and with no Include, so the
	// root has the shape a snug sandbox has.
	sshConfig := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(sshConfig, []byte("# authored by the integration harness\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range policy.SystemSSHConfigPaths {
		if _, err := os.Stat(p); err == nil {
			a.Account = append(a.Account, "--ro-bind", sshConfig, p)
		}
	}
	a.Account = append(a.Account, "--remount-ro", "/")
	return a
}

// Files opens the two data files afresh, to be set as exec.Cmd.ExtraFiles so
// they arrive as descriptors 3 and 4. Fresh per command: bwrap reads each to
// the end, and a descriptor shared by two commands would be empty for the
// second.
func (a authoredAccount) Files(t *testing.T) []*os.File {
	t.Helper()
	var fs []*os.File
	for _, p := range []string{a.passwd, a.group} {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		fs = append(fs, f)
	}
	return fs
}

// ShellRedirects is Files for a command line run by sh: it opens the same two
// files as descriptors 3 and 4 of that one command.
func (a authoredAccount) ShellRedirects() string {
	return "3<" + shQuote(a.passwd) + " 4<" + shQuote(a.group)
}

// wantAuthoredSource fails unless out carries the inner snug's account line
// naming the generated files as the source: the control that makes this
// harness's other assertions mean something.
func wantAuthoredSource(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "account: snugtest, home ") || !strings.Contains(out, fromSnugAuthoredSource) {
		t.Fatalf("control: the inner snug did not report reading the generated /etc/passwd "+
			"(want an `account: snugtest, home ... %s` line), so the harness did not take effect "+
			"and nothing below tests what it says:\n%s", fromSnugAuthoredSource, out)
	}
}
