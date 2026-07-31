package policy

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Golden argv files are the review artifact for a security change: a diff here
// is a diff in the sandbox's boundary, and it is what a human actually reads
// before approving. Regenerate with `go test ./internal/policy -update`, then
// READ the diff — never update one without saying in the commit what changed.
func TestGoldenBwrapArgs(t *testing.T) {
	cases := []struct {
		name string
		sel  []string
	}{
		{"sys", []string{"sys", "cwd-rw"}},
		// What a bare `snug <dir>` produces: the `defaults` setting. It is
		// byte-identical to the parent-ro case today, because `home` arrives via
		// `cwd-rw` anyway — but this is the file that changes if the shipped
		// defaults ever do, which is the diff a human most needs to see.
		{"defaults", testDefaults},
		{"parent-ro", []string{"sys", "cwd-rw", "parent-ro"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolve(t, tc.sel...)
			got := goldenFormat(p.BwrapArgs(1000, 1000))

			path := filepath.Join("testdata", tc.name+".bwrap.txt")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/policy -update)", err)
			}
			if got != string(want) {
				t.Errorf("argv changed — this is a change to the sandbox boundary.\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

// goldenFormat puts each flag and its operands on one line. The golden file is
// read by a human deciding whether a security change is safe, so it has to be
// legible; one token per line is technically stable and practically useless.
func goldenFormat(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if strings.HasPrefix(a, "--") && i > 0 {
			b.WriteString("\n")
		} else if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(a)
	}
	b.WriteString("\n")
	return b.String()
}

// The argv must be a pure function of the RESOLVED policy, never of the order
// the profiles were named. Emission order comes from the depth sort.
func TestBwrapArgsAreOrderIndependent(t *testing.T) {
	a := mustResolve(t, "sys", "home", "cwd-rw", "parent-ro")
	b := mustResolve(t, "parent-ro", "cwd-rw", "home", "sys")
	if strings.Join(a.BwrapArgs(1000, 1000), " ") != strings.Join(b.BwrapArgs(1000, 1000), " ") {
		t.Error("argv depends on the order profiles were named")
	}
}

// Ancestors must be emitted before descendants, or a read-only parent bind
// shadows the writable child and the sandbox silently loses its project.
func TestParentBindPrecedesChildBind(t *testing.T) {
	p := mustResolveDefaults(t)
	args := p.BwrapArgs(1000, 1000)

	parent, child := -1, -1
	for i, a := range args {
		if a == "/home/u/proj" && i > 0 && args[i-1] == "--ro-bind" {
			parent = i
		}
		if a == "/home/u/proj/sub" && i > 0 && args[i-1] == "--bind" {
			child = i
		}
	}
	if parent < 0 || child < 0 {
		t.Fatalf("expected both binds in argv; parent=%d child=%d", parent, child)
	}
	if parent > child {
		t.Errorf("read-only parent bind is emitted after the writable child; the child would be shadowed")
	}
}

// --remount-ro / must be the LAST filesystem operation, otherwise a later mount
// lands on a read-only root, or the skeleton stays writable.
func TestRemountRoIsLastFilesystemOp(t *testing.T) {
	args := mustResolveDefaults(t).BwrapArgs(1000, 1000)

	remount := -1
	for i, a := range args {
		if a == "--remount-ro" {
			remount = i
		}
	}
	if remount < 0 {
		t.Fatal("--remount-ro / is missing: the root skeleton would be writable")
	}
	fsOps := map[string]bool{
		"--bind": true, "--ro-bind": true, "--bind-try": true, "--ro-bind-try": true,
		"--tmpfs": true, "--symlink": true, "--proc": true, "--dev": true, "--dir": true,
	}
	for i := remount; i < len(args); i++ {
		if fsOps[args[i]] {
			t.Errorf("filesystem op %s at %d comes after --remount-ro / at %d", args[i], i, remount)
		}
	}
}

// --new-session keeps the sandbox from typing into the terminal that launched
// snug, but costs job control. It is worth paying for only where the kernel
// still allows TIOCSTI — and it must be present whenever it does.
func TestNewSessionTracksTIOCSTI(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		ctx := testCtx()
		ctx.LegacyTIOCSTI = legacy

		p, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv())
		if err != nil {
			t.Fatal(err)
		}
		has := slicesContains(p.BwrapArgs(1000, 1000), "--new-session")
		if has != legacy {
			t.Errorf("legacy_tiocsti=%v: --new-session present=%v, want %v", legacy, has, legacy)
		}
	}
}

func slicesContains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// REGRESSION: --seccomp was once appended to the full BwrapArgs, which puts it
// AFTER the `--` separator. bwrap stops parsing flags there, so it took the
// flag as an argument to the payload and installed no filter at all — silently,
// with a zero exit code. Seccomp: 0 in /proc/self/status was the only evidence.
//
// BwrapFlags must therefore contain no separator, so a caller has somewhere
// safe to add flags.
func TestBwrapFlagsHasNoSeparator(t *testing.T) {
	for i, a := range mustResolveDefaults(t).BwrapFlags(1000, 1000, func(string) int { return 9 }) {
		if a == "--" {
			t.Fatalf("BwrapFlags contains a `--` separator at %d; anything a caller appends "+
				"after it would be passed to the payload instead of to bwrap", i)
		}
	}
}

// And the full form must still end with the separator followed by the command,
// because that is what --dry-run shows and what the golden files record.
func TestBwrapArgsEndsWithSeparatorThenCommand(t *testing.T) {
	args := mustResolveDefaults(t).BwrapArgs(1000, 1000)
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatal("no `--` separator in BwrapArgs")
	}
	if got := strings.Join(args[sep+1:], " "); got != "/bin/sh" {
		t.Errorf("command after separator = %q, want /bin/sh", got)
	}
}

// The sandbox is offline in M0, and that must be visible in the argv rather
// than assumed: --unshare-all with no --share-net means a netns with only lo.
func TestSandboxIsOffline(t *testing.T) {
	args := mustResolveDefaults(t).BwrapArgs(1000, 1000)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--unshare-all") {
		t.Error("--unshare-all missing: the sandbox would share the host's namespaces")
	}
	if strings.Contains(joined, "--share-net") {
		t.Error("--share-net present: the sandbox would reach the host's loopback")
	}
}
