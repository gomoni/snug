package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// TestMain exists for ONE reason: preflightResolvConfBind re-execs
// /proc/self/exe with the hidden `__probebind` verb, and under `go test`
// /proc/self/exe is the TEST binary, not snug. Without this dispatch the child
// ignores the verb and runs the whole test suite again — which re-enters this
// probe, which forks another suite. That is not a hypothetical: it was measured
// as a fork bomb that hung the run until the timeout killed the tree.
//
// So the test binary answers the verb exactly as internal/cli's Main does, and
// the probe under test is the real one rather than a stub.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__probebind" {
		if err := probeBindResolvConf(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestPreflightResolvConfBindAsksTheHostAndAnswersByName is preflight P7. It
// cannot assert an outcome — whether a file can be bound over
// /etc/resolv.conf is a property of the HOST, and both answers are legitimate
// (this development host says no, issue #128; CI says yes) — so it asserts
// that the probe actually got to ASK, and that whichever answer it gives is
// legible.
//
// CONTROL, and the reason this is not a test that cannot fail: the probe's own
// two failure modes are distinguishable by name. "making / private" means the
// child never reached the question — its user namespace was not created, the
// probe machinery is broken — and that is a FAILURE here. "mounting a file
// over /etc/resolv.conf" means the child asked and the host said no, which is
// the answer P7 exists to collect. A probe that silently returned the machinery
// error as the host's answer would warn every user on every host, and this
// assertion is what stops that shipping.
func TestPreflightResolvConfBindAsksTheHostAndAnswersByName(t *testing.T) {
	err := preflightResolvConfBind()
	if err == nil {
		t.Log("P7: this host CAN bind over /etc/resolv.conf")
		return
	}

	// THE THIRD OUTCOME, and it is not a failure of either the host or the
	// probe: some hosts cannot create the throwaway user namespace at all —
	// CI's unit-test container is one, where the child never starts and the
	// error is "fork/exec /proc/self/exe: permission denied". The probe did
	// not ASK, so there is no answer to grade. What IS graded is that snug
	// classified it that way rather than reporting it as the host's answer,
	// which is what the caller keys on to stay silent.
	var unavailable *probeUnavailableError
	if errors.As(err, &unavailable) {
		t.Skipf("SKIP: P7 cannot run its probe on this host (no throwaway user namespace): %v", err)
	}

	msg := err.Error()
	t.Logf("P7: this host CANNOT bind over /etc/resolv.conf: %s", msg)

	if strings.Contains(msg, "making / private") {
		t.Fatalf("the probe never reached its question: the child could not make its own tree "+
			"private, so one of the two namespaces it asked for was not created and this is the "+
			"probe machinery failing, not the host answering. P7 would then warn on every "+
			"host: %s", msg)
	}
	if !strings.Contains(msg, "/etc/resolv.conf") {
		t.Errorf("P7's answer does not name what stopped working — it reports an errno and "+
			"leaves the reader to guess (CLAUDE.md, 'errors name the fix'): %s", msg)
	}
}

// TestProbeBindRefusesWithoutAFile: the hidden verb is reachable from a shell,
// so it must refuse a malformed invocation rather than doing something
// undefined with whatever argv happens to hold.
func TestProbeBindRefusesWithoutAFile(t *testing.T) {
	for _, argv := range [][]string{nil, {}, {""}, {"a", "b"}} {
		if err := probeBindResolvConf(argv); err == nil {
			t.Errorf("__probebind accepted argv %q", argv)
		}
	}
}

// TestP7DoesNotDisturbTheHostsOwnResolvConf: the probe mounts inside a
// throwaway user + mount namespace whose tree it makes MS_PRIVATE first, so the
// host's own /etc/resolv.conf must read identically before and after — and the
// probe's temporary file must not survive it.
func TestP7DoesNotDisturbTheHostsOwnResolvConf(t *testing.T) {
	// The probe's own temporary file goes here, so the leftover check below
	// sees THIS probe's litter and not some other run's — os.CreateTemp("")
	// honours $TMPDIR.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	before, errBefore := os.ReadFile("/etc/resolv.conf")

	_ = preflightResolvConfBind()

	after, errAfter := os.ReadFile("/etc/resolv.conf")
	if (errBefore == nil) != (errAfter == nil) {
		t.Fatalf("the probe changed whether /etc/resolv.conf is readable: %v then %v", errBefore, errAfter)
	}
	if errBefore == nil && string(before) != string(after) {
		t.Errorf("the probe changed the HOST's /etc/resolv.conf — its mount escaped the throwaway "+
			"namespace:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "snug-resolvbind-probe-") {
			t.Errorf("the probe left %s behind in %s", e.Name(), tmp)
		}
	}
}

// TestPreflightToolchainRootNamesRatherThanGuesses is P9, and every case here
// is one of the ways a derived answer would have been wrong.
//
// The positive control is first and is the whole reason the refusals below
// mean anything: a root that DOES contain the resolved engine is returned
// unchanged, so a test that only checked refusals could not tell "this
// refuses correctly" from "this refuses everything".
func TestPreflightToolchainRootNamesRatherThanGuesses(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "usr", "local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	podman := filepath.Join(binDir, "podman")
	if err := os.WriteFile(podman, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// CONTROL: the engine really is inside the named root — accepted.
	t.Setenv("SNUG_PODMAN_ROOT", root)
	got, err := preflightToolchainRoot(policy.OSEnviron{}, podman)
	if err != nil {
		t.Fatalf("control: a root that contains the resolved engine was refused, so every "+
			"refusal below could be refusing for the wrong reason: %v", err)
	}
	if got != root {
		t.Fatalf("control: got %q, want the named root %q", got, root)
	}

	// UNSET: empty, and NOT an error. This is the ordinary host — a
	// distribution podman in /usr/bin, which @sys already exposes, so G4's
	// first disjunct answers and there is nothing to record.
	t.Setenv("SNUG_PODMAN_ROOT", "")
	if got, err := preflightToolchainRoot(policy.OSEnviron{}, "/usr/bin/podman"); err != nil || got != "" {
		t.Errorf("with $SNUG_PODMAN_ROOT unset: got (%q, %v), want (\"\", nil) — an engine the "+
			"sandbox's own grants already expose needs no toolchain root, and making this a "+
			"failure would refuse a configuration that works", got, err)
	}

	// THE ONE CHECK THAT CAN BE MADE: a root that does not contain the engine.
	// Its symptom would otherwise be an engine that cannot exec, several
	// seconds later, inside a namespace nobody can look into.
	other := t.TempDir()
	t.Setenv("SNUG_PODMAN_ROOT", other)
	_, err = preflightToolchainRoot(policy.OSEnviron{}, podman)
	if err == nil {
		t.Fatalf("a root (%s) that does not contain the resolved engine (%s) was accepted",
			other, podman)
	}
	if !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), podman) {
		t.Errorf("the refusal names neither the root nor the engine, so a reader cannot see "+
			"which of the two to change:\n%v", err)
	}

	// A SIBLING of the root that merely shares its string prefix must not
	// count as containing the engine: the check is an ancestor test, not
	// strings.HasPrefix on the bare value.
	t.Setenv("SNUG_PODMAN_ROOT", root)
	if _, err := preflightToolchainRoot(policy.OSEnviron{}, root+"-other/bin/podman"); err == nil {
		t.Errorf("an engine at %s-other/bin/podman was accepted as living inside %s", root, root)
	}

	// RELATIVE: refused. snug resolves this before the sandbox exists, so a
	// relative root means one thing here and another to every process that
	// reads it later.
	t.Setenv("SNUG_PODMAN_ROOT", "relative/root")
	if _, err := preflightToolchainRoot(policy.OSEnviron{}, podman); err == nil {
		t.Error("a relative $SNUG_PODMAN_ROOT was accepted")
	}

	// NOT A DIRECTORY: refused. It names a tree, not a file.
	t.Setenv("SNUG_PODMAN_ROOT", podman)
	if _, err := preflightToolchainRoot(policy.OSEnviron{}, podman); err == nil {
		t.Error("a $SNUG_PODMAN_ROOT naming a FILE was accepted")
	}
}

// TestPreflightToolchainRootAgreesWithTheScreenOnOrdinarySpellings is issue
// #417 F2: P9 used to compare the resolved engine against the RAW
// $SNUG_PODMAN_ROOT string, while buildContainersReport's screen judges the
// same variable through JudgeEngineToolchain, which resolves it first. A
// trailing slash, a `..` segment, and root itself being a symlink into the
// real installation directory (a versioned install kept current by
// relinking, e.g. /opt/podman -> /opt/podman-1.2.3) are all ordinary human
// spellings that CLEARED on the screen and were REFUSED at P9 — a screen/run
// disagreement of exactly the kind issue #422 removed everywhere else.
func TestPreflightToolchainRootAgreesWithTheScreenOnOrdinarySpellings(t *testing.T) {
	base := t.TempDir()
	versionedRoot := filepath.Join(base, "pod-1.0")
	binDir := filepath.Join(versionedRoot, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	podman := filepath.Join(binDir, "podman")
	if err := os.WriteFile(podman, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkedRoot := filepath.Join(base, "pod")
	if err := os.Symlink(versionedRoot, symlinkedRoot); err != nil {
		t.Fatal(err)
	}

	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	screenPolicy, err := policy.Resolve(reg,
		[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("building the screen's own policy: %v", err)
	}

	spellings := []struct {
		name string
		root string
	}{
		{"control: canonical", versionedRoot},
		{"trailing slash", versionedRoot + string(filepath.Separator)},
		// filepath.Join would clean this lexically before it ever reached
		// $SNUG_PODMAN_ROOT, defeating the case — built with string
		// concatenation so the literal `..` survives into the env var, the
		// same way a human's shell would leave it.
		{"a `..` segment", versionedRoot + string(filepath.Separator) + ".." +
			string(filepath.Separator) + filepath.Base(versionedRoot)},
		{"symlinked install directory", symlinkedRoot},
	}
	for _, sp := range spellings {
		t.Run(sp.name, func(t *testing.T) {
			t.Setenv("SNUG_PODMAN_ROOT", sp.root)
			_, p9Err := preflightToolchainRoot(policy.OSEnviron{}, podman)
			_, screenErr := screenPolicy.JudgeEngineToolchain(policy.OSEnviron{}, sp.root)
			if p9Err != nil {
				t.Errorf("preflight P9 refused an ordinary spelling of the installation root "+
					"that the screen clears: %v", p9Err)
			}
			if screenErr != nil {
				t.Errorf("fixture: the screen's own JudgeEngineToolchain refused %q, so this row "+
					"cannot show a screen/run disagreement: %v", sp.root, screenErr)
			}
			if (p9Err != nil) != (screenErr != nil) {
				t.Errorf("P9 and the screen disagree about %q: P9=%v screen=%v", sp.root, p9Err, screenErr)
			}
		})
	}
}

// TestPreflightPodmanBinaryRefusesNonRegularObjects is issue #417 F3: P1 used
// to refuse only `err != nil || fi.IsDir()`, so a FIFO, a bound AF_UNIX
// socket or a device node at $SNUG_PODMAN was accepted and exec'd — none of
// them is a directory — while describeEngineSource's screen already required
// `fi.Mode().IsRegular()` to clear, rendering NOT JUDGED for exactly these
// objects. This needs a REAL filesystem: envFakeEnv's Stat reports every
// non-directory path as a regular file, so the committed equivalence
// fixtures (TestScreenRefusalAgreesWithTheRunForEverySpelling) cannot see
// this class at all.
//
// Every object here sits outside every grant this fixture's policy makes, so
// CheckEngineBinary's own writability question never enters into it — this
// is purely about the KIND gate P1 runs before that question is even asked.
func TestPreflightPodmanBinaryRefusesNonRegularObjects(t *testing.T) {
	base := t.TempDir()

	fifo := filepath.Join(base, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	// sun_path is 107 bytes and t.TempDir()'s own path alone already exceeds
	// it on this machine's /tmp, so the listener binds at a short name
	// directly under /tmp rather than inside base.
	sock := fmt.Sprintf("/tmp/snug-417-f3-%d.sock", os.Getpid())
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("binding a control AF_UNIX socket at %s (%d bytes): %v", sock, len(sock), err)
	}
	t.Cleanup(func() {
		ln.Close()
		os.Remove(sock)
	})

	dir := filepath.Join(base, "a-directory")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	clean := filepath.Join(base, "podman")
	if err := os.WriteFile(clean, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(base, "does-not-exist")

	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg,
		[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("building the fixture policy: %v", err)
	}

	cases := []struct {
		name    string
		path    string
		refused bool
	}{
		{"CONTROL: a clean regular file", clean, false},
		{"a FIFO", fifo, true},
		{"a bound AF_UNIX socket", sock, true},
		{"a device node: /dev/null", "/dev/null", true},
		{"a directory", dir, true},
		{"missing", missing, true},
	}

	env := policy.OSEnviron{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SNUG_PODMAN", tc.path)
			_, runErr := preflightPodmanBinary(env, pol)
			if (runErr != nil) != tc.refused {
				t.Errorf("preflightPodmanBinary(%q): refused=%v (err=%v), want refused=%v",
					tc.path, runErr != nil, runErr, tc.refused)
			}
			// The predicate this test is pinning: describeEngineSource's own
			// clearance gate (dryrun.go) is fi.Mode().IsRegular(), so P1's
			// refusal must agree with it exactly, independent of this
			// fixture's own `refused` table above.
			fi, statErr := env.Stat(tc.path)
			screenClears := statErr == nil && fi.Mode().IsRegular()
			if screenClears == (runErr != nil) {
				t.Errorf("P1 and the screen's own IsRegular gate disagree about %q: "+
					"P1 refused=%v, screen would clear=%v", tc.path, runErr != nil, screenClears)
			}
		})
	}
}
