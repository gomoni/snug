//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── caps regained in a self-made user namespace, and what they do not reach ──
//
// This is the committed form of the measurement internal/policy/enginecaps.go
// rests its CAP_NET_ADMIN exclusion on (issue #417, row 1). That file argues
// that excluding a capability from EngineCapBounding still means something
// even though a nested user namespace hands its creator the full set back,
// because the regained bits are namespace-relative and snug's network
// namespace N is owned further up. The argument was a comment citing a one-off
// run; nothing in the suite could see it stop being true.
//
// What would CATCH a change here: anything that lets a payload holding full
// caps in a user namespace of its OWN making administer, or re-enter, the
// network namespace snug created for it. If that becomes possible, the
// exclusion in enginecaps.go buys nothing and the file's own reasoning has to
// be rewritten rather than the test relaxed.
//
// The three negatives, each with the positive control that stops it passing on
// a nested namespace which regained nothing:
//
//	SIOCSIFFLAGS on N's lo -> EPERM        control: the same ioctl in a netns it owns SUCCEEDS and the flag flips
//	setns(saved N fd, CLONE_NEWNET) -> EPERM  control: setns into the netns it owns SUCCEEDS, same fd mechanism
//	remount rw of /usr and / -> EPERM      control: mounting a tmpfs of its own in its own mountns SUCCEEDS
//
// plus the precondition that makes them worth anything: CapEff and CapBnd in
// the nested namespace actually carry CAP_NET_ADMIN and CAP_SYS_ADMIN, while
// the payload that created it held neither.
//
// COVERAGE THIS DOES NOT CLAIM. The engine arm is not measured: podman and
// crun create their own nested user namespaces for a container, and this test
// never starts an engine, so what is pinned here is the KERNEL property the
// enginecaps.go argument uses, not the engine's use of it. The /etc remount
// is asserted only as "did not become writable" — it answers EINVAL rather
// than EPERM, because snug composes /etc out of individual binds so /etc
// itself is not a bind mount to remount, and that is a different refusal from
// the two this test pins by errno.
//
// Whether a nested user namespace can be created AT ALL under the default
// seccomp filter is not asked here and is not this test's subject:
// TestNestedUserNamespaceIsRefused pins the refusal, which is why every run
// below passes --no-seccomp. That flag is what makes the measurement possible;
// the property being measured is what holds when it fails.

// buildCapregainProbe compiles testdata/capregainprobe. None of what it does is
// shell-reachable — a self-made user namespace needs a single-threaded clone,
// and SIOCSIFFLAGS/setns need exact errnos rather than a utility's prose — so
// it is a small compiled Go binary, built the way this suite's other probes
// are (CGO_ENABLED=0, and the module's own x/sys).
func buildCapregainProbe(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "capregainprobe")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/capregainprobe")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/capregainprobe: %v: %s", err, out.String())
	}
	return bin
}

// stageCapregainProbe copies the built probe under the target, because that is
// the only place a `-p @cwd-rw` sandbox can see it: the build output lives in
// the test's own scratch directory, outside every grant.
func stageCapregainProbe(t *testing.T, proj, bin string) {
	t.Helper()
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading the built capregainprobe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, "capregainprobe"), data, 0o755); err != nil {
		t.Fatalf("staging capregainprobe into the target: %v", err)
	}
}

// capMask parses one of the kernel's 16-hex-digit capability words.
func capMask(t *testing.T, name, hex, out string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
	if err != nil {
		t.Fatalf("%s=%q is not a capability mask (%v), so nothing can be said about which "+
			"bits the nested namespace holds:\n%s", name, hex, err, out)
	}
	return v
}

// The two bits this test is about. CAP_NET_ADMIN is the one enginecaps.go
// excludes and the one the payload regains; CAP_SYS_ADMIN is what the mount
// half needs to be a real attempt.
const (
	capNetAdmin = 12
	capSysAdmin = 21
)

func TestNestedUserNamespaceCapsCannotReachSnugsNamespaces(t *testing.T) {
	// Before budget(): a cold `go build` outruns the sandbox budget, and a
	// test that fails on its own compile time says nothing about namespaces.
	bin := buildCapregainProbe(t)

	arms := []struct {
		name     string
		extra    []string
		needPast bool
	}{
		// N is bwrap's own, created by --unshare-net.
		{name: "offline"},
		// N is the STAGE's: created before bwrap and owned by the stage's user
		// namespace rather than the sandbox's. A different owner is a different
		// answer to "who may administer N", so both arms are measured.
		{name: "staged-net", extra: []string{"-p", "@net"}, needPast: true},
	}

	for _, arm := range arms {
		t.Run(arm.name, func(t *testing.T) {
			budget(t)
			requireSandbox(t)
			requireNestedUserNamespace(t)
			if arm.needPast {
				requirePasta(t)
			}

			proj, _ := target(t)
			stageCapregainProbe(t, proj, bin)

			args := append([]string{"--no-seccomp", "--no-defaults", "-p", "@sys", "-p", "@cwd-rw"}, arm.extra...)
			r := run(t, args, proj, "./capregainprobe").mustRun(t)
			f := parseProbeFields(r.out)

			field := func(name string) string {
				t.Helper()
				v, ok := f[name]
				if !ok {
					t.Fatalf("capregainprobe never printed a %q line, so nothing drawn from "+
						"it can be asserted:\n%s", name, r.out)
				}
				return v
			}
			// A negative that is compared against an absent field passes; every
			// assertion below therefore goes through field(), and the ones that
			// are preconditions are Fatal.
			eq := func(name, want, why string) {
				t.Helper()
				if got := field(name); got != want {
					t.Errorf("%s=%s, want %s — %s:\n%s", name, got, want, why, r.out)
				}
			}

			// ── the nested namespace exists and DID regain the caps ─────────
			if got := field("nested-userns"); got != "OK" {
				t.Fatalf("the payload could not create a user namespace of its own "+
					"(nested-userns=%s), so this test measures nothing. requireNestedUserNamespace "+
					"said this host can nest one, so this is a finding about snug rather than "+
					"about the host:\n%s", got, r.out)
			}
			if got := field("outer-capeff"); got != "0000000000000000" {
				t.Errorf("outer-capeff=%s: the payload snug started is supposed to hold no "+
					"capabilities at all, and the contrast with the nested namespace's full set "+
					"is what this test is about:\n%s", got, r.out)
			}
			for _, name := range []string{"nested-capeff", "nested-capbnd"} {
				mask := capMask(t, name, field(name), r.out)
				for bit, cap := range map[int]string{capNetAdmin: "CAP_NET_ADMIN", capSysAdmin: "CAP_SYS_ADMIN"} {
					if mask&(1<<uint(bit)) == 0 {
						t.Fatalf("%s=%s does not carry %s, so the refusals below could be "+
							"explained by the nested namespace holding no privilege — which is "+
							"not the property enginecaps.go rests on:\n%s",
							name, field(name), cap, r.out)
					}
				}
			}
			// The refusals must be about N, so the nested process has to still
			// be IN N when it makes them.
			if got, want := field("nested-netns"), field("outer-netns"); got != want {
				t.Fatalf("the nested process is in %s but the payload was in %s: it left N before "+
					"attacking it, so the EPERMs below would be about the wrong namespace:\n%s",
					got, want, r.out)
			}
			eq("in-N-getflags", "OK", "lo must be readable in N, or its refusal to be WRITTEN "+
				"could just mean there is no such interface")

			// ── negative 1: N's lo cannot be reconfigured ───────────────────
			eq("in-N-setflags", "operation not permitted", "full caps in a self-made user "+
				"namespace must not administer the network namespace snug created")
			if before, after := field("in-N-lo-flags"), field("in-N-lo-flags-after"); before != after {
				t.Errorf("N's lo flags went from %s to %s: the ioctl's errno is not the whole "+
					"story, the interface was actually changed:\n%s", before, after, r.out)
			}

			// ── negative 2: N cannot be re-entered ──────────────────────────
			eq("setns-into-N", "operation not permitted", "a descriptor for N is not authority "+
				"over N; ownership of N is, and a nested user namespace cannot acquire it")
			if got, n := field("final-netns"), field("nested-netns"); got == n {
				t.Errorf("the probe ended up back in N (%s) — setns reported a refusal and the "+
					"process moved anyway:\n%s", got, r.out)
			}

			// ── the controls for those two, same syscalls, own namespace ────
			eq("unshare-netns", "OK", "the control needs a netns of the probe's own")
			eq("in-own-setflags", "OK", "SIOCSIFFLAGS must SUCCEED where the caller's user "+
				"namespace owns the netns, or the EPERM above is not about ownership")
			eq("in-own-lo-changed", "true", "the successful ioctl must actually have changed the "+
				"flags, otherwise 'OK' is a control that measures nothing")
			eq("setns-into-own", "OK", "setns must SUCCEED into a netns the caller's user "+
				"namespace owns, with the same fd mechanism the refused call used")

			// ── the same shape one layer over: mounts ───────────────────────
			eq("unshare-mountns", "OK", "the mount half needs a mount namespace of the probe's own")
			eq("mount-own-tmpfs", "OK", "CAP_SYS_ADMIN in the probe's own mount namespace must be "+
				"real, or the remount refusals below prove nothing")
			eq("remount-rw-/usr", "operation not permitted", "bwrap's read-only /usr is locked by "+
				"the user namespace that made it")
			eq("remount-rw-/", "operation not permitted", "same, for the sandbox root")
			for _, path := range []string{"/usr", "/", "/etc"} {
				name := "remount-rw-" + path
				if got := field(name); got == "OK" {
					t.Errorf("%s=OK: a nested user namespace remounted a snug mount read-write:\n%s",
						name, r.out)
				}
				// Present only when the remount succeeded, so its absence is
				// the expected case and its presence is the finding.
				if got, ok := f["write-after-"+name]; ok && got == "OK" {
					t.Errorf("write-after-%s=OK: the payload wrote to %s through a remount:\n%s",
						name, path, r.out)
				}
			}
		})
	}
}

// ── the same argument, for CAP_SYS_PTRACE and a real process in U ──────────

// buildPtraceRegainProbe compiles testdata/ptraceregainprobe, the same
// build-a-small-Go-binary idiom buildCapregainProbe uses just above, for the
// same reason: an exact errno (EPERM vs EACCES vs ENOENT) is not something a
// shell one-liner can assert reliably.
func buildPtraceRegainProbe(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ptraceregainprobe")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/ptraceregainprobe")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/ptraceregainprobe: %v: %s", err, out.String())
	}
	return bin
}

// TestTheSandboxsPayloadRegainsPtraceInItsOwnUsernsAndItReachesNothingInU is
// issue #61 part (a)'s negative: it is what stops the userns-reset property
// stagecaps.go documents (a nested user namespace hands its creator the full
// bounding set back, CAP_SYS_PTRACE included) from being read as a hole in
// the gate the rest of this file's test and TestNothingSnugPutsInUHoldsCapSysPtrace
// (stageptracegate_test.go) pin.
//
// COVERAGE THIS DOES NOT CLAIM, stated the way the file-level comment above
// states its own gap: the attacking process here is NOT the sandboxed
// payload's own pid-namespace-confined process. It cannot be, and running it
// there would test something WEAKER than intended: bwrap always creates a
// fresh pid namespace for the sandbox (policy.Topology.UnshareFlags, "pid"),
// and a pid namespace's own visibility rule means a process inside it has NO
// number at all for an ancestor-namespace process like P1 — /proc/<P1>/mem
// would not even resolve (ENOENT), which says something about pid-namespace
// opacity, not about the user-namespace hierarchy stagecaps.go's own claim
// rests on. So this probe runs in P1's OWN pid namespace (sharing it, since
// stageCloneflags carries no CLONE_NEWPID and P1's pid is therefore resolvable
// here) and creates ONLY a nested USER namespace of its own — isolating the
// one mechanism under test. What this does NOT measure is layered on top of
// what it does: an actual sandboxed payload gets BOTH protections (pid
// opacity AND the userns hierarchy), and this test is only the second.
func TestTheSandboxsPayloadRegainsPtraceInItsOwnUsernsAndItReachesNothingInU(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requireNestedUserNamespace(t)

	bin := buildPtraceRegainProbe(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "10")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: the stage (P1) never appeared")
	}
	if _, ok := findDescendant(cmd.Process.Pid, isComm("sleep"), 5*time.Second); !ok {
		t.Fatal("PRECONDITION: the payload ('sleep') never appeared")
	}

	out, err := exec.Command(bin, strconv.Itoa(stagePID)).CombinedOutput()

	cmd.Process.Kill()
	cmd.Wait()
	killed = true

	if err != nil {
		t.Fatalf("ptraceregainprobe exited non-zero: %v\n%s", err, out)
	}
	f := parseProbeFields(string(out))
	field := func(name string) string {
		t.Helper()
		v, ok := f[name]
		if !ok {
			t.Fatalf("ptraceregainprobe never printed a %q line, so nothing drawn from it "+
				"can be asserted:\n%s", name, out)
		}
		return v
	}
	eq := func(name, want, why string) {
		t.Helper()
		if got := field(name); got != want {
			t.Errorf("%s=%s, want %s — %s:\n%s", name, got, want, why, out)
		}
	}

	// PRECONDITION: the target it attacked really is the pid this test found
	// for P1 — a probe that silently attacked pid 0 or misparsed its argv
	// would make every refusal below meaningless.
	if got, want := field("target-pid"), strconv.Itoa(stagePID); got != want {
		t.Fatalf("target-pid=%s, want %s — the probe attacked the wrong process:\n%s", got, want, out)
	}
	// PRECONDITION: the nested namespace was actually created.
	eq("nested-userns", "OK", "the probe could not create a user namespace of its own, so "+
		"this test measures nothing")

	// THE FACT, STATED PLAINLY: the nested namespace DID regain CAP_SYS_PTRACE.
	// What stops the attack below is namespace ownership, not this bit's
	// absence — hiding this reading would let the test look like it is about
	// a capability that is simply missing, which is not stagecaps.go's claim.
	const capSysPtraceBit = 19
	bnd := capMask(t, "nested-capbnd", field("nested-capbnd"), string(out))
	if bnd&(1<<capSysPtraceBit) == 0 {
		t.Fatalf("nested-capbnd=%s does not carry CAP_SYS_PTRACE, so the refusals below could "+
			"be explained by the nested namespace holding no privilege at all — which is not "+
			"the property this test is about:\n%s", field("nested-capbnd"), out)
	}

	// ── the negative: a real process in U ───────────────────────────────
	eq("vm-readv-target", "operation not permitted", "full CAP_SYS_PTRACE in a self-made "+
		"user namespace must not let process_vm_readv reach a process in U — the namespace "+
		"is a SIBLING of U, never an ancestor of it")
	eq("open-mem-target", "permission denied", "same target, the /proc/<pid>/mem path — the "+
		"kernel reports this one as EACCES rather than process_vm_readv's EPERM, and both are "+
		"asserted by their own exact errno rather than merely \"not OK\"")

	// ── the positive control: a peer inside the SAME nested namespace ──
	eq("vm-readv-peer", "OK", "the identical call, against a process the attacker's own "+
		"nested namespace really does own, must succeed — otherwise the refusals above could "+
		"be a broken probe rather than a namespace boundary")
	eq("open-mem-peer", "OK", "same control, the /proc/<pid>/mem path")
}
