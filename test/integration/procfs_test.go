//go:build integration

package integration

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// procfsReplaced are the entries snug replaces with an empty file
// (internal/policy/procfs.go, issue #29 / PSEUDOFS-AUDIT R3 Tier 1).
var procfsReplaced = []string{"/proc/config.gz", "/proc/keys", "/proc/key-users"}

// TestProcfsEntriesSnugReplacesAreEmptyInside is the audit's R3, measured from
// inside a real sandbox rather than read off the argv.
//
// THE POSITIVE CONTROL IS THE HOST, and it is the whole test. "Empty inside"
// is equally true of a kernel that publishes nothing there, of a procfs that
// failed to mount, and of a probe that read the wrong path — so each entry is
// read on the HOST first, and an entry that carries nothing there is reported
// as proving nothing rather than counted as a pass. The size is taken by
// READING, never by stat: procfs reports st_size 0 for /proc/keys on a host
// where `cat` returns a keyring.
func TestProcfsEntriesSnugReplacesAreEmptyInside(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	hostBytes := map[string]int{}
	demonstrable := 0
	for _, p := range procfsReplaced {
		data, err := os.ReadFile(p)
		switch {
		case err != nil:
			hostBytes[p] = -1 // this kernel does not publish it at all
		default:
			hostBytes[p] = len(data)
			if len(data) > 0 {
				demonstrable++
			}
		}
		t.Logf("host %s: %d byte(s) (-1 = absent)", p, hostBytes[p])
	}

	var script strings.Builder
	for _, p := range procfsReplaced {
		fmt.Fprintf(&script, "if [ -e %s ]; then echo \"SIZE %s $(wc -c < %s)\"; "+
			"else echo \"ABSENT %s\"; fi\n", p, p, p, p)
	}
	script.WriteString("echo \"CPUINFO $(grep -c ^processor /proc/cpuinfo)\"\necho PROBE-DONE\n")

	r := runEnv(t, nil, nil, proj, script.String()).mustRun(t)
	if !strings.Contains(r.out, "PROBE-DONE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	// CONTROL: procfs inside is real and readable. Without it, "every file we
	// asked about was empty" is also what a broken /proc looks like.
	if n := probeField(t, r.out, "CPUINFO"); n < 1 {
		t.Fatalf("no CPUs in the sandbox's /proc/cpuinfo — the procfs the other assertions "+
			"read is not a working one:\n%s", r.out)
	}

	for _, p := range procfsReplaced {
		switch {
		case hostBytes[p] < 0:
			// snug mounts nothing it cannot see on the host (--ro-bind-data has
			// no -try spelling), so the sandbox must not have it either.
			if !strings.Contains(r.out, "ABSENT "+p) {
				t.Errorf("%s is absent on this host but present inside the sandbox — snug "+
					"invented a procfs entry:\n%s", p, r.out)
			}
			t.Logf("%s: absent on this host, nothing to close", p)
		case hostBytes[p] == 0:
			// Present but empty on the host: the closure is still asserted, and
			// it is said out loud that this entry demonstrates nothing today.
			if got := sizeOf(t, r.out, p); got != 0 {
				t.Errorf("%s reads %d byte(s) inside, want 0", p, got)
			}
			t.Logf("%s: empty on this host too, so this row proves nothing about the closure", p)
		default:
			got := sizeOf(t, r.out, p)
			if got != 0 {
				t.Errorf("%s reads %d byte(s) inside the sandbox while the host publishes %d — "+
					"snug's empty replacement is not in effect (issue #29):\n%s",
					p, got, hostBytes[p], r.out)
			}
		}
	}

	if demonstrable == 0 {
		t.Skip("none of the replaced entries carries anything on this host, so this run " +
			"cannot distinguish a working closure from an empty kernel")
	}
}

// TestProcSysIsReadOnlyAndStillTheSandboxsOwn is the audit's R4, and it
// asserts BOTH halves because the objection to R4 is the second one: binding
// the host's /proc/sys could have imported the host's namespace-scoped
// sysctls. It does not — those resolve through the reading task's namespaces —
// and that is measured here rather than argued in a comment.
func TestProcSysIsReadOnlyAndStillTheSandboxsOwn(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	hostIfaces, err := os.ReadDir("/proc/sys/net/ipv4/conf")
	if err != nil {
		t.Fatalf("reading the host's own /proc/sys/net/ipv4/conf: %v", err)
	}
	var hostNames []string
	for _, e := range hostIfaces {
		hostNames = append(hostNames, e.Name())
	}
	// CONTROL: the host has an interface beyond the ones a fresh netns has, or
	// there is no leak this test could ever detect.
	extra := ""
	for _, n := range hostNames {
		if n != "all" && n != "default" && n != "lo" {
			extra = n
			break
		}
	}
	if extra == "" {
		t.Skip("this host's own netns has no interface beyond lo, so a leaked host view " +
			"would be indistinguishable from the sandbox's own")
	}
	t.Logf("control: the host's netns names %v", hostNames)

	script := `
echo -n "WRITE "; (echo 1 > /proc/sys/kernel/ns_last_pid) 2>&1 | tail -1
echo "READ $(cat /proc/sys/kernel/pid_max)"
echo "IFACES $(ls /proc/sys/net/ipv4/conf | tr '\n' ' ')"
echo PROBE-DONE
`
	r := runEnv(t, nil, nil, proj, script).mustRun(t)
	if !strings.Contains(r.out, "PROBE-DONE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}

	// The write side is snug's now, not a capability check snug does not own.
	if !strings.Contains(r.out, "Read-only file system") {
		t.Errorf("writing /proc/sys/kernel/ns_last_pid inside did not fail with EROFS — the "+
			"read-only bind of /proc/sys (issue #29 / R4) is not in effect:\n%s", r.out)
	}
	// CONTROL: read-only, not absent. A missing /proc/sys would satisfy the
	// assertion above and break every build that reads a sysctl.
	if !strings.Contains(r.out, "READ ") || strings.Contains(r.out, "READ \n") {
		t.Errorf("/proc/sys/kernel/pid_max is not readable inside — R4 must close the write "+
			"side only:\n%s", r.out)
	}
	// And the view is still the sandbox's own netns.
	if strings.Contains(r.out, "IFACES") && strings.Contains(r.out, extra) {
		t.Errorf("the sandbox's /proc/sys/net names the host interface %q — binding the host's "+
			"/proc/sys imported the host's network namespace view, which is exactly what R4 "+
			"must not do:\n%s", extra, r.out)
	}
}

func sizeOf(t *testing.T, out, path string) int {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "SIZE" && f[1] == path {
			n, err := strconv.Atoi(f[2])
			if err != nil {
				t.Fatalf("unparseable size for %s: %q", path, line)
			}
			return n
		}
	}
	t.Fatalf("no SIZE line for %s — the probe did not report on it at all:\n%s", path, out)
	return -1
}

func probeField(t *testing.T, out, key string) int {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			n, err := strconv.Atoi(f[1])
			if err != nil {
				t.Fatalf("unparseable %s: %q", key, line)
			}
			return n
		}
	}
	t.Fatalf("no %s line:\n%s", key, out)
	return -1
}

// TestTheEngineRunsAndAnOrdinaryRunKeepsItsMasks is the PAIR, and the pair is
// what pins issue #29's decision rather than either half alone.
//
// The kernel refuses a fresh procfs mount inside a nested user namespace while
// any mount covers part of a procfs it can see. snug's closures are exactly
// such mounts, and the container engine mounts its own procfs for its own pid
// namespace — so the two cannot both happen in one run. Measured, with the
// closures applied unconditionally:
//
//	snug: __inengine: mounting a fresh /proc for this engine's own pid
//	namespace: operation not permitted
//
// Both ways of having both are closed: unmounting the closures inside the
// engine's own mount namespace is refused by MNT_LOCKED, and installing them
// where the engine tolerates them puts them where the payload never sees them.
//
// The decision was to keep the closures for every ordinary run and exempt an
// engine run, with --dry-run disclosing it. This test asserts that split as
// TWO runs, because that is what it now is:
//
//   - an ENGINE run starts, and the engine's /proc is its own;
//   - an ORDINARY run still reads 0 bytes from the closed entries.
//
// Neither half alone is the property. The first passing on its own is what a
// build that quietly dropped the closures everywhere looks like; the second
// passing on its own is what a build that broke the engine looks like. The
// scoping — that having a container profile INSTALLED does not weaken an
// ordinary run — is asserted where it can be stated exactly, in
// internal/policy's TestProcfsClosuresAreSkippedForAnEngineRun.
func TestTheEngineRunsAndAnOrdinaryRunKeepsItsMasks(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	// CONTROL: this host publishes something to close, or the second half
	// cannot tell a working closure from an empty kernel.
	var demonstrable []string
	for _, p := range procfsReplaced {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			demonstrable = append(demonstrable, p)
		}
	}
	if len(demonstrable) == 0 {
		t.Skip("this host publishes none of the replaced procfs entries, so a closure that " +
			"silently stopped applying would look identical to one that held")
	}

	// ── half one: an engine run starts, and its /proc is its own ──────────
	bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 120`)
	bg.ready(t)
	// waitForState is the assertion that the engine came up: a run whose
	// engine never created its socket dies here rather than reaching the
	// mountinfo read below.
	bg.waitForState(t)
	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	if root := mountRootFor(t, enginePID, "/proc"); root == "" {
		t.Errorf("the engine (pid %d) has no /proc mount of its own. With the closures applied "+
			"to an engine run the kernel refuses it one, which is why they are exempted "+
			"there (issue #29):\n%s", enginePID, bg.log())
	}

	// The exemption is what makes that work, so the engine run must NOT have
	// the closures. Asserted from inside that same sandbox rather than from
	// the screen: this is what the payload actually reads.
	engineOut := attachScript(t, env, proj, sizeScript(demonstrable))
	if !strings.Contains(engineOut.out, "PROBE-DONE") {
		t.Fatalf("the engine-run probe did not finish:\n%s", engineOut.out)
	}
	for _, p := range demonstrable {
		if got := sizeOf(t, engineOut.out, p); got == 0 {
			t.Errorf("%s reads 0 bytes inside an ENGINE run. The closures are exempted there "+
				"because the engine cannot otherwise mount its own procfs — if this fires, "+
				"either the exemption stopped applying (and the engine above is about to "+
				"fail) or this host publishes nothing there", p)
		}
	}

	// ── half two: an ORDINARY run still closes them ───────────────────────
	other, _ := target(t)
	r := runEnv(t, nil, nil, other, sizeScript(demonstrable)).mustRun(t)
	if !strings.Contains(r.out, "PROBE-DONE") {
		t.Fatalf("the ordinary-run probe did not finish:\n%s", r.out)
	}
	for _, p := range demonstrable {
		if got := sizeOf(t, r.out, p); got != 0 {
			t.Errorf("%s reads %d byte(s) in an ORDINARY run — the exemption is meant to be "+
				"scoped to runs that start an engine, and this run started none:\n%s",
				p, got, r.out)
		}
	}
}

// sizeScript prints one `SIZE <path> <bytes>` line per entry, read rather than
// stat'ed: procfs reports st_size 0 for /proc/keys on a host where `cat`
// returns a keyring.
func sizeScript(paths []string) string {
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "echo \"SIZE %s $(wc -c < %s)\"\n", p, p)
	}
	b.WriteString("echo PROBE-DONE\n")
	return b.String()
}

// mountRootFor returns the source root of the mount at guest in pid's own
// mount table, or "" when that pid has no mount there at all.
func mountRootFor(t *testing.T, pid int, guest string) string {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatalf("reading pid %d's mountinfo: %v", pid, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && f[4] == guest {
			return f[3]
		}
	}
	return ""
}
