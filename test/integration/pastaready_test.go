//go:build integration

package integration

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// inet6Row is one line of /proc/net/if_inet6: address, prefix length, scope
// and flags, all hex in the file.
type inet6Row struct {
	addr   netip.Addr
	prefix int
	scope  int
	flags  int
	iface  string
}

func parseIfInet6(text string) []inet6Row {
	var rows []inet6Row
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 6 || len(f[0]) != 32 {
			continue
		}
		var b [16]byte
		ok := true
		for i := range 16 {
			v, err := strconv.ParseUint(f[0][2*i:2*i+2], 16, 8)
			if err != nil {
				ok = false
				break
			}
			b[i] = byte(v)
		}
		prefix, e1 := strconv.ParseInt(f[2], 16, 32)
		scope, e2 := strconv.ParseInt(f[3], 16, 32)
		flags, e3 := strconv.ParseInt(f[4], 16, 32)
		if !ok || e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		rows = append(rows, inet6Row{netip.AddrFrom16(b), int(prefix), int(scope), int(flags), f[5]})
	}
	return rows
}

// TestPastaFinishesSnug0BeforeTheStageSealsIt is the regression for issue #605.
//
// pasta raises snug0 before it copies the host's addresses onto it, and the
// stage used to seal the host's addresses (as /128) the moment snug0 was up.
// A seal that beat pasta's own copy of a global v6 address made pasta's add
// EEXIST, pasta died with "Couldn't set IPv6 address(es) in namespace: File
// exists", and the run went on with loopback only. It needed load to lose the
// race, so this runs several @net sandboxes at once, more than once.
//
// Asserted per run, from inside: snug0 carries every global v6 address pasta
// copies from the host's default interface UNDER THE HOST'S PREFIX LENGTH —
// pasta's copy, not the seal's /128 — and no "network helper exited" line.
//
// Adjacent, and it must stay closed: the host's own link-local is on snug0 as
// a /128, i.e. the seal still runs, just after pasta rather than during it.
func TestPastaFinishesSnug0BeforeTheStageSealsIt(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)
	requirePasta(t)

	iface, ll, ok := hostDefaultIfaceLinkLocal6(t)
	if !ok {
		t.Skip("no IPv6 link-local on the host's default-route interface; pasta copies no v6 here")
	}
	hostText, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		t.Fatal(err)
	}
	// What pasta's nl_addr_dup copies: not link-scope, not deprecated.
	const ifaFDeprecated = 0x20
	var copied []inet6Row
	for _, r := range parseIfInet6(string(hostText)) {
		if r.iface == iface && r.scope == 0 && r.flags&ifaFDeprecated == 0 && r.prefix < 128 {
			copied = append(copied, r)
		}
	}
	if len(copied) == 0 {
		t.Skipf("%s carries no global IPv6 address below /128 for pasta to copy; the race "+
			"this test is about cannot happen here", iface)
	}

	proj, _ := target(t)
	const payload = `sleep 1; echo ` + payloadMarker + `; cat /proc/net/if_inet6`

	type result struct {
		out  string
		code int
		err  error
	}
	const rounds, concurrent = 3, 8
	for round := range rounds {
		results := make([]result, concurrent)
		var wg sync.WaitGroup
		for i := range concurrent {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
				defer cancel()
				cmd := exec.CommandContext(ctx, snugBin, "-p", "@net", proj, "--", "/bin/sh", "-c", payload)
				cmd.Env = baseEnv()
				cmd.WaitDelay = waitDelay
				out, err := cmd.CombinedOutput()
				results[i] = result{out: string(out), code: cmd.ProcessState.ExitCode(), err: err}
			}()
		}
		wg.Wait()

		for i, r := range results {
			where := fmt.Sprintf("round %d run %d", round, i)
			if r.code != 0 || !strings.Contains(r.out, payloadMarker) {
				t.Fatalf("%s: PRECONDITION: the @net run failed (exit %d, %v):\n%s", where, r.code, r.err, r.out)
			}
			if strings.Contains(r.out, "network helper exited") {
				t.Errorf("%s: pasta died during the run (issue #605):\n%s", where, r.out)
				continue
			}
			inside := map[netip.Addr]int{}
			for _, row := range parseIfInet6(r.out) {
				if row.iface == "snug0" {
					inside[row.addr] = row.prefix
				}
			}
			for _, c := range copied {
				got, ok := inside[c.addr]
				switch {
				case !ok:
					t.Errorf("%s: %s is not on snug0 at all", where, c.addr)
				case got != c.prefix:
					t.Errorf("%s: %s is on snug0 as /%d, not the host's /%d: the stage's seal "+
						"got there before pasta's copy (issue #605)", where, c.addr, got, c.prefix)
				}
			}
			if got, ok := inside[ll]; !ok || got != 128 {
				t.Errorf("%s: the host's link-local %s is not sealed on snug0 as /128 "+
					"(present=%v, prefix=%d): the seal no longer runs", where, ll, ok, got)
			}
		}
	}
}

// TestAGatedRunWhosePastaDiesBeforeReleaseIsRefusedWithoutALoopbackWarning is
// the regression for red-team finding F2 on issue #605's fix.
//
// A gated run (@net + @podman-socket) parks its payload until the release
// byte, and a pasta that dies before that byte is refused (exit 69). watch()
// used to be armed before the sandbox was built, so the same death ALSO
// printed "the sandbox now has loopback only" — false, since that sandbox
// never runs. Measured on the previous commit: a real pasta killed 20–120ms
// after its pid line printed both lines, 10 of 10.
//
// The fake pasta runs the real one, passes its pid line through, and kills it
// after a delay. A delay that misses the window (the payload ran) says nothing
// about this finding and is not counted; at least one must land in it.
func TestAGatedRunWhosePastaDiesBeforeReleaseIsRefusedWithoutALoopbackWarning(t *testing.T) {
	budget(t, 180*time.Second)
	requirePasta(t)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	realPasta, err := exec.LookPath("pasta")
	if err != nil {
		t.Fatal(err)
	}
	proj, _ := target(t)
	marker := filepath.Join(proj, "RAN")
	fakeBin := t.TempDir()

	refused := 0
	for _, delay := range []string{"0.02", "0.05", "0.08"} {
		script := "#!/bin/sh\n" + realPasta + " \"$@\" | { read l; echo \"$l\"; sleep " + delay +
			"; kill -9 \"$l\"; }\nexit 1\n"
		if err := os.WriteFile(filepath.Join(fakeBin, "pasta"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		os.Remove(marker)
		out, code := cli(t, append(append([]string{}, env...), "PATH="+fakeBin+":"+os.Getenv("PATH")),
			"-p", "@net", "-p", "@podman-socket", proj, "--", "/bin/sh", "-c", `touch "$SNUG_TARGET/RAN"`)
		if _, err := os.Stat(marker); err == nil {
			t.Logf("delay %ss: the payload ran (exit %d), so pasta died after the release; not counted", delay, code)
			continue
		}
		if code != 69 || !strings.Contains(out, "exited before the payload started") {
			t.Fatalf("delay %ss: pasta died before the release and the run was not refused "+
				"with exit 69 (exit %d):\n%s", delay, code, out)
		}
		refused++
		if strings.Contains(out, "now has loopback only") {
			t.Errorf("delay %ss: a refused run also claimed its sandbox now has loopback only, "+
				"for a sandbox that never ran:\n%s", delay, out)
		}
	}
	if refused == 0 {
		t.Fatal("PRECONDITION: no delay killed pasta before the release, so nothing was exercised")
	}
}

// TestANetRunWhosePastaDiesDuringTheBwrapBuildIsRefused is the regression for
// red-team finding F1 on issue #605's fix.
//
// An @net run with no container engine used to be ungated: the last look at
// pasta came before StartSandbox, and a pasta that died while bwrap built the
// sandbox (the red team measured about 110ms) left the payload running with
// loopback only and a warning. Every @net run is now parked on --block-fd, the
// stage reports ready only once bwrap's mounts are finished, and P0 looks at
// pasta again right before the release byte.
//
// The kill is placed by a handshake rather than timed. The stage hands the
// sandbox to whatever `bwrap` P0 resolved on PATH, so a fake bwrap runs after
// P0's last look at pasta before StartSandbox and before the build. It cannot
// signal pasta itself — it is pid 1 of its own pid namespace, and measured,
// `kill` there says "No such process" — so it touches a file, and a watcher
// the fake pasta left in the host pid namespace SIGKILLs pasta, waits until
// P0 has reaped it, and answers with a second file. Only then does the fake
// exec the real bwrap, so pasta is always dead before the build and the
// release. The first version polled `pgrep -P <stage> -x bwrap` from a fake
// pasta instead; on the ubuntu-24.04 CI runner the build and release beat the
// poll: 4 of 5 runs ran the payload (exit 0, no output), so the kill never
// landed inside the window and the run said nothing about the fix. Measured
// before this change (with the poll, locally): 5 of 5 such runs ran the
// payload with the warning.
func TestANetRunWhosePastaDiesDuringTheBwrapBuildIsRefused(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)
	requirePasta(t)
	realPasta, err := exec.LookPath("pasta")
	if err != nil {
		t.Fatal(err)
	}
	realBwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	proj, _ := target(t)
	marker := filepath.Join(proj, "RAN")
	fakeBin := t.TempDir()
	state := t.TempDir()
	goFile, deadFile := filepath.Join(state, "go"), filepath.Join(state, "dead")
	// exec keeps $$, so the watcher's target is the real pasta P0 waits on. Its
	// stdio is /dev/null: it must not hold pasta's readiness or stderr pipe.
	pastaScript := "#!/bin/sh\np=$$\n" +
		"( while [ ! -e " + goFile + " ]; do :; done; kill -9 $p; " +
		"while [ -e /proc/$p ]; do :; done; : > " + deadFile + " ) </dev/null >/dev/null 2>&1 &\n" +
		"exec " + realPasta + " \"$@\"\n"
	// bwrap runs with an empty environment: absolute paths and builtins only.
	// snug asks bwrap --help once, before anything starts, to learn it can bind
	// by descriptor; that call must not take part in the handshake.
	bwrapScript := "#!/bin/sh\n[ \"$1\" = --help ] && exec " + realBwrap + " \"$@\"\n: > " + goFile + "\n" +
		"while [ ! -e " + deadFile + " ]; do :; done\n" +
		"exec " + realBwrap + " \"$@\"\n"
	for name, body := range map[string]string{"pasta": pastaScript, "bwrap": bwrapScript} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for i := range 5 {
		os.Remove(marker)
		os.Remove(goFile)
		os.Remove(deadFile)
		out, code := cli(t, baseEnv("PATH="+fakeBin+":"+os.Getenv("PATH")),
			"-p", "@net", proj, "--", "/bin/sh", "-c", `touch "$SNUG_TARGET/RAN"`)
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("run %d: pasta was killed while bwrap built the sandbox and the payload ran "+
				"anyway (exit %d):\n%s", i, code, out)
			continue
		}
		if code != 69 || !strings.Contains(out, "exited before the payload started") {
			t.Fatalf("run %d: not refused by the pre-release check (exit %d), so the kill did "+
				"not land in the bwrap build:\n%s", i, code, out)
		}
		if strings.Contains(out, "now has loopback only") {
			t.Errorf("run %d: a refused run also claimed its sandbox now has loopback only:\n%s", i, out)
		}
	}
}
