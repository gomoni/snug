package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The store key is what teardown uses as identity, so two different sandboxes
// must never share one, and the same sandbox must get the same one twice.
func TestStoreKeyIdentifiesTheSandbox(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	a, err := New([]policy.ProfileName{"@sys", "@podman-socket"}, "/proj/one")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]policy.ProfileName{"@podman-socket", "@sys"}, "/proj/one")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New([]policy.ProfileName{"@sys", "@podman-socket"}, "/proj/two")
	if err != nil {
		t.Fatal(err)
	}
	if a.store != b.store {
		t.Errorf("profile order changed the store: %s vs %s", a.store, b.store)
	}
	if a.store == c.store {
		t.Errorf("two targets share a store: %s", a.store)
	}
	if !strings.Contains(a.store, "/snug/engines/") {
		t.Errorf("store %q is not under snug's own engine directory", a.store)
	}

	// The socket and runroot (issue #63, Tier B) live under this RUN's own
	// /tmp directory — never under $XDG_DATA_HOME's store tree, which is
	// shared across runs on purpose, and never under $XDG_RUNTIME_DIR, which
	// a root-in-userns podman masks with its own tmpfs on /run.
	if strings.Contains(a.sock, "/snug/engines/") || strings.Contains(a.runroot, "/snug/engines/") {
		t.Errorf("socket %q / runroot %q must NOT be under the shared store tree", a.sock, a.runroot)
	}

	// The socket is the teardown identity and must name THIS run, not the
	// store — otherwise teardown reaches into a concurrent sandbox that
	// resolved to the same key.
	if a.sock == c.sock {
		t.Errorf("two sandboxes share a socket: %s", a.sock)
	}
	if !strings.Contains(a.sock, "podman-"+strconv.Itoa(os.Getpid())+".sock") {
		t.Errorf("socket %q does not identify this run", a.sock)
	}
	// The socket lives in THIS run's own hardened directory (createRunDir),
	// unique per pid. The runroot, MEASURED, deliberately does NOT: podman's
	// own libpod database (inside the persisted store) records the runroot a
	// run used and refuses a LATER run against the same store with a
	// different one, so runroot is keyed by the same profiles+target key the
	// store already is, shared across runs the way the store is (Spec's own
	// doc comment). The two are therefore in DIFFERENT directories now,
	// which is the corrected shape, not a regression of the earlier "both in
	// one run directory" assertion this replaces.
	if filepath.Dir(a.sock) == filepath.Dir(a.runroot) {
		t.Errorf("socket %q and runroot %q are in the same directory; the runroot must be keyed "+
			"by the store's own key so it stays stable across runs sharing that store, not by "+
			"this run's own pid", a.sock, a.runroot)
	}
	if !strings.Contains(a.runroot, "snug-engines-") {
		t.Errorf("runroot %q is not under the shared, store-keyed engines directory", a.runroot)
	}
}

// The engine's run directory is hardened, not a blind MkdirAll into
// world-writable /tmp: it must be owned by this uid and mode exactly 0700,
// and a second claim of the identical name (this test's own re-derivation of
// runDirName with the SAME sequence number New already consumed) must be
// refused rather than silently reused.
func TestEngineRunDirIsHardenedAndNotReused(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(e.runDir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", e.runDir)
	}
	if mode := fi.Mode().Perm(); mode != 0o700 {
		t.Errorf("run directory mode is %#o, want 0700", mode)
	}

	if err := createRunDir(e.runDir); err == nil {
		t.Fatal("createRunDir silently reused an existing directory; it must refuse")
	}
}

// ownedPIDs is what reaps an engine that is not snug's child. It has to find
// the real thing (positive control) and it must never claim a process that
// merely looks like podman.
func TestOwnedPIDsMatchesOnlyThisEnginesPaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}

	// Positive control: a process whose command line names our socket. Without
	// this assertion the negative ones below could pass on a sweep that never
	// matches anything at all.
	mine := marker(t, "unix://"+e.sock)

	// Two things that must NEVER match: the user's own rootless podman, and a
	// CONCURRENT snug sandbox that resolved to the same store. The store is
	// shared on purpose (warm start), so it is not an identity.
	home, _ := os.UserHomeDir()
	theirs := marker(t, "podman --root "+filepath.Join(home, ".local/share/containers/storage")+
		" --runroot /run/user/1000/containers system service")

	sibling := marker(t, "podman --root "+e.store+" --runroot "+e.runroot+
		" system service --time 10 unix://"+filepath.Join(filepath.Dir(e.sock), "podman-999999.sock"))

	var pids []int
	for i := 0; i < 100; i++ {
		pids = ownedPIDs(e.paths(), map[int]bool{os.Getpid(): true})
		if len(pids) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	found := false
	for _, p := range pids {
		if p == mine.Process.Pid {
			found = true
		}
		if p == theirs.Process.Pid {
			t.Fatalf("the sweep claimed the host's own podman (pid %d); it must only ever "+
				"match this run's own socket", p)
		}
		if p == sibling.Process.Pid {
			t.Fatalf("the sweep claimed a concurrent sandbox's engine on the same store "+
				"(pid %d); teardown would kill a sibling that is still working", p)
		}
	}
	if !found {
		t.Fatalf("the sweep did not find pid %d, which names %s — it cannot reap what it "+
			"cannot see", mine.Process.Pid, e.store)
	}

	// Exclusion is honoured: the pid named in `exclude` is not returned, and
	// nothing else under test has crept in.
	//
	// It asserts about THESE pids rather than demanding the result be empty,
	// and the difference is what a CI failure taught. `len(excl) != 0` is a
	// claim about the whole machine — that no other process anywhere names our
	// socket — which is not what this test is named for and not something the
	// code under test controls. It failed once on a GitHub runner with one
	// unexplained pid, and the message said only "still got [4381]", so the
	// cause is not known and this comment will not pretend otherwise: the
	// helpers below no longer fork (one candidate removed) and anything
	// unexpected is now logged WITH ITS COMMAND LINE, so a recurrence explains
	// itself instead of costing another round trip.
	excl := ownedPIDs(e.paths(), map[int]bool{os.Getpid(): true, mine.Process.Pid: true})
	for _, p := range excl {
		switch p {
		case mine.Process.Pid:
			t.Errorf("exclusion is not honoured: pid %d was named in exclude and returned anyway", p)
		case theirs.Process.Pid, sibling.Process.Pid:
			t.Errorf("the sweep claimed pid %d, which does not own this engine's socket:\n%s",
				p, describe([]int{p}))
		}
	}
	if len(excl) > 0 {
		t.Logf("note: %d process(es) other than the ones under test name %s:\n%s",
			len(excl), e.sock, describe(excl))
	}
}

// marker starts a process whose command line contains arg and which NEVER
// FORKS, then blocks until the test ends.
//
// The non-forking part is deliberate. The helper used to be
// `sh -c "sleep 30; true" ARG`, and sh forks to run sleep — between the fork
// and the exec the child is a copy of sh, command line and marker included, so
// a /proc sweep can see a second pid carrying our socket. That was the leading
// theory for the CI failure above and it is NOT confirmed: 40 trials of a tight
// scan immediately after Start never caught the window on this developer's box.
// Removing the fork is still right (fewer processes, and one fewer thing the
// test depends on), it is simply not known to be the cause.
//
// `read` is a shell builtin, so this sh runs it in-process and never has a
// child at all; closing stdin is what ends it.
func marker(t *testing.T, arg string) *exec.Cmd {
	t.Helper()
	c := exec.Command("/bin/sh", "-c", "read x", arg)
	stdin, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
	})
	return c
}

// The reaper is the only thing that runs after snug is SIGKILLed, and it is
// triggered by EOF on a pipe. Assert both edges: it fires on EOF, and it does
// nothing when snug cleaned up and said so.
func TestReaperFiresOnEOFAndStandsDown(t *testing.T) {
	run := func(t *testing.T, standDown bool) bool {
		dir := t.TempDir()
		marker := filepath.Join(dir, "reaped")
		fake := filepath.Join(dir, "podman")
		script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + marker + "\n"
		if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}

		sock := filepath.Join(dir, "podman-1.sock")
		r, err := startReaper(fake, filepath.Join(dir, "storage"), filepath.Join(dir, "rr"), sock, RunLabelKey+"=test")
		if err != nil {
			t.Fatal(err)
		}
		// The reaper must not name the socket in its own command line, or the
		// /proc sweep would find snug's own cleanup and report it as a leak.
		cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(r.cmd.Process.Pid) + "/cmdline")
		if err == nil && strings.Contains(string(cmdline), sock) {
			t.Errorf("the reaper's command line names the socket; the sweep will match itself")
		}

		if standDown {
			r.standDown()
		} else {
			r.w.Close() // exactly what the kernel does when snug is SIGKILLed
			_, _ = r.cmd.Process.Wait()
		}

		for i := 0; i < 200; i++ {
			if _, err := os.Stat(marker); err == nil {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}

	if !run(t, false) {
		t.Error("snug died and the reaper did not stop the sandbox's containers")
	}
	if run(t, true) {
		t.Error("snug cleaned up and told the reaper to stand down, but it ran anyway")
	}
}

// specConf runs Spec against a throwaway Engine and returns the generated
// containers.conf's content together with the environment the engine will be
// started with. It is the shared setup for every #126/#132 assertion below.
func specConf(t *testing.T, net policy.NetPolicy, cgroupsDisabled bool) (conf string, env []string) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	e, err := New([]policy.ProfileName{"@podman-socket"}, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := e.Spec("/usr/bin/podman", []string{"PATH=/usr/bin"}, cgroupsDisabled, net)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, kv := range spec.Env {
		if rest, ok := strings.CutPrefix(kv, "CONTAINERS_CONF="); ok {
			path = rest
		}
	}
	if path == "" {
		t.Fatal("Spec set no CONTAINERS_CONF at all — the engine reads the HOST's containers.conf")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data), spec.Env
}

// TestTheEngineReadsOnlySnugsOwnContainersConf is issue #132's structural half.
// Both variables must name snug's generated file: CONTAINERS_CONF is what
// REPLACES the host's /etc/containers/containers.conf and
// ~/.config/containers/containers.conf, and CONTAINERS_CONF_OVERRIDE is what
// still wins if something between here and the engine exports CONTAINERS_CONF
// of its own (issue #133 is exactly that, in the test wrapper).
//
// CONTROL: the file the variables name must EXIST and be non-empty — otherwise
// this test passes on a Spec that names a path it never wrote.
func TestTheEngineReadsOnlySnugsOwnContainersConf(t *testing.T) {
	conf, env := specConf(t, policy.NetPolicy{Mode: policy.NetEgress, Nameservers: []string{"192.0.2.53"}}, false)
	if strings.TrimSpace(conf) == "" {
		t.Fatal("CONTAINERS_CONF names an empty file")
	}

	var confPath, overridePath string
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "CONTAINERS_CONF="); ok {
			confPath = rest
		}
		if rest, ok := strings.CutPrefix(kv, "CONTAINERS_CONF_OVERRIDE="); ok {
			overridePath = rest
		}
	}
	if overridePath == "" {
		t.Error("Spec set no CONTAINERS_CONF_OVERRIDE: an export of CONTAINERS_CONF anywhere " +
			"between here and the engine silently restores the host's configuration (issue #133)")
	}
	if confPath != overridePath {
		t.Errorf("the two variables name different files (%q vs %q): the engine's configuration "+
			"then depends on which one podman happens to load", confPath, overridePath)
	}
}

// TestGeneratedContainersConfClosesTheHostInjectionKeys is issue #132's
// enumerated half — the keys a host containers.conf would otherwise have
// supplied on EVERY container, none of them client-requested and none of them
// visible to the proxy's bind filter or to --dry-run. CONTAINERS_CONF already
// stops those files being read; naming the keys is "never trust a helper's
// default, in either direction", and it is what still holds if a future podman
// changes CONTAINERS_CONF from "replaces" to "merges".
func TestGeneratedContainersConfClosesTheHostInjectionKeys(t *testing.T) {
	conf, _ := specConf(t, policy.NetPolicy{Mode: policy.NetEgress, Nameservers: []string{"192.0.2.53"}}, false)
	for _, want := range []string{
		"mounts = []",
		"volumes = []",
		"devices = []",
		"env = []",
		"env_host = false",
		"http_proxy = false",
		"hooks_dir = []",
		"annotations = []",
		"privileged = false",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated containers.conf does not close %q:\n%s", want, conf)
		}
	}
}

// TestTheInjectionKeyListSaysWhatItDoesNotClose is the honesty half, and it
// exists because the first version of this list was PRESENTED as complete and
// was not — a red-team pass measured a bare `env` key injecting into every
// container while the doc comment said the keys a host config "would otherwise
// have supplied" were closed.
//
// default_capabilities, default_sysctls, default_ulimits, seccomp_profile and
// userns are deliberately NOT closed: emptying or pinning any of them
// overrides podman's own default for every container, a policy decision
// writeContainersConf must not make silently. For those the guarantee is
// CONTAINERS_CONF's replacement alone (issue #136).
//
// This test fails if one of them is added WITHOUT the comment being updated,
// which is the drift it exists to catch — a list whose prose and content
// disagree is how the finding happened in the first place.
func TestTheInjectionKeyListSaysWhatItDoesNotClose(t *testing.T) {
	conf, _ := specConf(t, policy.NetPolicy{Mode: policy.NetEgress, Nameservers: []string{"192.0.2.53"}}, false)
	for _, notClosed := range []string{
		"default_capabilities",
		"default_sysctls",
		"default_ulimits",
		"seccomp_profile",
		"userns",
	} {
		if strings.Contains(conf, notClosed) {
			t.Errorf("generated containers.conf now names %q, which writeContainersConf's own "+
				"comment lists as deliberately NOT closed. Either the comment and issue #136 "+
				"are stale, or a value was chosen on podman's behalf without deciding to:\n%s",
				notClosed, conf)
		}
	}
}

// TestGeneratedContainersConfTakesDNSFromTheResolvedPolicy is issue #126's
// container half: podman generates every container's /etc/resolv.conf from the
// ENGINE's own unless containers.conf names DNS, and its /etc/hosts from the
// host's unless base_hosts_file says otherwise.
//
// The assertion is that the file carries the POLICY's nameserver, not the
// host's — with a nameserver no host has, so a pass cannot be an accident of
// this machine's own resolver configuration.
func TestGeneratedContainersConfTakesDNSFromTheResolvedPolicy(t *testing.T) {
	net := policy.NetPolicy{Mode: policy.NetEgress, Nameservers: []string{"192.0.2.53"}}
	conf, _ := specConf(t, net, false)

	for _, want := range []string{
		`dns_servers = ["192.0.2.53"]`,
		`dns_searches = ["."]`, // dns_servers ALONE still leaked the host's search domain
		`dns_options = ["edns0"]`,
		`base_hosts_file = "none"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated containers.conf is missing %s:\n%s", want, conf)
		}
	}
}

// TestGeneratedContainersConfNeverLeavesDNSUNSETOffline is the sharp edge of
// the above: podman reads dns_servers = [] as "not configured" and falls back
// to the engine's own /etc/resolv.conf — so an EMPTY list would reopen exactly
// the leak this closes, on the one configuration (offline) where it matters
// most. Offline must therefore name a server that resolves nothing rather than
// naming none.
//
// CONTROL: the egress case above proves a real nameserver does reach the file,
// so "non-empty offline" is not passing because the key is hardcoded.
func TestGeneratedContainersConfNeverLeavesDNSUnsetOffline(t *testing.T) {
	conf, _ := specConf(t, policy.NetPolicy{Mode: policy.NetIsolated}, false)
	if strings.Contains(conf, "dns_servers = []") {
		t.Errorf("offline containers.conf leaves dns_servers EMPTY, which podman reads as "+
			"'not configured' and answers from the engine's own /etc/resolv.conf:\n%s", conf)
	}
	if !strings.Contains(conf, "dns_servers = [") {
		t.Errorf("offline containers.conf names no dns_servers at all:\n%s", conf)
	}
	if !strings.Contains(conf, `base_hosts_file = "none"`) {
		t.Errorf("offline containers.conf still copies the host's /etc/hosts:\n%s", conf)
	}
}

// TestTheEnginesTwoDNSRenderingsCannotDiverge is invariant 6 ("one Policy, one
// author") applied to the one fact that now has two renderings: the engine's
// /etc/resolv.conf and the containers.conf keys. Both must come from the SAME
// policy.NetPolicy — this test fails if a future change re-derives either one.
func TestTheEnginesTwoDNSRenderingsCannotDiverge(t *testing.T) {
	net := policy.NetPolicy{Mode: policy.NetEgress, Nameservers: []string{"198.51.100.7"}}
	conf, _ := specConf(t, net, false)
	resolv := string(net.ResolvConf())

	if !strings.Contains(resolv, "nameserver 198.51.100.7") {
		t.Fatalf("control: the policy's own resolv.conf does not name the policy's nameserver:\n%s", resolv)
	}
	if !strings.Contains(conf, `"198.51.100.7"`) {
		t.Errorf("containers.conf and /etc/resolv.conf disagree about the nameserver:\n%s\n%s", conf, resolv)
	}
}

// TestCgroupsDisabledStillReachesTheEngine guards the job this file had BEFORE
// #126 gave it two more: preflight P5's selection is a containers.conf setting,
// and it must survive the file gaining other content.
//
// CONTROL: the same Spec with cgroupsDisabled=false must NOT carry it, so this
// is not asserting a constant.
func TestCgroupsDisabledStillReachesTheEngine(t *testing.T) {
	net := policy.NetPolicy{Mode: policy.NetEgress, Nameservers: []string{"192.0.2.53"}}
	with, _ := specConf(t, net, true)
	if !strings.Contains(with, `cgroups = "disabled"`) {
		t.Errorf("preflight P5's selection did not reach the engine:\n%s", with)
	}
	without, _ := specConf(t, net, false)
	if strings.Contains(without, `cgroups = "disabled"`) {
		t.Errorf("cgroups was disabled without P5 selecting it:\n%s", without)
	}
}
