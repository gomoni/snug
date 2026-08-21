//go:build integration

package integration

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestTheRunDirectoryIsInMountinfoOnlyWhenAProxySocketIsMounted pins what the
// payload can learn about its supervisor from its own mount table.
//
// NAMED FOR WHAT IT ASSERTS. The row in tracker #33 asked for
// `TestMountinfoNeverNamesTheSupervisorPid`, and that name is a claim the tree
// does not support: on a run that mounts a proxy socket, the payload reads
// snug's host pid out of field 4 of its own /proc/self/mountinfo. Measured
// (#272), from inside the sandbox:
//
//	68896 68857 0:70 /snug/run-901003/ssh-agent.sock /snug/ssh-agent.sock rw,…
//
// Field 4 is the root WITHIN THE SOURCE FILESYSTEM, so the bind's host-side
// path comes along, and the run directory is named run-<snug's pid>. The
// maintainer accepted that (sev:low, information disclosure only: the payload
// is in its own pid namespace, so it cannot see, signal or /proc-inspect that
// process — what it gains is a target if some other bug ever yields a way to
// act on the host). A test called "never names" would have been the
// documented-but-not-implemented shape with a green tick on it.
//
// So this test pins the ACCEPTED behaviour, in both arms, and the arms are not
// redundant:
//
//   - A DEFAULT run mounts nothing out of the run directory at all. The
//     directory exists on every real run (#61), but nothing binds out of it
//     unless a profile puts a proxy socket there — so a one-armed "no pid in
//     mountinfo" test would pass here for a reason that has nothing to do with
//     the property, and would keep passing if the identity case got worse.
//   - An IDENTITY run mounts the ssh-agent proxy socket, and its source names
//     the run directory, whose name is the supervisor's pid. Asserted against
//     the pid of the snug process this test actually started, rather than
//     against a regexp that would match any number.
//
// If #272 is ever closed by making the run-directory name pid-free, this test
// fails and must be rewritten — which is the point of pinning it: the change
// has to be deliberate.
func TestTheRunDirectoryIsInMountinfoOnlyWhenAProxySocketIsMounted(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)

	// ── arm one: a default run mounts nothing out of the run directory ────
	proj, _ := target(t)
	r := runEnv(t, nil, nil, proj, `
grep -c 'run-[0-9]' /proc/self/mountinfo || true
echo "LINES $(wc -l < /proc/self/mountinfo)"
echo "TARGET-BOUND $(grep -c "$SNUG_TARGET" /proc/self/mountinfo)"
echo PROBE-DONE
`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-DONE") {
		t.Fatalf("the default-run probe did not finish:\n%s", r.out)
	}
	// CONTROL: this is a real mount table with the run's own grants in it.
	// Without it, "no run- line" is equally true of an empty file, a probe
	// that read the wrong path, or a sandbox that never started.
	if n := probeField(t, r.out, "LINES"); n < 5 {
		t.Fatalf("the payload's mountinfo has %d line(s) — that is not a mount table:\n%s", n, r.out)
	}
	if n := probeField(t, r.out, "TARGET-BOUND"); n < 1 {
		t.Fatalf("the payload's mountinfo does not name its own target, so this is not the "+
			"view the assertion is about:\n%s", r.out)
	}
	if strings.Contains(r.out, "/snug/run-") {
		t.Errorf("a DEFAULT run mounts something out of the run directory. Today nothing binds "+
			"out of it unless a profile puts a proxy socket there, and this arm is what keeps "+
			"the identity arm below from being the only thing measured:\n%s", r.out)
	}

	// ── arm two: an identity run mounts the proxy socket, and its source
	//    names the supervisor's pid ─────────────────────────────────────────
	pub, sock := sshAgentAndKey(t)
	idProj, _ := target(t)
	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"one throwaway key\"\n"+
		"[profile.pinned.identity]\n"+
		"ssh_mode = \"agent-proxy\"\n"+
		"ssh_key = \""+pub+"\"\n", "SSH_AUTH_SOCK="+sock)

	bg := startAttachSandbox(t, env, []string{"-p", "pinned"}, idProj, `sleep 120`)
	bg.ready(t)
	bg.waitForState(t)

	got := attachScript(t, env, idProj, "grep ssh-agent.sock /proc/self/mountinfo\necho PROBE-DONE\n")
	if !strings.Contains(got.out, "PROBE-DONE") {
		t.Fatalf("the identity-run probe did not finish:\n%s", got.out)
	}
	// CONTROL: the socket really is mounted. The disclosure below is a
	// property of that mount, so an absent mount would make the assertion
	// vacuous rather than passing.
	if !strings.Contains(got.out, "/snug/ssh-agent.sock") {
		t.Fatalf("the ssh-agent proxy socket is not in the payload's mount table, so there is "+
			"no mount for this arm to be about:\n%s", got.out)
	}

	// The accepted disclosure, asserted against the pid of the snug process
	// this test started rather than against "some number".
	want := fmt.Sprintf("/snug/run-%d/", bg.pid())
	if !strings.Contains(got.out, want) {
		t.Errorf("the proxy socket's source does not name %s. If the run directory stopped "+
			"carrying the supervisor's pid, #272 is fixed and this test is the one that has to "+
			"be rewritten — deliberately, which is why it pins the old behaviour:\n%s",
			want, got.out)
	}

	// And the number really is a pid rather than a coincidence of the path:
	// the field it appears in is the source root, so it is the HOST path.
	if m := regexp.MustCompile(`/snug/run-(\d+)/ssh-agent\.sock`).FindStringSubmatch(got.out); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n != bg.pid() {
			t.Errorf("the run directory in the payload's mountinfo names pid %d, but the snug "+
				"supervising this sandbox is %d — one of the two is not what this test thinks "+
				"it is", n, bg.pid())
		}
	} else {
		t.Errorf("no /snug/run-<pid>/ssh-agent.sock source in the mount table:\n%s", got.out)
	}
}
