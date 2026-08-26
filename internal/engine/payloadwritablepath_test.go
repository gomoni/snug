package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestNoGeneratedConfigNamesAPayloadWritablePath is issue #390's regression,
// and it asserts a SET rather than the two sites the issue named.
//
// The two sites were helper_binaries_dir (writeContainersConf) and
// mount_program (writeStorageConf). Both derived a value from
// filepath.Dir(podman) and mapped it through policy.EngineGuestPath, whose bind
// arm resolves through ANY KindBind mount — it has no Access test at all. So
// with $SNUG_PODMAN inside a target that @cwd-rw grants writable, MEASURED on
// cd17ea0:
//
//	helper_binaries_dir = ["/proj/bin", "/usr/libexec/podman", …]
//	mount_program       = "/proj/bin/fuse-overlayfs"
//
// The engine resolves conmon, crun, netavark and fuse-overlayfs out of those as
// root in the sandbox's user namespace with EngineCapBounding and the whole
// delegated subuid range, so the payload chose what the engine executed.
//
// WHY THE SET AND NOT THE SITES. Fixing two keys and testing two keys is how
// both of these arrived: helper_binaries_dir was added without anyone asking
// whether mount_program had the same derivation, and mount_program's own
// comment argued it was "inert" — which answers whether podman HONOURS the key
// and says nothing about whether snug WRITES it. A third key deriving a path
// the same way would land unguarded. This asks of every absolute path in every
// generated config: can the payload write here?
//
// WHY THERE IS NO GOLDEN FOR THIS. Measured: no fixture under any testdata/
// renders helper_binaries_dir or mount_program, so the fix produces no golden
// diff at all — CLAUDE.md's "a security change that produces no golden diff is
// probably untested" shape. This test is that assertion; there is nothing on
// screen and nothing in a golden to catch a regression here.
//
// THE FIXTURE IS THE LOAD-BEARING PART, and it is where this nearly went
// wrong twice. testPol returns &Policy{Profiles, Target} with NO resolved
// Mounts, so a target-relative engine path fails earlier at Spec's
// engine-binary visibility refusal and never reaches the code under test — red
// for the wrong reason, which reads exactly like a passing direction check.
// And mount_program is absent unless fuse-overlayfs REALLY sits beside the
// engine, so a fixture without it shows no mount_program line and the absence
// looks like safety. Both are fixtures that could not express the
// precondition. Do not simplify either away.
func TestNoGeneratedConfigNamesAPayloadWritablePath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	target := t.TempDir()

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, target))
	if err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Podman: policy.PodmanSocket,
		Mounts: map[string]policy.Mount{
			"/proj": {Guest: "/proj", Host: target, Kind: policy.KindBind,
				Access: policy.AccessRW, From: []string{"@cwd-rw"}},
			"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind,
				Access: policy.AccessRO, From: []string{"@sys"}},
		},
	}
	if err := e.GraftInto(policy.OSEnviron{}, p); err != nil {
		t.Fatal(err)
	}

	// The engine, and a helper beside it, both inside the writable target.
	bin := filepath.Join(target, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"podman", "fuse-overlayfs"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	spec, err := e.Spec(p, filepath.Join(bin, "podman"), []string{"PATH=/usr/bin"}, true, "crun", noSignaturePolicy(t))
	if err != nil {
		t.Fatalf("Spec refused, so this fixture never reaches the generated configs — the "+
			"precondition is an engine INSIDE a writable grant, and without it this test "+
			"asserts nothing: %v", err)
	}

	// POSITIVE CONTROL on the fixture itself: the guest path the engine binary
	// maps to must really be payload-writable, or every assertion below is
	// vacuous.
	if !writableInSandbox(p, "/proj/bin") {
		t.Fatal("fixture: /proj/bin is not payload-writable, so this test cannot detect the defect")
	}

	quoted := regexp.MustCompile(`"(/[^"]*)"`)
	var checked int
	for _, name := range []string{"CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF",
		"CONTAINERS_REGISTRIES_CONF", "REGISTRY_AUTH_FILE"} {
		v, n := envValue(spec.Env, name)
		if n != 1 || v == "" {
			continue
		}
		raw, err := os.ReadFile(hostSideOf(t, e, v))
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range quoted.FindAllStringSubmatch(line, -1) {
				checked++
				if writableInSandbox(p, m[1]) {
					t.Errorf("%s names %q, which the PAYLOAD can write — the engine resolves "+
						"its helpers out of paths in these files as root in the sandbox's user "+
						"namespace, so this is the payload choosing what the engine execs "+
						"(issue #390):\n  %s", name, m[1], strings.TrimSpace(line))
				}
			}
		}
	}
	// POSITIVE CONTROL on the sweep: a run that read no paths would report
	// success. The generated files carry the store, the runroot, the socket and
	// the helper directories, so a single-digit count means something stopped
	// being written and this test quietly stopped measuring.
	if checked < 5 {
		t.Errorf("the sweep examined only %d quoted absolute paths across the generated configs; "+
			"it is no longer reading what it thinks it is", checked)
	}
}

// writableInSandbox answers whether the payload can write a GUEST path, by the
// same rule the sandbox itself uses: effective access at a path is that of the
// DEEPEST mount covering it (CLAUDE.md invariant 1's non-monotone corollary —
// ro /proj plus rw /proj/src is how .git stays read-only). A shallower rw mount
// under a deeper ro one must not read as writable, which is why this cannot be
// a simple prefix scan.
func writableInSandbox(p *policy.Policy, guest string) bool {
	best, bestLen := policy.Mount{}, -1
	for _, m := range p.Mounts {
		if m.Guest != guest && !strings.HasPrefix(guest, strings.TrimSuffix(m.Guest, "/")+"/") {
			continue
		}
		if len(m.Guest) > bestLen {
			best, bestLen = m, len(m.Guest)
		}
	}
	return bestLen >= 0 && best.Access == policy.AccessRW
}
