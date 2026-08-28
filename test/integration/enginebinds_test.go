//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// ── issue #376: a DECLARED source inside the target is bindable ──────────────

// TestADeclaredEngineBindIsForwardedAsTheGraftRoot is the integration half of
// issue #376, and its whole point is the pair of verdicts against ONE real
// engine: the path a profile declared is accepted where the identical
// undeclared path is refused, and what the engine was actually asked for is the
// GRAFT, not the host name.
//
// #284's anchored-source rule refuses every path strictly below the target,
// because the engine re-resolves the forwarded STRING at container start and
// the payload can swap a name in the gap. Fork A does not relax that rule; it
// stops the source being a string. snug clones the declared host directory into
// the engine's own mount namespace at /snug/engine/binds/<base name> — before
// the payload has ever run, since bwrap parks it behind --block-fd until the
// engine answers — and forwards that guest path instead.
//
// THE LOAD-BEARING ASSERTION IS THE INSPECT, not the 201. A create returning
// 201 proves only that snug allowed the request; a run that forwarded the host
// path and got 201 anyway would be issue #284 reopened with a green test. So
// the probe reads Mounts[].Source back off the created container and requires
// it to be the graft path, exactly as internal/dockerproxy's own test asserts
// on the forwarded body rather than on the status.
//
// NO requireRealEngine, DELIBERATELY, and it costs this test its row in
// SNUG_ENGINE_FLOOR (the Makefile's own comment: membership is reaching the
// "snug-engine-ran:" marker, never a name sweep). Everything under test lives
// on the CREATE path, and on a host with no CAP_NET_ADMIN a container cannot
// START at all — so gating on requireRealEngine would skip this on the machine
// it was written on. The CONTROL create is the gate instead: an anchored
// read-only bind of /usr must return 201, and without that every refusal below
// is equally explained by an engine that never came up. Same choice, same
// reason, as TestCreateTopLevelIsFilteredEndToEnd.
//
// WHAT A CREATE-ONLY TEST STILL PROVES ABOUT THE GRAFT ITSELF, because "no
// container was started, so no mount happened" is the reasonable objection: the
// graft is installed by __inengine at ENGINE startup, before any request, and
// its openat2(RESOLVE_NO_SYMLINKS) + open_tree(OPEN_TREE_CLONE) + move_mount
// failures are all fatal to the engine. So an engine that answered the build
// above is an engine that really did clone the declared host directory into its
// own namespace. What is NOT covered here is crun mounting the graft INTO a
// container, which needs `start`; the by-hand equivalent is VERIFY.md
// 9c-quinquies.
//
// MEASURED, this host, podman 6.0.2: BUILD 200, CONTROL-ANCHORED 201 with
// source /usr, DECLARED 201 with `DECLARED-SOURCE: /snug/engine/binds/data ->
// /data`, and 403 for each of DECLARED-TAIL, SIBLING and RELATIVE.
func TestADeclaredEngineBindIsForwardedAsTheGraftRoot(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	proj, _ := target(t)

	// The declared directory, and a sibling that is NOT declared. The sibling
	// is what makes the accepted case attributable to the declaration rather
	// than to the rule having been loosened for the whole target.
	for _, d := range []string{"data", "data/sub", "other"} {
		if err := os.MkdirAll(filepath.Join(proj, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A file the graft must carry across, so the ACCEPTED case is more than a
	// path comparison: the mount has to hold the declared tree's content.
	if err := os.WriteFile(filepath.Join(proj, "data", "MARKER"), []byte("declared\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "bindprobe"), []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "declared.toml"), []byte(
		"[profile.declared-bind]\n"+
			"description = \"issue #376: one declared engine bind inside the target\"\n"+
			"include = [\"@podman-build\", \"@cwd-rw\"]\n"+
			"engine_binds = [\"{target}/data\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env = append(env, "XDG_CONFIG_HOME="+cfg)

	tag := "snugtest-declaredbind:1"
	script := buildScratchProbeImageFor(tag, "bindprobe") + fmt.Sprintf(`
def create(label, src, dst="/x", opts="rw"):
    body = json.dumps({"Image": "localhost/%[1]s",
                       "HostConfig": {"Binds": ["%%s:%%s:%%s" %% (src, dst, opts)]}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    text = resp.decode(errors="replace")
    print("%%s: %%d %%s" %% (label, status, text[:600].replace("\n", " | ")), flush=True)
    if status != 201:
        return status
    cid = json.loads(resp)["Id"]
    st, ins = req("GET", "/v1.41/containers/%%s/json" %% cid)
    if st == 200:
        for m in json.loads(ins).get("Mounts", []):
            print("%%s-SOURCE: %%s -> %%s" %% (label, m.get("Source"), m.get("Destination")), flush=True)
    else:
        print("%%s-INSPECT-FAILED: %%d" %% (label, st), flush=True)
    req("DELETE", "/v1.41/containers/%%s?force=1" %% cid)
    return status

if build_scratch_probe():
    # CONTROL: an anchored source is still mountable against this engine.
    create("CONTROL-ANCHORED", "/usr", "/u", "ro")

    here = os.getcwd()
    # The declaration itself: refused before issue #376 in every layout.
    create("DECLARED", os.path.join(here, "data"), "/data")
    # The three that must STAY refused with the declaration in place.
    create("DECLARED-TAIL", os.path.join(here, "data", "sub"))
    create("SIBLING", os.path.join(here, "other"))
    create("RELATIVE", "./data")
print("PROBE-COMPLETE", flush=True)
`, tag)
	if err := os.WriteFile(filepath.Join(proj, "declaredbind.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"--no-defaults", "-p", "declared-bind"}, proj,
		`python3 declaredbind.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Skipf("the from-scratch image did not build, so no create in this test means "+
			"anything about the bind filter:\n%s", r.out)
	}
	if !strings.Contains(r.out, "CONTROL-ANCHORED: 201") {
		t.Skipf("control: an anchored read-only bind of /usr was NOT accepted (want 201), so "+
			"this engine cannot create containers at all and every verdict below is "+
			"unattributable:\n%s", r.out)
	}

	if !strings.Contains(r.out, "DECLARED: 201") {
		t.Errorf("a path DECLARED with engine_binds was still refused — issue #376 is not "+
			"delivered:\n%s", r.out)
	}
	// The load-bearing one. Read the engine's own idea of the mount source
	// back: it must be snug's guest path, and the host path must not appear.
	wantSource := policy.EngineBindsDir + "/data"
	if !strings.Contains(r.out, "DECLARED-SOURCE: "+wantSource+" -> /data") {
		t.Errorf("the engine was not asked for the graft root %s — if it was handed the host "+
			"path instead, the string is re-resolved at container start and issue #284 is "+
			"reopened through the declaration:\n%s", wantSource, r.out)
	}

	for _, label := range []string{"DECLARED-TAIL", "SIBLING", "RELATIVE"} {
		if !strings.Contains(r.out, label+": 403") {
			t.Errorf("%s was not refused with 403 — Fork A grants only DECLARED sources, at "+
				"their exact root:\n%s", label, r.out)
		}
	}
	// DECLARED-TAIL is the one worth a second assertion: graft-root plus a
	// request-supplied tail is #284 through the graft, because crun re-resolves
	// the whole forwarded string at start and open_tree(OPEN_TREE_CLONE) pins
	// an inode only at the graft's own root.
	if strings.Contains(r.out, "DECLARED-TAIL-SOURCE") {
		t.Errorf("a create for the declared root plus a tail was FORWARDED:\n%s", r.out)
	}
}

// TestDeclaredEngineBindAppearsInDryRun is the ticket's own standard — "a mount
// the payload asked for is a mount a human should be able to see before it
// exists" — asserted against the real binary rather than against a golden.
//
// It needs no engine at all and therefore runs everywhere, which is the point:
// the golden in internal/cli pins the block's TEXT, and this pins that the text
// reaches a user who types the command. Both halves have to be present, because
// the argv line and the graft row are produced by different code from the same
// resolved value, and a change that dropped one would leave a plausible screen.
func TestDeclaredEngineBindAppearsInDryRun(t *testing.T) {
	proj, _ := target(t)
	if err := os.MkdirAll(filepath.Join(proj, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "declared.toml"), []byte(
		"[profile.declared-bind]\n"+
			"include = [\"@podman-socket\", \"@cwd-rw\"]\n"+
			"engine_binds = [\"{target}/data\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	out, code := cli(t, env, "--dry-run", "--no-defaults", "-p", "declared-bind", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	guest := policy.EngineBindsDir + "/data"
	// The ENGINE VIEW row, with its source and its abuse sentence.
	if !strings.Contains(out, "graft-rw    "+guest) {
		t.Errorf("--dry-run's ENGINE VIEW block does not show the declared bind at %s:\n%s",
			guest, out)
	}
	if !strings.Contains(out, "from "+filepath.Join(proj, "data")) {
		t.Errorf("the ENGINE VIEW row does not name the host tree it clones:\n%s", out)
	}
	if !strings.Contains(out, "Declared by declared-bind with engine_binds") {
		t.Errorf("the ENGINE VIEW row does not name the profile that declared it, so a reader "+
			"cannot tell which line of which profile to delete:\n%s", out)
	}
	// The argv that pre-creates the destination. Without it the graft's
	// move_mount(2) has nowhere to land — the sandbox root is read-only by
	// then, so mkdir fails EROFS — and the row above would describe a mount
	// that cannot happen.
	if !strings.Contains(out, "--dir "+policy.EngineBindsDir+"\n") {
		t.Errorf("the bwrap argv does not pre-create %s:\n%s", policy.EngineBindsDir, out)
	}
	if !strings.Contains(out, "--dir "+guest+"\n") {
		t.Errorf("the bwrap argv does not pre-create the declared bind's destination %s:\n%s",
			guest, out)
	}
}
