package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// doorRegistry adds a profile that opens an http door and one that sets
// login = ["claude"], neither granting anything else.
func doorRegistry() map[ProfileName]*Profile {
	reg := testRegistry()
	reg["door"] = &Profile{Name: "door", ListenNames: []string{"web"}}
	reg["bridge"] = &Profile{Name: "bridge", Login: []string{"claude"}, Network: "egress"}
	// A runtime that is not @sys's: /usr comes from a host directory that
	// holds no sh, and /bin is not linked to it.
	reg["bare"] = &Profile{Name: "bare", RO: []string{"/opt/bin:/usr"}}
	return reg
}

// TestDoorNeedsNoShell fails if a door selection is ever refused again for want
// of a shell: the handover is snug's own binary now, so a selection whose
// runtime is a bare /usr with no /bin link must resolve, with the wrapper as
// the command's entry and the payload behind the verb. It cannot show that no
// shell is present at run time (Resolve sees mounts, not files); the
// integration test for a door with a static payload and no @sys does.
func TestDoorNeedsNoShell(t *testing.T) {
	p, err := Resolve(doorRegistry(), []ProfileName{"bare", "@target-rw", "door"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("a door with no shell was refused: %v", err)
	}
	want := append([]string{WrapperGuest, DoorExecVerb}, testCtx().Command...)
	if !reflect.DeepEqual(p.Command, want) {
		t.Errorf("Command = %q, want %q", p.Command, want)
	}
	// POSITIVE CONTROL: the selection really has no shell, or the test proved
	// nothing about needing none.
	for _, g := range []string{"/bin", "/bin/sh"} {
		if _, ok := p.Mounts[g]; ok {
			t.Fatalf("control: %s is mounted, so this selection has a /bin to find a shell in", g)
		}
	}
	if p.Mounts["/usr"].Host != "/opt/bin" {
		t.Fatalf("control: /usr = %+v, want the bare runtime from /opt/bin", p.Mounts["/usr"])
	}
}

// TestLoginNeedsNoShell fails if login = ["claude"] starts requiring a shell
// again: BROWSER is a symlink to snug's own binary.
func TestLoginNeedsNoShell(t *testing.T) {
	p, err := Resolve(doorRegistry(), []ProfileName{"bare", "@target-rw", "bridge"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("login = [\"claude\"] with no shell was refused: %v", err)
	}
	if m := p.Mounts[BrowserGuest]; m.Kind != KindSymlink || m.Host != WrapperGuest {
		t.Errorf("BROWSER link = %+v, want a symlink to %s", m, WrapperGuest)
	}
	for _, g := range []string{"/bin", "/bin/sh"} {
		if _, ok := p.Mounts[g]; ok {
			t.Fatalf("control: %s is mounted, so this selection has a /bin to find a shell in", g)
		}
	}
	if p.Mounts["/usr"].Host != "/opt/bin" {
		t.Fatalf("control: /usr = %+v, want the bare runtime from /opt/bin", p.Mounts["/usr"])
	}
}

// TestWrapperStagedOnceForDoorAndLogin fails if the two features each write the
// wrapper mount: the second Replace would record "replaces:(snug)", snug
// displacing itself, on a --dry-run row a human reads for what was overridden.
func TestWrapperStagedOnceForDoorAndLogin(t *testing.T) {
	p, err := Resolve(doorRegistry(), []ProfileName{"@sys", "@target-rw", "door", "bridge"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	w, ok := p.Mounts[WrapperGuest]
	if !ok {
		t.Fatalf("no mount at %s", WrapperGuest)
	}
	if !reflect.DeepEqual(w.From, []string{"(snug)"}) {
		t.Errorf("From = %q, want exactly [(snug)] with no replaces:", w.From)
	}
	if w.Kind != KindBind || w.Access != AccessRO || w.Host != SelfExeHost || !w.Authored {
		t.Errorf("wrapper mount = %+v, want an authored read-only bind of %s", w, SelfExeHost)
	}
	b := p.Mounts[BrowserGuest]
	if !reflect.DeepEqual(b.From, []string{"(snug)"}) {
		t.Errorf("browser link From = %q, want exactly [(snug)]", b.From)
	}
}

// TestWrapperAbsentWithoutDoorOrLogin fails if snug's own binary is bound into
// a sandbox that has no feature using it: it is a readable and runnable copy of
// the launcher, which nothing but those two features justifies.
func TestWrapperAbsentWithoutDoorOrLogin(t *testing.T) {
	reg := doorRegistry()
	reg["netty-only"] = &Profile{Name: "netty-only", Network: "egress"}
	for _, sel := range [][]ProfileName{
		{"@sys", "@target-rw"},
		{"@sys", "@target-rw", "netty-only"},
	} {
		p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("Resolve(%v): %v", sel, err)
		}
		for _, g := range []string{WrapperGuest, BrowserGuest} {
			if _, ok := p.Mounts[g]; ok {
				t.Errorf("%v: a mount at %s without a door or a login", sel, g)
			}
		}
	}
	// POSITIVE CONTROL: either feature alone does stage it.
	for _, feature := range []ProfileName{"door", "bridge"} {
		p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", feature}, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.Mounts[WrapperGuest]; !ok {
			t.Errorf("control: %s alone did not stage %s", feature, WrapperGuest)
		}
	}
}

// TestDoorAloneDoesNotPutStagedBinOnPATH fails if the door goes back to staging
// something under /snug/bin: that makes snug's directory first on the payload's
// PATH, where the shim used to put it, for a feature that has no command.
func TestDoorAloneDoesNotPutStagedBinOnPATH(t *testing.T) {
	p, err := Resolve(doorRegistry(), []ProfileName{"@sys", "@target-rw", "door"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if p.HasStagedBin() {
		t.Error("HasStagedBin() is true for a door alone")
	}
	path, ok := p.EnvValue("PATH")
	if !ok {
		t.Fatal("control: PATH is not authored at all")
	}
	for _, dir := range []string{StagedBinDir, SnugLibDir, SnugDir + "/lib"} {
		for _, e := range strings.Split(path, ":") {
			if e == dir {
				t.Errorf("PATH %q contains %s", path, dir)
			}
		}
	}
	if !strings.Contains(path, "/usr/bin") {
		t.Errorf("control: PATH %q lacks /usr/bin, so the split above ran over nothing", path)
	}
}

// TestBindByPathSelfExe fails if /proc/self/exe is handed to bwrap as a path:
// bwrap would resolve it in its OWN process and bind bwrap, not snug. The
// ordinary /proc rule is checked beside it as the control.
func TestBindByPathSelfExe(t *testing.T) {
	if BindByPath(SelfExeHost) {
		t.Errorf("BindByPath(%s) is true; it must be opened as a descriptor in snug", SelfExeHost)
	}
	if !BindByPath("/proc/keys") {
		t.Error("control: BindByPath(/proc/keys) is false")
	}
}

// TestSelfExeHostRefusedUnlessAuthoredAtWrapper fails if SelfExeHost can be the
// host of any mount but the one snug authors read-only at WrapperGuest. The
// launcher opens it following the magic link and Resolve's canonical-host loop
// skips it, so a second spelling would inherit both exemptions.
func TestSelfExeHostRefusedUnlessAuthoredAtWrapper(t *testing.T) {
	good, err := Resolve(doorRegistry(), []ProfileName{"@sys", "@target-rw", "door"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if err := good.Validate(newFakeEnv()); err != nil {
		t.Fatalf("control: the resolved policy does not validate: %v", err)
	}
	cases := map[string]func(p *Policy){
		"authored rw at the wrapper": func(p *Policy) {
			m := p.Mounts[WrapperGuest]
			m.Access = AccessRW
			p.Mounts[WrapperGuest] = m
		},
		"authored at another guest": func(p *Policy) {
			p.Mounts["/snug/bin/x"] = Mount{Guest: "/snug/bin/x", Kind: KindBind, Access: AccessRO,
				Host: SelfExeHost, Authored: true, From: []string{"(snug)"}}
		},
		"unauthored at the wrapper's guest": func(p *Policy) {
			m := p.Mounts[WrapperGuest]
			m.Authored = false
			p.Mounts[WrapperGuest] = m
		},
		"authored wrapper with another host": func(p *Policy) {
			m := p.Mounts[WrapperGuest]
			m.Host = "/usr/bin"
			p.Mounts[WrapperGuest] = m
		},
		"unauthored elsewhere": func(p *Policy) {
			p.Mounts["/opt/x"] = Mount{Guest: "/opt/x", Kind: KindBind, Access: AccessRO,
				Host: SelfExeHost, From: []string{"evil"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := Resolve(doorRegistry(), []ProfileName{"@sys", "@target-rw", "door"}, testCtx(), newFakeEnv())
			if err != nil {
				t.Fatal(err)
			}
			mutate(p)
			if err := p.Validate(newFakeEnv()); err == nil {
				t.Errorf("Validate accepted %s", name)
			}
		})
	}
}

// TestProfileCannotMountUnderSnugLib fails if a profile can place anything at,
// above or below SnugLibDir: a profile mount is a SEPARATE mount that
// --remount-ro / does not reach, so a writable one under the wrapper's
// directory would let the payload swap the binary the door execs.
func TestProfileCannotMountUnderSnugLib(t *testing.T) {
	guests := []string{"/snug/lib", SnugLibDir, SnugLibDir + "/x", WrapperGuest, BrowserGuest}
	for _, g := range guests {
		for kind, prof := range map[string]*Profile{
			"ro bind": {RO: []string{"/usr/bin:" + g}},
			"tmpfs":   {Tmpfs: []string{g}},
			"symlink": {Symlink: []Symlink{{At: g, Target: "usr/bin"}}},
		} {
			t.Run(kind+" at "+g, func(t *testing.T) {
				reg := doorRegistry()
				prof.Name = "hostile"
				reg["hostile"] = prof
				// With and without a door, so the refusal is not the wrapper's own mount
				// colliding with it.
				for _, sel := range [][]ProfileName{
					{"@sys", "@target-rw", "hostile"},
					{"@sys", "@target-rw", "door", "hostile"},
				} {
					p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
					if err == nil && g == WrapperGuest && len(sel) == 4 {
						// snug's own write at the wrapper's path wins over
						// a profile's, like a generated gitconfig over a
						// bound one, and --dry-run shows the displacement.
						// What must hold is that the survivor is snug's.
						m := p.Mounts[g]
						if m.Host != SelfExeHost || m.Access != AccessRO || !m.Authored ||
							!strings.Contains(strings.Join(m.From, "+"), "replaces:hostile") {
							t.Errorf("%v: mount at %s = %+v, want snug's wrapper displacing the profile's", sel, g, m)
						}
						continue
					}
					if err == nil {
						t.Errorf("%v resolved with a profile %s at %s", sel, kind, g)
					}
				}
			})
		}
	}
	// POSITIVE CONTROL: the same profile shape one directory over is fine, so
	// the refusals above are about the path and not about the fixture.
	reg := doorRegistry()
	reg["ok"] = &Profile{Name: "ok", RO: []string{"/usr/bin:/srv/bin"}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "ok"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: an ordinary ro bind was refused: %v", err)
	}
}

// TestProfileSelfExeSpecCanonicalises fails if ro = ["/proc/self/exe:/x"] can
// reach the launcher as SelfExeHost: a profile bind's host goes through
// EvalSymlinks, which follows the magic link, so what a profile names is
// snug's real path and never the exemption.
func TestProfileSelfExeSpecCanonicalises(t *testing.T) {
	env := newFakeEnv()
	env.links = map[string]string{"/proc/self/exe": "/usr/bin"}
	reg := doorRegistry()
	reg["selfy"] = &Profile{Name: "selfy", RO: []string{"/proc/self/exe:/srv/x"}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "selfy"}, testCtx(), env)
	if err != nil {
		t.Fatalf("control: the profile's bind did not resolve (%v), so nothing was compared", err)
	}
	for g, m := range p.Mounts {
		if m.Host == SelfExeHost {
			t.Errorf("mount at %s has host %s from a profile spec", g, SelfExeHost)
		}
	}
	if m, ok := p.Mounts["/srv/x"]; !ok || m.Host == SelfExeHost {
		t.Errorf("control: /srv/x = %+v, want a bind whose host is the resolved path", m)
	}
}

// TestGoldenBwrapDoorNoSys pins the argv of an http door whose runtime is not
// @sys: the review artifact for "the door adds snug's own binary, read-only,
// at WrapperGuest, the two directories above it, LISTEN_FDS and
// LISTEN_FDNAMES, and nothing under /snug/bin or on PATH". It fails on any
// change to that set. It does not show LISTEN_PID, which is set inside by the
// wrapper and appears in no argv.
func TestGoldenBwrapDoorNoSys(t *testing.T) {
	p, err := Resolve(doorRegistry(), []ProfileName{"bare", "@target-rw", "door"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := goldenFormat(p.BwrapArgs(1000, 1000))
	for _, want := range []string{"--ro-bind-fd", WrapperGuest, "LISTEN_FDS", DoorExecVerb} {
		if !strings.Contains(got, want) {
			t.Fatalf("control: the argv has no %q, so the golden would pin a door-less sandbox:\n%s", want, got)
		}
	}
	path := filepath.Join("testdata", "door-no-sys.bwrap.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/policy -update, then READ the diff)", err)
	}
	if got != string(want) {
		t.Errorf("argv changed — this is a change to the sandbox boundary.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
