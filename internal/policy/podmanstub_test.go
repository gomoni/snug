package policy

import (
	"io/fs"
	"strings"
	"testing"
)

// TestPodmanStubStagedOnlyForADetectedShim is the positive/negative pair for
// the trigger CONTAINER-CLIENT.md §8 specifies: staging follows detection,
// not mere selection of a podman profile.
func TestPodmanStubStagedOnlyForADetectedShim(t *testing.T) {
	sel := []ProfileName{"@sys", "@target-rw", "@podman-socket"}

	withShim, err := Resolve(testRegistry(), sel, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := withShim.Mounts[PodmanStubGuest]; !ok {
		t.Error("a detected shim + a podman profile must stage the stub, and did not")
	}

	withoutShim, err := Resolve(testRegistry(), sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := withoutShim.Mounts[PodmanStubGuest]; ok {
		t.Error("no shim was detected (ctx.HostShims is empty), but the stub was staged anyway")
	}
}

// TestPodmanStubStagedOnlyWhenPodmanIsSelected: a detected shim with no
// podman profile selected must not stage anything — the stub is gated on
// p.Podman, not merely on what the host looks like, so a sandbox that never
// asked for containers never sees a new executable on its PATH.
func TestPodmanStubStagedOnlyWhenPodmanIsSelected(t *testing.T) {
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@target-rw"}, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Podman != PodmanOff {
		t.Fatalf("test fixture error: expected PodmanOff, got %s", p.Podman)
	}
	if _, ok := p.Mounts[PodmanStubGuest]; ok {
		t.Error("stub staged despite no podman profile being selected")
	}
}

// TestPodmanStubBeatsUsrBinPodmanButLosesToProfilePath pins the ordering
// CONTAINER-CLIENT.md §8 calls load-bearing: profile-contributed PATH
// entries, then the stub's directory, then the base PATH (which is where
// /usr/bin lives). The stub's whole job is beating /usr/bin/podman; it must
// still lose to an explicit human grant.
func TestPodmanStubBeatsUsrBinPodmanButLosesToProfilePath(t *testing.T) {
	// "cwd-ro" carries a `path` entry in the fixture registry (see
	// testRegistry's comment on it) — reused here rather than inventing a new
	// fixture profile.
	sel := []ProfileName{"@sys", "@target-rw", "@podman-socket", "cwd-ro"}
	p, err := Resolve(testRegistry(), sel, testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	path, _ := p.EnvValue("PATH")
	profileDir := "/home/u/.local/bin"
	iProfile := strings.Index(path, profileDir)
	iStub := strings.Index(path, StagedBinDir)
	iBase := strings.Index(path, "/usr/bin")

	if iProfile < 0 || iStub < 0 || iBase < 0 {
		t.Fatalf("PATH is missing an expected entry: %q", path)
	}
	if !(iProfile < iStub && iStub < iBase) {
		t.Errorf("PATH order wrong: got %q, want profile dir, then %s, then the base PATH",
			path, StagedBinDir)
	}
}

// TestPodmanStubIsALinkToTheWrapper: the stub is snug's own image under the
// name podman, so it runs in a selection with no /bin/sh (issue #691), and the
// wrapper bind it points at is staged with it. Authored, or rejectMasking
// would treat it as a profile grant.
func TestPodmanStubIsALinkToTheWrapper(t *testing.T) {
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@target-rw", "@podman-socket"},
		testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	m, ok := p.Mounts[PodmanStubGuest]
	if !ok {
		t.Fatal("stub not staged")
	}
	if m.Kind != KindSymlink || m.Host != WrapperGuest || !m.Authored {
		t.Errorf("stub = %s -> %s (authored %v), want an authored symlink to %s",
			m.Kind, m.Host, m.Authored, WrapperGuest)
	}
	w, ok := p.Mounts[WrapperGuest]
	if !ok || w.Kind != KindBind || w.Host != SelfExeHost || w.Access != AccessRO {
		t.Errorf("wrapper mount = %+v (present %v), want a read-only bind of %s", w, ok, SelfExeHost)
	}
}

// clientHost is a host with executables at the given paths and nothing else
// but the directories above them.
type clientHost map[string]fs.FileMode

func (h clientHost) Lstat(p string) (fs.FileInfo, error) {
	if m, ok := h[p]; ok {
		return fakeInfo{name: p, mode: m}, nil
	}
	for q := range h {
		if strings.HasPrefix(q, p+"/") {
			return fakeInfo{name: p, dir: true, mode: fs.ModeDir | 0o755}, nil
		}
	}
	return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}

func (clientHost) Readlink(p string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
}

// TestPodmanStubClientIsWhatTheStubWouldExec is --dry-run's answer to "which
// client will the stub use": docker before podman-remote whatever the PATH
// order, a file without an execute bit is not a client, and none is "".
func TestPodmanStubClientIsWhatTheStubWouldExec(t *testing.T) {
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@target-rw", "@podman-socket"},
		testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, tc := range []struct {
		name       string
		host       clientHost
		want, path string
	}{
		{"neither", clientHost{"/usr/bin/true": 0o755}, "", ""},
		{"podman-remote only", clientHost{"/usr/bin/podman-remote": 0o755}, "podman-remote", "/usr/bin/podman-remote"},
		{"both", clientHost{"/usr/bin/podman-remote": 0o755, "/usr/bin/docker": 0o755}, "docker", "/usr/bin/docker"},
		{"docker not executable", clientHost{"/usr/bin/podman-remote": 0o755, "/usr/bin/docker": 0o644}, "podman-remote", "/usr/bin/podman-remote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, guest, writable := p.PodmanStubClient(tc.host)
			if writable != "" {
				t.Errorf("writable = %q, want none: nothing on this PATH is a writable grant", writable)
			}
			if name != tc.want || guest != tc.path {
				t.Errorf("PodmanStubClient = %q at %q, want %q at %q", name, guest, tc.want, tc.path)
			}
		})
	}
}

// TestPodmanStubClientNamesAWritablePATHDirectory: a profile that puts a
// writable directory on PATH, even after /usr/bin, lets the payload drop a
// docker the stub execs, so a client named from what is on disk now is not
// the answer and --dry-run must say so (red team, issue #691).
func TestPodmanStubClientNamesAWritablePATHDirectory(t *testing.T) {
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@target-rw", "@podman-socket"},
		testCtxWithPodmanShim(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	p.AuthorEnvList("PATH", []string{p.Target}, "test")
	host := clientHost{"/usr/bin/podman-remote": 0o755}
	name, _, writable := p.PodmanStubClient(host)
	if name != "podman-remote" || writable != p.Target {
		t.Fatalf("PodmanStubClient = %q, writable %q; want podman-remote with %s writable", name, writable, p.Target)
	}
}
