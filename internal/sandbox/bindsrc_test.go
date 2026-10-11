package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// TestOpenBindSourceRefusesALinkAtAnyComponent fails if a grant's host path is
// opened through a symlink: the canonical path snug resolved had none, so a
// link there was put there afterwards.
func TestOpenBindSourceRefusesALinkAtAnyComponent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{filepath.Join(root, "link"), filepath.Join(root, "link", "sub")} {
		_, _, err := openBindSource(policy.Mount{Host: host, Guest: "/mnt/x", Kind: policy.KindBind})
		if !errors.Is(err, ErrGrantRefused) || !strings.Contains(err.Error(), "became a symlink") {
			t.Errorf("%s: err = %v, want ErrGrantRefused naming the swap", host, err)
		}
	}

	f, ok, err := openBindSource(policy.Mount{Host: filepath.Join(real, "sub"), Guest: "/mnt/x", Kind: policy.KindBind})
	if err != nil || !ok {
		t.Fatalf("control: the real path was refused: ok=%v err=%v", ok, err)
	}
	f.Close()
}

func TestOpenBindSourceAbsent(t *testing.T) {
	host := filepath.Join(t.TempDir(), "gone")
	if _, ok, err := openBindSource(policy.Mount{Host: host, Guest: "/g", Kind: policy.KindBind, Optional: true}); ok || err != nil {
		t.Errorf("optional and absent: ok=%v err=%v, want omitted without error", ok, err)
	}
	_, _, err := openBindSource(policy.Mount{Host: host, Guest: "/g", Kind: policy.KindBind})
	if err == nil || errors.Is(err, ErrGrantRefused) {
		t.Errorf("required and absent: err = %v, want a plain refusal", err)
	}
}

// TestOpenBindSourceRefusesASymlinkAtAnyDepth fails if the descriptor is
// opened through a link that is not the last component, or if the refusal
// stops naming the path: the control inside it is that the link's destination
// exists and is readable, so ENOENT cannot be what refused it.
func TestOpenBindSourceRefusesASymlinkAtAnyDepth(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(filepath.Join(secret, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "a", "b", "f"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(work, "real", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secret, "a"), filepath.Join(work, "mid")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secret, "a", "b", "f"), filepath.Join(work, "real", "b", "final")); err != nil {
		t.Fatal(err)
	}

	for name, host := range map[string]string{
		"middle component": filepath.Join(work, "mid", "b"),
		"final component":  filepath.Join(work, "real", "b", "final"),
		"first component":  filepath.Join(work, "mid"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := os.Stat(host); err != nil {
				t.Fatalf("control: following the link works on the host (%v), so ENOENT is not the refusal", err)
			}
			f, ok, err := openBindSource(policy.Mount{Host: host, Guest: "/mnt/x", Kind: policy.KindBind})
			if f != nil {
				f.Close()
				t.Fatal("a descriptor was returned for a path through a symlink")
			}
			if ok || !errors.Is(err, ErrGrantRefused) {
				t.Fatalf("ok=%v err=%v, want ErrGrantRefused", ok, err)
			}
			if !strings.Contains(err.Error(), host) || !strings.Contains(err.Error(), "/mnt/x") {
				t.Errorf("refusal %q does not name the path and the guest", err)
			}
		})
	}
}

// TestOpenBindSourceIsOPathAndCloexec fails if the grant source is opened
// readable (the descriptor then carries access of its own, and a leaked copy
// reads the tree) or without close-on-exec (it survives into every child snug
// forks that is not told about it). The control is an ordinary open, which
// reports neither property, so the flag readback is measuring something.
func TestOpenBindSourceIsOPathAndCloexec(t *testing.T) {
	dir := t.TempDir()
	ordinary, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	fl, err := unix.FcntlInt(ordinary.Fd(), unix.F_GETFL, 0)
	if err != nil || fl&unix.O_PATH != 0 {
		t.Fatalf("control: an ordinary open reports O_PATH (flags %#x, err %v)", fl, err)
	}

	f, ok, err := openBindSource(policy.Mount{Host: dir, Guest: "/g", Kind: policy.KindBind})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	defer f.Close()
	fl, err = unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || fl&unix.O_PATH == 0 {
		t.Errorf("F_GETFL = %#x (err %v), want O_PATH set", fl, err)
	}
	fdfl, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil || fdfl&unix.FD_CLOEXEC == 0 {
		t.Errorf("F_GETFD = %#x (err %v), want FD_CLOEXEC set", fdfl, err)
	}
	if _, err := f.Read(make([]byte, 1)); err == nil {
		t.Error("read on the grant descriptor succeeded; it grants access of its own")
	}
}

// TestOptionalBindAbsentAtLaunchIsOmitted fails if an optional grant whose
// source is missing at launch is refused (the -try semantics the path form had)
// or leaves a gap or a stale number in the descriptor map. The present source
// beside it is the control that the map is built at all and numbered from base.
func TestOptionalBindAbsentAtLaunchIsOmitted(t *testing.T) {
	root := t.TempDir()
	present := filepath.Join(root, "present")
	if err := os.Mkdir(present, 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{Mounts: map[string]policy.Mount{
		"/a": {Guest: "/a", Host: filepath.Join(root, "gone"), Kind: policy.KindBind, Optional: true},
		"/b": {Guest: "/b", Host: present, Kind: policy.KindBind},
	}}
	var extra []*os.File
	defer func() {
		for _, f := range extra {
			f.Close()
		}
	}()
	fds, err := openBindSources(p, &extra, func() int { return 7 + len(extra) })
	if err != nil {
		t.Fatal(err)
	}
	if _, has := fds["/a"]; has {
		t.Errorf("the absent optional source got descriptor %d", fds["/a"])
	}
	if fds["/b"] != 7 || len(extra) != 1 {
		t.Errorf("fds = %v with %d files, want only /b at 7", fds, len(extra))
	}
}

// TestRequiredBindAbsentAtLaunchRefuses fails if a non-optional grant whose
// source vanished between resolve and launch is silently dropped, which would
// start the payload without a mount its profile says it has (invariant 5).
// Nothing may be left open on the way out.
func TestRequiredBindAbsentAtLaunchRefuses(t *testing.T) {
	root := t.TempDir()
	present := filepath.Join(root, "present")
	if err := os.Mkdir(present, 0o755); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(root, "gone")
	p := &policy.Policy{Mounts: map[string]policy.Mount{
		"/a": {Guest: "/a", Host: present, Kind: policy.KindBind},
		"/b": {Guest: "/b", Host: gone, Kind: policy.KindBind},
	}}
	var extra []*os.File
	fds, err := openBindSources(p, &extra, func() int { return 3 + len(extra) })
	for _, f := range extra {
		f.Close()
	}
	if err == nil || fds != nil {
		t.Fatalf("fds=%v err=%v, want a refusal", fds, err)
	}
	if !errors.Is(err, unix.ENOENT) || !strings.Contains(err.Error(), gone) {
		t.Errorf("err = %v, want ENOENT naming %s", err, gone)
	}
}

// TestOpenat2UnavailableRefuses fails if a kernel or seccomp filter without
// openat2 makes snug fall back to handing bwrap the path, which is the race
// this whole path exists to close. The refusal must say what to upgrade.
func TestOpenat2UnavailableRefuses(t *testing.T) {
	dir := t.TempDir()
	orig := openat2
	t.Cleanup(func() { openat2 = orig })
	for _, errno := range []unix.Errno{unix.ENOSYS, unix.EPERM} {
		openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, errno }
		f, ok, err := openBindSource(policy.Mount{Host: dir, Guest: "/g", Kind: policy.KindBind, Optional: true})
		if f != nil || ok || err == nil {
			t.Fatalf("%v: f=%v ok=%v err=%v, want a refusal even for an optional grant", errno, f, ok, err)
		}
		if !errors.Is(err, errno) || !strings.Contains(err.Error(), "Linux 5.6") || !strings.Contains(err.Error(), dir) {
			t.Errorf("%v: err = %q, want it to wrap the errno, name Linux 5.6 and the path", errno, err)
		}
	}
	openat2 = orig
	if f, ok, err := openBindSource(policy.Mount{Host: dir, Guest: "/g", Kind: policy.KindBind}); err != nil || !ok {
		t.Fatalf("control: the real openat2 failed here: ok=%v err=%v", ok, err)
	} else {
		f.Close()
	}
}
