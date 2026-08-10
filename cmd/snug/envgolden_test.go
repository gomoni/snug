package main

import (
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

var update = flag.Bool("update", false, "rewrite golden files")

// ── the review artifact for the environment ──────────────────────────────────
//
// internal/policy's .bwrap.txt goldens are generated from testRegistry(), a
// FAKE profile set. Nothing golden covers internal/profile/profiles/base.toml,
// so a change to what @home or @claude puts in the environment would ship with
// no diff for a human to read — and CLAUDE.md says a security change producing
// no golden diff is probably untested.
//
// These files close that gap: the ENVIRONMENT block of --dry-run, resolved
// against profile.Builtins() (the REAL profiles, with no host layers merged in
// so the result cannot depend on whose machine ran the test).

// envFakeEnv is a fake host, deliberately duplicated from internal/policy's
// fakeEnv rather than exported from production code: a test fake that has to
// live in a non-test file is a fake that can be reached by something other than
// a test. Forty lines is the price and it is the right one.
//
// The paths in dirs are exactly what the shipped profiles need in order to
// resolve. @sys's optional entries are deliberately ABSENT — an optional grant
// whose host path is missing is skipped, which is the arrangement most hosts
// are actually in for at least one of them.
type envFakeEnv struct {
	dirs map[string]bool
	env  map[string]string
}

func newEnvFakeEnv() *envFakeEnv {
	return &envFakeEnv{
		dirs: map[string]bool{
			"/usr": true,
			// @sys's non-optional /etc entries. Without these Resolve refuses,
			// because a grant that is not marked optional must exist.
			"/etc/ld.so.cache": true, "/etc/ld.so.conf": true,
			"/etc/nsswitch.conf": true, "/etc/passwd": true, "/etc/group": true,
			// the fixture home and project
			"/home/u": true, "/home/u/proj": true, "/home/u/proj/sub": true,
		},
		// EDITOR is set because @claude re-admits it past --clearenv. It is the
		// POSITIVE CONTROL for that whole mechanism: without one variable the
		// host actually has, the @claude golden would be identical to the
		// defaults one and could not tell "nothing was inherited" from "the
		// inherit machinery is broken".
		env: map[string]string{"USER": "u", "EDITOR": "vim"},
	}
}

func (f *envFakeEnv) EvalSymlinks(p string) (string, error) {
	if f.dirs[p] {
		return p, nil
	}
	return "", &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
}

func (f *envFakeEnv) Stat(p string) (fs.FileInfo, error) {
	if f.dirs[p] {
		return envFakeInfo{name: p}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
}

func (f *envFakeEnv) Getenv(k string) string { return f.env[k] }
func (f *envFakeEnv) Uid() int               { return 1000 }
func (f *envFakeEnv) Gid() int               { return 1000 }

type envFakeInfo struct{ name string }

func (i envFakeInfo) Name() string       { return i.name }
func (i envFakeInfo) Size() int64        { return 0 }
func (i envFakeInfo) Mode() fs.FileMode  { return fs.ModeDir }
func (i envFakeInfo) ModTime() time.Time { return time.Time{} }
func (i envFakeInfo) IsDir() bool        { return true }
func (i envFakeInfo) Sys() any           { return nil }

// envGoldenCtx pins Target and Home to fixed FAKE paths. Not t.TempDir():
// SNUG_TARGET and the {home}-derived values are rendered into the golden, so a
// per-run temporary directory would make the file unstable and unreviewable.
func envGoldenCtx() policy.Context {
	return policy.Context{
		Target:  "/home/u/proj/sub",
		Home:    "/home/u",
		Shell:   "/usr/bin/bash",
		Command: []string{"/bin/sh"},
	}
}

func TestGoldenEnvironment(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []string
		ctx  policy.Context
	}{
		// What a bare `snug <dir>` selects.
		{"defaults", profile.BuiltinDefaults(), envGoldenCtx()},
		// The one shipped profile that touches the environment today: @claude's
		// `env = [...]` and `path = [...]`. None of its host variables is set on
		// this fake host, so what the golden shows is the `path` entry reaching
		// PATH — and, once the verbs land, whatever inherit does instead.
		{"claude", append(append([]string{}, profile.BuiltinDefaults()...), "@claude"), envGoldenCtx()},
		// Containers, with a host whose podman is a distrobox shim — so the
		// staged stub's directory appears on PATH and the golden shows where in
		// the ordering it lands.
		{"podman-socket", []string{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtxWithShim()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[string]*policy.Profile(reg), tc.sel, tc.ctx, newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f *os.File) { describeEnvironment(f, p) })

			path := filepath.Join("testdata", "env."+tc.name+".txt")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./cmd/snug -update)", err)
			}
			if got != string(want) {
				t.Errorf("the environment changed — every line here is something the payload "+
					"and all its children can read out of /proc/self/environ.\n--- got\n%s\n--- want\n%s",
					got, want)
			}
		})
	}
}

func envGoldenCtxWithShim() policy.Context {
	ctx := envGoldenCtx()
	ctx.HostShims = []policy.HostShim{
		{Name: "podman", Path: "/usr/bin/podman", Resolved: "/usr/bin/distrobox-host-exec"},
	}
	return ctx
}
