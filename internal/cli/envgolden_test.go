package cli

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
			// @claude's binary. Present on purpose, and it is a POSITIVE
			// CONTROL rather than scenery: every other @claude grant is
			// optional and absent here, so this one file is what makes the
			// staged-bin band appear at all. Remove it and the golden shows a
			// PATH with no /run/snug/bin entry — which is correct (nothing was
			// staged) and would silently stop testing that staging reaches PATH.
			"/home/u/.local/bin/claude": true,
		},
		// EDITOR is set because @claude re-admits it past --clearenv. It is the
		// POSITIVE CONTROL for that whole mechanism: without one variable the
		// host actually has, the @claude golden would be identical to the
		// defaults one and could not tell "nothing was inherited" from "the
		// inherit machinery is broken".
		// NO_COLOR is present and EMPTY, which is its specified spelling — "set
		// to any value, including empty" — and the case a `v != ""` read of the
		// host silently turned back into "colour on".
		env: map[string]string{"USER": "u", "EDITOR": "vim", "NO_COLOR": ""},
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

func (f *envFakeEnv) LookupEnv(k string) (string, bool) {
	v, ok := f.env[k]
	return v, ok
}
func (f *envFakeEnv) Uid() int { return 1000 }
func (f *envFakeEnv) Gid() int { return 1000 }

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
		sel  []policy.ProfileName
		ctx  policy.Context
		// refused is true where Validate rejects the selection. Resolve's
		// contract returns the policy ANYWAY in that case (see its doc comment),
		// and --dry-run renders it — which is the only way to see the §4.2 marks,
		// since the selection that produces them is one nothing can run.
		refused bool
		// reg overrides profile.Builtins() for a case that needs a USER profile
		// in the registry. Only the marks case uses it, and it has to: no shipped
		// profile carries a three-mark row, and no shipped profile ever should —
		// checkBuiltinEnvRoster refuses a builtin writing an unrostered name, so
		// `← unchecked` cannot appear beside a builtin at all. The screen that
		// renders three marks at once was therefore asserted only inside a test's
		// string comparisons and had no committed artifact until this case.
		reg func(*testing.T) map[policy.ProfileName]*policy.Profile
	}{
		// What a bare `snug <dir>` selects.
		//
		// THIS FILE STAYING UNCHANGED IS THE REVIEW ARTIFACT FOR ISSUE #84. The
		// XDG base directories @home `set` are measured exec surfaces — git reads
		// a command table from $XDG_CONFIG_HOME/git/config, and bash-completion
		// SOURCES $XDG_DATA_HOME/bash-completion/completions/<cmd>, both with the
		// control — and both directories are @home's writable tmpfs. Annotating
		// them would put four sentences on EVERY default run, advising something
		// @home structurally cannot do (an XDG base directory must be writable;
		// that is what it is). The hazard is the writable tmpfs, which the
		// FILESYSTEM block already shows, so it is #84 and it is deferred rather
		// than half-done. If this golden ever grows an XDG mark, that decision has
		// been reversed and owes an argument.
		//
		// READ THAT AS "AN XDG MARK", NOT AS "ANY LINE", because the file is no
		// longer byte-identical to the one a red team last compared against main:
		// it carries a two-line PWD row at the end, in bwrap's own provenance. That
		// is the F5 fix — bwrap authors PWD from --chdir and this block used to
		// claim it was the WHOLE environment — and it is snug disclosing something,
		// which is the opposite of #84's question. The check to run against a
		// future default golden is "does an XDG row carry a mark", not "did this
		// file change".
		{"defaults", profile.BuiltinDefaults(), envGoldenCtx(), false, nil},
		// The one shipped profile that touches the environment today. What the
		// golden shows: EDITOR and NO_COLOR arriving through `inherit`, and
		// /run/snug/bin on PATH because the profile's binary is staged there.
		// @claude names NO PATH directory of its own — the band is snug's, and
		// that is the fix for the shadow slot the old `merge {home}/.local/bin`
		// installed (TestNoBuiltinPutsAWritableDirectoryOnPATH).
		{"claude", append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude"), envGoldenCtx(), false, nil},
		// Containers, with a host whose podman is a distrobox shim — so the
		// staged stub's directory appears on PATH and the golden shows where in
		// the ordering it lands.
		{"podman-socket", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtxWithShim(), false, nil},
		// The MARKS screen, and the reason it is a golden rather than a handful of
		// strings.Contains: this is the layout a human reads when a profile hands
		// over something snug has a measurement about. It carries, in one render,
		// a three-mark row (GIT_SSH_COMMAND: unchecked + annotation + not
		// granted), a two-mark rostered row (BASH_ENV), a one-mark pointer row
		// (CARGO_HOME, F1), PATH's shadow-slot mark on a multi-band variable, and
		// the unmarked controls. Before the mark lines were split out, the
		// equivalent rows were 264–277 columns wide.
		{"marks", append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "markjoin"),
			envGoldenCtx(), false, markJoinRegistry},
		// §4.2, the case the design measured and nothing rendered: snug authors
		// HOME, SHELL and the four base PATH entries unconditionally, and with
		// only @parent-ro selected NONE of those paths is granted. It must keep
		// authoring them — §4.3 shows PATH and HOME have no safe absent state —
		// so the repair is that this block SAYS SO.
		{"parent-ro-marks", []policy.ProfileName{"@parent-ro"}, envGoldenCtx(), true, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[policy.ProfileName]*policy.Profile(reg)
			if tc.reg != nil {
				m = tc.reg(t)
			}
			p, err := policy.Resolve(m, tc.sel, tc.ctx, newEnvFakeEnv())
			switch {
			case tc.refused && err == nil:
				t.Fatalf("Resolve(%v) was expected to be refused; if this selection became "+
					"runnable, the case no longer shows what it was written for", tc.sel)
			case !tc.refused && err != nil:
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
				t.Fatalf("%v (run: go test ./internal/cli -update)", err)
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
