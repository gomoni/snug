package policy

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/test/modroot"
)

// TestTargetGraftIsInstalledOnEveryEngineRun pins the shape a container run
// always gets since issue #376: a graft at EngineBindsDir+"/"+base(target),
// Host == the resolved target, Kind == KindGraft, From == "(snug)" — the
// installer's own literal, checked here so a future edit that installs it
// under a different provenance string is visible.
func TestTargetGraftIsInstalledOnEveryEngineRun(t *testing.T) {
	sel := append(append([]ProfileName{}, testDefaults...), "@podman-socket")
	p, err := Resolve(testRegistry(), sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	guest, access, ok := p.EngineTargetGraft()
	if !ok {
		t.Fatalf("EngineTargetGraft() ok=false for the default fixture, whose target %s is granted "+
			"read-write by @cwd-rw — this is the ordinary case a container run always gets", p.Target)
	}
	if want := EngineBindsDir + "/" + filepath.Base(p.Target); guest != want {
		t.Errorf("EngineTargetGraft() guest = %q, want %q", guest, want)
	}
	if access != AccessRW {
		t.Errorf("EngineTargetGraft() access = %v, want AccessRW — the fixture's target is @cwd-rw, "+
			"read-write", access)
	}

	if err := p.Graft(newFakeEnv(), Graft{
		Mount: Mount{
			Guest: guest, Host: p.Target,
			Kind: KindGraft, Access: access, From: []string{"(snug)"},
		},
		Why: "test abuse sentence: a hostile process inside the sandbox can use this to test",
	}); err != nil {
		t.Fatalf("installing the target graft the shape installEngineTargetGraft installs was "+
			"refused: %v", err)
	}
	gr, installed := p.Grafts[guest]
	if !installed {
		t.Fatalf("no graft recorded at %s after Policy.Graft succeeded", guest)
	}
	if gr.Host != p.Target {
		t.Errorf("graft.Host = %q, want the resolved target %q", gr.Host, p.Target)
	}
	if gr.Kind != KindGraft {
		t.Errorf("graft.Kind = %v, want KindGraft", gr.Kind)
	}
	if len(gr.From) != 1 || gr.From[0] != "(snug)" {
		t.Errorf("graft.From = %v, want [\"(snug)\"]", gr.From)
	}
}

// TestTargetGraftAccessFollowsTheSandbox is the table: EngineTargetGraft's
// access is exactly what HostPathVisible already says about the target,
// never invented independently.
func TestTargetGraftAccessFollowsTheSandbox(t *testing.T) {
	cases := []struct {
		name   string
		mounts map[string]Mount
		target string
		want   Access
	}{
		{
			// @cwd-rw's own shape: the target is bound read-write at itself.
			name: "@cwd-rw -> AccessRW",
			mounts: map[string]Mount{
				"/home/u/proj/sub": {Guest: "/home/u/proj/sub", Kind: KindBind,
					Host: "/home/u/proj/sub", Access: AccessRW},
			},
			target: "/home/u/proj/sub",
			want:   AccessRW,
		},
		{
			// @sys @parent-ro alone, no @cwd-rw: nothing binds the target
			// directly, and the only coverage is the parent's read-only bind
			// reaching it by prefix.
			name: "@sys @parent-ro -> AccessRO",
			mounts: map[string]Mount{
				"/usr": {Guest: "/usr", Kind: KindBind, Host: "/usr", Access: AccessRO},
				"/home/u/proj": {Guest: "/home/u/proj", Kind: KindBind,
					Host: "/home/u/proj", Access: AccessRO},
			},
			target: "/home/u/proj/sub",
			want:   AccessRO,
		},
		{
			// The target sits under an ancestor bound read-write, with no
			// dedicated bind of the target itself — the same prefix rule,
			// the other access.
			name:   "target under an rw ancestor bind -> AccessRW",
			target: "/home/u/proj/sub",
			mounts: map[string]Mount{
				"/home/u/proj": {Guest: "/home/u/proj", Kind: KindBind,
					Host: "/home/u/proj", Access: AccessRW},
			},
			want: AccessRW,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Policy{Target: tc.target, Podman: PodmanSocket, Mounts: tc.mounts}
			_, access, ok := p.EngineTargetGraft()
			if !ok {
				t.Fatalf("EngineTargetGraft() ok=false, want a graft at %v", tc.want)
			}
			if access != tc.want {
				t.Errorf("EngineTargetGraft() access = %v, want %v", access, tc.want)
			}
		})
	}
}

// TestEngineTargetGraftNeverLandsOnTheBindsDirectoryItself pins section 3's
// one input that would produce a WRONG MOUNT rather than a refusal:
// filepath.Base("/") is "/", so the naive join collapses to EngineBindsDir
// itself — a graft of the whole host root onto the directory snug
// pre-creates for the target graft, admitted by G1b (anything under
// EngineDir).
//
// A root BIND is in Mounts on purpose, not an empty map: HostPathVisible
// walks p.Mounts, so with nothing bound at all it returns false regardless
// of either guard and this test would pass whether or not the guards exist —
// exactly the "cannot fail" shape. With a root bind present, HostPathVisible
// would say yes and the guards are the only thing standing between this
// input and a graft of the whole host root.
//
// MUTATION CHECK, and the guard is triply redundant for this one input, not
// singly: removing ONLY `t == "/"` leaves this test green, because
// filepath.Base("/") is ALSO "/" and trips the basename check on the next
// line twice over — both `base == "/"` itself AND `strings.Contains(base,
// "/")`, since "/" contains "/" as its own substring. Removing all three
// (the early t=="/" exit, the base=="/" arm, and the Contains arm) is what
// finally turns this red: EngineTargetGraft then returns
// ("/snug/engine/binds//", AccessRW, true), the exact wrong mount section 3
// describes. Recorded here rather than left as a single-guard claim, since
// the depth of the redundancy is worth knowing rather than hiding.
func TestEngineTargetGraftNeverLandsOnTheBindsDirectoryItself(t *testing.T) {
	p := &Policy{
		Target: "/", Podman: PodmanSocket,
		Mounts: map[string]Mount{
			"/": {Guest: "/", Host: "/", Kind: KindBind, Access: AccessRW},
		},
	}
	guest, access, ok := p.EngineTargetGraft()
	if ok {
		t.Fatalf("EngineTargetGraft() = (%q, %v, true) for Target \"/\" — filepath.Base(\"/\") is "+
			"\"/\", so the naive join collapses to EngineBindsDir itself, cloning the host root", guest, access)
	}
	if guest != "" || access != AccessNone {
		t.Errorf("EngineTargetGraft() = (%q, %v, false), want (\"\", AccessNone, false)", guest, access)
	}

	args := p.BwrapArgs(1000, 1000)
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--dir" && args[i+1] == EngineBindsDir {
			t.Fatalf("bwrap argv creates %s despite EngineTargetGraft refusing to produce a graft "+
				"for Target \"/\": %v", EngineBindsDir, args)
		}
	}
}

// TestTargetGraftIsForwardedAtAnyDepth is the fix for the depth-dependent
// coin toss issue #376 closes: whatever depth the target sits at below its
// nearest anchored ancestor, EngineTargetGraft/EngineTargetForwarded forward
// it identically, because HostPathVisible walks Mount.Host by prefix and
// never asks about intermediate path components at all.
//
// THIS IS THE ROW THAT FAILS ON MAIN: before issue #376,
// internal/policy/enginebind_test.go's "deepest anchored ancestor is a
// tmpfs" row pinned the opposite outcome for exactly the depth-4 shape below
// — CheckEngineBindSource(target) itself refused the target root with no
// substitute. The depth-4 case here builds the identical mount table and
// asserts CheckEngineBindSource(target) STILL refuses it (the fallback rule
// is unchanged) while EngineTargetGraft/EngineTargetForwarded now forward it
// regardless — the graft's exact-match rewrite runs before checkOne ever
// reaches that rule.
func TestTargetGraftIsForwardedAtAnyDepth(t *testing.T) {
	cases := []struct {
		name   string
		mounts map[string]Mount
		target string
		// wantBindSourceRefused is whether CheckEngineBindSource(target),
		// asked DIRECTLY, still refuses the bare root at this depth — the
		// fact that varies with depth and that the graft makes irrelevant
		// to a real client.
		wantBindSourceRefused bool
	}{
		{
			name:   "depth-1: a bare mount root with no complex ancestry",
			target: "/work",
			mounts: map[string]Mount{
				"/work": {Guest: "/work", Kind: KindBind, Host: "/work", Access: AccessRW},
			},
		},
		{
			// Two levels below $HOME: the M1/M3 shape (enginebind_test.go) —
			// anchored because the mount root sits directly under the home
			// tmpfs and nothing else covers it.
			name:   "depth-2: mount root directly under a writable tmpfs ancestor",
			target: "/home/u/src",
			mounts: map[string]Mount{
				"/home/u":     {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
				"/home/u/src": {Guest: "/home/u/src", Kind: KindBind, Host: "/home/u/src", Access: AccessRW},
			},
		},
		{
			// Four levels below $HOME: one level deeper than
			// enginebind_test.go's own row, so CheckEngineBindSource's walk
			// stops on a plain, un-anchored name (/home/u/src) and refuses
			// the root outright.
			name:   "depth-4: deepest anchored ancestor is a tmpfs, one level further",
			target: "/home/u/src/deep/projects/foo",
			mounts: map[string]Mount{
				"/home/u":                       {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
				"/home/u/src/deep/projects":     {Guest: "/home/u/src/deep/projects", Kind: KindBind, Host: "/home/u/src/deep/projects", Access: AccessRO},
				"/home/u/src/deep/projects/foo": {Guest: "/home/u/src/deep/projects/foo", Kind: KindBind, Host: "/home/u/src/deep/projects/foo", Access: AccessRW},
			},
			wantBindSourceRefused: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Policy{Target: tc.target, Podman: PodmanSocket, Mounts: tc.mounts}

			bindErr := p.CheckEngineBindSource(tc.target)
			if tc.wantBindSourceRefused && bindErr == nil {
				t.Fatalf("fixture: CheckEngineBindSource(%s) accepted the root; this case is meant "+
					"to demonstrate the fallback rule STILL refuses it while the graft forwards it "+
					"regardless — if it stopped refusing, this case pins nothing", tc.target)
			}
			if !tc.wantBindSourceRefused && bindErr != nil {
				t.Fatalf("fixture: CheckEngineBindSource(%s) refused the root unexpectedly: %v",
					tc.target, bindErr)
			}

			guest, access, ok := p.EngineTargetGraft()
			if !ok {
				t.Fatalf("EngineTargetGraft() ok=false for %s", tc.target)
			}
			wantGuest := EngineBindsDir + "/" + filepath.Base(tc.target)
			if guest != wantGuest {
				t.Errorf("EngineTargetGraft() guest = %q, want %q", guest, wantGuest)
			}

			if err := p.Graft(newFakeEnv(), Graft{
				Mount: Mount{Guest: guest, Host: tc.target, Kind: KindGraft, Access: access,
					From: []string{"(snug)"}},
				Why: "test abuse sentence: a hostile process inside the sandbox can use this to test",
			}); err != nil {
				t.Fatalf("installing the target graft: %v", err)
			}

			fwd, fok := p.EngineTargetForwarded(tc.target, access == AccessRW)
			if !fok {
				t.Fatalf("EngineTargetForwarded(%s) = (_, false), want the graft forwarded "+
					"regardless of depth — CheckEngineBindSource's own refusal above (if any) must "+
					"never reach a client asking for the target root", tc.target)
			}
			if fwd != wantGuest {
				t.Errorf("EngineTargetForwarded(%s) = %q, want %q", tc.target, fwd, wantGuest)
			}
		})
	}
}

// TestBwrapPreCreatesTheTargetGraftDestination pins the intermediate
// directory ordering section 3 depends on: bubblewrap's --dir creates no
// ancestors and --remount-ro / is the last filesystem operation, so
// EngineBindsDir has to exist before the target's own destination under it
// can be created, and both have to exist before the root goes read-only.
func TestBwrapPreCreatesTheTargetGraftDestination(t *testing.T) {
	p, err := Resolve(testRegistry(), append(append([]ProfileName{}, testDefaults...), "@podman-socket"),
		testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Base(p.Target)
	targetDir := EngineBindsDir + "/" + base

	args := p.BwrapFlags(1000, 1000, func(string) int { return 10 })

	indexOfDir := func(dir string) int {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "--dir" && args[i+1] == dir {
				return i
			}
		}
		return -1
	}
	indexOfFlag := func(flag, val string) int {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == flag && args[i+1] == val {
				return i
			}
		}
		return -1
	}

	engineIdx := indexOfDir(EngineDir)
	bindsIdx := indexOfDir(EngineBindsDir)
	targetIdx := indexOfDir(targetDir)
	remountIdx := indexOfFlag("--remount-ro", "/")

	if engineIdx < 0 || bindsIdx < 0 || targetIdx < 0 || remountIdx < 0 {
		t.Fatalf("one of the expected --dir/--remount-ro entries is missing from the argv:\n"+
			"  /snug/engine index: %d\n  %s index: %d\n  %s index: %d\n  --remount-ro / index: %d\n%v",
			engineIdx, EngineBindsDir, bindsIdx, targetDir, targetIdx, remountIdx, args)
	}
	if !(engineIdx < bindsIdx && bindsIdx < targetIdx && targetIdx < remountIdx) {
		t.Errorf("--dir ordering is wrong: want /snug/engine (%d) < %s (%d) < %s (%d) < "+
			"--remount-ro / (%d)", engineIdx, EngineBindsDir, bindsIdx, targetDir, targetIdx, remountIdx)
	}
}

// TestOnlyOneGraftLandsUnderTheBindsDirectory sweeps every non-test function
// module-wide and asserts exactly one calls BOTH Policy.EngineTargetGraft and
// Policy.Graft — the target graft's own installer
// (internal/cli/enginetarget.go). A call site's Guest is EngineBindsDir+"/"+
// base by construction only through EngineTargetGraft's own return value
// (enginetarget.go), so a function that never calls it cannot be grafting
// under EngineBindsDir at all; this is what makes the pairing a sound proxy
// for "names a Guest under EngineBindsDir" without a full dataflow analysis
// of the call's own arguments. Section 4 records the collision rule as dead
// now that there is exactly one child under EngineBindsDir; this pins that
// "exactly one" mechanically, in the style TestGraftCarriesAnAbuseSentence
// sweeps for Why, rather than trusting the count from a comment.
func TestOnlyOneGraftLandsUnderTheBindsDirectory(t *testing.T) {
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	walked := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		// A source sweep walks a tree other packages' tests are writing in
		// (`go test ./...` runs concurrently) — an entry that vanished
		// between its parent's ReadDir and this call is not a source file
		// and is not this sweep's business (issue #350).
		if errors.Is(werr, fs.ErrNotExist) {
			return nil
		}
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		walked[filepath.ToSlash(filepath.Dir(rel))] = true

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if errors.Is(perr, fs.ErrNotExist) {
			return nil
		}
		if perr != nil {
			return perr
		}
		forEachFunc(f, func(name string, root ast.Node) {
			callsGraft, callsEngineTargetGraft := false, false
			ast.Inspect(root, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel == nil {
					return true
				}
				switch sel.Sel.Name {
				case "Graft":
					callsGraft = true
				case "EngineTargetGraft":
					callsEngineTargetGraft = true
				}
				return true
			})
			if callsGraft && callsEngineTargetGraft {
				hits = append(hits, rel+": "+name)
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	requireWalked(t, walked)

	// POSITIVE CONTROL: the sweep must find at least the one call site it is
	// meant to — otherwise "exactly one" would be equally true of a sweep
	// that finds none.
	if len(hits) == 0 {
		t.Fatal("the sweep found no function calling both Policy.EngineTargetGraft and Policy.Graft; " +
			"either installEngineTargetGraft was removed or the sweep is broken, and either way " +
			"this test proves nothing")
	}
	if len(hits) != 1 {
		t.Errorf("%d function(s) call both Policy.EngineTargetGraft and Policy.Graft, want exactly "+
			"1 — a second one would graft a second Guest under EngineBindsDir, the collision "+
			"section 4 says a single always-on target graft no longer has to guard against:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}
