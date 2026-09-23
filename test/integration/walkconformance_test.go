//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Issue #604's conformance round (gh issue view 604, the "Conformance round"
// comment): --dry-run's verdict about a PATH element is computed by
// policy.View.walkLinks, a STATIC model of what bwrap and the kernel will do
// once the sandbox is actually running. A model and the thing it models can
// drift, and #604's own history is two rounds of exactly that drift — a host
// symlink under a read-only bind the first walk never followed, then a
// lexical `..` the second walk cancelled before a link ahead of it was even
// read. Both were found by hand, one fixture at a time; this file automates
// the comparison instead: for a PATH element, ask --dry-run what it says and
// ask a real sandbox what the kernel does, and fail whenever the model is
// LESS SAFE than reality — a kernel write that --dry-run's screen does not
// mark `shadow_slot` or `unresolved`. A kernel refusal under a mark is not a
// failure: over-marking costs a human a moment's doubt, under-marking costs
// them the sandbox.

// wcRoot returns a fresh fixture root explicitly under /tmp, so a merged PATH
// element inside it sits under snug's own unconditional writable /tmp grant
// (resolve.go's `(snug)` tmpfs) unless something more specific shadows it —
// which is what makes "an ungranted sibling" in these fixtures a real,
// writable landing rather than an absence.
//
// Not t.TempDir(): several rows chmod a directory to 0 to test a host read
// failure, and t.TempDir()'s own cleanup cannot remove that without help — the
// registered cleanup below restores every directory's mode before letting
// os.RemoveAll near it.
func wcRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "snugwc")
	if err != nil {
		t.Fatalf("wcRoot: %v", err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
		_ = os.RemoveAll(root)
	})
	return root
}

func wcMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func wcSymlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s -> %s: %v", path, target, err)
	}
}

// shq single-quotes a shell word. Every path these fixtures build comes from
// os.MkdirTemp/t.TempDir, which never contain a single quote, so this need not
// handle one.
func shq(s string) string { return "'" + s + "'" }

// touchProbe is the DEFAULT kernel probe: can the payload create a file
// directly at elem. It is wrong for exactly two shapes — a writable-ground
// symlink whose OWN target is read-only (row 12), and a read-only landing
// ALIASED by a separate writable grant (rows 16, 22) — which is why those
// build their own probe below rather than sharing this one.
func touchProbe(elem string) string {
	return fmt.Sprintf(`if touch %s 2>/dev/null; then echo KERNEL_W; else echo KERNEL_R; fi`,
		shq(elem+"/.probe"))
}

// replaceProbe is the probe for a symlink standing on WRITABLE ground: the
// payload does not need to write through the link, it unlinks it and mkdirs
// its own directory at that name (envresolve.go's own `resolveThroughLinks`
// doc comment gives the identical shape for snug's own symlink grants).
func replaceProbe(elem string) string {
	return fmt.Sprintf(`if rm -f %s 2>/dev/null && mkdir %s 2>/dev/null && touch %s 2>/dev/null; `+
		`then echo KERNEL_W; else echo KERNEL_R; fi`, shq(elem), shq(elem), shq(elem+"/.probe"))
}

// aliasProbe is the probe for a read-only landing whose host tree is reachable
// through a SEPARATE writable grant: write and mark an executable through the
// writable side, then execute it through elem. A plain `touch elem` would
// (correctly) refuse EROFS and say nothing about the alias.
func aliasProbe(writeDir, elem string) string {
	bin := writeDir + "/wcprobebin"
	return fmt.Sprintf(`mkdir -p %s 2>/dev/null
printf '#!/bin/sh\necho WC_ALIAS_RAN\n' > %s 2>/dev/null
chmod +x %s 2>/dev/null
if %s 2>/dev/null | grep -q WC_ALIAS_RAN; then echo KERNEL_W; else echo KERNEL_R; fi`,
		shq(writeDir), shq(bin), shq(bin), shq(elem+"/wcprobebin"))
}

// wcRow is one conformance fixture: grants is the profile TOML lines the row
// needs beyond the profile header and the PATH merge (ro/rw/tmpfs/symlink),
// elem is the merged PATH element under test, and probe is the shell
// fragment that ends in exactly one line of KERNEL_W or KERNEL_R.
type wcRow struct {
	name  string
	build func(t *testing.T, proj string) (grants, elem, probe string)
}

func wcRows() []wcRow {
	return []wcRow{
		// Round-1 table, in the issue's own order.

		{"absolute host link to tmp", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, "/tmp/sx", filepath.Join(hd, "abs"))
			elem := hd + "/abs"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem,
				"mkdir -p /tmp/sx\n" + touchProbe(elem)
		}},

		{"relative link to an ungranted sibling on tmpfs", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, "../w", filepath.Join(hd, "rel"))
			elem := hd + "/rel"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem,
				"mkdir -p " + shq(root+"/w") + "\n" + touchProbe(elem)
		}},

		{"relative link to a real ro dir (control)", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, filepath.Join(hd, "realdir"))
			wcSymlink(t, "realdir", filepath.Join(hd, "rellink"))
			elem := hd + "/rellink"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		{"link to /usr/bin (control)", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, "/usr/bin", filepath.Join(hd, "tousrbin"))
			elem := hd + "/tousrbin"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		{"dotdot through a real dir stays inside the grant", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, filepath.Join(hd, "sub2"))
			wcMkdir(t, filepath.Join(hd, "bin"))
			// Lexically inside hd (Clean cancels sub2/..), so this stays legal
			// under the coupling rule (§2.5) while still exercising a literal
			// ".." over a REAL directory rather than a link's own text.
			elem := hd + "/sub2/../bin"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		// Finding 1: a link INSIDE a host link's own text is followed before
		// the trailing ".." is applied. Measured on 14e9f48: grant "" (no
		// mark) while the kernel lands on a writable tmpfs directory and runs
		// whatever the payload put there.
		{"link inside a host link's own text (finding 1)", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, filepath.Join(hd, "bin"))
			wcSymlink(t, filepath.Join(root, "a", "b"), filepath.Join(hd, "l2"))
			wcSymlink(t, "l2/../bin", filepath.Join(hd, "trick"))
			elem := hd + "/trick"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem,
				fmt.Sprintf("mkdir -p %s %s\n", shq(root+"/a/b"), shq(root+"/a/bin")) + touchProbe(elem)
		}},

		// Finding 2: ".." typed directly into the PATH element, AFTER a host
		// link. Measured on 14e9f48: the whole element was lexically Cleaned
		// before any link was followed, cancelling "abs/.." to a real ro
		// directory next to it and reporting no mark, while the kernel
		// resolves the symlink first and lands on writable ground.
		{"dotdot after a host link in the PATH element (finding 2)", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, filepath.Join(root, "sx"), filepath.Join(hd, "abs"))
			elem := hd + "/abs/../bin"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem,
				fmt.Sprintf("mkdir -p %s %s\n", shq(root+"/sx"), shq(root+"/bin")) + touchProbe(elem)
		}},

		{"host link cycle terminates", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, "c2", filepath.Join(hd, "c1"))
			wcSymlink(t, "c1", filepath.Join(hd, "c2"))
			elem := hd + "/c1"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		{"mode-000 dir on the way is unresolved, not guessed past", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			blocked := filepath.Join(hd, "blocked")
			wcMkdir(t, blocked)
			if err := os.Chmod(blocked, 0); err != nil {
				t.Fatalf("chmod 0 %s: %v", blocked, err)
			}
			// Restore before wcRoot's own cleanup walk needs to open it.
			t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
			elem := hd + "/blocked/target"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		{"link into a second ro bind that itself links to tmpfs", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			hd2 := filepath.Join(root, "hd2")
			wcMkdir(t, hd)
			wcMkdir(t, hd2)
			wcSymlink(t, filepath.Join(hd2, "x"), filepath.Join(hd, "tosecond"))
			wcSymlink(t, "/tmp/w10", filepath.Join(hd2, "x"))
			elem := hd + "/tosecond"
			return `ro = ["` + hd + `", "` + hd2 + `", "/usr/bin"]`, elem,
				"mkdir -p /tmp/w10\n" + touchProbe(elem)
		}},

		{"host link lands on a snug symlink grant that targets tmpfs", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, "/data/bin", filepath.Join(hd, "tolink"))
			elem := hd + "/tolink"
			grants := `ro = ["` + hd + `", "/usr/bin"]` + "\n" +
				`symlink = [{ at = "/data/bin", target = "/tmp/w11" }]`
			return grants, elem, "mkdir -p /tmp/w11\n" + touchProbe(elem)
		}},

		{"link inside a writable bind, to /usr/bin, is replaceable", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			rw := filepath.Join(root, "rw1")
			wcMkdir(t, rw)
			wcSymlink(t, "/usr/bin", filepath.Join(rw, "tobin"))
			elem := rw + "/tobin"
			return `rw = ["` + rw + `"]` + "\nro = [\"/usr/bin\"]", elem, replaceProbe(elem)
		}},

		{"translating bind with a relative link climbing to tmpfs", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hostHd := filepath.Join(root, "hd")
			wcMkdir(t, hostHd)
			wcSymlink(t, "../w13", filepath.Join(hostHd, "rel"))
			elem := "/tmp/gh/rel"
			return `ro = ["` + hostHd + `:/tmp/gh", "/usr/bin"]`, elem,
				"mkdir -p /tmp/w13\n" + touchProbe(elem)
		}},

		{"chain of 39 host links, one short of the kernel's own bound", func(t *testing.T, proj string) (string, string, string) {
			return wcHostLinkChain(t, 39, "/tmp/w39")
		}},
		{"chain of exactly 40 host links, the kernel's own bound", func(t *testing.T, proj string) (string, string, string) {
			return wcHostLinkChain(t, 40, "/tmp/w40")
		}},
		{"chain of 41 host links, one past the kernel's own bound", func(t *testing.T, proj string) (string, string, string) {
			return wcHostLinkChain(t, 41, "/tmp/w41")
		}},

		{"link to the rw target", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			sub := filepath.Join(proj, "wc15")
			wcSymlink(t, sub, filepath.Join(hd, "torw"))
			elem := hd + "/torw"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem,
				"mkdir -p " + shq(sub) + "\n" + touchProbe(elem)
		}},

		// Finding 4: a `ro` bind whose own Access says read-only, but whose
		// HOST tree sits inside a separate WRITABLE grant's host tree, so a
		// write through that other grant is visible — and executable — here
		// too. Measured on 14e9f48, which has no aliasing check at all: no
		// mark, and the planted binary ran through the read-only path.
		{"ro bind aliasing the rw target (finding 4)", func(t *testing.T, proj string) (string, string, string) {
			realbin := filepath.Join(proj, "wc16-realbin")
			wcMkdir(t, realbin)
			elem := "/srv/wc16aliasedbin"
			grants := `ro = ["` + realbin + `:` + elem + `", "/usr/bin"]`
			return grants, elem, aliasProbe(realbin, elem)
		}},

		{"dotdot climbs out of a bind, into tmp", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			// Enough ".." to reach "/" from any depth t.TempDir()/MkdirTemp
			// can produce; walkLinks clamps Dir("/") to "/", so extras at the
			// root are inert rather than wrong.
			climb := strings.Repeat("../", 20) + "tmp/w17"
			wcSymlink(t, climb, filepath.Join(hd, "climb"))
			elem := hd + "/climb"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, "mkdir -p /tmp/w17\n" + touchProbe(elem)
		}},

		{"leading dotdot in an absolute PATH element stays at root", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			elem := "/../../tmp/w18"
			// The coupling rule (§2.5) reads this element LEXICALLY —
			// Clean("/../../tmp/w18") is "/tmp/w18" — so the profile has to
			// name /tmp itself; it is otherwise inert here (snug's own tmpfs
			// grant already covers it identically).
			return `ro = ["` + hd + `", "/usr/bin"]` + "\ntmpfs = [\"/tmp\"]", elem,
				"mkdir -p /tmp/w18\n" + touchProbe(elem)
		}},

		{"a component nothing covers, followed by dotdot", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, filepath.Join(hd, "bin"))
			// Lexically inside hd (Clean cancels nothing/..), legal under
			// coupling; "nothing" itself is never created, so the host read
			// on the way answers ENOENT rather than a real directory.
			elem := hd + "/nothing/../bin"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		{"link text is exactly dot", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, ".", filepath.Join(hd, "dot"))
			elem := hd + "/dot"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, touchProbe(elem)
		}},

		{"link text is exactly dotdot", func(t *testing.T, proj string) (string, string, string) {
			root := wcRoot(t)
			hd := filepath.Join(root, "hd")
			wcMkdir(t, hd)
			wcSymlink(t, "..", filepath.Join(hd, "dotdot"))
			elem := hd + "/dotdot"
			return `ro = ["` + hd + `", "/usr/bin"]`, elem, "mkdir -p " + shq(root) + "\n" + touchProbe(elem)
		}},

		{"aliasing through a translating bind whose host sits under the rw target", func(t *testing.T, proj string) (string, string, string) {
			writeDir := filepath.Join(proj, "wc22-write")
			wcMkdir(t, writeDir)
			elem := "/srv/wc22"
			grants := `ro = ["` + writeDir + `:` + elem + `", "/usr/bin"]`
			return grants, elem, aliasProbe(writeDir, elem)
		}},
	}
}

// wcHostLinkChain builds a chain of n real host symlinks under a fresh ro
// bind, hd/h0 -> h1 -> ... -> h(n-1) -> finalTarget, so the walk's own hop
// counter (maxGuestLinkHops, envresolve.go) is exercised at exactly n hops.
func wcHostLinkChain(t *testing.T, n int, finalTarget string) (grants, elem, probe string) {
	root := wcRoot(t)
	hd := filepath.Join(root, "hd")
	wcMkdir(t, hd)
	for i := 0; i < n-1; i++ {
		wcSymlink(t, fmt.Sprintf("h%d", i+1), filepath.Join(hd, fmt.Sprintf("h%d", i)))
	}
	wcSymlink(t, finalTarget, filepath.Join(hd, fmt.Sprintf("h%d", n-1)))
	elem = filepath.Join(hd, "h0")
	grants = `ro = ["` + hd + `", "/usr/bin"]`
	probe = "mkdir -p " + shq(finalTarget) + "\n" + touchProbe(elem)
	return grants, elem, probe
}

// wcDryRunGrant runs `snug --dry-run --json` and returns the `grant` code
// (dryrunjson.go's jsonEnvEntry.Grant: "", "shadow_slot", "not_granted", or
// "unresolved") for the PATH entry whose value is exactly elem.
func wcDryRunGrant(t *testing.T, env []string, proj, elem string) string {
	t.Helper()
	out, code := cli(t, env, "--dry-run", "--json", "-p", "wcrow", proj)

	var doc struct {
		Snug struct {
			Outcome string `json:"outcome"`
		} `json:"snug"`
		Refusal *struct {
			Message string `json:"message"`
		} `json:"refusal"`
		Environment []struct {
			Name    string `json:"name"`
			Entries []struct {
				Value string `json:"value"`
				Grant string `json:"grant"`
			} `json:"entries"`
		} `json:"environment"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("--dry-run --json did not parse (exit %d): %v\n%s", code, err, out)
	}
	if doc.Snug.Outcome != "ok" {
		msg := ""
		if doc.Refusal != nil {
			msg = doc.Refusal.Message
		}
		t.Fatalf("policy refused, which means the fixture itself is wrong (this test is about "+
			"a RESOLVED policy's verdict, not about coupling or another static refusal): %s", msg)
	}
	for _, v := range doc.Environment {
		if v.Name != "PATH" {
			continue
		}
		for _, e := range v.Entries {
			if e.Value == elem {
				return e.Grant
			}
		}
	}
	t.Fatalf("no PATH entry named %q in --dry-run --json:\n%s", elem, out)
	return ""
}

// TestWalkVerdictIsNeverLessSafeThanTheKernel is issue #604's conformance
// round made permanent: for each fixture, ask --dry-run what it says about one
// PATH element and ask a real sandbox whether the kernel actually lets the
// payload create a file there. A kernel write ("KERNEL_W") the JSON verdict
// does not carry as "shadow_slot" or "unresolved" is the model being LESS
// SAFE than reality, which is the one direction this suite must never allow.
// A kernel refusal ("KERNEL_R") under either mark is over-cautious, not
// unsafe, and is not asserted against.
func TestWalkVerdictIsNeverLessSafeThanTheKernel(t *testing.T) {
	budget(t, 180*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	type outcome struct {
		name    string
		elem    string
		grant   string
		kernelW bool
	}
	var table []outcome
	sawW, sawR := false, false

	for _, row := range wcRows() {
		row := row
		t.Run(row.name, func(t *testing.T) {
			grants, elem, probe := row.build(t, proj)

			toml := "[profile.wcrow]\n" +
				"description = \"walk-conformance fixture: " + row.name + "\"\n" +
				grants + "\n" +
				"\n[profile.wcrow.environ.merge]\n" +
				"PATH = [\"" + elem + "\", \"/usr/bin\"]\n"
			env := envProfileLayer(t, "wcrow.toml", toml, os.Getenv("PATH"))

			grant := wcDryRunGrant(t, env, proj, elem)

			r := runEnv(t, env, []string{"-p", "wcrow"}, proj, probe).mustRun(t)
			kernelW := strings.Contains(r.out, "KERNEL_W")
			kernelR := strings.Contains(r.out, "KERNEL_R")
			if !kernelW && !kernelR {
				t.Fatalf("the probe printed neither KERNEL_W nor KERNEL_R, so this row proves "+
					"nothing:\n%s", r.out)
			}
			if kernelW {
				sawW = true
			} else {
				sawR = true
			}

			table = append(table, outcome{row.name, elem, grant, kernelW})
			t.Logf("%-70s grant=%-14q kernel=%s", row.name, grant, map[bool]string{true: "W", false: "R"}[kernelW])

			if kernelW && grant != "shadow_slot" && grant != "unresolved" {
				t.Errorf("the kernel let the payload create a file at %s (element %q), but "+
					"--dry-run's verdict was %q, neither shadow_slot nor unresolved: the trust "+
					"screen is LESS SAFE than the sandbox it describes", elem, elem, grant)
			}
		})
	}

	// A positive control on the whole mechanism: without both a row that
	// actually shows KERNEL_W and one that shows KERNEL_R, the assertion
	// above could pass merely because the probe always answers the same way.
	if !sawW {
		t.Error("no row in this table ever observed KERNEL_W — the probe mechanism itself may be " +
			"broken, and every row above passed vacuously")
	}
	if !sawR {
		t.Error("no row in this table ever observed KERNEL_R — every fixture landed on writable " +
			"ground, which is not the spread this table intends")
	}

	var b strings.Builder
	b.WriteString("\nwalk-conformance table (name, grant, kernel):\n")
	for _, o := range table {
		fmt.Fprintf(&b, "  %-70s %-14s %s\n", o.name, o.grant, map[bool]string{true: "KERNEL_W", false: "KERNEL_R"}[o.kernelW])
	}
	t.Log(b.String())
}

// TestUnreadSSHConfigAcceptanceMatchesSSH is issue #604's conformance round,
// finding 3: a host link chain whose text, joined and Cleaned LEXICALLY,
// happens to land exactly on the generated ~/.ssh/config — while the kernel,
// meeting a DANGLING link partway through, never gets there at all. Measured
// on 14e9f48: snug accepted (exit 0) and ssh inside read no pinned identity
// (`identitiesonly no`); the fix is refuseUnreadSSHConfig walking the same
// component-at-a-time chain #604's PATH fix does, rather than a lexical join.
//
// Two accept controls run the identical assertion the other direction: a
// profile symlink straight to the real HOME, and a host link straight to it
// with no dotdot at all, must both make ssh read the pinned config.
func TestUnreadSSHConfigAcceptanceMatchesSSH(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	pw := hostPasswdHome(t)
	dir, _ := requireHostSystemSSHConfig(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	home := t.TempDir()

	real, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}

	pinned := "[profile.pinned]\n" +
		"description = \"one throwaway key\"\n" +
		"[profile.pinned.identity.ssh]\n" +
		"agent = \"proxy\"\n" +
		"key = \"" + pub + "\"\n"

	// sshGVerdict runs `ssh -G` against identity.SSHHost()'s own default
	// (policy.DefaultIdentityHost, "github.com" — the generated config's
	// `Host` line names it and NOTHING else, so any other hostname would
	// fail this check regardless of whether pw_dir resolves correctly) inside
	// a sandbox selecting pwlinkTOML (plus the pinned identity and the
	// sshcover control), and reports whether ssh actually read the pin.
	sshGVerdict := func(t *testing.T, pwlinkTOML string) (ran bool, identitiesOnlyYes bool, out string) {
		t.Helper()
		profiles := map[string]string{"pinned": pinned, "sshcover": sshCoverageProfile(dir), "pwlink": pwlinkTOML}
		env := writeProfiles(t, profiles, "HOME="+home, "SSH_AUTH_SOCK="+sock)
		r := runEnv(t, env, []string{"-p", "pinned", "-p", "sshcover", "-p", "pwlink"}, proj,
			"ssh -G "+policy.DefaultIdentityHost)
		return r.ran, strings.Contains(r.out, "\nidentitiesonly yes\n"), r.out
	}

	t.Run("dangling link after a lexically-cancelling dotdot chain refuses", func(t *testing.T) {
		// hl sits two levels under dirname(real) so that a LEXICAL Clean of
		// "l3/../../../"+base(real), joined against hl, cancels exactly back
		// to dirname(real)+"/"+base(real) == real — the shape that made
		// 14e9f48 accept. The kernel instead meets l3 (dangling) first and
		// never gets there.
		homeParent := filepath.Dir(real)
		hl := filepath.Join(homeParent, "wc599x1", "wc599x2")
		wcMkdir(t, hl)
		wcSymlink(t, "/nonexist/wc599/a/b", filepath.Join(hl, "l3"))
		wcSymlink(t, "l3/../../../"+filepath.Base(real), filepath.Join(hl, "t"))
		t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(homeParent, "wc599x1")) })

		pwlink := "[profile.pwlink]\n" +
			"description = \"a dangling host link chain a lexical clean would mistake for HOME\"\n" +
			"ro = [\"" + hl + "\"]\n" +
			"symlink = [{ at = \"" + pw + "\", target = \"" + filepath.Join(hl, "t") + "\" }]\n"

		profiles := map[string]string{"pinned": pinned, "sshcover": sshCoverageProfile(dir), "pwlink": pwlink}
		env := writeProfiles(t, profiles, "HOME="+home, "SSH_AUTH_SOCK="+sock)
		out, code := cli(t, env, "-p", "pinned", "-p", "sshcover", "-p", "pwlink", proj, "--", "true")
		accepted := code == 0

		ran, idYes, sshOut := sshGVerdict(t, pwlink)
		kernelReads := ran && idYes

		t.Logf("dangling-chain row: snug accepted=%v (exit %d), ssh actually read the pin=%v\n%s",
			accepted, code, kernelReads, out)

		if kernelReads && !accepted {
			t.Errorf("ssh inside actually read the pinned identity but snug refused the policy — " +
				"over-cautious, not unsafe, but worth knowing about")
		}
		if accepted && !kernelReads {
			t.Errorf("snug accepted the policy (exit 0) but ssh inside did NOT read the pinned "+
				"identity (ran=%v): the trust screen is LESS SAFE than the sandbox it describes\n"+
				"ssh -G output:\n%s", ran, sshOut)
		}
	})

	t.Run("direct symlink to the real HOME accepts and ssh reads the pin", func(t *testing.T) {
		pwlink := passwdHomeLink(t, home)
		out, code := cli(t, writeProfiles(t, map[string]string{"pinned": pinned,
			"sshcover": sshCoverageProfile(dir), "pwlink": pwlink}, "HOME="+home, "SSH_AUTH_SOCK="+sock),
			"-p", "pinned", "-p", "sshcover", "-p", "pwlink", proj, "--", "true")
		if code != 0 {
			t.Fatalf("control: snug refused the direct-symlink control (exit %d):\n%s", code, out)
		}
		ran, idYes, sshOut := sshGVerdict(t, pwlink)
		if !ran || !idYes {
			t.Errorf("control: ssh inside did not read the pinned identity through a direct "+
				"symlink to HOME (ran=%v):\n%s", ran, sshOut)
		}
	})

	t.Run("host link straight to the real HOME accepts and ssh reads the pin", func(t *testing.T) {
		hl2 := filepath.Join(t.TempDir(), "hl2")
		wcMkdir(t, hl2)
		wcSymlink(t, real, filepath.Join(hl2, "h"))
		pwlink := "[profile.pwlink]\n" +
			"description = \"a host link straight to the real HOME, no dotdot\"\n" +
			"ro = [\"" + hl2 + "\"]\n" +
			"symlink = [{ at = \"" + pw + "\", target = \"" + filepath.Join(hl2, "h") + "\" }]\n"
		out, code := cli(t, writeProfiles(t, map[string]string{"pinned": pinned,
			"sshcover": sshCoverageProfile(dir), "pwlink": pwlink}, "HOME="+home, "SSH_AUTH_SOCK="+sock),
			"-p", "pinned", "-p", "sshcover", "-p", "pwlink", proj, "--", "true")
		if code != 0 {
			t.Fatalf("control: snug refused the direct-host-link control (exit %d):\n%s", code, out)
		}
		ran, idYes, sshOut := sshGVerdict(t, pwlink)
		if !ran || !idYes {
			t.Errorf("control: ssh inside did not read the pinned identity through a host link "+
				"straight to HOME (ran=%v):\n%s", ran, sshOut)
		}
	})
}
