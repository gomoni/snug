//go:build integration

package integration

// podmanversiongate_test.go is issue #384's integration layer: it drives the
// consolidated checkedPodmanBundle resolver (containerengine_test.go) and
// PROVENANCE cross-check through a REAL subprocess and a REAL installed
// bundle, which is what the pure table in internal/engine/podmanpin_test.go
// cannot reach — that file never touches a filesystem path, this one does.
//
// Two independent things are asserted, and they must not be confused:
//
//   - TestCheckedPodmanBundleGate exercises the RESOLVER (checkedPodmanBundle,
//     via podmanBundle) end to end, using a FAKE bundle under a fake $HOME —
//     never the real one — so ABSENT/MATCH/MISMATCH/non-executable can all be
//     produced on demand, on any host, without depending on what happens to
//     be installed here.
//   - TestPodmanBundleProvenanceMatchesPin and
//     TestPodmanBundleBinariesMatchProvenanceHashes read the REAL, installed
//     PROVENANCE file and the REAL binaries beside it, because those are the
//     one thing that cannot be faked without defeating the point: they prove
//     THIS machine's bundle is what it claims to be, not that the checking
//     code works in the abstract.
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/gomoni/snug/internal/engine"
)

// ── TestCheckedPodmanBundleGate: the resolver, against a fake bundle ───────

// podmanVersionGateHelperEnv gates TestPodmanVersionGateHelperProcess so it
// never runs except as the subprocess runPodmanVersionGateHelper starts —
// the same convention internal/sandbox/teardown_test.go's
// teardownHelperSig/teardownHelperSet use, and for the same reason: a Fatal
// or a Skip inside the function under test must be observed from OUTSIDE the
// process it happens in, since either one halts the calling goroutine
// (runtime.Goexit) before this file's own assertions could run.
const podmanVersionGateHelperEnv = "SNUG_PODMANVERSIONGATE_HELPER"

// TestPodmanVersionGateHelperProcess is not a test to run directly — it is
// the body runPodmanVersionGateHelper re-execs. It calls the SAME podmanBundle
// every real-engine test in containerengine_test.go calls, pointed at a fake
// $HOME the outer test built, and prints a marker only if the call returns
// normally (neither Skip nor Fatal): that marker is what tells the outer
// test the gate did not stop it.
func TestPodmanVersionGateHelperProcess(t *testing.T) {
	if os.Getenv(podmanVersionGateHelperEnv) != "1" {
		t.Skip("SKIP: this test only runs as a subprocess of TestCheckedPodmanBundleGate")
	}
	fmt.Println("HELPER-STARTED HOME=" + os.Getenv("HOME"))
	podmanBundle(t)
	fmt.Println("HELPER-REACHED-END")
}

// runPodmanVersionGateHelper re-execs this same test binary restricted to
// TestPodmanVersionGateHelperProcess, with HOME pointed at the caller's fake
// bundle tree, and reports its combined output and exit code.
func runPodmanVersionGateHelper(t *testing.T, home string) (output string, exitCode int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPodmanVersionGateHelperProcess$", "-test.v=true")
	// Re-execing os.Args[0] runs this package's OWN TestMain unconditionally
	// (Go always calls it, before any -test.run filtering) — sandbox_test.go's
	// TestMain does a real `go build -o snugBin ./cmd/snug`. If HOME is the
	// only variable overridden, that build's own GOPATH/GOMODCACHE default to
	// $HOME/go, so it re-downloads every module into a fresh cache under the
	// fake bundle's temp home and then fails to clean itself up (some cached
	// files under golang.org/x/sys's windows/ tree are read-only) — measured
	// while writing this test. Pinning the REAL GOPATH/GOMODCACHE/GOCACHE/
	// GOENV explicitly keeps HOME's override scoped to what this test is
	// actually about (os.UserHomeDir(), read by checkedPodmanBundle) without
	// also redirecting the Go toolchain's own cache.
	realGoEnv := map[string]string{}
	for _, k := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOENV"} {
		if v, err := exec.Command("go", "env", k).Output(); err == nil {
			realGoEnv[k] = strings.TrimSpace(string(v))
		}
	}
	cmd.Env = append(os.Environ(), "HOME="+home, podmanVersionGateHelperEnv+"=1")
	for k, v := range realGoEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, runErr := cmd.CombinedOutput()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	} else if runErr != nil {
		code = -1
	}
	return string(out), code
}

// buildFakePodmanBundleHome creates a fake $HOME whose
// .local/opt/podman-static/usr/local/bin/podman is a COPY of the shared
// fakepodman binary (gate_test.go's fakePodmanBin), with a sidecar .cfg
// naming version so fakepodman's own "--version" mode answers with it (see
// testdata/fakepodman/main.go's doc comment). version == "" writes no cfg at
// all, which is only used by the non-executable case below, where the exec
// fails before fakepodman ever gets to read it.
func buildFakePodmanBundleHome(t *testing.T, version string, executable bool) string {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, podmanStaticRootRel)
	podmanPath := engine.PinnedPodmanBundleBinary(root)
	if err := os.MkdirAll(filepath.Dir(podmanPath), 0o755); err != nil {
		t.Fatal(err)
	}
	src := fakePodmanBin(t)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o755)
	if !executable {
		mode = 0o644
	}
	if err := os.WriteFile(podmanPath, data, mode); err != nil {
		t.Fatal(err)
	}
	if version != "" {
		if err := os.WriteFile(podmanPath+".cfg", []byte("version="+version+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// TestCheckedPodmanBundleGate is issue #384's crux, tested against a fake
// bundle rather than the real one so every branch is reachable on any host:
// ABSENT skips, an exact MATCH passes through, and a version that is present
// but wrong — including the substring-trap neighbours named in issue #384 —
// is FATAL, never silently accepted, never confused with a parse failure.
func TestCheckedPodmanBundleGate(t *testing.T) {
	t.Run("match_passes", func(t *testing.T) {
		home := buildFakePodmanBundleHome(t, engine.PinnedPodmanBundleVersion, true)
		out, code := runPodmanVersionGateHelper(t, home)
		if code != 0 {
			t.Fatalf("expected exit 0 for a matching version, got %d:\n%s", code, out)
		}
		// This IS the positive control the rest of this test needs: it proves
		// the fixture mechanics (fake HOME, a real copy of fakepodman, the
		// subprocess re-exec) actually reach the gate and pass through it when
		// nothing is wrong — so a mismatch failing below is the GATE catching
		// something, not the fixture being broken in a way that fails no
		// matter what version string is written.
		if !strings.Contains(out, "HELPER-REACHED-END") {
			t.Fatalf("a MATCHING version did not reach past the gate — the fixture itself is "+
				"broken, which would make every mismatch case below pass for the wrong reason:\n%s", out)
		}
	})

	t.Run("absent_skips_cleanly", func(t *testing.T) {
		home := t.TempDir() // no .local/opt/podman-static tree at all
		out, code := runPodmanVersionGateHelper(t, home)
		if code != 0 {
			t.Fatalf("expected exit 0 (a clean skip) for an absent bundle, got %d:\n%s", code, out)
		}
		if strings.Contains(out, "HELPER-REACHED-END") {
			t.Fatalf("an absent bundle reached past the gate instead of skipping:\n%s", out)
		}
		if !strings.Contains(out, "SKIP") {
			t.Fatalf("expected the helper's own SKIP for an absent bundle, got:\n%s", out)
		}
	})

	// The substring-trap sweep, run through the REAL exec path this time
	// (fakepodman really answering "podman --version", not a string handed
	// straight to the pure parser) — "9.9.9" is a plain mismatch, the other
	// three are near-misses that a strings.Contains or prefix/suffix check
	// would wrongly accept as "5.8.4".
	mismatches := []string{"9.9.9", "5.8.40", "15.8.4", "5.8.4-rc1"}
	for _, v := range mismatches {
		v := v
		t.Run("mismatch_"+v, func(t *testing.T) {
			home := buildFakePodmanBundleHome(t, v, true)
			out, code := runPodmanVersionGateHelper(t, home)
			if code == 0 {
				t.Fatalf("version %q must be refused (pin is %s), but the helper exited 0:\n%s",
					v, engine.PinnedPodmanBundleVersion, out)
			}
			if strings.Contains(out, "HELPER-REACHED-END") {
				t.Fatalf("version %q reached past the gate instead of failing it:\n%s", v, out)
			}
			if !strings.Contains(out, "PRESENT but failed the pinned-version check") {
				t.Fatalf("expected checkedPodmanBundle's own FATAL message naming the pin "+
					"failure, got:\n%s", out)
			}
		})
	}

	t.Run("non_executable_fatals_as_an_exec_error", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("SKIP: root ignores the executable bit, so this case cannot fail for the " +
				"right reason as root")
		}
		home := buildFakePodmanBundleHome(t, "", false)
		out, code := runPodmanVersionGateHelper(t, home)
		if code == 0 {
			t.Fatalf("a non-executable bundle binary must be refused, but the helper exited 0:\n%s", out)
		}
		// The exact phrases engine.CheckPodmanVersion/ParsePodmanVersion use for
		// their own two error shapes (checked, not "does not match"/"could not
		// parse" alone: checkedPodmanBundle's own wrapper prose talks about the
		// pin in a way that contains the bare word "match", which would make a
		// looser substring here a false positive against its OWN wording).
		if strings.Contains(out, "does not match the pinned") || strings.Contains(out, "could not parse a podman version") {
			t.Fatalf("a non-executable file must fail as an EXEC error, not be misreported as a "+
				"version mismatch or a parse failure:\n%s", out)
		}
		if !strings.Contains(out, "PRESENT but failed the pinned-version check") {
			t.Fatalf("expected checkedPodmanBundle's own FATAL message, got:\n%s", out)
		}
	})
}

// ── PROVENANCE: the real, installed bundle ─────────────────────────────────

// podmanProvenance is the subset of ~/.local/opt/podman-static/PROVENANCE
// this file reads. Deliberately NOT DisallowUnknownFields: that discipline
// (internal/profile) exists to stop a negation key being smuggled into a
// TRUST-BEARING profile, which PROVENANCE is not — it feeds a test assertion,
// never a grant, so a future field must not break this reader.
type podmanProvenance struct {
	Artifact struct {
		Tag string `toml:"tag"`
	} `toml:"artifact"`
	Versions struct {
		Podman string `toml:"podman"`
	} `toml:"versions"`
	Binaries map[string]string `toml:"binaries"`
}

// loadPodmanProvenance reads and parses the REAL PROVENANCE file beside the
// REAL installed bundle.
//
// ABSENT is a skip, reversed from an earlier draft of this gate. §3 of
// .claude/design/PODMAN-STATIC.md documents a minimal install
// (`README.md etc/ usr/` and nothing else) as a legitimate, supported shape —
// measured on the development host itself, issue #384 — and PROVENANCE is
// not part of it. Fataling on absence would fail every test in this file,
// and every future CI runner, for anyone who followed that documented path
// literally, over a file the design doc never promises. PRESENT but
// unparseable, or present but DISAGREEING with the pin, is a different
// claim — that bundle asserts something about itself and is wrong — and
// stays fatal, which is what the two tests below do.
func loadPodmanProvenance(t *testing.T) (*podmanProvenance, string) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("SKIP: cannot determine $HOME to look for PROVENANCE: " + err.Error())
	}
	path := filepath.Join(home, podmanStaticRootRel, "PROVENANCE")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("SKIP: no PROVENANCE at " + path + " — §3's documented minimal install " +
			"(.claude/design/PODMAN-STATIC.md) does not ship one, so absence here is not a " +
			"broken install")
	}
	var p podmanProvenance
	if err := toml.Unmarshal(data, &p); err != nil {
		t.Fatalf("%s exists but does not parse as TOML: %v", path, err)
	}
	return &p, path
}

// TestPodmanBundleProvenanceMatchesPin cross-checks the REAL, installed
// PROVENANCE's [versions].podman against engine.PinnedPodmanBundleVersion —
// the two are recorded independently (one measured by host-bridge running
// `podman --version` while provisioning, one hand-written into the pin), so
// agreement here is not a tautology.
func TestPodmanBundleProvenanceMatchesPin(t *testing.T) {
	p, path := loadPodmanProvenance(t)
	if p.Versions.Podman != engine.PinnedPodmanBundleVersion {
		t.Fatalf("%s records [versions].podman = %q, but engine.PinnedPodmanBundleVersion = %q.\n"+
			"       This is a PRESENT-but-disagreeing PROVENANCE, not an absent one: the "+
			"installed bundle claims a version the pin does not recognise. If this is a "+
			"deliberate re-pin, update engine.PinnedPodmanBundleVersion AND "+
			".claude/design/PODMAN-STATIC.md §1 together.",
			path, p.Versions.Podman, engine.PinnedPodmanBundleVersion)
	}
	// The tag and the bare version are deliberately both present in
	// PROVENANCE (the file's own [artifact] comment names why: a naive
	// compare against the tag's "v" prefix must not be the one that matches).
	// Cross-checking them against each other here is what makes that
	// deliberate choice a checked fact instead of a comment nobody re-reads.
	if p.Artifact.Tag != "" {
		wantTag := "v" + p.Versions.Podman
		if p.Artifact.Tag != wantTag {
			t.Fatalf("%s: [artifact].tag = %q does not agree with [versions].podman = %q "+
				"(expected tag %q) — these two fields exist precisely so a bare-version compare "+
				"cannot be fooled by the tag's leading \"v\", and they have drifted apart",
				path, p.Artifact.Tag, p.Versions.Podman, wantTag)
		}
	}
}

// checkOneBinaryHash is the pure half of the [binaries] sweep, split out so
// it can be exercised against a KNOWN-BAD hash below — proof the comparison
// itself can fail, not only that the real PROVENANCE happens to agree with
// itself.
func checkOneBinaryHash(path, wantHex string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != wantHex {
		return fmt.Errorf("%s: sha256 %s does not match PROVENANCE's recorded %s", path, got, wantHex)
	}
	return nil
}

// TestCheckOneBinaryHashRejectsATamperedHash is the positive control for
// TestPodmanBundleBinariesMatchProvenanceHashes: it proves checkOneBinaryHash
// can actually fail, against a fixture this test controls, before the real
// test below trusts it to compare the installed bundle's binaries — a hash
// check that has never been observed to disagree with anything is not yet
// known to be checking.
func TestCheckOneBinaryHashRejectsATamperedHash(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "not-actually-podman")
	if err := os.WriteFile(f, []byte("hello, world"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrongHash := strings.Repeat("0", 64)
	if err := checkOneBinaryHash(f, wrongHash); err == nil {
		t.Fatal("expected a mismatch error against a deliberately wrong hash")
	}
	// And the flip side: the SAME function must accept the file's own real
	// hash, so the failure above is the comparison working, not the function
	// always erroring.
	sum := sha256.Sum256([]byte("hello, world"))
	if err := checkOneBinaryHash(f, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("checkOneBinaryHash rejected the file's own correct hash: %v", err)
	}
}

// TestPodmanBundleBinariesMatchProvenanceHashes cross-checks every entry
// under the REAL, installed PROVENANCE's [binaries] table against a freshly
// computed sha256 of the file AS INSTALLED — never against the 45MB
// tarball itself, which is explicitly out of scope (re-hashing it here would
// duplicate host-bridge's own provisioning-time check, at real cost, for no
// new coverage: this test's job is "does the file on disk still match the
// record", not "was the record honest about the tarball").
func TestPodmanBundleBinariesMatchProvenanceHashes(t *testing.T) {
	p, path := loadPodmanProvenance(t)
	if len(p.Binaries) == 0 {
		t.Fatalf("%s exists but its [binaries] table is empty — nothing for this test to check, "+
			"which would make the loop below vacuously pass", path)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("SKIP: cannot determine $HOME: " + err.Error())
	}
	root := filepath.Join(home, podmanStaticRootRel)
	checked := 0
	for rel, wantHash := range p.Binaries {
		full := filepath.Join(root, rel)
		if err := checkOneBinaryHash(full, wantHash); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		checked++
	}
	t.Logf("checked %d [binaries] entries from %s against the installed bundle", checked, path)
}
