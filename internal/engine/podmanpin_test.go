package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// podmanpin_test.go is the pure, privilege-free half of issue #384's gate:
// ParsePodmanVersion and CheckPodmanVersionSupported take a string and return
// a string or an error, so every case here runs under `make gate` with no
// bundle installed and no sandbox. CheckPodmanBinaryVersionSupported's own
// exec is exercised too, but only against fixtures this test writes itself,
// never against ~/.local/opt/podman-static — that belongs to
// test/integration/podmanversiongate_test.go, which can skip when the bundle
// is absent; this file must not skip, ever, so it never touches a real path.

func TestParsePodmanVersionExact(t *testing.T) {
	got, err := ParsePodmanVersion("podman version 5.8.4\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "5.8.4" {
		t.Fatalf("got %q, want %q", got, "5.8.4")
	}
}

// TestParsePodmanVersionRejects is the substring-trap sweep for the PARSE
// half: every case here is a string that a naive strings.Contains(output,
// want) check would accept as "5.8.4" and that field-splitting must not.
func TestParsePodmanVersionRejects(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"whitespace only":      "   \n",
		"missing version word": "podman 5.8.4",
		"wrong program name":   "notpodman version 5.8.4",
		"leading noise":        "Warning: something\npodman version 5.8.4",
		"multiline":            "podman version 5.8.4\nextra trailing line\n",
		"too many fields":      "podman version 5.8.4 extra",
		"too few fields":       "podman version",
	}
	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ParsePodmanVersion(output)
			if err == nil {
				t.Fatalf("ParsePodmanVersion(%q) = %q, nil; want an error", output, got)
			}
			if !strings.Contains(err.Error(), "could not parse") {
				t.Fatalf("error %q does not identify itself as a PARSE failure, which is what "+
					"lets a caller tell a parse failure apart from a version mismatch", err.Error())
			}
		})
	}
}

// pinnedVersion is the one version SupportedPodmanBundles ships today, read
// from the set rather than repeated as a literal — the set is the only
// authority for this fact.
func pinnedVersion(t *testing.T) string {
	t.Helper()
	if len(SupportedPodmanBundles) == 0 {
		t.Fatal("SupportedPodmanBundles is empty; every test in this file needs at least one entry")
	}
	return SupportedPodmanBundles[0].Version
}

func TestCheckPodmanVersionSupportedExactMatch(t *testing.T) {
	v := pinnedVersion(t)
	if err := CheckPodmanVersionSupported("podman version " + v + "\n"); err != nil {
		t.Fatalf("unexpected error on a supported version: %v", err)
	}
}

// TestCheckPodmanVersionSupportedRejectsSubstringNeighbours is the
// substring-trap sweep named in issue #384: each case CONTAINS a supported
// version as a substring and must still be refused, because membership is
// checked with `==` per element, never strings.Contains, never a prefix or
// suffix.
func TestCheckPodmanVersionSupportedRejectsSubstringNeighbours(t *testing.T) {
	v := pinnedVersion(t)
	cases := []string{
		v + "0",    // v is a PREFIX of this
		"1" + v,    // v is a SUFFIX of this
		v + "-rc1", // v is a PREFIX of this
	}
	for _, got := range cases {
		t.Run(got, func(t *testing.T) {
			output := fmt.Sprintf("podman version %s\n", got)
			err := CheckPodmanVersionSupported(output)
			if err == nil {
				t.Fatalf("CheckPodmanVersionSupported(%q) = nil; %q must not be accepted as "+
					"supported even though it contains %q as a substring", output, got, v)
			}
			if strings.Contains(err.Error(), "could not parse") {
				t.Fatalf("error %q is a PARSE failure, not the MISMATCH this case is meant to "+
					"exercise — %q parses fine as a version, it is just unsupported", err.Error(), got)
			}
			if !strings.Contains(err.Error(), got) {
				t.Fatalf("error %q does not name the unsupported version it rejected", err.Error())
			}
		})
	}
}

func TestCheckPodmanVersionSupportedPropagatesParseFailure(t *testing.T) {
	err := CheckPodmanVersionSupported("not a version string at all")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("CheckPodmanVersionSupported must surface ParsePodmanVersion's own PARSE error "+
			"verbatim when the output cannot be parsed at all, not fold it into a mismatch: got %q",
			err.Error())
	}
}

// TestSupportedPodmanBundlesVersionHasNoVPrefix guards the exact hazard named
// in podmanpin.go: the GitHub tag carries "v", `podman --version` never does,
// so a "v" smuggled into Version would reject the pinned binary itself.
func TestSupportedPodmanBundlesVersionHasNoVPrefix(t *testing.T) {
	for _, b := range SupportedPodmanBundles {
		if strings.HasPrefix(b.Version, "v") {
			t.Fatalf("SupportedPodmanBundles entry %+v has a Version with a leading %q; "+
				"podman --version prints the bare form", b, "v")
		}
		if err := CheckPodmanVersionSupported("podman version " + b.Version + "\n"); err != nil {
			t.Fatalf("bundle %+v does not accept its own Version: %v", b, err)
		}
	}
}

// TestSupportedPodmanBundlesTagCarriesVPrefix is the flip side of the trap
// above: Tag is the GitHub release tag, and it DOES carry the "v" that
// Version must not, so a bundle whose two fields drifted apart is caught
// here.
func TestSupportedPodmanBundlesTagCarriesVPrefix(t *testing.T) {
	for _, b := range SupportedPodmanBundles {
		want := "v" + b.Version
		if b.Tag != want {
			t.Fatalf("SupportedPodmanBundles entry has Tag = %q, want %q (from Version = %q)",
				b.Tag, want, b.Version)
		}
	}
}

func TestSupportedPodmanBundleLookup(t *testing.T) {
	v := pinnedVersion(t)
	got, ok := SupportedPodmanBundle(v)
	if !ok {
		t.Fatalf("SupportedPodmanBundle(%q) = _, false; want the pinned bundle", v)
	}
	if got.Version != v {
		t.Fatalf("SupportedPodmanBundle(%q).Version = %q, want %q", v, got.Version, v)
	}
	if _, ok := SupportedPodmanBundle("9.9.9"); ok {
		t.Fatal("SupportedPodmanBundle(\"9.9.9\") = _, true; want false for an unsupported version")
	}
}

func TestSupportedPodmanVersionsMatchesBundles(t *testing.T) {
	var want []string
	for _, b := range SupportedPodmanBundles {
		want = append(want, b.Version)
	}
	got := SupportedPodmanVersions()
	if !slices.Equal(got, want) {
		t.Fatalf("SupportedPodmanVersions() = %v, want %v (SupportedPodmanBundles' own Version "+
			"fields, in order)", got, want)
	}
}

func TestPinnedPodmanBundleBinaryJoinsUnderUsrLocalBin(t *testing.T) {
	got := PinnedPodmanBundleBinary("/some/root")
	want := filepath.Join("/some/root", "usr", "local", "bin", "podman")
	if got != want {
		t.Fatalf("PinnedPodmanBundleBinary(%q) = %q, want %q", "/some/root", got, want)
	}
}

// writeFakeVersionScript writes a tiny shell script at path that prints
// output to stdout and exits 0. mode controls the executable bit, so the
// non-executable-file case can be exercised without shelling out to chmod
// from the test body twice.
func writeFakeVersionScript(t *testing.T, path, output string, mode os.FileMode) {
	t.Helper()
	script := "#!/bin/sh\nprintf '%s'\n"
	if err := os.WriteFile(path, []byte(fmt.Sprintf(script, output)), mode); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPodmanBinaryVersionSupportedMatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SKIP: fixture is a #!/bin/sh script, this test assumes a POSIX shell is exec'able")
	}
	v := pinnedVersion(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-podman")
	writeFakeVersionScript(t, bin, "podman version "+v+"\n", 0o755)

	if err := CheckPodmanBinaryVersionSupported(bin); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPodmanBinaryVersionSupportedMismatchIsDistinguishableFromParseFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SKIP: fixture is a #!/bin/sh script, this test assumes a POSIX shell is exec'able")
	}
	v := pinnedVersion(t)
	dir := t.TempDir()

	mismatch := filepath.Join(dir, "fake-podman-mismatch")
	writeFakeVersionScript(t, mismatch, "podman version "+v+"-rc1\n", 0o755)
	err := CheckPodmanBinaryVersionSupported(mismatch)
	if err == nil {
		t.Fatal("expected a mismatch error")
	}
	if strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("mismatch error %q is a PARSE failure, not a MISMATCH", err.Error())
	}

	unparseable := filepath.Join(dir, "fake-podman-garbage")
	writeFakeVersionScript(t, unparseable, "not a version line\n", 0o755)
	err = CheckPodmanBinaryVersionSupported(unparseable)
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("parse error %q is not textually distinguishable as a PARSE failure", err.Error())
	}
}

// TestCheckPodmanBinaryVersionSupportedNonExecutableFileIsAnExecErrorNotAParseOrMismatch
// is issue #384's third named case: a file that exists at the expected path
// (0o644, no exec bit) is neither "absent" nor "unsupported" — it is a broken
// install that never produces any output to parse, so its error must be
// distinguishable from both other error shapes.
func TestCheckPodmanBinaryVersionSupportedNonExecutableFileIsAnExecErrorNotAParseOrMismatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SKIP: this test depends on the POSIX executable-bit permission model")
	}
	if os.Getuid() == 0 {
		t.Skip("SKIP: root ignores the executable bit, so this test cannot fail for the right " +
			"reason as root")
	}
	v := pinnedVersion(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-podman-not-executable")
	writeFakeVersionScript(t, bin, "podman version "+v+"\n", 0o644)

	err := CheckPodmanBinaryVersionSupported(bin)
	if err == nil {
		t.Fatal("expected an exec error for a non-executable file")
	}
	if strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("a non-executable file must fail as an EXEC error, not be misreported as a "+
			"parse failure: %v", err)
	}
	if !strings.Contains(err.Error(), bin) {
		t.Fatalf("exec error %q does not name the path that failed to run", err.Error())
	}
	// Positive control for the negative above: confirm the OS really does
	// refuse to exec this file directly, so "an error came back" is not
	// passing for an unrelated reason (a missing binary, a bad shebang).
	if execErr := exec.Command(bin, "--version").Run(); execErr == nil {
		t.Fatal("positive control failed: a 0o644 file with no exec bit ran successfully, so " +
			"this test's exec-error case never had a chance to be exercised for the reason it " +
			"claims")
	}
}

func TestCheckPodmanBinaryVersionSupportedMissingBinaryIsAnExecError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")
	err := CheckPodmanBinaryVersionSupported(missing)
	if err == nil {
		t.Fatal("expected an error for a binary that does not exist")
	}
	if strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("a missing binary must fail as an EXEC error, not be misreported as a parse "+
			"failure: %v", err)
	}
}
