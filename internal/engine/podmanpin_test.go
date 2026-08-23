package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// podmanpin_test.go is the pure, privilege-free half of issue #384's gate:
// ParsePodmanVersion and CheckPodmanVersion take a string and return a
// string or an error, so every case here runs under `make gate` with no
// bundle installed and no sandbox — CheckPodmanBinaryVersion's own exec is
// exercised too, but only against fixtures this test writes itself, never
// against the real ~/.local/opt/podman-static bundle (that belongs to
// test/integration/podmanversiongate_test.go, which can skip when the bundle
// is absent; this file must not skip, ever, so it never touches a real path).

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

func TestCheckPodmanVersionExactMatch(t *testing.T) {
	if err := CheckPodmanVersion("podman version 5.8.4\n", "5.8.4"); err != nil {
		t.Fatalf("unexpected error on an exact match: %v", err)
	}
}

// TestCheckPodmanVersionRejectsSubstringNeighbours is the substring-trap
// sweep named explicitly in issue #384: "5.8.40", "15.8.4" and "5.8.4-rc1"
// all CONTAIN "5.8.4" as a substring and must still be refused, because the
// comparison in CheckPodmanVersion is `==` on the whole parsed field, never
// strings.Contains and never a prefix/suffix check.
func TestCheckPodmanVersionRejectsSubstringNeighbours(t *testing.T) {
	cases := []string{
		"5.8.40",    // "5.8.4" is a PREFIX of this
		"15.8.4",    // "5.8.4" is a SUFFIX of this
		"5.8.4-rc1", // "5.8.4" is a PREFIX of this
	}
	for _, got := range cases {
		t.Run(got, func(t *testing.T) {
			output := fmt.Sprintf("podman version %s\n", got)
			err := CheckPodmanVersion(output, "5.8.4")
			if err == nil {
				t.Fatalf("CheckPodmanVersion(%q, %q) = nil; %q must not be accepted as a match "+
					"for the pin even though it contains it as a substring", output, "5.8.4", got)
			}
			if !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("error %q does not identify itself as a MISMATCH, distinct from a parse "+
					"failure — a caller needs to tell the two apart", err.Error())
			}
		})
	}
}

func TestCheckPodmanVersionPropagatesParseFailure(t *testing.T) {
	err := CheckPodmanVersion("not a version string at all", "5.8.4")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("CheckPodmanVersion must surface ParsePodmanVersion's own PARSE error verbatim "+
			"when the output cannot be parsed at all, not fold it into a mismatch: got %q", err.Error())
	}
}

// TestPinnedPodmanBundleVersionHasNoVPrefix guards the exact hazard the
// constant's own doc comment names: the GitHub tag is "v5.8.4" but `podman
// --version` prints the bare form, so a "v" smuggled into the constant would
// make CheckPodmanVersion reject every real binary it is pointed at.
func TestPinnedPodmanBundleVersionHasNoVPrefix(t *testing.T) {
	if strings.HasPrefix(PinnedPodmanBundleVersion, "v") {
		t.Fatalf("PinnedPodmanBundleVersion = %q carries a leading %q; podman --version prints "+
			"the bare form and CheckPodmanVersion compares with ==, so this would reject the "+
			"pinned binary itself", PinnedPodmanBundleVersion, "v")
	}
	// Sanity check on the flip side: the fixture above only catches a literal
	// "v" prefix, so also assert the pin round-trips through the same parser
	// CheckPodmanVersion uses, against the exact line the real binary prints.
	if err := CheckPodmanVersion("podman version "+PinnedPodmanBundleVersion+"\n", PinnedPodmanBundleVersion); err != nil {
		t.Fatalf("the pin does not accept itself: %v", err)
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

func TestCheckPodmanBinaryVersionMatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SKIP: fixture is a #!/bin/sh script, this test assumes a POSIX shell is exec'able")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-podman")
	writeFakeVersionScript(t, bin, "podman version 5.8.4\n", 0o755)

	if err := CheckPodmanBinaryVersion(bin, "5.8.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckPodmanBinaryVersionMismatchIsDistinguishableFromParseFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SKIP: fixture is a #!/bin/sh script, this test assumes a POSIX shell is exec'able")
	}
	dir := t.TempDir()

	mismatch := filepath.Join(dir, "fake-podman-mismatch")
	writeFakeVersionScript(t, mismatch, "podman version 5.8.4-rc1\n", 0o755)
	err := CheckPodmanBinaryVersion(mismatch, "5.8.4")
	if err == nil {
		t.Fatal("expected a mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch error %q is not textually distinguishable as a MISMATCH", err.Error())
	}

	unparseable := filepath.Join(dir, "fake-podman-garbage")
	writeFakeVersionScript(t, unparseable, "not a version line\n", 0o755)
	err = CheckPodmanBinaryVersion(unparseable, "5.8.4")
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("parse error %q is not textually distinguishable as a PARSE failure", err.Error())
	}
}

// TestCheckPodmanBinaryVersionNonExecutableFileIsAnExecErrorNotAParseOrMismatch
// is issue #384's third named case: a file that exists at the expected path
// (0o644, no exec bit) is neither "absent" nor "wrong version" — it is a
// broken install that never produces any output to parse at all, so its
// error must be distinguishable from both CheckPodmanVersion error shapes
// ("could not parse", "does not match").
func TestCheckPodmanBinaryVersionNonExecutableFileIsAnExecErrorNotAParseOrMismatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SKIP: this test depends on the POSIX executable-bit permission model")
	}
	if os.Getuid() == 0 {
		t.Skip("SKIP: root ignores the executable bit, so this test cannot fail for the right " +
			"reason as root")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-podman-not-executable")
	writeFakeVersionScript(t, bin, "podman version 5.8.4\n", 0o644)

	err := CheckPodmanBinaryVersion(bin, "5.8.4")
	if err == nil {
		t.Fatal("expected an exec error for a non-executable file")
	}
	if strings.Contains(err.Error(), "could not parse") || strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a non-executable file must fail as an EXEC error, not be misreported as a "+
			"parse failure or a version mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), bin) {
		t.Fatalf("exec error %q does not name the path that failed to run", err.Error())
	}
	// Positive control for the negative above: confirm the OS really does
	// refuse to exec this file directly, so "CheckPodmanBinaryVersion
	// returned an error" is not passing because of something else (a missing
	// binary, a bad shebang) that happens to also error.
	if execErr := exec.Command(bin, "--version").Run(); execErr == nil {
		t.Fatal("positive control failed: a 0o644 file with no exec bit ran successfully, so " +
			"this test's exec-error case never had a chance to be exercised for the reason it " +
			"claims")
	}
}

func TestCheckPodmanBinaryVersionMissingBinaryIsAnExecError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")
	err := CheckPodmanBinaryVersion(missing, "5.8.4")
	if err == nil {
		t.Fatal("expected an error for a binary that does not exist")
	}
	if strings.Contains(err.Error(), "could not parse") || strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a missing binary must fail as an EXEC error, not be misreported as a parse "+
			"failure or a version mismatch: %v", err)
	}
}
