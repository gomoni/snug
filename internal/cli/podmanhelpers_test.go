package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findPodmanHelperIn must answer with the FIRST directory holding an executable
// of that name, must ignore a non-executable file, and must ignore a directory
// wearing the helper's name. Each arm has its positive control in the same
// table: an arm that only ever returns "" would pass a test asserting absence.
func TestFindPodmanHelperIn(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, d := range []string{first, second} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// An executable in `second` only: found, and the path names `second`.
	exe := filepath.Join(second, "netavark")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A NON-executable of the same name earlier on the list must not shadow it.
	if err := os.WriteFile(filepath.Join(first, "netavark"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A DIRECTORY wearing a helper's name must not count as the helper.
	if err := os.MkdirAll(filepath.Join(first, "conmon"), 0o755); err != nil {
		t.Fatal(err)
	}

	dirs := []string{first, second}

	if got := findPodmanHelperIn(dirs, "netavark"); got != exe {
		t.Errorf("netavark: got %q, want %q — a non-executable file earlier on the "+
			"list must not shadow a real executable later on it", got, exe)
	}
	// Positive control for the two negatives below: the call above found
	// something, so "" here is a fact about the tree and not about the walk
	// silently failing.
	if got := findPodmanHelperIn(dirs, "conmon"); got != "" {
		t.Errorf("conmon: got %q, want \"\" — a directory named like a helper is not "+
			"a helper", got)
	}
	if got := findPodmanHelperIn(dirs, "aardvark-dns"); got != "" {
		t.Errorf("aardvark-dns: got %q, want \"\" — nothing of that name exists in "+
			"either directory", got)
	}
	if got := findPodmanHelperIn(nil, "netavark"); got != "" {
		t.Errorf("empty dir list: got %q, want \"\"", got)
	}
}

// The directories are the ones libpod REPORTED in its own error messages,
// measured on this host. If this list drifts from podman's, doctor checks a
// different question than the one the user will hit, so the two libpod named are
// pinned explicitly rather than left to review.
func TestPodmanHelperDirsCoverTheOnesLibpodNamed(t *testing.T) {
	dirs := podmanHelperDirs()
	seen := map[string]bool{}
	for _, d := range dirs {
		seen[d] = true
	}
	// From `could not find a working conmon binary (configured options: [...])`
	// and `could not find "netavark" in one of [...]`, both captured on this
	// host against the pinned bundle.
	for _, want := range []string{
		"/usr/libexec/podman", "/usr/local/libexec/podman", "/usr/local/lib/podman",
		"/usr/lib/podman", "/usr/bin", "/usr/sbin", "/usr/local/bin",
		"/usr/local/sbin", "/run/current-system/sw/bin",
	} {
		if !seen[want] {
			t.Errorf("podmanHelperDirs omits %q, which libpod named in its own "+
				"helper-lookup error — doctor would report a helper as missing that "+
				"podman can find, or the reverse", want)
		}
	}
	if len(dirs) == 0 {
		t.Fatal("podmanHelperDirs is empty, so every helper reads as missing")
	}
}

// rootlessport must NOT be required: snug publishes no ports (the engine holds
// no CAP_NET_ADMIN), so warning about it names no action the user could take.
// This is the assertion that stops someone "completing" the list later.
func TestRequiredPodmanHelpersExcludesRootlessport(t *testing.T) {
	req := requiredPodmanHelpers()
	if len(req) == 0 {
		t.Fatal("requiredPodmanHelpers is empty, so reportPodmanHelpers can never warn")
	}
	for _, h := range req {
		if h == "rootlessport" {
			t.Error("rootlessport is in the required set — snug publishes no ports, so " +
				"its absence changes nothing and the warning names no action")
		}
		if h == "crun" || h == "runc" {
			t.Errorf("%q is in the required set, but crun and runc are an either/or — "+
				"requiring one reports a working host as broken", h)
		}
	}
}

// The OCI runtime is ONE row, and which binary it names is a question about
// this host's cgroups rather than about which files exist. Listing crun and
// runc side by side printed runc's path beside a 📍 on a host where
// ociRuntimeMissing had already ruled it out — every container inside a
// container, where preflight P5 selects cgroups=disabled and podman answers
// the create with 500 `requested OCI runtime runc is not compatible with
// NoCgroups`.
func TestTheOCIRuntimeRowNamesTheRuntimeThatWillActuallyServe(t *testing.T) {
	for _, tc := range []struct {
		name             string
		crun, runc       string
		cgroupsDisabled  bool
		wantName, wantIn string
		wantNoteEmpty    bool
	}{
		{name: "crun wins wherever it is present", crun: "/usr/bin/crun", runc: "/usr/bin/runc",
			wantName: "crun", wantIn: "/usr/bin/crun", wantNoteEmpty: true},
		{name: "crun wins even with cgroups disabled", crun: "/usr/bin/crun", cgroupsDisabled: true,
			wantName: "crun", wantIn: "/usr/bin/crun", wantNoteEmpty: true},
		{name: "runc alone serves where cgroups are usable", runc: "/usr/bin/runc",
			wantName: "runc", wantIn: "cgroups are usable"},
		// THE ONE THAT MATTERS: runc is present, so a bare existence check
		// says the host is fine, and the run then fails at create.
		{name: "runc alone cannot serve where cgroups are disabled", runc: "/usr/bin/runc",
			cgroupsDisabled: true, wantName: "runc", wantIn: "CANNOT serve here"},
		{name: "neither gets no row at all", wantName: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, path, note := ociRuntimeRow(tc.crun, tc.runc, tc.cgroupsDisabled)
			if name != tc.wantName {
				t.Fatalf("row names %q, want %q", name, tc.wantName)
			}
			if name == "" {
				return
			}
			if tc.wantNoteEmpty {
				if note != "" {
					t.Errorf("note = %q, want none — crun serves everywhere and a line saying so "+
						"is a line to read", note)
				}
				if path != tc.wantIn {
					t.Errorf("path = %q, want %q", path, tc.wantIn)
				}
				return
			}
			if !strings.Contains(note, tc.wantIn) {
				t.Errorf("note = %q, want it to contain %q", note, tc.wantIn)
			}
		})
	}
}
