package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestDryRunStatesTheTmpfsBound is the human-screen half of issue #281's
// disclosure requirement: --dry-run is CLAUDE.md's stated mechanism for a
// human to trust snug at all, and a tmpfs a payload could fill without this
// line is exactly the kind of unstated capability that mechanism exists to
// surface.
func TestDryRunStatesTheTmpfsBound(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@parent-ro"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.TmpfsSizeBytes == 0 {
		t.Fatal("the resolved policy carries no tmpfs bound at all, so this test measures nothing")
	}
	got := dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)

	want := "(max " + policy.FormatBytes(p.TmpfsSizeBytes) + ")"
	tmpLine := ""
	roLine := ""
	for _, line := range strings.Split(got, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "tmpfs" && fields[1] == "/tmp" {
			tmpLine = line
		}
		if fields[0] == "ro" && strings.Contains(fields[1], "/usr") {
			roLine = line
		}
	}
	if tmpLine == "" {
		t.Fatalf("no FILESYSTEM row for /tmp found in the rendered screen:\n%s", got)
	}
	if !strings.Contains(tmpLine, want) {
		t.Errorf("the /tmp row does not state its bound (%q):\n%s", want, tmpLine)
	}

	// NEGATIVE, so the assertion above is about tmpfs rows specifically and
	// not about every row growing a "(max ...)" suffix regardless of kind.
	if roLine == "" {
		t.Fatalf("no ro-bind row for /usr found in the rendered screen, so this control measures nothing:\n%s", got)
	}
	if strings.Contains(roLine, "max") {
		t.Errorf("a read-only bind row states a tmpfs bound, which does not apply to it:\n%s", roLine)
	}
}

// TestDryRunJSONCarriesTheTmpfsBound is dryRunStatesTheTmpfsBound's machine-
// format twin: size_bytes must be present and equal to Policy.TmpfsSizeBytes
// on every "kind": "tmpfs" mount, and ABSENT (not zero — omitempty means the
// KEY itself does not appear) on every other kind. The absence half is the one
// a reader gets wrong: a bare 0 on a non-tmpfs row would read as "unbounded"
// rather than "not applicable" (dryrunjson.go's own doc comment on
// jsonMount.SizeBytes).
func TestDryRunJSONCarriesTheTmpfsBound(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var buf bytes.Buffer
	if err := dryRun(newEnvFakeEnv(), &buf, p, p.BwrapArgs(0, 0), config{json: true}, nil, nil); err != nil {
		t.Fatalf("dryRun --json: %v", err)
	}

	var doc struct {
		Mounts []map[string]any `json:"mounts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the JSON renderer did not produce a parseable document: %v", err)
	}
	if len(doc.Mounts) == 0 {
		t.Fatal("the JSON document lists no mounts at all, so this test measures nothing")
	}

	tmpfsSeen, otherSeen := 0, 0
	for _, m := range doc.Mounts {
		kind, _ := m["kind"].(string)
		_, hasSize := m["size_bytes"]
		if kind == "tmpfs" {
			tmpfsSeen++
			raw, ok := m["size_bytes"]
			if !ok {
				t.Errorf("a tmpfs mount %v carries no size_bytes key at all", m["guest"])
				continue
			}
			got, ok := raw.(float64)
			if !ok {
				t.Errorf("size_bytes on %v is not a number: %v", m["guest"], raw)
				continue
			}
			if uint64(got) != p.TmpfsSizeBytes {
				t.Errorf("tmpfs %v carries size_bytes=%v, want %d", m["guest"], raw, p.TmpfsSizeBytes)
			}
		} else {
			otherSeen++
			if hasSize {
				t.Errorf("a %q mount %v carries a size_bytes key, which omitempty should have "+
					"dropped for every non-tmpfs kind: %v", kind, m["guest"], m)
			}
		}
	}
	// POSITIVE CONTROLS for both halves: without these, "every tmpfs carries
	// the key" and "every other kind lacks it" could each be vacuously true of
	// a selection carrying none of one kind or the other.
	if tmpfsSeen == 0 {
		t.Fatal("the JSON document lists no tmpfs mount at all, so the presence half of this test measures nothing")
	}
	if otherSeen == 0 {
		t.Fatal("the JSON document lists no non-tmpfs mount at all, so the absence half of this test measures nothing")
	}
}
