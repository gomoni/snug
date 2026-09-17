package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestHostDestExistsIsOnlyEverSetOnAnAccessROMount sweeps the two shipped
// writers that set HostDestExists — stageProjectClaudeSettings and
// stageProjectMCPJSON, both in claude.go — and checks that every mount either
// of them stages with HostDestExists true is AccessRO.
//
// bwrap.go decides how a KindData mount is rendered by its Access alone:
// AccessRW becomes --file, which COPIES onto its destination — the exact host
// write rejectGeneratedOntoHost's ARM 2 exists to refuse — while AccessRO
// becomes --ro-bind-data, which binds over the EXISTING inode rather than
// creating a mountpoint (issue #73). That is what makes HostDestExists's
// carve-out in ARM 2 sound for one and unsound for the other. Not a live hole
// today — both writers pass AccessRO — but the two facts are decided
// independently, at two different call sites, with nothing else tying them
// together; this is the assertion that keeps a future edit to either site
// from drifting AccessRW and HostDestExists onto the same mount.
func TestHostDestExistsIsOnlyEverSetOnAnAccessROMount(t *testing.T) {
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{
		filepath.Join(target, ".claude", "settings.json"),
		filepath.Join(target, ".claude", "settings.local.json"),
		filepath.Join(target, ".mcp.json"),
	} {
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	pol := &policy.Policy{Mounts: map[string]policy.Mount{}, Target: target}
	n := newNotes(io.Discard, false)
	if err := stageProjectClaudeSettings(pol, n); err != nil {
		t.Fatalf("stageProjectClaudeSettings: %v", err)
	}
	if err := stageProjectMCPJSON(pol, n); err != nil {
		t.Fatalf("stageProjectMCPJSON: %v", err)
	}

	swept := 0
	for guest, m := range pol.Mounts {
		if !m.HostDestExists {
			continue
		}
		swept++
		if m.Access != policy.AccessRO {
			t.Errorf("%s: HostDestExists is true and Access is %v, not AccessRO — bwrap renders "+
				"an AccessRW KindData mount as --file, which COPIES onto an existing destination, "+
				"so the carve-out ARM 2 gives HostDestExists would be wrong for this mount",
				guest, m.Access)
		}
	}
	// POSITIVE CONTROL: the three planted files above must all have been
	// staged with HostDestExists set, or the loop above swept nothing and
	// every assertion in it passed vacuously.
	if swept < 3 {
		t.Fatalf("only %d mount(s) carried HostDestExists, want at least 3 (two settings files "+
			"plus .mcp.json) — the fixture files were not staged at all", swept)
	}
}
