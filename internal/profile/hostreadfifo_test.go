package profile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── regression test for issue #337: a profiles.d file read with hostread ────
//
// loadDir used to read each *.toml file in a profiles.d layer with a bare
// os.ReadFile. This is the headline site among the six issue #337 named: it
// is the one where the attacker does not need the HOST USER's own files or
// cooperation at all — $XDG_CONFIG_HOME can point into a checked-out repo
// (CLAUDE.md invariant 3's known gap), and a hostile repo need only ship
// profiles.d/evil.toml as a FIFO. Before the fix that hung `snug profile
// list`, `snug --dry-run` and every real run in open(2) forever — before a
// single profile had loaded, with nothing on screen to say why.
//
// This test pins the property the issue calls out as the one most likely to
// be broken by a later change: a FIFO is ONE FILE'S problem, recorded as a
// BadFile with a named refusal, and the REST OF THE LAYER — including the
// builtins, which are merged in the same Load() call as a separate layer —
// still loads.
func TestProfilesDFIFODoesNotHangAndTheRestOfTheLayerStillLoads(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}

	// Sorted first, so it is reached BEFORE the good file — otherwise this
	// would pass on an implementation that merely finished the loop without
	// ever reaching the FIFO.
	fifoPath := filepath.Join(pd, "a-evil.toml")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Skipf("SKIP: cannot create a FIFO here: %v", err)
	}
	write(t, filepath.Join(pd, "b-fine.toml"), "[profile.mine]\nro = [\"/opt\"]\n")
	t.Setenv("XDG_CONFIG_HOME", dir)

	type result struct {
		reg Registry
		bad []BadFile
		err error
	}
	done := make(chan result, 1)
	go func() {
		reg, bad, err := Load()
		done <- result{reg, bad, err}
	}()

	var r result
	select {
	case r = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Load did not return within 5s with a FIFO in profiles.d — this is the exact " +
			"hang issue #337 measured: open(2) blocking forever, before a single profile has " +
			"loaded, with nothing on any screen to explain why")
	}

	if r.err != nil {
		t.Fatalf("Load returned a hard error for one unreadable file: %v", r.err)
	}

	// The named refusal: recorded as this file's problem, naming the path and
	// the node type, not a hang and not a bare "read error".
	if len(r.bad) != 1 {
		t.Fatalf("bad = %+v, want exactly the one file that could not be read", r.bad)
	}
	if !strings.HasSuffix(r.bad[0].Path, "a-evil.toml") {
		t.Errorf("bad file recorded is %q, want a-evil.toml", r.bad[0].Path)
	}
	if r.bad[0].Err == nil || !strings.Contains(r.bad[0].Err.Error(), "not a regular file") {
		t.Errorf("the recorded error does not say what was wrong with the file: %v", r.bad[0].Err)
	}
	if r.bad[0].Err == nil || !strings.Contains(r.bad[0].Err.Error(), fifoPath) {
		t.Errorf("the recorded error does not name the path: %v", r.bad[0].Err)
	}

	// POSITIVE CONTROL, and it is the whole point: the rest of the layer —
	// builtins AND the good custom file in the SAME directory — must still be
	// there. Without these assertions the test would pass on a Load that
	// refused to load anything at all once it hit the FIFO.
	if _, ok := r.reg["@sys"]; !ok {
		t.Error("@sys is missing: the FIFO in profiles.d took down the builtins too")
	}
	if _, ok := r.reg["mine"]; !ok {
		t.Error("the good file in the same directory did not load: the loop stopped at the FIFO " +
			"instead of continuing past it")
	}
}

// TestProfilesDOversizedFileIsRefusedOnTheCap is the cap half of the same
// site: a file that opens and stats fine but whose content is over
// maxProfileFileBytes must be refused for exceeding the cap, not read whole
// into memory.
func TestProfilesDOversizedFileIsRefusedOnTheCap(t *testing.T) {
	dir := t.TempDir()
	pd := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}

	// A well-formed TOML comment padded past the cap, so a failure here is
	// legibly about SIZE rather than about a parse error the padding could
	// otherwise cause.
	oversized := "# " + strings.Repeat("A", maxProfileFileBytes) + "\n[profile.mine]\nro = [\"/opt\"]\n"
	if len(oversized) <= maxProfileFileBytes {
		t.Fatalf("fixture is %d bytes, not over the %d-byte cap", len(oversized), maxProfileFileBytes)
	}
	write(t, filepath.Join(pd, "oversized.toml"), oversized)
	t.Setenv("XDG_CONFIG_HOME", dir)

	reg, bad, err := Load()
	if err != nil {
		t.Fatalf("Load returned a hard error for one oversized file: %v", err)
	}
	if len(bad) != 1 {
		t.Fatalf("bad = %+v, want exactly the one oversized file", bad)
	}
	if bad[0].Err == nil || !strings.Contains(bad[0].Err.Error(), "cap") {
		t.Errorf("the recorded error does not say the file exceeded the cap: %v", bad[0].Err)
	}
	if _, ok := reg["mine"]; ok {
		t.Error("a profile from the oversized file made it into the registry")
	}
	if _, ok := reg["@sys"]; !ok {
		t.Error("@sys is missing: the oversized file took down the builtins too")
	}
}
