package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── regression tests for loadHostClaudeSettings' non-regular-file handling ───
//
// Both defects here were in the FIRST version of loadHostClaudeSettings, which
// did `os.Stat(path)` on the PATH and then `os.ReadFile(path)`, and both
// falsified the doc comment three paragraphs up ("EVERY FAILURE DEGRADES TO
// carry nothing... none of them may fail the run"):
//
//   - a FIFO at this path made os.ReadFile block in open(2) forever, waiting
//     for a writer that never came — no sandbox, no exit code, no message on
//     any screen. Strictly worse than the fatal error the degradation rule
//     forbids.
//   - os.Stat follows symlinks and reports st_size, which a symlink to
//     /dev/zero or anything under /proc reports as 0 regardless of how much
//     data is actually there — so the size check that was supposed to be the
//     cap did nothing, and the process read an unbounded amount into memory
//     (measured: 3.1 GB and climbing in two seconds against /dev/zero).
//
// The fix opens with O_NONBLOCK, stats the DESCRIPTOR rather than the path,
// refuses anything that is not IsRegular, and reads through
// io.LimitReader(f, maxBytes+1) rather than trusting st_size. These tests are
// what would have caught the two defects before they shipped.

// TestLoadHostClaudeSettingsFIFODoesNotHang is the regression test for the
// hang. mkfifo with no writer on the other end is exactly the shape that made
// the pre-fix os.ReadFile block forever; a DEADLINE is load-bearing here,
// because the failure mode this guards against is the test process itself
// hanging, not a returned error — a version of this test with no deadline
// would simply never finish, which `go test`'s own timeout would eventually
// catch as a much less legible failure far from its cause.
func TestLoadHostClaudeSettingsFIFODoesNotHang(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	type result struct {
		raw      map[string]any
		degraded string
	}
	done := make(chan result, 1)
	go func() {
		raw, degraded := loadHostClaudeSettings(path, "~/.claude/settings.json", 1<<20)
		done <- result{raw, degraded}
	}()

	select {
	case r := <-done:
		if r.raw != nil {
			t.Errorf("a FIFO produced a non-nil settings map: %+v", r.raw)
		}
		if r.degraded == "" {
			t.Error("a FIFO at this path produced no degradation message — the human has no " +
				"way to know why their settings did not carry")
		}
		if !strings.Contains(r.degraded, path) && !strings.Contains(r.degraded, "settings.json") {
			t.Errorf("the degradation message does not name the path: %q", r.degraded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loadHostClaudeSettings did not return within 5s for a FIFO with no writer — " +
			"this is the exact hang the O_NONBLOCK fix exists to prevent; os.ReadFile blocked " +
			"in open(2) forever, with no sandbox started, no exit code, and nothing on any screen")
	}
}

// TestLoadHostClaudeSettingsBoundsAReadEvenWhenSizeLies is the regression test
// for the unbounded read. /proc/self/environ is the portable, in-repo
// stand-in for the red team's /dev/zero symlink: both report st_size == 0
// via stat while actually containing data, so a cap that trusts st_size does
// nothing for either. /dev/zero is unbounded and this test cannot run it to
// completion without reintroducing the hazard it is meant to catch; environ
// is finite, which is what makes it possible to run this without a device
// node and without the test itself risking a multi-gigabyte read if the fix
// regresses — the assertion below is what catches that regression instead.
func TestLoadHostClaudeSettingsBoundsAReadEvenWhenSizeLies(t *testing.T) {
	if fi, err := os.Stat("/proc/self/environ"); err != nil {
		t.Skip("no /proc/self/environ on this host to use as the stand-in")
	} else if fi.Size() != 0 {
		t.Skip("/proc/self/environ does not stat as 0 bytes on this host; the premise this " +
			"test's stand-in relies on does not hold here")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.Symlink("/proc/self/environ", path); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// A cap far smaller than /proc/self/environ's real content (a test binary's
	// environment is at minimum a few hundred bytes: PATH, HOME, and whatever
	// go test itself sets). If st_size (0) were trusted, this would sail past
	// the size check exactly the way the red team's /dev/zero case did.
	const maxBytes = 8

	type result struct {
		raw      map[string]any
		degraded string
	}
	done := make(chan result, 1)
	go func() {
		raw, degraded := loadHostClaudeSettings(path, "~/.claude/settings.json", maxBytes)
		done <- result{raw, degraded}
	}()

	select {
	case r := <-done:
		if r.raw != nil {
			t.Errorf("a file whose real content is over the cap produced a non-nil settings "+
				"map: %+v", r.raw)
		}
		if r.degraded == "" {
			t.Fatal("no degradation message at all — the read either silently truncated or " +
				"silently carried everything, both of which are the defect this test guards " +
				"against")
		}
		// The message this test is really pinning: a size-based degradation
		// message that quotes the LYING stat size (0) is proof the cap fired on
		// the actual bytes read, not on st_size — see loadHostClaudeSettings'
		// "the real cap" branch.
		if !strings.Contains(r.degraded, "0") {
			t.Errorf("the degradation message does not read as the size-lie branch (expected "+
				"the reported size, 0, to appear in it): %q", r.degraded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loadHostClaudeSettings did not return within 5s for a file whose stat lies " +
			"about its size — the read is supposed to be bounded by maxBytes+1 regardless of " +
			"st_size, and a hang here means it is not")
	}
}

// TestLoadHostClaudeSettingsRefusesADirectory is a control for the IsRegular
// check: a directory at this path must degrade, not error out of the run and
// not somehow get treated as an empty file.
func TestLoadHostClaudeSettingsRefusesADirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	raw, degraded := loadHostClaudeSettings(path, "~/.claude/settings.json", 1<<20)
	if raw != nil {
		t.Errorf("a directory produced a non-nil settings map: %+v", raw)
	}
	if degraded == "" {
		t.Error("a directory at this path produced no degradation message")
	}
	if !strings.Contains(degraded, "not a regular file") {
		t.Errorf("the degradation message does not say WHY: %q", degraded)
	}
}

// TestLoadHostClaudeSettingsReadsAnOrdinaryFile is the positive control every
// negative above needs: without it, a version of loadHostClaudeSettings that
// refuses EVERYTHING (including an ordinary file) would pass every test in
// this file.
func TestLoadHostClaudeSettingsReadsAnOrdinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, degraded := loadHostClaudeSettings(path, "~/.claude/settings.json", 1<<20)
	if degraded != "" {
		t.Fatalf("an ordinary, well-formed settings file produced a degradation message: %q", degraded)
	}
	if got, ok := raw["theme"]; !ok || got != "dark" {
		t.Fatalf("an ordinary settings file was not read correctly: %+v", raw)
	}
}

// TestLoadHostClaudeSettingsAbsentFileIsSilent is the control for the "absent
// file needs no line" rule stated in stageClaudeSettings' own doc comment: a
// host that has never run Claude Code must get no degradation message at all.
func TestLoadHostClaudeSettingsAbsentFileIsSilent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json") // never created

	raw, degraded := loadHostClaudeSettings(path, "~/.claude/settings.json", 1<<20)
	if raw != nil {
		t.Errorf("an absent file produced a non-nil settings map: %+v", raw)
	}
	if degraded != "" {
		t.Errorf("an absent file produced a degradation message %q; a host that has never run "+
			"Claude Code has nothing to be told snug ignored", degraded)
	}
}

// ── the fold onto internal/hostread ─────────────────────────────────────────
//
// loadHostClaudeSettings reads through hostread.Clause. Two things have to hold
// for that to be one read sequence rather than two that agree today.

// TestClaudeSettingsMessagesAreOneSentence makes the composition ruling
// checkable. hostread returns a bare clause and this site supplies the subject,
// so `<label> <clause>` must read as one sentence — the failure it prevents is
// a second subject arriving in the middle, which is what hostread.Optional's
// pronoun produces when a caller has already named the file:
//
//	the host's installed_plugins.json it is not a regular file
//
// That sentence is what kept a second copy of the read sequence alive here.
func TestClaudeSettingsMessagesAreOneSentence(t *testing.T) {
	const label = "~/.claude/settings.json"
	dir := t.TempDir()

	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, path string
		max        int64
	}{
		{"a FIFO", fifo, 1 << 20},
		{"a directory", dir, 1 << 20},
		{"over the cap", big, 16},
		{"not JSON", bad, 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, degraded := loadHostClaudeSettings(tc.path, label, tc.max)
			if raw != nil {
				t.Fatalf("carried %v, want nothing", raw)
			}
			// POSITIVE CONTROL: there IS a message. Without this, every
			// assertion below passes on silence, which is the one outcome the
			// degradation rule forbids for a file that exists and is wrong.
			if degraded == "" {
				t.Fatal("degraded silently, so this test measures nothing")
			}
			rest, ok := strings.CutPrefix(degraded, label+" ")
			if !ok {
				t.Fatalf("the message does not open with the label:\n  %s", degraded)
			}
			// The subject is the label. A pronoun here is a second one.
			if first, _, _ := strings.Cut(rest, " "); first == "it" || first == "It" {
				t.Errorf("the clause supplies its own subject, so the message reads "+
					"%q — two subjects, one sentence. hostread.Clause returns a bare "+
					"clause for exactly this reason; hostread.Optional is the pronoun "+
					"form and is for callers that name no file.", degraded)
			}
			// "carrying nothing" for a read failure, "carries nothing into the
			// sandbox" for the JSON-decode branch, whose sentence is this
			// site's own and deliberately different. The property is that the
			// message states the OUTCOME, not that it uses one spelling.
			if !strings.Contains(degraded, "carrying nothing") &&
				!strings.Contains(degraded, "carries nothing") {
				t.Errorf("the message does not say what snug did about it:\n  %s", degraded)
			}
		})
	}
}

// TestClaudeSettingsHasNoSecondReadSequence is the ratchet. The fold is only
// worth anything while it stays folded, and what would undo it is a plain
// os.ReadFile or os.OpenFile appearing in this file again — the FIFO hang and
// the /dev/zero symlink at the top of this file are both what a raw read here
// buys.
//
// The check is on the FILE rather than on the function: a helper beside
// loadHostClaudeSettings doing its own open is the same defect one identifier
// over.
func TestClaudeSettingsHasNoSecondReadSequence(t *testing.T) {
	const file = "claude.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "os" {
			return true
		}
		switch sel.Sel.Name {
		case "ReadFile", "Open", "OpenFile":
			found = append(found, fmt.Sprintf("%s:%d os.%s",
				file, fset.Position(call.Pos()).Line, sel.Sel.Name))
		}
		return true
	})

	// POSITIVE CONTROL on the detector, against source the test authors: a
	// check that matched nothing would report no raw read and read as proof.
	probe := `package cli
func f(path string) { _, _ = os.ReadFile(path) }`
	pf, perr := parser.ParseFile(token.NewFileSet(), "probe.go", probe, 0)
	if perr != nil {
		t.Fatal(perr)
	}
	hits := 0
	ast.Inspect(pf, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && sel.Sel.Name == "ReadFile" {
					hits++
				}
			}
		}
		return true
	})
	if hits != 1 {
		t.Fatalf("the detector found %d raw reads in a fixture containing exactly one, "+
			"so its verdict on %s means nothing", hits, file)
	}

	if len(found) != 0 {
		t.Errorf("%s reads a host file directly: %v.\n"+
			"       Every host path snug does not own goes through internal/hostread — one "+
			"O_NONBLOCK open, one fstat, one limited read, one post-read cap re-check. A raw "+
			"read here is the FIFO hang and the /dev/zero symlink at the top of this file, "+
			"back at the site that first measured them.", file, found)
	}
}
