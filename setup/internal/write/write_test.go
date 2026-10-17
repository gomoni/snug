package write

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLineDiff(t *testing.T) {
	if got := LineDiff("a\nb\n", "a\nc\n"); got != "- b\n+ c" {
		t.Errorf("%q", got)
	}
	if got := LineDiff("", "x\n"); got != "+ x" {
		t.Errorf("%q", got)
	}
	if got := LineDiff("a\n", "a\n"); got != "(no line changes)" {
		t.Errorf("%q", got)
	}
	if got := LineDiff("bad\x1b[2J\n", ""); got != "- bad[2J" {
		t.Errorf("escape reached the diff: %q", got)
	}
}

func TestReadProfileRefusesFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f.toml")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	if _, _, err := ReadProfile(p); err == nil {
		t.Errorf("a FIFO was read")
	}
	if _, exists, err := ReadProfile(p + ".none"); exists || err != nil {
		t.Errorf("missing file: %v %v", exists, err)
	}
}

func TestWriteProfileNewIsExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "x.toml")
	if err := WriteProfile(p, "one", false); err != nil {
		t.Fatal(err)
	}
	if err := WriteProfile(p, "two", false); err == nil {
		t.Errorf("replaced an existing file without overwrite")
	}
	if err := WriteProfile(p, "two", true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Errorf("%q", b)
	}
}
