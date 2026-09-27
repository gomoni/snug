package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A name a builtin profile writes is snug's, and a human profile may not
// declare a type for it, even one that agrees with the roster. A name snug
// merely knows about (LD_AUDIT carries a warning note, no roster row, no
// builtin writer) stays declarable: snug refuses what contradicts it, not every
// configuration that could be written wrongly.
func TestDeclaringANameABuiltinWritesIsRefused(t *testing.T) {
	builtins, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	written := builtinEnvWriters(builtins)
	if written["XDG_CONFIG_HOME"] != "@home" {
		t.Fatalf("fixture drifted: @home no longer writes XDG_CONFIG_HOME (writers: %v)", written)
	}

	load := func(t *testing.T, body string) (Registry, []BadFile) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "p.toml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		reg, bad, err := loadDir(dir, written)
		if err != nil {
			t.Fatal(err)
		}
		return reg, bad
	}

	_, bad := load(t, `
[profile.cfg]
description = "x"
[profile.cfg.environ.types]
XDG_CONFIG_HOME = "path"
[profile.cfg.environ.set]
XDG_CONFIG_HOME = "/opt/cfg"
`)
	if len(bad) != 1 {
		t.Fatalf("declaring XDG_CONFIG_HOME was admitted; want one bad file, got %v", bad)
	}
	for _, want := range []string{"XDG_CONFIG_HOME", "builtin profile @home writes", "p.toml"} {
		if !strings.Contains(bad[0].Err.Error(), want) {
			t.Errorf("refusal %q does not name %q", bad[0].Err, want)
		}
	}

	for _, body := range []string{`
[profile.audit]
description = "x"
[profile.audit.environ.types]
LD_AUDIT = "path-list"
[profile.audit.environ.merge]
LD_AUDIT = ["/opt/audit.so"]
`, `
[profile.py]
description = "x"
[profile.py.environ.types]
PYTHONPATH = "path-list"
[profile.py.environ.merge]
PYTHONPATH = ["/opt/py"]
`} {
		reg, bad := load(t, body)
		if len(bad) != 0 || len(reg) != 1 {
			t.Errorf("declaration of a name no builtin writes was refused: %v", bad)
		}
	}
}
