package profile

import (
	"strings"
	"testing"
)

// nscdSockets is nscd's own request socket, under both spellings glibc's
// nss_nscd module tries (issue #612's residual): if a profile bound either,
// nscd could answer getpwuid()/getgrgid() AHEAD of the generated /etc/passwd
// and /etc/group, with the host's own account data. None of this is reachable
// from inside the sandbox on any profile snug ships — this test is the
// regression that keeps it that way, because "by construction" for the
// generated files holds only as long as nothing answers first.
var nscdSockets = []string{"/run/nscd", "/var/run/nscd"}

// guestOf mirrors internal/policy's splitSpec well enough for a static string
// scan: "path" or "host:guest", first ':' wins. None of base.toml's grants
// template one of nscdSockets, so no {variable} expansion is needed here — a
// future one would still be caught, because the raw spec string carries the
// literal path either side of the colon.
func guestOf(spec string) string {
	if _, g, ok := strings.Cut(spec, ":"); ok {
		return g
	}
	return spec
}

// TestNoBuiltinGrantsTheNscdSocket pins the residual issue #612 leaves: the
// generated /etc/passwd and /etc/group answer getpwuid()/getgrgid() only
// while glibc's `files`/`compat` NSS modules ask first. A profile granting
// nscd's request socket would let it answer ahead of them instead — this
// test fails the moment a builtin does.
func TestNoBuiltinGrantsTheNscdSocket(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatalf("Builtins(): %v", err)
	}
	for name, p := range reg {
		for _, list := range [][]string{p.RO, p.RW, p.Optional} {
			for _, spec := range list {
				guest := guestOf(spec)
				for _, sock := range nscdSockets {
					if guest == sock || strings.HasPrefix(guest, sock+"/") {
						t.Errorf("profile %s grants %q, which reaches the nscd socket %q",
							name, spec, sock)
					}
				}
			}
		}
		for _, s := range p.Symlink {
			for _, sock := range nscdSockets {
				if s.At == sock || strings.HasPrefix(s.At, sock+"/") {
					t.Errorf("profile %s symlinks %q, which reaches the nscd socket %q",
						name, s.At, sock)
				}
			}
		}
	}
}
