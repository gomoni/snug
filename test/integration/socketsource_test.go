//go:build integration

package integration

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDryRunRefusesABindOfASocket is issue #219's second half, end to end and
// on --dry-run specifically.
//
// The decision was explicit that the refusal must be visible on --dry-run and
// not only at launch: --dry-run is the screen a human reads to decide whether
// to trust a run, and a grant that is refused only when the sandbox starts is
// a grant that reads as fine on the artifact people actually look at.
//
// A REAL socket, not a fixture: the check asks the filesystem what is at the
// path (S_IFSOCK) rather than matching path text, so a test that could not
// produce a real socket would not be testing the mechanism. The positive
// controls are the same profile, the same guest path, with a regular FILE and
// then a DIRECTORY at the source — those must resolve cleanly, or the refusal
// is about the path rather than about what is there.
func TestDryRunRefusesABindOfASocket(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("creating the fixture socket: %v", err)
	}
	defer ln.Close()

	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "a-dir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		source  string
		refused bool
	}{
		{"socket", sock, true},
		{"regular file", file, false},
		{"directory", subdir, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := writeProfile(t, "[profile.binder]\n"+
				"description = \"binds one host path\"\n"+
				"ro = [\""+tc.source+":{home}/mounted\"]\n")

			out, code := cli(t, env, "--dry-run", "-p", "binder", proj)

			if !tc.refused {
				if code != 0 {
					t.Fatalf("a bind of a %s was refused (exit %d) — the refusal is supposed to "+
						"be about the source being a SOCKET, and this is not one:\n%s",
						tc.name, code, out)
				}
				if strings.Contains(out, "unix SOCKET") {
					t.Errorf("the socket refusal fired for a %s:\n%s", tc.name, out)
				}
				return
			}

			if code == 0 {
				t.Fatalf("--dry-run accepted a bind whose source is a unix socket. Read-only "+
					"does not restrain a socket — measured in issue #219, a payload enumerated "+
					"the host's ssh-agent and signed with it through this shape:\n%s", out)
			}
			// The screen must SAY it, not merely exit non-zero: a human reading
			// --dry-run to decide whether to trust this run has to see why.
			for _, want := range []string{
				"unix SOCKET",
				"@ssh-agent",     // the narrower thing to select instead
				"NOTE THE LIMIT", // and what this check does not cover
				"DIRECTORY",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the --dry-run refusal does not mention %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestABindOfADirectoryHoldingASocketIsStillAccepted is the limit, asserted
// rather than left to prose.
//
// This is the case the check does NOT cover: a stat at resolve time sees only
// sockets that exist then, and a grant of a DIRECTORY is a grant of every
// socket anyone puts in it afterwards. The refusal text says so, the doc
// comment says so, and this test pins it so that the day someone closes the
// gap they have to come here and change a test that states the old behaviour —
// rather than discovering years later that "sockets are refused" was half true.
//
// It is deliberately NOT phrased as an approval of the gap. A check that
// silently covers half its rule is this project's most-repeated defect, and the
// counter-measure is that the half it does not cover is written down in the
// three places a reader might look.
func TestABindOfADirectoryHoldingASocketIsStillAccepted(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	dir := t.TempDir()
	inner := filepath.Join(dir, "holder")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(inner, "agent.sock"))
	if err != nil {
		t.Fatalf("creating the fixture socket: %v", err)
	}
	defer ln.Close()

	env := writeProfile(t, "[profile.binder]\n"+
		"description = \"binds a directory that holds a socket\"\n"+
		"ro = [\""+inner+":{home}/mounted\"]\n")

	out, code := cli(t, env, "--dry-run", "-p", "binder", proj)
	if code != 0 {
		t.Fatalf("a bind of a DIRECTORY containing a socket was refused (exit %d). That is not "+
			"today's behaviour and not what the refusal claims: it checks the SOURCE, and a "+
			"directory is not a socket. If this was closed deliberately, this test and the "+
			"three places that state the limit all need updating together:\n%s", code, out)
	}
	if strings.Contains(out, "unix SOCKET") {
		t.Errorf("the socket refusal fired for a directory:\n%s", out)
	}
}
