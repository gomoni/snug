//go:build integration

package integration

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestDryRunRefusesABindOfAnEndpoint is issues #219 and #287's second half,
// end to end and on --dry-run specifically.
//
// The decision was explicit that the refusal must be visible on --dry-run and
// not only at launch: --dry-run is the screen a human reads to decide whether
// to trust a run, and a grant that is refused only when the sandbox starts is
// a grant that reads as fine on the artifact people actually look at.
//
// REAL fixtures, not mocks: the check asks the filesystem what is at the path
// (S_IFSOCK / S_IFIFO) rather than matching path text, so a test that could
// not produce a real socket and a real FIFO would not be testing the
// mechanism. The positive controls are the same profile, the same guest path,
// with a regular FILE and then a DIRECTORY at the source — those must resolve
// cleanly, or the refusal is about the path rather than about what is there.
func TestDryRunRefusesABindOfAnEndpoint(t *testing.T) {
	budget(t, 60*time.Second)
	proj, _ := target(t)

	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("creating the fixture socket: %v", err)
	}
	defer ln.Close()

	fifo := filepath.Join(dir, "agent.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("creating the fixture FIFO: %v", err)
	}

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
		noun    string
		refused bool
	}{
		{"socket", sock, "unix SOCKET", true},
		{"fifo", fifo, "FIFO", true},
		{"regular file", file, "", false},
		{"directory", subdir, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := writeProfile(t, "[profile.binder]\n"+
				"description = \"binds one host path\"\n"+
				"ro = [\""+tc.source+":{home}/mounted\"]\n")

			out, code := cli(t, env, "--dry-run", "-p", "binder", proj)

			if !tc.refused {
				if code != 0 {
					t.Fatalf("a bind of a %s was refused (exit %d) — the refusal is supposed to "+
						"be about the source being an endpoint, and this is not one:\n%s",
						tc.name, code, out)
				}
				if strings.Contains(out, "unix SOCKET") || strings.Contains(out, "FIFO") {
					t.Errorf("the endpoint refusal fired for a %s:\n%s", tc.name, out)
				}
				return
			}

			if code == 0 {
				t.Fatalf("--dry-run accepted a bind whose source is a %s. Read-only does not "+
					"restrain an endpoint — measured for a socket (issue #219, a payload "+
					"enumerated and signed with the host's ssh-agent) and for a FIFO (issue #287, "+
					"a payload wrote through it and a host reader received the bytes):\n%s",
					tc.name, out)
			}
			// The screen must SAY it, not merely exit non-zero: a human reading
			// --dry-run to decide whether to trust this run has to see why.
			for _, want := range []string{
				tc.noun,
				`ssh_mode = "agent-proxy"`, // the narrower thing to select instead. Issue #289: an
				// earlier version of this message named the nonexistent '@ssh-agent', and this
				// test asserted THAT string — which is why it kept passing after #289 broke the
				// message it was meant to be verifying end to end.
				"NOTE THE LIMIT", // and what this check does not cover
				"DIRECTORY",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("the --dry-run refusal for a %s does not mention %q:\n%s", tc.name, want, out)
				}
			}
			if strings.Contains(out, "@ssh-agent") {
				t.Errorf("the --dry-run refusal names '@ssh-agent', a profile snug does not ship "+
					"(issue #289):\n%s", out)
			}
		})
	}
}

// TestABindOfADirectoryHoldingAnEndpointIsStillAccepted is the limit, asserted
// rather than left to prose.
//
// This is the case the check does NOT cover: a stat at resolve time sees only
// endpoints that exist then, and a grant of a DIRECTORY is a grant of every
// socket AND every FIFO anyone puts in it afterwards. The refusal text says
// so, the doc comment says so, and this test pins it so that the day someone
// closes the gap they have to come here and change a test that states the old
// behaviour — rather than discovering years later that "endpoints are
// refused" was half true. TestAFifoInAGrantedDirectoryStillReachesTheHost
// (fiforesidual_test.go) is this same gap's REAL-WORLD residual, measured
// through the default profile selection rather than through --dry-run alone.
//
// It is deliberately NOT phrased as an approval of the gap. A check that
// silently covers half its rule is this project's most-repeated defect, and
// the counter-measure is that the half it does not cover is written down in
// the three places a reader might look.
func TestABindOfADirectoryHoldingAnEndpointIsStillAccepted(t *testing.T) {
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
	if err := syscall.Mkfifo(filepath.Join(inner, "agent.fifo"), 0o600); err != nil {
		t.Fatalf("creating the fixture FIFO: %v", err)
	}

	env := writeProfile(t, "[profile.binder]\n"+
		"description = \"binds a directory that holds a socket and a fifo\"\n"+
		"ro = [\""+inner+":{home}/mounted\"]\n")

	out, code := cli(t, env, "--dry-run", "-p", "binder", proj)
	if code != 0 {
		t.Fatalf("a bind of a DIRECTORY containing a socket and a FIFO was refused (exit %d). "+
			"That is not today's behaviour and not what the refusal claims: it checks the "+
			"SOURCE, and a directory is not an endpoint. If this was closed deliberately, this "+
			"test and the three places that state the limit all need updating together:\n%s",
			code, out)
	}
	if strings.Contains(out, "unix SOCKET") || strings.Contains(out, "FIFO") {
		t.Errorf("the endpoint refusal fired for a directory:\n%s", out)
	}
}
