package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// EVERY CALLER OF ForeignUsernsChild PASSES BWRAP'S USER NAMESPACE, NEVER ITS
// OWN — and this is a source guard because no behavioural test can tell the
// two apart on the arm where it matters.
//
// internal/initwalk's package comment states the rule and the drift condition:
// the identity guard is "this child is in a user namespace that is not
// BWRAP's", and "'Not bwrap's' — not 'not the caller's', and the difference is
// the whole discrimination. In the staged measurement above bwrap ITSELF
// shares P1's user namespace (4026533424) and only the init has its own, so
// with either spelling the test selects the init and skips the process that
// forked it. They stop agreeing the moment bwrap does NOT share the caller's
// user namespace: then every child of bwrap is foreign to the CALLER, the test
// admits all of them, and the first one walked lands in a record
// killOrphanInit later SIGKILLs."
//
// So on the staged arm the two spellings return the SAME pid today, and a test
// that ran the walk would pass with either one. What makes the wrong spelling
// a defect is not today's answer, it is that the answer is correct by a
// coincidence about bwrap rather than by the property being tested. The
// offline arm already learned this: issue #101's F4 changed
// internal/sandbox/initwatch.go's watchForInit from snug's namespace to
// bwrap's, because there bwrap IS foreign to snug and the caller's id admitted
// every child of bwrap. internal/stage/serve.go was the one caller left
// spelling it as the caller's, and it is the line that would turn a future
// intermediate pid namespace on the staged arm into a wrong-process SIGKILL.
//
// The guard is deliberately over a NamespaceInode call in the same function
// rather than over a name: what must not come back is os.Getpid(), whatever
// the surrounding code is called after the next refactor.
func TestEveryForeignUsernsChildCallerPassesBwrapsNamespace(t *testing.T) {
	files := []string{
		filepath.Join("..", "..", "internal", "stage", "serve.go"),
		filepath.Join("..", "..", "internal", "sandbox", "initwatch.go"),
	}

	// The argument to NamespaceInode, up to the comma that ends it.
	call := regexp.MustCompile(`initwalk\.NamespaceInode\(([^,]+),`)

	found := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("control: reading %s: %v — this guard names its files by path and one moved", f, err)
		}
		matches := call.FindAllSubmatch(src, -1)
		if len(matches) == 0 {
			t.Fatalf("control: no initwalk.NamespaceInode call in %s. Either the identity guard moved "+
				"out of this file or it is spelled differently now, and this test is asserting "+
				"nothing about it", f)
		}
		for _, m := range matches {
			found++
			arg := string(m[1])
			if arg == "os.Getpid()" {
				t.Errorf("%s passes os.Getpid() to initwalk.NamespaceInode: that is the CALLER's user "+
					"namespace, and the identity guard needs BWRAP's. See internal/initwalk's package "+
					"comment — with the caller's id, every child of bwrap is foreign the moment bwrap "+
					"stops sharing the caller's user namespace, the walk admits all of them, and the "+
					"first one lands in a record killOrphanInit later SIGKILLs. Pass the pid of the "+
					"bwrap whose children are being walked", f)
			}
		}
	}

	// POSITIVE CONTROL: without this, deleting both calls would pass the loop
	// above silently. Two callers exist today, one per arm.
	if found < 2 {
		t.Fatalf("control: found %d NamespaceInode call(s) across %v, expected at least 2 — one per "+
			"arm. A caller was removed, or this guard is no longer reading the files that have them",
			found, files)
	}
}
