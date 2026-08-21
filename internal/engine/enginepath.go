package engine

// enginepath.go holds the engine's PATH and the check that it means what it
// says in the engine's OWN mount view.
//
// WHY THE CHECK EXISTS SEPARATELY FROM THE PIN. Spec has pinned the value since
// issue #125's C2-path: the engine is root-in-U with CAP_SYS_ADMIN and the full
// delegated subuid range, so a writable directory in front of `crun` is the
// payload choosing what the engine executes. Pinning a literal answers "whose
// PATH is it"; it does not answer "is /usr/bin read-only in the namespace the
// engine will actually resolve it in", and that second question is about this
// run's resolved policy — a profile granting {home} over /usr, a graft landing
// on top of one of these four — not about the literal. Tier C's derived view is
// what makes the question askable at all: before it, the engine's namespace was
// a private copy of the HOST tree and no Policy described it, so there was
// nothing to ask.
//
// It is a REFUSAL, unlike the sandbox-side IsShadowSlot caller, and the
// difference is deliberate. IsShadowSlot's own doc comment says it "is NOT a
// refusal, and must not become one without a decision", because a human's own
// profile putting a writable directory on the PAYLOAD's PATH is their
// declaration to make. The engine's PATH is not theirs to declare: no profile
// authors it, snug pins it, and the process that resolves it holds capabilities
// no payload has. So "snug ships that slot pre-installed" — the one thing that
// comment says must never happen — is the only way this can fire.

import (
	"fmt"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// PinnedPATH is the engine's PATH, exported so the sweep in
// enginepath_test.go reads the value Spec really sets rather than a copy of it
// beside the code — a second literal would agree with the first until the day
// somebody changed one.
//
// /bin and /sbin are @sys's own symlinks into /usr, so all four elements
// resolve inside the same read-only bind.
const PinnedPATH = "/usr/bin:/usr/sbin:/bin:/sbin"

// checkEnginePATH refuses to build a spec whose PATH has a writable element in
// the engine's derived view.
//
// The view must EXIST: Spec is reached only after Engine.GraftInto has recorded
// this run's store, runroot, socket and config grafts, and installEngineViewGrafts
// has recorded the engine's own /proc, /sys/fs/cgroup, /var/tmp and /run before
// that. A Policy with no grafts at this point is a caller that skipped one of
// them, and answering "no slots" about a view nothing modelled is the shape
// CLAUDE.md names as documented-but-not-implemented — so it is an error with the
// missing call in it, not a silent pass.
func checkEnginePATH(pol *policy.Policy) error {
	view, ok := pol.EngineView()
	if !ok {
		return fmt.Errorf("the engine's PATH cannot be checked: this policy models no grafts, so "+
			"there is no engine view to resolve %s in.\n"+
			"       Engine.GraftInto must run before Spec — it is what records this run's store, "+
			"runroot, socket and config grafts, and the check below is the reason the order "+
			"matters rather than merely being conventional.", PinnedPATH)
	}
	if elem, bad := firstShadowSlot(view, PinnedPATH); bad {
		return fmt.Errorf("the container engine's PATH element %q is WRITABLE in the engine's "+
			"own mount view.\n"+
			"       The engine runs as root in the sandbox's user namespace with the full "+
			"delegated subuid range, so a writable directory ahead of crun on its PATH is the "+
			"payload choosing what the engine executes as root.\n"+
			"       PATH is snug's own (%s) and no profile authors it, so this means a grant "+
			"or a graft in this run's policy landed on top of it. Run 'snug --dry-run' and "+
			"look for a writable mount covering %s.", elem, PinnedPATH, elem)
	}
	return nil
}

// firstShadowSlot is the sweep, separated from the refusal so a test can feed
// it a PATH that is not snug's — which is the positive control the assertion
// needs: a sweep that has never returned true about anything is a sweep that
// might be answering "no" for the wrong reason.
//
// AN EMPTY ELEMENT IS A SLOT WITHOUT ASKING THE VIEW, and it is not a
// hypothetical: POSIX reads "" as the current directory, `PATH=/usr/bin:`
// and a leading or doubled colon all produce one, and the engine's current
// directory is not a path any View can resolve — so the view would answer
// "not a slot" about the one element whose meaning depends on where the
// process happens to stand. The measurement in Spec's own comment found an
// empty element in the development host's PATH.
func firstShadowSlot(view policy.View, path string) (string, bool) {
	for _, elem := range strings.Split(path, ":") {
		if elem == "" {
			return elem, true
		}
		if view.IsShadowSlot(elem) {
			return elem, true
		}
	}
	return "", false
}
