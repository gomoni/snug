package cli

import "fmt"

// reportExec is how snug turns one helper's argv[0] into a binary, and it is
// the fact under BOTH renderers' argv blocks. One producer, two printers, the
// arrangement grantMark/envGrantVerdict already uses.
//
// Issue #332 gave `pasta.argv[0]` the literal string "pasta" by copying
// jsonBwrap.Argv[0]'s reasoning, which is an argument about GOLDEN FIXTURES
// (a resolved path is host-dependent and would put a per-developer value into
// a committed file) and not about what the artifact claims. --dry-run's rule is
// that it states what will be EXECUTED, and on both helpers the bare word is
// not that.
//
// MEASURED, in the two files that start them:
//
//	internal/sandbox/exec.go:121   bwrap, err := exec.LookPath("bwrap")
//	                        :303   cmd := exec.Command(bwrap, argv...)
//	internal/sandbox/netns.go:93   pasta, err := exec.LookPath("pasta")
//	                         :102  cmd := exec.Command(pasta, args...)
//
// exec.Command sets Args[0] to the string it is handed, and it is handed
// LookPath's answer, so the argv[0] the kernel actually sees is an ABSOLUTE
// PATH in both cases — never the bare word either renderer prints. Nor is the
// search the kernel's: snug performs it itself, from snug's own environment,
// which is the HOST user's $PATH and has nothing to do with the sandbox's
// cleared one.
//
// So neither renderer can state what will be executed, and the honest artifact
// says so rather than printing a word that looks like an answer. Resolving at
// dry-run time and printing the path was rejected twice over: it makes every
// golden host-dependent (the trap issues #301 and #320 both refused), and it
// would still be a claim snug cannot keep, because the resolution that matters
// happens on the next run and not while this artifact is being written.
//
// The trust consequence is worth one sentence on the screen rather than only in
// this comment: a directory earlier on the host user's $PATH than /usr/bin
// chooses the bwrap that builds the sandbox, and that choice is made after
// --dry-run has said everything it has to say.
type reportExec struct {
	// Argv0 is the word both renderers print at index 0. Bare, and the same
	// on both, so a golden diff stays a diff about the argv.
	Argv0 string
	// Resolved is false: the binary is chosen at run time, not now. It is a
	// field rather than an implied constant so a consumer branches on the
	// fact, and so the day snug does resolve one of these the document says
	// it changed.
	Resolved bool
	// Note is the sentence, identical in the JSON document and (wrapped) on
	// the human screen.
	Note string
}

// execResolution is the fact function. Both renderers call it; neither writes
// the sentence itself.
//
// It takes no *policy.Policy, which is why the AST sweep in
// factproducersweep_test.go structurally cannot see it — the sweep's producer
// predicate is "takes the resolved policy". Adding a parameter it does not read
// to be swept would be a lie told to a test, so the agreement between the two
// renderers is checked by EXECUTION instead:
// TestBothRenderersStateTheSameArgv0Resolution drives both and compares the
// strings.
func execResolution(name string) reportExec {
	return reportExec{
		Argv0:    name,
		Resolved: false,
		Note: fmt.Sprintf("argv[0] is the bare name %q and snug does not exec that name: it "+
			"calls exec.LookPath(%q) against the HOST user's own $PATH at the moment the run "+
			"starts, and execs the absolute path that search returns. WHICH %s runs is "+
			"therefore a fact about that $PATH then — a directory earlier on it than /usr/bin "+
			"chooses the binary, after this artifact has said everything it has to say. Settle "+
			"it by hand with: command -v %s", name, name, name, name),
	}
}
