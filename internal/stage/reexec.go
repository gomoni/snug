package stage

import "syscall"

// execSelf re-execs THIS SAME PROCESS IMAGE as /proc/self/exe, never a path
// taken from the environment or argv[0] — the previous generation's review
// found exactly that shape ($NSD_SELF) to be a same-uid replacement window.
// The environment is always empty: nothing __stage-setup, __stage-serve or __innetns do
// next needs anything from the host's, and CLAUDE.md's "/proc/1/environ leaked
// everything" lesson applies one layer up from where it was found — a process
// that joins the sandbox's namespaces is a process whose OWN /proc/<pid>/
// exposure is worth asking about.
func execSelf(verb string, extraArgv ...string) error {
	argv := append([]string{"snug", verb}, extraArgv...)
	return syscall.Exec("/proc/self/exe", argv, []string{})
}
