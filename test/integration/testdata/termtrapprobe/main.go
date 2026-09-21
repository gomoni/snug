// Command termtrapprobe is a from-scratch container's entrypoint that INSTALLS
// a SIGTERM handler (issue #174), as opposed to holder next door, which
// installs none and so relies on a container runtime's pid-1 signal semantics
// (signal(7): a process running as pid 1 of its own pid namespace ignores any
// signal for which it has not registered a handler, even one whose default
// action is termination) to survive a stop it should not receive.
//
// It exists to tell apart two things that otherwise look identical from the
// host: a container that EXITED, and a container that received a SPECIFIC
// signal and chose to act on it. holder cannot make that distinction — with no
// handler installed for anything, it never exits on its own, so its absence
// after a test only proves *something* killed it (the pid-namespace collapse
// behind a SIGKILL, and a graceful stop, look the same from outside). This
// probe instead writes a marker to disk the moment ITS TERM HANDLER RUNS,
// which happens only when the process is actually delivered a SIGTERM while
// still alive to run Go code — never on a SIGKILL, and never on the pid
// namespace simply collapsing out from under it.
//
// Usage: termtrapprobe TOKEN FLAGDIR
//
// Prints "TRAPPING <TOKEN>" and then waits for either SIGTERM or holdFor to
// elapse. On SIGTERM it writes FLAGDIR/<TOKEN>.stopped and exits 0
// immediately — no extra sleep — so a graceful stop is fast, matching #174's
// own measurement of a TERM-handling pid 1 (134ms). FLAGDIR is expected to be
// a bind mount the host can also read, since the token file is the only
// evidence this process leaves behind once its pid namespace is gone.
//
// holdFor bounds the wait so that a test which fails before its own cleanup
// runs cannot leave a container holding a namespace on the developer's
// machine indefinitely — the same reasoning holder's own doc comment gives.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const holdFor = 5 * time.Minute

func main() {
	token := "no-token"
	flagDir := ""
	if len(os.Args) > 1 {
		token = os.Args[1]
	}
	if len(os.Args) > 2 {
		flagDir = os.Args[2]
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)

	fmt.Printf("TRAPPING %s\n", token)
	os.Stdout.Sync()

	select {
	case <-term:
		path := filepath.Join(flagDir, token+".stopped")
		// The write failing is not this process's problem to solve — a test
		// that expected the flag will fail its own read, with the flag dir
		// argument it passed in the message. Best-effort exactly like
		// holder's own os.Stdout.Sync().
		_ = os.WriteFile(path, []byte("STOPPED "+token+"\n"), 0o644)
		fmt.Printf("STOPPED %s\n", token)
		os.Stdout.Sync()
	case <-time.After(holdFor):
	}
}
