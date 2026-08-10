// Command nsd is a proof of concept for snug's fork-exec supervisor model.
//
// The model under test:
//
//	P0  nsd up            host process; creates the stage, writes its uid maps,
//	                      runs pasta against it, then gets out of the way
//	P1  nsd __stage1      owns U (user namespace, full subuid map) + N (network
//	                      namespace) + a private mount namespace + a cgroup
//	                      namespace. Serves a control socket on the HOST
//	                      filesystem. Never exposed inside a sandbox.
//	P2  bwrap             child of P1: inherits U and N by descent, creates the
//	                      sandbox's own mount/pid/ipc/uts namespaces on top.
//	P2' engine stage      a different child of P1: inherits U and N, but takes a
//	                      private copy of the HOST mount tree instead.
//	P3  payload           child of P2, or a later process injected into P2's
//	                      namespaces by P1 (the "attach" path).
//
// Nothing here is production code. It exists to answer questions by execution.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "ctl":
		err = cmdCtl(os.Args[2:])
	case "__stage0":
		err = stage0()
	case "__stage1":
		err = stage1()
	case "__sandbox-init":
		err = sandboxInit()
	case "probe":
		err = cmdProbe(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "nsd: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  nsd up --run DIR [--net] [--bind DIR]     start the supervisor (P1), stay in foreground
  nsd ctl DIR OP [args...]                  talk to a running supervisor
  nsd probe                                 print namespace ids, uid, caps of the calling process
`)
	os.Exit(2)
}
