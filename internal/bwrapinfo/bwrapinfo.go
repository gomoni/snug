// Package bwrapinfo owns exactly one thing: the JSON document bwrap writes to
// --info-fd, and the bounded read of it.
//
// It is its own package because TWO processes now read that document, in two
// different topologies, and a format with two parsers is a format with two
// authorities (invariant 6, one layer down):
//
//   - internal/sandbox, on the offline / host-network arm, where P0 forks bwrap
//     itself and holds the read end;
//   - internal/stage, on the staged arm, where P1 forks bwrap and holds the read
//     end — because P1 is the process that must KILL bwrap's init if anything
//     between the fork and the payload's release fails, and it cannot kill a pid
//     it was never told (issue #125, the C2 gate).
//
// What travels back to P0 from the stage is this struct, parsed by the process
// that owns the descriptor — never a pid P0 handed the stage and the stage had
// to trust. See internal/stage/proto.go on that direction.
package bwrapinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Info is bwrap's answer: the pid of the sandbox's own init — a HOST pid, since
// bwrap itself is outside the pid namespace it creates — and the namespace
// inodes it reported.
//
// Namespaces always carries all six keys, even the ones bwrap left out. bwrap
// writes NO "<kind>-namespace" key at all for a namespace it did not itself
// create with its own --unshare-* flag, which json silently zero-values, so a
// key present with the value 0 means "bwrap said nothing", not "namespace 0".
// Recovering a real inode for such a key is a read of /proc/<pid>/ns/<kind> and
// belongs to the caller (internal/sandbox's fillMissingNamespaceIDs); this
// package reports what bwrap said and does not guess.
type Info struct {
	InitPID    int
	Namespaces map[string]uint64
}

// Read decodes one info document from r, bounded by timeout.
//
// json.Decoder.Decode, not ReadAll: Decode stops at one complete JSON value
// rather than waiting for EOF, and every caller keeps its OWN copy of the write
// end open for the life of the run (it is in the descriptor block handed to
// bwrap), so waiting for EOF here would wait forever.
//
// The goroutine+select shape, rather than SetReadDeadline, is the one used
// everywhere else in this tree for a raw inherited descriptor: *os.File wrapping
// a pipe does not reliably support a deadline the way a net.Conn does. A timeout
// leaves the inner goroutine blocked until the caller closes r — which, at both
// call sites, is a process that is about to exit anyway.
func Read(r io.Reader, timeout time.Duration) (Info, error) {
	type result struct {
		info Info
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var raw struct {
			ChildPID int    `json:"child-pid"`
			Mnt      uint64 `json:"mnt-namespace"`
			Pid      uint64 `json:"pid-namespace"`
			Net      uint64 `json:"net-namespace"`
			Ipc      uint64 `json:"ipc-namespace"`
			Uts      uint64 `json:"uts-namespace"`
			Cgroup   uint64 `json:"cgroup-namespace"`
		}
		if err := json.NewDecoder(r).Decode(&raw); err != nil {
			ch <- result{err: fmt.Errorf("reading bwrap's --info-fd: %w", err)}
			return
		}
		ch <- result{info: Info{
			InitPID: raw.ChildPID,
			Namespaces: map[string]uint64{
				"mnt": raw.Mnt, "pid": raw.Pid, "net": raw.Net,
				"ipc": raw.Ipc, "uts": raw.Uts, "cgroup": raw.Cgroup,
			},
		}}
	}()
	select {
	case res := <-ch:
		return res.info, res.err
	case <-time.After(timeout):
		return Info{}, fmt.Errorf("bwrap did not answer on --info-fd within %s", timeout)
	}
}
