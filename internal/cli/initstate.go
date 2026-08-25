package cli

// initstate.go is the orphan-kill record for the window issue #236 measured:
// bwrap answers --info-fd, naming its init, long before runOneSandbox reports
// "enginestarted" — the mount settle and, on a container run, the engine's
// whole cold start sit in between — and exec.go's publishInfo only runs AFTER
// that, and after a gated run's release byte, on purpose (issue #125: an
// attachable sandbox is a sandbox `snug attach` could put a process into
// before its gate opened). For that whole interval state.json does not exist
// yet, so sweepOneOrphan's kill has nothing to read and a SIGKILLed snug
// leaves an init the next run cannot find.
//
// This file is written the moment sandbox.Options.OnInit fires — before any
// of that — and removed the moment writeRunState succeeds, so the two files
// together always name at least one record for the init between "bwrap
// forked" and "snug exited cleanly": never neither.
//
// It is deliberately NOT a view over runState: a field added to state.json
// (a command, an argv, a seccomp digest, anything else runstate.go's own
// abuse-sentence list forbids there) must not be able to reach this file by
// sharing its type. Five keys, checked byte-for-byte by
// testdata/initstate.golden.json, so a sixth key shows up in review rather
// than arriving silently through an embedded runState.
//
// WHY THIS FILE IS MORE SENSITIVE THAN state.json, NOT LESS, and why nothing
// but the sweep ever opens its name: at the moment it is written, bwrap has
// only just answered --info-fd — its own comment in internal/stage/serve.go
// measures the init's mount namespace at that instant still holding the whole
// host tree at /oldroot with a writable root, settling ~150ms later to the
// sandbox's own read-only view. A record any attach path could read would
// therefore hand out a sandbox before it exists, up to that ~150ms early on
// every run and the whole of the engine's cold start on a gated one.
//
// The abuse sentence: a same-uid process can read this file and learn a
// sandbox init's pid and namespace ids 1-2s earlier than state.json would
// have said so, and nothing more — the same same-uid process can already
// enumerate every process in a foreign pid namespace from
// /proc/<pid>/ns/pid unaided, and it is the kernel, not snug, that permits it
// to setns there. It carries no seccomp state, no digest, no profiles, no
// chdir, no env pairs, no command and no argv, so reading it early grants
// nothing state.json itself does not already grant once published.

import (
	"encoding/json"
	"fmt"
	"io"
)

// initStateSchema is the only version this binary understands, exactly as
// runStateSchema is for state.json — a separate constant because the two
// files are separate formats that must be free to version independently.
const initStateSchema = 1

// initState is initstate.go's own JSON shape: schema, target and the four
// identity fields killOrphanInit needs to confirm a pid before signalling it.
// Nothing else — see this file's own doc comment for why that absence is the
// point.
type initState struct {
	Schema        int               `json:"schema"`
	Target        string            `json:"target"`
	InitPID       int               `json:"init_pid"`
	InitStarttime uint64            `json:"init_starttime"`
	Namespaces    map[string]uint64 `json:"namespaces"`
}

// initStateName is targetStateName's sibling, keyed by the same
// targetkey.Hash so the two sort together, but with no ".json" suffix — that
// absence is structural, not cosmetic: sweepOrphanedSandboxesIn's existing
// ".json" filter cannot claim this name by accident, so the two sweep
// branches stay disjoint by filename rather than by a hash comparison that
// happens to fail.
func initStateName(realpath string) string {
	return targetKeyPrefix(realpath) + ".starting"
}

// writeInitState publishes the orphan-kill record for pid, the sandbox's
// init, the instant sandbox.Options.OnInit reports it.
//
// Identity is read exactly as writeRunState already reads it — procStartTime
// plus all six namespace inodes via procNamespaceInodes, fstat on an opened
// fd, never readlink — and the same zero refusal applies: any of the six
// coming back 0, or procStartTime failing, means this returns an error and
// publishes nothing, because a record killOrphanInit cannot use to confirm
// identity is worse than no record (it would fail the write it exists to
// enable, silently, on the one run where the sweep needed it most).
func writeInitState(target string, pid int) error {
	starttime, err := procStartTime(pid)
	if err != nil {
		return fmt.Errorf("init state: reading start time of pid %d: %w", pid, err)
	}

	nsIno, err := procNamespaceInodes(pid)
	if err != nil {
		return fmt.Errorf("init state: reading namespace ids of pid %d: %w", pid, err)
	}
	namespaces, err := validatedInitNamespaces(nsIno)
	if err != nil {
		return err
	}

	st := initState{
		Schema:        initStateSchema,
		Target:        target,
		InitPID:       pid,
		InitStarttime: starttime,
		Namespaces:    namespaces,
	}
	return writeTargetFile(initStateName(target), st)
}

// validatedInitNamespaces is writeInitState's own zero-refusal guard
// (runstate.go's writeRunState carries the same one against a different
// source — bwrap's --info-fd answer rather than a direct /proc read — kept
// as a separate copy there because the two refuse in different words). Split
// out so the guard itself is testable against a fabricated map: a live pid's
// procNamespaceInodes can never actually produce a zero inode, so the
// refusal this exists to prove has no reachable path through writeInitState
// alone.
func validatedInitNamespaces(nsIno map[string]uint64) (map[string]uint64, error) {
	namespaces := make(map[string]uint64, len(runStateNamespaceKinds))
	for _, k := range runStateNamespaceKinds {
		v, ok := nsIno[k]
		if !ok || v == 0 {
			return nil, fmt.Errorf("init state: could not determine the %q namespace id (got %d)", k, v)
		}
		namespaces[k] = v
	}
	return namespaces, nil
}

// removeInitState drops target's ".starting" record. Called only after
// writeRunState has already succeeded — never before, and never on its own —
// so that a SIGKILL between the two calls always leaves at least one record
// naming the same init: the second pidfd_open a sweep would then attempt
// against it (once from each record, in the ordinary case where neither race
// happens) simply returns ESRCH the second time, which killOrphanInit already
// reads as "already gone".
func removeInitState(target string) error {
	return removeTargetFile(initStateName(target))
}

// decodeInitState parses and validates one ".starting" record, the same
// shape decodeRunState gives state.json: strict on the schema, silent about
// everything else, because a file this version cannot parse may belong to a
// newer snug whose run is still live.
func decodeInitState(r io.Reader) (initState, error) {
	var st initState
	if err := json.NewDecoder(r).Decode(&st); err != nil {
		return initState{}, fmt.Errorf("parsing init state: %w", err)
	}
	if st.Schema != initStateSchema {
		return initState{}, fmt.Errorf("init state schema %d, this binary understands %d",
			st.Schema, initStateSchema)
	}
	for _, k := range runStateNamespaceKinds {
		if _, ok := st.Namespaces[k]; !ok {
			return initState{}, fmt.Errorf("init state is missing the %q namespace id", k)
		}
	}
	return st, nil
}
