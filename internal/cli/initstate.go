package cli

// initstate.go is the orphan-kill record for the window issue #236 measured:
// bwrap answers --info-fd, naming its init, long before runOneSandbox reports
// "enginestarted" — the mount settle and, on a container run, the engine's
// whole cold start sit in between — and exec.go's publishInfo only runs AFTER
// that, and after a gated run's release byte, on purpose (issue #125: a record
// naming a sandbox whose payload the gate is still holding announces a run that
// does not yet exist). For that whole interval state.json does not exist yet,
// so sweepOneOrphan's kill has nothing to read and a SIGKILLed snug leaves an
// init the next run cannot find.
//
// This file is written the moment sandbox.Options.OnInit fires — before any
// of that — and removed the moment writeRunState succeeds, so the two files
// together always name at least one record for the init between "bwrap
// forked" and "snug exited cleanly": never neither.
//
// It is deliberately NOT a view over runState: a field added to state.json
// (a command, an argv, a seccomp digest, anything else runstate.go's own
// abuse-sentence list forbids there) must not be able to reach this file by
// sharing its type. Six keys, checked byte-for-byte by
// testdata/initstate.golden.json, so a seventh key shows up in review rather
// than arriving silently through an embedded runState.
//
// WHY THIS FILE IS MORE SENSITIVE THAN state.json, NOT LESS, and why nothing
// but the sweep ever opens its name: at the moment it is written, bwrap has
// only just answered --info-fd — its own comment in internal/stage/serve.go
// measures the init's mount namespace at that instant still holding the whole
// host tree at /oldroot with a writable root, settling ~150ms later to the
// sandbox's own read-only view. A record anything could act on would therefore
// describe a sandbox before it exists, up to that ~150ms early on every run and
// the whole of the engine's cold start on a gated one.
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
	"os"
)

// initStateSchema is the only version this binary understands, exactly as
// runStateSchema is for state.json — a separate constant because the two
// files are separate formats that must be free to version independently.
const initStateSchema = 1

// initState is initstate.go's own JSON shape: schema, target, the three
// identity fields killOrphanInit needs to confirm a pid before signalling it,
// and the owner record its #489 gate reads.
// Nothing else — see this file's own doc comment for why that absence is the
// point.
type initState struct {
	Schema        int               `json:"schema"`
	Target        string            `json:"target"`
	InitPID       int               `json:"init_pid"`
	InitStarttime uint64            `json:"init_starttime"`
	Namespaces    map[string]uint64 `json:"namespaces"`

	// Owner carries the same second liveness signal state.json does, for the
	// same reason and read by the same gate — see stateowner.go and issue
	// #489. A gate present in only one of the two records would leave the
	// hole open for whichever window the other covers.
	Owner stateOwner `json:"owner"`
}

// initStateName is targetStateName's sibling: the same target stem and the
// same owning pid, so a run's two records sort together, but with no ".json"
// suffix — that absence is structural, not cosmetic: sweepOrphanedSandboxesIn's
// existing ".json" filter cannot claim this name by accident, so the two sweep
// branches stay disjoint by filename rather than by a hash comparison that
// happens to fail.
//
// The pid is here for the reason it is in state.json's name and it matters
// more here: this is the record that exists precisely while a run is too
// young to have published anything else, so two runs starting on one target
// within a second of each other are exactly the case where one overwriting
// the other loses an init nothing else names.
func initStateName(realpath string, pid int) string {
	return fmt.Sprintf("%s.%d.starting", targetKeyPrefix(realpath), pid)
}

// initStateNameMatches is targetStateNameMatches' sibling for the
// ".starting" record — same generations, same reason.
func initStateNameMatches(realpath, name string) bool {
	return targetRecordNameMatches(realpath, name, ".starting")
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

	owner, err := currentOwner()
	if err != nil {
		return fmt.Errorf("init state: %w", err)
	}

	st := initState{
		Schema:        initStateSchema,
		Target:        target,
		InitPID:       pid,
		InitStarttime: starttime,
		Namespaces:    namespaces,
		Owner:         owner,
	}
	// owner.PID is this process (currentOwner reads os.Getpid()), and taking
	// the name's pid from the record rather than calling os.Getpid() again is
	// writeTargetState's rule: the name addresses the owner the body names,
	// or the sweep's liveness gate is aimed at a different process.
	return writeTargetFile(initStateName(target, owner.PID), st)
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

// removeInitState drops THIS process's ".starting" record for target — never
// a peer run's, which is what the os.Getpid() in the name buys: a second snug
// on the same directory has its own record and its own init, and removing it
// here would blind every later sweep to that init.
//
// Called only after writeRunState has already succeeded — never before, and
// never on its own — so that a SIGKILL between the two calls always leaves at
// least one record naming the same init: the second pidfd_open a sweep would
// then attempt against it (once from each record, in the ordinary case where
// neither race happens) simply returns ESRCH the second time, which
// killOrphanInit already reads as "already gone".
func removeInitState(target string) error {
	return removeTargetFile(initStateName(target, os.Getpid()))
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
