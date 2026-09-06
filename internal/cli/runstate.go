package cli

// runstate.go is the write and read side of `state.json`, the one file a run
// publishes about itself. It has exactly two readers left: the orphan sweep,
// which needs the identity chain (init pid, its start time, its six namespace
// inodes, and the owner record) to decide whether a leftover init may be
// signalled, and `snug proxy`, which needs run_dir to find the http-doors
// file a run published beside its sockets.
//
// Nothing here resolves a profile, reads TOML, or makes a policy decision —
// it renders facts about a sandbox that is already running.
//
// The abuse sentence for the file itself: a hostile process with the same uid
// as the run's owner can read state.json and learn a sandbox's init pid and
// its namespace ids, neither of which grants it anything it could not already
// reach with `nsenter` and worse hygiene — the kernel gates that by uid, and
// snug never did. What state.json must NEVER carry is a command, an argv, an
// executable path, or a host-environment value a profile merely passed
// through: every one of those is a secret a same-uid reader would not
// otherwise have, written to disk for its benefit.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
	"golang.org/x/sys/unix"
)

// runStateSchema is the only version this binary understands. A mismatch is
// refused outright — there is no best-effort partial read of an older or
// newer shape.
const runStateSchema = 1

// runState is state.json's Go shape. Field order here is cosmetic; the JSON
// key names are the contract (§6.2 of the attach design) and every one of
// them is tagged explicitly rather than left to reflection's default
// casing, so a struct-field rename can never silently change the file.
type runState struct {
	Schema  int             `json:"schema"`
	Target  string          `json:"target"`
	Sandbox runStateSandbox `json:"sandbox"`

	// Owner is the snug process that holds this target's lock, and it is the
	// sweep's second liveness signal — the one an `rm` or an `mv` of the lock
	// file cannot detach from the run (issue #489). See stateowner.go.
	Owner stateOwner `json:"owner"`

	// RunDir is this run's own runtime directory, and it is here for one
	// consumer: `snug proxy` has to find the http-doors file the run published
	// beside its sockets. Optional — a run with no doors has nothing there to
	// read, and an older state file simply does not carry one.
	//
	// It is published rather than recomputed because the run directory is
	// derived from $XDG_RUNTIME_DIR/$TMPDIR, and `snug proxy` need not have
	// been launched with the same ones: a path published by the run is a fact,
	// where a path the reader derives is an agreement neither side made.
	RunDir string `json:"run_dir,omitempty"`
}

type runStateSandbox struct {
	InitPID       int               `json:"init_pid"`
	InitStarttime uint64            `json:"init_starttime"`
	Namespaces    map[string]uint64 `json:"namespaces"`
}

// runStateNamespaceKinds is every namespace state.json's "namespaces" object
// must name, and the same six the ".starting" record carries. A struct
// literal with named fields would let a future editor add "mnt" under two
// different spellings in two different places; this is the one list every
// writer and every reader ranges over.
var runStateNamespaceKinds = []string{"mnt", "pid", "net", "ipc", "uts", "cgroup"}

// writeRunState renders pol and info into this run's state.json, through
// targetstate.go's writeTargetState — the TARGET-keyed path, so the orphan
// sweep and `snug proxy` find the file whatever $XDG_RUNTIME_DIR each was
// launched with (issue #123).
//
// Called from a background goroutine (sandbox.Options.OnInfo), once bwrap
// has answered on --info-fd — see internal/sandbox/exec.go's reportInfo.
// info.InitPID names the process whose /proc/<pid>/stat this reads
// immediately: field 22 (starttime), the second half of the pid-reuse guard
// alongside the six namespace inodes info already carries.
func writeRunState(pol *policy.Policy, info sandbox.RunInfo, runDirPath string) error {
	starttime, err := procStartTime(info.InitPID)
	if err != nil {
		return fmt.Errorf("run state: reading start time of pid %d: %w", info.InitPID, err)
	}

	namespaces := make(map[string]uint64, len(runStateNamespaceKinds))
	for _, k := range runStateNamespaceKinds {
		v, ok := info.Namespaces[k]
		if !ok {
			return fmt.Errorf("run state: bwrap's --info-fd answer did not carry a %q namespace id", k)
		}
		if v == 0 {
			// 0 is never a real namespace inode on any Linux kernel. bwrap
			// omits a "<kind>-namespace" key ENTIRELY for a namespace it did
			// not itself unshare (internal/sandbox/exec.go's
			// fillMissingNamespaceIDs is the fallback for that, reading
			// /proc/<pid>/ns/<kind> directly) — if this is still 0 here, that
			// fallback itself failed, most likely because the pid was
			// already gone. Refusing to publish is invariant 5: a record the
			// orphan sweep would refuse to act on anyway (killOrphanInit
			// treats any recorded 0 as a guaranteed mismatch) is worse than
			// no record, because the failure should say so at the source
			// rather than as a leftover init nobody can explain.
			return fmt.Errorf("run state: could not determine the %q namespace id (got 0)", k)
		}
		namespaces[k] = v
	}

	owner, err := currentOwner()
	if err != nil {
		return fmt.Errorf("run state: %w", err)
	}

	st := runState{
		Schema: runStateSchema,
		Target: pol.Target,
		Sandbox: runStateSandbox{
			InitPID:       info.InitPID,
			InitStarttime: starttime,
			Namespaces:    namespaces,
		},
		Owner:  owner,
		RunDir: runDirPath,
	}

	// Published to the TARGET-keyed path (targetstate.go), not into this run's
	// own directory: the reader is a LATER snug process, and the run directory
	// is derived from $XDG_RUNTIME_DIR/$TMPDIR, which the two need not agree
	// on (issue #123).
	//
	// That change also left this function taking a runPath it never used —
	// carried for three releases because callers had one to pass. A function
	// that needs the runtime directory should say so in its signature; this
	// one does not need it, so it no longer says so (issue #103).
	if err := writeTargetState(pol.Target, st); err != nil {
		return err
	}
	return nil
}

// procStartTime reads field 22 (starttime) of /proc/<pid>/stat. The comm
// field (field 2) is parenthesised and may itself contain spaces or
// parentheses, so this finds the LAST ')' and counts fields from there
// rather than splitting naively on whitespace — the standard, and only
// correct, way to parse this file.
func procStartTime(pid int) (uint64, error) {
	fields, err := procStatAfterComm(pid)
	if err != nil {
		return 0, err
	}
	// After the comm field, field 3 (state) is fields[0]; field 22
	// (starttime) is therefore fields[22-3] = fields[19].
	const starttimeIndex = 22 - 3
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("/proc/%d/stat has %d fields after comm, need at least %d",
			pid, len(fields), starttimeIndex+1)
	}
	v, err := strconv.ParseUint(fields[starttimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing starttime field of /proc/%d/stat: %w", pid, err)
	}
	return v, nil
}

// procStatAfterComm is the parse both readers of /proc/<pid>/stat share, so
// the comm-field rule above is stated once. It returns the whitespace-split
// fields FROM field 3 (state) onwards: fields[0] is the state character and
// fields[n-3] is field n of proc(5).
func procStatAfterComm(pid int) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return nil, fmt.Errorf("unrecognised /proc/%d/stat format", pid)
	}
	return strings.Fields(s[i+2:]), nil
}

// decodeRunState is the parse-and-validate half of reading a state file. Its
// two callers — readTargetState and the orphan sweep — go through it rather
// than each decoding, so neither can accept a file the other rejects.
func decodeRunState(r io.Reader) (runState, error) {
	var st runState
	if err := json.NewDecoder(r).Decode(&st); err != nil {
		return runState{}, fmt.Errorf("parsing state.json: %w", err)
	}
	if st.Schema != runStateSchema {
		return runState{}, fmt.Errorf("state.json schema %d, this binary understands %d",
			st.Schema, runStateSchema)
	}
	for _, k := range runStateNamespaceKinds {
		if _, ok := st.Sandbox.Namespaces[k]; !ok {
			return runState{}, fmt.Errorf("state.json is missing the %q namespace id", k)
		}
	}
	return st, nil
}

// procNamespaceInodes reads the six namespace ids by OPENING and FSTATing
// each /proc/<pid>/ns/<kind> descriptor — not readlink, which returns a
// string of the same form but is one syscall this function does not need to
// trust the kernel to have rendered consistently with what the caller will
// later compare against. Its two callers are the orphan sweep's identity
// chain (killOrphanInit) and the record writers that feed it.
func procNamespaceInodes(pid int) (map[string]uint64, error) {
	out := make(map[string]uint64, len(runStateNamespaceKinds))
	for _, k := range runStateNamespaceKinds {
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/%s", pid, k))
		if err != nil {
			return nil, err
		}
		var st unix.Stat_t
		ferr := unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if ferr != nil {
			return nil, ferr
		}
		out[k] = st.Ino
	}
	return out, nil
}
