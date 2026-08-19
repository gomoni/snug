package cli

// runstate.go is the write side and the read/discovery side of `state.json`
// — the one file a run publishes about itself so `snug attach` can find and
// join it. It lives next to runtimedir.go because it needs that file's
// *os.Root machinery, which stays package-private on purpose (CLAUDE.md,
// invariant 3's neighbourhood: a runtime directory reached by a bare path
// lookup is exactly the shape issue #61(c)/#85 closed).
//
// Nothing here resolves a profile, reads TOML, or makes a policy decision —
// it renders a policy that has ALREADY been resolved (writeRunState) or reads
// back what a run already published (readRunStateFrom, decodeRunState). The
// abuse sentence for the file itself: a hostile process with the same uid as
// the run's owner can read state.json and learn a sandbox's init pid, its
// namespace ids and its seccomp digest — none of which grants it anything it
// could not already reach with `nsenter` and worse hygiene (issue #61's own
// settlement: attach gates nothing, the kernel already does, by uid). What
// state.json must NEVER carry is a command, an argv, an executable path
// beyond the one bounded exception (SHELL, §8.4), or a host-environment value
// a profile merely passed through — see snugAuthoredEnvPairs below.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
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
	Schema   int             `json:"schema"`
	Target   string          `json:"target"`
	Profiles []string        `json:"profiles"`
	Chdir    string          `json:"chdir"`
	Sandbox  runStateSandbox `json:"sandbox"`
	Seccomp  runStateSeccomp `json:"seccomp"`
	Env      [][2]string     `json:"env"`
	Revision string          `json:"revision,omitempty"`
}

type runStateSandbox struct {
	InitPID       int               `json:"init_pid"`
	InitStarttime uint64            `json:"init_starttime"`
	Namespaces    map[string]uint64 `json:"namespaces"`
}

type runStateSeccomp struct {
	// State is "active" or "none" — never a bare bool, so a reader printing
	// it (an error message, a future --list) never has to invent the words.
	State  string `json:"state"`
	Digest string `json:"digest,omitempty"`
}

// runStateNamespaceKinds is every namespace state.json's "namespaces" object
// must name, in the order attach's own checks read them. A struct literal
// with named fields would let a future editor add "mnt" under two different
// spellings in two different places; this is the one list both the writer
// and the reader range over.
var runStateNamespaceKinds = []string{"mnt", "pid", "net", "ipc", "uts", "cgroup"}

// writeRunState renders pol and info into this run's own state.json, through
// targetstate.go's writeTargetState — the TARGET-keyed path, so a run and
// the `snug attach` that must find it agree on where the file is whatever
// $XDG_RUNTIME_DIR each was launched with (issue #123).
//
// Called from a background goroutine (sandbox.Options.OnInfo), once bwrap
// has answered on --info-fd — see internal/sandbox/exec.go's reportInfo.
// info.InitPID names the process whose /proc/<pid>/stat this reads
// immediately: field 22 (starttime), the second half of the pid-reuse guard
// alongside the six namespace inodes info already carries.
func writeRunState(runPath string, pol *policy.Policy, info sandbox.RunInfo) error {
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
			// already gone. Refusing to publish is invariant 5: a state file
			// `snug attach` would refuse anyway (its own live check treats
			// any recorded 0 as a guaranteed mismatch) is worse than no
			// state file, because "unattachable" should say so at the
			// source rather than as a confusing refusal minutes later.
			return fmt.Errorf("run state: could not determine the %q namespace id (got 0)", k)
		}
		namespaces[k] = v
	}

	seccomp := runStateSeccomp{State: "none"}
	if info.SeccompActive {
		seccomp = runStateSeccomp{State: "active", Digest: info.SeccompDigest}
	}

	profiles := make([]string, 0, len(pol.Selected))
	for _, p := range pol.Selected {
		profiles = append(profiles, string(p))
	}

	st := runState{
		Schema:   runStateSchema,
		Target:   pol.Target,
		Profiles: profiles,
		Chdir:    pol.Chdir,
		Sandbox: runStateSandbox{
			InitPID:       info.InitPID,
			InitStarttime: starttime,
			Namespaces:    namespaces,
		},
		Seccomp:  seccomp,
		Env:      snugAuthoredEnvPairs(pol),
		Revision: buildRevision(),
	}

	// Published to the TARGET-keyed path (targetstate.go), not into this
	// run's own directory: a run and the `snug attach` that must find it have
	// to agree on where the file is, and runPath is derived from
	// $XDG_RUNTIME_DIR/$TMPDIR, which they need not agree on (issue #123).
	// runPath stays a parameter because it still names the directory this
	// run's sockets live in and because callers pass it; nothing here writes
	// to it any more.
	if err := writeTargetState(pol.Target, st); err != nil {
		return err
	}
	return nil
}

// snugAuthoredEnvPairs is Policy.AuthoredEnvNames() (verb VerbSnug)
// intersected with Policy.EnvPairs(): the subset of the resolved
// environment snug ITSELF wrote, rendered as the name/value pairs the
// attached shell will actually see. Restricting the record to these names —
// rather than every variable the run has — is what keeps a token some
// profile merely passed through (environ.set DOCKER_HOST = "ssh://…", say)
// off disk: a profile cannot write one of these names at all (env.go,
// SnugOwnedEnv), so this set can never carry one.
func snugAuthoredEnvPairs(pol *policy.Policy) [][2]string {
	authored := make(map[string]bool)
	for _, name := range pol.AuthoredEnvNames() {
		authored[name] = true
	}
	out := make([][2]string, 0, len(authored))
	for _, kv := range pol.EnvPairs() {
		if authored[kv[0]] {
			out = append(out, kv)
		}
	}
	return out
}

// procStartTime reads field 22 (starttime) of /proc/<pid>/stat. The comm
// field (field 2) is parenthesised and may itself contain spaces or
// parentheses, so this finds the LAST ')' and counts fields from there
// rather than splitting naively on whitespace — the standard, and only
// correct, way to parse this file.
func procStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return 0, fmt.Errorf("unrecognised /proc/%d/stat format", pid)
	}
	fields := strings.Fields(s[i+2:])
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

// buildRevision is debug.ReadBuildInfo()'s vcs.revision, if present — used
// ONLY to make a seccomp-digest-mismatch message concrete ("this sandbox was
// started by revision X, this binary is Y"). No decision anywhere reads this
// field; the digest comparison is the decision.
func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
}

// readRunStateFrom parses and validates state.json from an already-opened,
// already-ownership-verified run directory. This is the full §6.3 refusal
// list EXCEPT the two checks that need live process state (init_starttime
// against /proc, the six namespace inodes, the userns-is-ours check, and the
// seccomp digest rebuild) — those are attach.go's job, against the ONE run a
// human actually named, not every run discovery walks past.
func readRunStateFrom(runRoot *os.Root) (runState, error) {
	if fi, err := runRoot.Lstat("state.json"); err != nil {
		return runState{}, err
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return runState{}, fmt.Errorf("state.json is a symlink")
	}

	f, err := runRoot.OpenFile("state.json", os.O_RDONLY, 0)
	if err != nil {
		return runState{}, err
	}
	defer f.Close()

	return decodeRunState(f)
}

// decodeRunState is the parse-and-validate half of reading a state file,
// split out from readRunStateFrom so the target-keyed layout (targetstate.go,
// issue #123) validates through exactly the same code rather than a second
// copy that could accept a file the other rejects.
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

// filterDigestConsistent is a tiny, table-free assertion used by
// runstate_test.go: it exists so a test can confirm sandbox.FilterDigest and
// this file's own reader agree on the SHAPE of a digest string
// ("sha256:" + 64 hex chars) without duplicating the hashing logic.
func filterDigestConsistent(digest string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return false
	}
	hexPart := strings.TrimPrefix(digest, prefix)
	if len(hexPart) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}
