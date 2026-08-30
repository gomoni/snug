package dockerproxy

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// namedvolume.go lets a container mount a NAMED volume (issue #464), and holds
// the three checks that make that safe. `-v myvol:/data` used to refuse with
// "mount source \"myvol\" must be an absolute path" on every wire.
//
// # Why a name needs a check at all, measured rather than argued
//
// A volume name is a reference snug forwards UNRESOLVED; the ENGINE resolves it,
// in a store keyed on the target directory and shared with every later run and
// with any host process using the same `--root`. So the string snug judged is
// not the thing that gets mounted. That is exactly the rule checkOne states for
// itself — "a field that carries a path is allowlistable only if snug both
// RESOLVES it and FORWARDS the resolved string" — and a bare name fails it.
//
// MEASURED, podman 6.0.2, isolated store:
//
//	podman volume create --opt type=none --opt o=bind --opt device=/home/<u>/.ssh EVIL
//	GET /v1.41/volumes/EVIL
//	  {"Driver":"local", ...,
//	   "Options":{"device":"/home/<u>/.ssh","o":"bind","type":"none"}}
//	podman run --rm -v EVIL:/x alpine ls /x
//	  -> the host's private keys, listed
//
// Note `Driver` is still `"local"`. A driver check alone clears that volume.
// What separates it from an ordinary one is the OPTIONS, and the inspect answer
// carries them, which is what makes the check below possible at all.
//
// handleVolumeCreate refuses `Options`/`DriverOpts` — but it governs only
// volumes created THROUGH this proxy, and the threat is a volume already in the
// shared store. So the check has to happen at USE time.
//
// # THE ABUSE SENTENCE
//
// A hostile process inside the sandbox can use a named volume to write bytes
// that OUTLIVE this run into a name a later run of this project will mount, and
// to read what an earlier run left there — the engine store is keyed on the
// target directory, and a volume carries no ownership of its own until snug
// stamps one. It cannot use a name to reach a host path: the volume is inspected
// at use time and refused unless the engine reports the `local` driver with NO
// options, which is what a host-bind volume is made of.

// isVolumeName reports whether a mount source is a volume NAME rather than a
// path. podman's own rule is that a name matches [a-zA-Z0-9][a-zA-Z0-9_.-]*; a
// source containing a slash is a path, and one that is not absolute is refused
// by checkOne as it always was.
//
// The `.`/`..` cases fall out of the first character rather than needing an arm:
// `.` is not alphanumeric. That matters — a source of `..` reaching the engine
// as a volume NAME would be a name the engine resolves relative to its store.
func isVolumeName(s string) bool {
	if s == "" || strings.ContainsRune(s, '/') {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// volumeInfo is the engine's answer about a volume. The docker-compat spelling
// on purpose, for the reason inspectContainer gives: it is the schema this
// filter reads.
type volumeInfo struct {
	Name    string            `json:"Name"`
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
	Labels  map[string]string `json:"Labels"`
}

func (p *Proxy) inspectVolume(ctx context.Context, name string) (volumeInfo, error) {
	var v volumeInfo
	// url.PathEscape for inspectContainer's reason: the reference arrives from
	// a client and this BUILDS a request URI out of it.
	if err := p.inspect(ctx, "/v1.41/volumes/"+url.PathEscape(name), name, &v); err != nil {
		return volumeInfo{}, err
	}
	return v, nil
}

// checkNamedVolume is the use-time gate. Fail-closed in every direction: a name
// the engine does not know, a non-200, an undecodable body and a driver or
// option snug did not clear all refuse.
func (p *Proxy) checkNamedVolume(ctx context.Context, name string) error {
	if !isVolumeName(name) {
		return fmt.Errorf("mount source %q is neither an absolute path nor a volume name "+
			"(a name is [a-zA-Z0-9][a-zA-Z0-9_.-]*), so snug cannot tell which it is and "+
			"refuses rather than guessing", name)
	}
	v, err := p.inspectVolume(ctx, name)
	if err != nil {
		return fmt.Errorf("snug could not confirm what volume %q IS (%v), so it refuses to "+
			"mount it. A volume name is resolved by the ENGINE, in a store shared with every "+
			"other run on this target, so snug asks the engine what the name holds before "+
			"forwarding it — and a check that did not complete is not a pass. If the volume "+
			"does not exist yet, create it first: `docker volume create %s`", name, err, name)
	}
	if v.Name != name {
		return fmt.Errorf("the engine's answer for volume %q names it %q, which is not the "+
			"volume snug asked about, so snug refuses to mount it. An answer that does not "+
			"name the object it describes is not an answer this gate can act on", name, v.Name)
	}
	if v.Driver != "local" {
		return fmt.Errorf("volume %q reports the driver %q, and only %q is permitted. Another "+
			"driver resolves the name somewhere snug cannot see — a remote share, or a plugin "+
			"running outside this sandbox — and an EMPTY driver is an answer snug did not "+
			"understand, which is not a pass either", name, v.Driver, "local")
	}
	if len(v.Options) > 0 {
		names := make([]string, 0, len(v.Options))
		for k := range v.Options {
			names = append(names, k)
		}
		return fmt.Errorf("volume %q carries local-driver options (%s) and is refused. "+
			"MEASURED against podman 6.0.2: a volume created with "+
			"`--opt type=none --opt o=bind --opt device=/home/<user>/.ssh` still reports "+
			"driver \"local\", and mounting it by name puts the host directory inside the "+
			"container — snug never sees a path, because the name is resolved by the engine. "+
			"An option-free local volume is a directory in the engine's own store and is "+
			"permitted; this one is not. Use a fresh name: `docker volume create <name>`",
			name, quoteList(names))
	}
	return nil
}

// volumeOwnedByThisRun answers `DELETE /volumes/{name}`. It is the volume twin
// of ownership.go's container gate and is deliberately the same shape: ask the
// ENGINE, compare this run's label, fail closed.
//
// Volumes created before snug stamped them carry no label and are refused, which
// is the same answer ownership.go gives a container without the stamp.
func (p *Proxy) volumeOwnedByThisRun(ctx context.Context, name string) error {
	v, err := p.inspectVolume(ctx, name)
	if err != nil {
		return fmt.Errorf("snug could not confirm that volume %q belongs to this sandbox run "+
			"(%v), so it refuses to remove it. Ownership is checked against the engine, and a "+
			"check that did not complete is not a pass", name, err)
	}
	key, want, _ := strings.Cut(p.runLabel, "=")
	got, ok := v.Labels[key]
	if !ok {
		return fmt.Errorf("volume %q carries no %s label at all, so snug did not create it, "+
			"and removing it is refused. Every volume snug creates is stamped at create time; "+
			"one without the stamp was made by something else sharing this engine's store — "+
			"an earlier run of this project, or a host process using the same --root — and it "+
			"holds that data, not this run's", name, key)
	}
	if got != want {
		return fmt.Errorf("volume %q was created by another sandbox run (%s=%s), so removing "+
			"it is refused. The engine's store is keyed on the target directory and persists "+
			"across runs — that sharing is what makes a warm start warm — so it holds volumes "+
			"earlier runs of this project wrote. Create your own volume instead",
			name, key, got)
	}
	return nil
}
