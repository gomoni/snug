package stage

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The control protocol travels over one inherited SOCK_SEQPACKET socketpair —
// no pathname, no listener, nothing running as your uid can reach it, because
// there is no name to reach it by (SUPERVISOR-DESIGN.md §3.3). SEQPACKET
// preserves message boundaries, so one JSON document is one datagram; there is
// no length prefix and no framing to get wrong.
//
// Strict decode, typed structs, default-deny dispatch — the internal/dockerproxy
// house style, applied here because this IS the enforcement point Phase 2
// inherits when a pathname socket and a second client show up. Getting the
// discipline right costs nothing today and is exactly the kind of thing that
// would otherwise be bolted on under schedule pressure later.
//
// Two things are absent from the schema ON PURPOSE, and the absence is stronger
// than a validation rule would be: there is no field for a capability drop (a
// client cannot even express the request), and no field naming a target sandbox
// by pid (a future attach target is an opaque handle P1 issues, never a raw
// pid it is asked to trust).
//
// That second absence survived issue #125's gate, and it is the reason the
// engine's start moved INTO "start" rather than into a request of its own. A
// separate post-"start" request would have had to carry bwrap's child pid from
// P0 to P1 — a pid the stage would then act on — and the alternative to
// trusting it is a validation step (pidfd, then confirm PPid is the bwrap P1
// itself forked) that is more code for a principle still bent. Under one
// request the pid travels the OTHER way: P1 reads it from bwrap's own
// --info-fd answer, on a descriptor P1 owns, about a process P1 is the
// grandparent of, and reports it to P0 in an EVENT. An event carrying a pid is
// not the hazard a request carrying one is.
const maxMessage = 64 * 1024

// request is a P0 -> P1 message. Four ops. The stage answers at most one
// "netready" and exactly one "start" before it exits, in that order; "stop"
// tears it down and is sent by Close rather than StartSandbox. "mapped" is
// issue #63, Tier B and — unlike the others — is sent
// UNSOLICITED-BY-CALLER-CODE: Start sends it only in reply to a "needmap"
// event, never on its own initiative, so it cannot arrive before __stage-setup
// is actually blocked waiting for it.
//
// "startengine" was a fifth op for one milestone (issue #63, Tier B) and is
// GONE, folded into "start" by issue #125's C2 gate. It had to go: under the
// gate the engine is started while bwrap's payload is parked, so the engine's
// start is no longer a step BEFORE the sandbox exists — it is a step INSIDE
// the one request that creates it. Keeping it separate would have meant
// "start" no longer being the request after which MainServe returns, which is
// the stage's one-shot property stated as code rather than as a comment.
type request struct {
	Op string `json:"op"` // "netready" | "start" | "stop" | "mapped"

	// "netready" only (issue #63, Tier B). NetIface names the interface whose
	// UP+RUNNING state confirms the sandbox's network: "snug0" (pasta's own
	// interface name, internal/policy/net.go) for a run with pasta attached,
	// "lo" for a stage that owns no pasta at all — an offline @podman-socket
	// run, which still needs a stage for the container engine's own U. Chosen
	// by P0 from the resolved policy's Net.Mode, never guessed by the stage;
	// empty falls back to "snug0" for a caller on the pre-Tier-B protocol.
	NetIface string `json:"net_iface,omitempty"`

	// "start" only.
	Bwrap string   `json:"bwrap,omitempty"`
	Argv  []string `json:"argv,omitempty"`
	// Passthrough is the count of the sandbox's own descriptors P1 must pass
	// through to bwrap unchanged, starting at fd 3 in ITS OWN process — the
	// numbers already baked into the args memfd P0 built. P1 never opens or
	// reads them; it only forwards the *os.File values.
	Passthrough int `json:"passthrough,omitempty"`
	// Gated says that the argv above carries bwrap's --block-fd and --sync-fd,
	// so the sandbox's init will PARK before forking any payload and P0 holds
	// the byte that releases it (issue #125, C2 gate).
	//
	// It is a field rather than something P1 infers, because it names an
	// OBLIGATION rather than a fact: a parked init has not yet armed
	// --die-with-parent (measured — killing the outer bwrap leaves it alive and
	// still releasable), so for as long as this is true P1 owns killing that
	// init explicitly on every abort path, and on its own teardown. P1 cannot
	// see the flags to infer it: they are inside the args memfd, and the argv
	// P1 receives is just "--args N -- cmd...".
	Gated bool `json:"gated,omitempty"`

	// "start" only, and only when a container engine is selected (issue #63,
	// Tier B; moved here from the deleted "startengine" op by issue #125's C2
	// gate). EnginePodman is the resolved,
	// preflight-checked path to a REAL podman binary — P0's own preflight
	// already refused a host-escape shim, so the stage does not re-check it.
	// EngineArgv is exactly what follows it on the command line.
	// EngineEnv is the explicit, minimal environment P0 built for it (PATH,
	// HOME, XDG_RUNTIME_DIR, CONTAINERS_*, …) — never the stage's own
	// os.Environ(), which is empty anyway, and never inherited from the host.
	// EngineSock is the pathname socket P0 already created the parent
	// directory for (engine.New, hardened per #61/#85): the stage polls for
	// it rather than trusting the fork succeeded, because "the process
	// started" and "podman finished getting to a listening socket" are two
	// different facts.
	EnginePodman string   `json:"engine_podman,omitempty"`
	EngineArgv   []string `json:"engine_argv,omitempty"`
	EngineEnv    []string `json:"engine_env,omitempty"`
	EngineSock   string   `json:"engine_sock,omitempty"`
	// EngineGrafts is the derived view the engine is given: one entry per
	// host directory, with the guest path it is attached at. See EngineSpec's
	// own field for why the clone happens before the namespace join.
	EngineGrafts []EngineGraft `json:"engine_grafts,omitempty"`
}

// event is a P1 -> P0 message. Five shapes: "needmap", sent at most once,
// before "ready", ONLY when __stage-setup's own uid is still the overflow id
// after the clone (issue #63, Tier B — cfg.Topology.Subuid == SubuidFull left
// the map for P0 to write via newuidmap/newgidmap instead of writing it
// itself); "ready", sent once at startup with the namespace ids and the
// pinned netns fd; "netready", the answer to a "netready" request, carrying
// Err when the interface never came up; "enginestarted" and "exited", the TWO
// answers to the one "start" request.
//
// "enginestarted" is the first of that pair and reports the whole of the
// startup that happens while no payload exists: bwrap forked, bwrap's own
// --info-fd answer parsed, and — when the request carried an engine — the
// engine forked into N and its socket confirmed. Err is set when any of that
// failed, in which case P1 has already killed bwrap AND its init and reaped
// both. It keeps that name on a run with no engine at all, where it means the
// same thing minus the engine: ONE name and one code path for the single
// moment at which invariant 5 is enforced beats a second name for the
// engineless spelling of it.
//
// "exited" is sent once after P1 has reaped the one payload this stage will
// ever run, whatever the outcome.
type event struct {
	Op string `json:"op"` // "needmap" | "ready" | "netready" | "enginestarted" | "exited"

	// "ready" only.
	Netns   string `json:"netns,omitempty"`
	Userns  string `json:"userns,omitempty"`
	NetnsFD int    `json:"netns_fd,omitempty"`

	// "enginestarted" only: bwrap's own --info-fd answer, parsed by P1 because
	// P1 is the process that holds the descriptor (fds.go's fdBwrapInfo).
	// InitPID is a HOST pid — bwrap sits outside the pid namespace it creates,
	// and P0, P1 and bwrap are all in the host's — so it means the same thing
	// on both sides of this socket. Zero when bwrap never answered, which is
	// fatal for a gated run and warn-only ("this run will not be attachable")
	// for one with no engine.
	InitPID    int               `json:"init_pid,omitempty"`
	Namespaces map[string]uint64 `json:"namespaces,omitempty"`

	// "exited" only. WaitStatus is syscall.WaitStatus's own underlying uint32
	// representation on linux/amd64 — carried as a plain integer rather than a
	// decoded struct, so a wire format that outlives this package's own
	// interpretation of WIFEXITED/WIFSIGNALED does not have to change shape.
	WaitStatus uint32 `json:"wait_status,omitempty"`
	// Err is set when P1 could not get a payload to the starting line at all —
	// bwrap never forked, bwrap never answered on --info-fd, the engine's fork
	// or capability drop failed, or its socket never appeared. One field for
	// every one of those because P0 does the same thing with all of them:
	// refuses the run.
	Err string `json:"err,omitempty"`
}

// encode marshals v and refuses anything too large for one SEQPACKET write to
// carry reliably. There is no length prefix to get wrong because SEQPACKET
// already preserves the boundary; this bound exists so a runaway argv fails
// loudly here instead of as a truncated write on the socket.
func encode(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > maxMessage {
		return nil, fmt.Errorf("control message is %d bytes, over the %d ceiling", len(b), maxMessage)
	}
	return b, nil
}

// decodeStrict rejects an unknown field and rejects trailing data after the one
// JSON value a SEQPACKET datagram is supposed to carry — the second check is
// what a struct tag cannot express: DisallowUnknownFields catches an extra
// FIELD, dec.More() is what catches an extra VALUE concatenated after it.
func decodeStrict(b []byte, v any) error {
	if len(b) > maxMessage {
		return fmt.Errorf("control message is %d bytes, over the %d ceiling", len(b), maxMessage)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decoding control message: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("control message carries more than one JSON value")
	}
	return nil
}
