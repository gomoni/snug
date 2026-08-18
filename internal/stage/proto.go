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
const maxMessage = 64 * 1024

// request is a P0 -> P1 message. Six ops now. The stage answers at most one
// "netready", at most one "startengine", and exactly one "start" before it
// exits, in that order; "stop" tears it down and is sent by Close rather than
// StartSandbox. "mapped" is new with issue #63, Tier B and — unlike the
// others — is sent UNSOLICITED-BY-CALLER-CODE: Start sends it only in reply
// to a "needmap" event, never on its own initiative, so it cannot arrive
// before __stage-setup is actually blocked waiting for it. "startengine" is
// also new with issue #63, Tier B: unlike "start", answering it does NOT end
// the stage's loop — the state machine becomes "at most one netready, at most
// one startengine, then exactly one start", still finite, still no
// loop-into-server.
type request struct {
	Op string `json:"op"` // "netready" | "startengine" | "start" | "stop" | "mapped"

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

	// "startengine" only (issue #63, Tier B). EnginePodman is the resolved,
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
	// EngineResolvConf is a HOST path holding the SAME generated
	// /etc/resolv.conf content the sandbox payload gets (issue #126) —
	// never the content itself, and never the host's real
	// /etc/resolv.conf. __inengine bind-mounts it over /etc/resolv.conf
	// inside the engine's own private mount-namespace copy of the host
	// tree, before exec.
	EngineResolvConf string `json:"engine_resolv_conf,omitempty"`
}

// event is a P1 -> P0 message. Five shapes: "needmap", sent at most once,
// before "ready", ONLY when __stage-setup's own uid is still the overflow id
// after the clone (issue #63, Tier B — cfg.Topology.Subuid == SubuidFull left
// the map for P0 to write via newuidmap/newgidmap instead of writing it
// itself); "ready", sent once at startup with the namespace ids and the
// pinned netns fd; "netready", the answer to a "netready" request, carrying
// Err when the interface never came up; "enginestarted", the answer to a
// "startengine" request (issue #63, Tier B), carrying Err when the fork, the
// setns into N, the private-tree mount, the capability drop, or the bounded
// wait for the engine's own socket failed; "started", the answer to a
// "start" request, carrying Err when bwrap itself never forked; "exited",
// sent once after P1 has reaped the one payload this stage will ever run,
// whatever the outcome.
type event struct {
	Op string `json:"op"` // "needmap" | "ready" | "netready" | "enginestarted" | "started" | "exited"

	// "ready" only.
	Netns   string `json:"netns,omitempty"`
	Userns  string `json:"userns,omitempty"`
	NetnsFD int    `json:"netns_fd,omitempty"`

	// "exited" only. WaitStatus is syscall.WaitStatus's own underlying uint32
	// representation on linux/amd64 — carried as a plain integer rather than a
	// decoded struct, so a wire format that outlives this package's own
	// interpretation of WIFEXITED/WIFSIGNALED does not have to change shape.
	WaitStatus uint32 `json:"wait_status,omitempty"`
	// Err is set when P1 could not even start bwrap (LookPath failure, fork
	// failure) — a "start" that never produced a payload to wait for. Reused,
	// unchanged in shape, for "enginestarted"'s own failure case.
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
