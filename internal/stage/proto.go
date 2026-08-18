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

// request is a P0 -> P1 message. Four ops, and the stage answers at most one
// "netready" and exactly one "start" before it exits; "stop" tears it down and
// is sent by Close rather than StartSandbox. "mapped" is new with issue #63,
// Tier B and — unlike the other three — is sent UNSOLICITED-BY-CALLER-CODE:
// Start sends it only in reply to a "needmap" event, never on its own
// initiative, so it cannot arrive before __stage-setup is actually blocked
// waiting for it.
type request struct {
	Op string `json:"op"` // "netready" | "start" | "stop" | "mapped"

	// "start" only.
	Bwrap string   `json:"bwrap,omitempty"`
	Argv  []string `json:"argv,omitempty"`
	// Passthrough is the count of the sandbox's own descriptors P1 must pass
	// through to bwrap unchanged, starting at fd 3 in ITS OWN process — the
	// numbers already baked into the args memfd P0 built. P1 never opens or
	// reads them; it only forwards the *os.File values.
	Passthrough int `json:"passthrough,omitempty"`
}

// event is a P1 -> P0 message. Four shapes: "needmap", sent at most once,
// before "ready", ONLY when __stage-setup's own uid is still the overflow id
// after the clone (issue #63, Tier B — cfg.Topology.Subuid == SubuidFull left
// the map for P0 to write via newuidmap/newgidmap instead of writing it
// itself); "ready", sent once at startup with the namespace ids and the
// pinned netns fd; "netready", the answer to a "netready" request, carrying
// Err when the interface never came up; "exited", sent once after P1 has
// reaped the one payload this stage will ever run, whatever the outcome.
type event struct {
	Op string `json:"op"` // "needmap" | "ready" | "netready" | "exited"

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
	// failure) — a "start" that never produced a payload to wait for.
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
