package stage

// Issue #613: encode's over-the-ceiling refusal named only a byte count, with
// nothing pointing a reader at WHICH of the protocol's several request/event
// shapes grew too large — in practice, almost always the "start" request's
// own Argv, the one field on any message this protocol carries that a user's
// own command line fills.

import (
	"strings"
	"testing"
)

func TestEncodeOversizeNamesTheStartRequestsArgv(t *testing.T) {
	req := request{Op: "start", Argv: make([]string, 20000)}
	for i := range req.Argv {
		req.Argv[i] = "argument-padding-to-cross-the-ceiling"
	}
	_, err := encode(req)
	if err == nil {
		t.Fatal("encode accepted a request far over maxMessage")
	}
	for _, want := range []string{`"start"`, "sandboxed command's own argv"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}

func TestEncodeOversizeNamesTheEventOp(t *testing.T) {
	ev := event{Op: "ready", Netns: strings.Repeat("x", 70000)}
	_, err := encode(ev)
	if err == nil {
		t.Fatal("encode accepted an event far over maxMessage")
	}
	if !strings.Contains(err.Error(), `"ready"`) {
		t.Errorf("refusal %q does not name the event op", err)
	}
}
