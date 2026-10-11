package sandbox

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestRelaySocketsAreRefusedWhereNothingCanMakeOrHoldThem: only the stage can
// create a socket in the sandbox's netns, so a count on a stageless policy
// cannot be honoured and is refused rather than quietly dropped (invariant 5);
// and a count with no OnRelaySockets would be sockets in N held by nobody.
func TestRelaySocketsAreRefusedWhereNothingCanMakeOrHoldThem(t *testing.T) {
	hold := func([]*os.File) {}
	for _, c := range []struct {
		name string
		p    *policy.Policy
		opts Options
		want string
	}{
		{"no stage", &policy.Policy{Topology: policy.Topology{Netns: policy.NetnsSandbox}},
			Options{RelaySockets: 1, OnRelaySockets: hold}, "no stage"},
		{"nobody holds them", &policy.Policy{Topology: policy.Topology{Netns: policy.NetnsStage}},
			Options{RelaySockets: 1}, "OnRelaySockets is nil"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Run(c.p, os.Getuid(), os.Getgid(), c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Run = %v, want a refusal containing %q", err, c.want)
			}
		})
	}
}
