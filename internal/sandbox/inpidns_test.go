package sandbox

import (
	"os"
	"strings"
	"testing"
)

// TestEnterPidNSRefusesWhenItIsNotPidOne is the guard on the verb's ONE
// precondition, and it runs unprivileged because that is the point: the check
// is what stops `snug __inpidns 0 /bin/true`, typed at a shell, from mounting
// a procfs over the caller's own /proc in the caller's own mount namespace.
// The clone in exec.go is the only thing that produces pid 1 here.
func TestEnterPidNSRefusesWhenItIsNotPidOne(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("this test process IS pid 1 (a container's init, or a pid namespace of its " +
			"own), so the refusal under test cannot fire")
	}
	err := EnterPidNS([]string{"0", "/bin/true"})
	if err == nil {
		t.Fatal("EnterPidNS returned nil outside a pid namespace of its own — it either " +
			"mounted a procfs over this process's /proc or exec'd /bin/true, and both are " +
			"failures of the same guard")
	}
	if !strings.Contains(err.Error(), "not pid 1") {
		t.Errorf("the refusal does not name the reason: %v", err)
	}
}

// TestEnterPidNSRefusesAMalformedRequest keeps the usage errors distinct from
// the refusal above: a caller that got the argument shape wrong has a
// different bug from one that reached the verb from the wrong place, and one
// message for both would hide whichever is rarer.
func TestEnterPidNSRefusesAMalformedRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"empty", nil, "usage"},
		{"count only", []string{"3"}, "usage"},
		{"count is not a number", []string{"three", "/bin/true"}, "bad descriptor count"},
		{"count is negative", []string{"-1", "/bin/true"}, "bad descriptor count"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EnterPidNS(tc.argv)
			if err == nil {
				t.Fatalf("EnterPidNS(%q) returned nil", tc.argv)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("EnterPidNS(%q) = %v, which does not name %q", tc.argv, err, tc.want)
			}
		})
	}
}
