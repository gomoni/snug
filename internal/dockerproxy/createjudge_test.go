package dockerproxy

import (
	"strings"
	"testing"
)

// createjudge_test.go pins the pure functions createjudge.go split out of
// create.go (issue #459 phase 1). Every path through handleCreate already
// exercises these indirectly via the package's existing suite — this file
// tests the functions directly, which is what libpodcreate.go's own decoder
// leans on without going through an HTTP request at all.

func TestCompatNSModeClassifiesEveryLegalSpelling(t *testing.T) {
	cases := []struct {
		raw  string
		mode string
	}{
		{"host", "host"},
		{"HOST", "host"},
		{" Host ", "host"},
		{"container:abc123", "container"},
		{"Container:ABC", "container"},
		{"ns:/proc/1/ns/net", "path"},
		{"NS:/proc/1/ns/net", "path"},
		{"default", "default"},
		{"bridge", "bridge"},
		{"none", "none"},
		{"private", "private"},
		{"shareable", "shareable"},
		{"keep-id", "keep-id"},
	}
	for _, c := range cases {
		got := compatNSMode(c.raw)
		if got.Mode != c.mode {
			t.Errorf("compatNSMode(%q).Mode = %q, want %q", c.raw, got.Mode, c.mode)
		}
		if got.Raw != c.raw {
			t.Errorf("compatNSMode(%q).Raw = %q, want the untouched client string", c.raw, got.Raw)
		}
	}
}

func TestJudgeNamespaceModeNetworkModeIsAnAllowlist(t *testing.T) {
	spell := compatFieldSpelling
	accepted := []string{"host", "default"}
	for _, raw := range accepted {
		if err := judgeNamespaceMode("NetworkMode", compatNSMode(raw), spell); err != nil {
			t.Errorf("NetworkMode %q: got %v, want accepted", raw, err)
		}
	}
	refused := []string{"none", "bridge", "private", "container:abc", "ns:/proc/1/ns/net", "pasta", "slirp4netns"}
	for _, raw := range refused {
		if err := judgeNamespaceMode("NetworkMode", compatNSMode(raw), spell); err == nil {
			t.Errorf("NetworkMode %q: got accepted, want refused", raw)
		}
	}
}

func TestJudgeNamespaceModeOtherFiveAreADenylist(t *testing.T) {
	spell := compatFieldSpelling
	for _, key := range []string{"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"} {
		for _, raw := range []string{"host", "container:abc", "ns:/proc/1/ns/net"} {
			if err := judgeNamespaceMode(key, compatNSMode(raw), spell); err == nil {
				t.Errorf("%s %q: got accepted, want refused", key, raw)
			}
		}
		// A value that is none of the three refused shapes is FORWARDED
		// unjudged for these five keys — the denylist, not an allowlist.
		for _, raw := range []string{"private", "shareable", "none", "keep-id", "nomap", "auto"} {
			if err := judgeNamespaceMode(key, compatNSMode(raw), spell); err != nil {
				t.Errorf("%s %q: got refused (%v), want forwarded", key, raw, err)
			}
		}
	}
}

func TestJudgeAskedFieldUsesTheSharedReasonTable(t *testing.T) {
	err := judgeAskedField("Privileged", compatFieldSpelling)
	if err == nil {
		t.Fatal("expected an error")
	}
	got := err.Error()
	if !containsAll(got, "HostConfig.Privileged", refusalReason["Privileged"]) {
		t.Errorf("message %q does not carry the canonical spelling and reason", got)
	}
}

func TestJudgeRestartPolicyNameAcceptsOnlyNo(t *testing.T) {
	for _, name := range []string{"", "no"} {
		if err := judgeRestartPolicyName(name, compatFieldSpelling); err != nil {
			t.Errorf("RestartPolicy %q: got %v, want accepted", name, err)
		}
	}
	for _, name := range []string{"always", "on-failure", "unless-stopped"} {
		if err := judgeRestartPolicyName(name, compatFieldSpelling); err == nil {
			t.Errorf("RestartPolicy %q: got accepted, want refused", name)
		}
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
