package dockerproxy

import (
	"slices"
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

// TestJudgeBindOptionsAllowlist pins judgeBindOptions directly — the one
// allowlist both create.go's Binds parser and libpodcreate.go's mounts[]
// decoder now call (issue #459: they used to disagree, one refusing an
// option the other forwarded verbatim).
func TestJudgeBindOptionsAllowlist(t *testing.T) {
	// The accepted set, individually and mixed. "" is the shape an absent
	// third bind field or an omitted libpod "options" entry takes, not
	// something a client spells literally.
	accepted := []struct {
		opts    []string
		wantRO  bool
		wantFwd []string
	}{
		{nil, false, nil},
		{[]string{""}, false, nil},
		{[]string{"ro"}, true, []string{"ro"}},
		{[]string{"rw"}, false, nil},
		{[]string{"z"}, false, []string{"z"}},
		{[]string{"Z"}, false, []string{"Z"}},
		{[]string{"ro", "z"}, true, []string{"ro", "z"}},
		{[]string{"ro", "z", "Z"}, true, []string{"ro", "z", "Z"}},
		// The rebuild is CANONICAL, not a copy of what arrived: "rw" and the
		// redundant ordering are both gone, only "ro"+"z" survive and "ro"
		// sorts first regardless of where the client put it. A future
		// refactor that forwards m.Options unchanged after a successful
		// judgeBindOptions call — the shape issue #459 was — would still
		// forward "rw" here, which this pins against.
		{[]string{"rw", "ro", "z"}, true, []string{"ro", "z"}},
	}
	for _, c := range accepted {
		ro, fwd, err := judgeBindOptions(c.opts)
		if err != nil {
			t.Errorf("judgeBindOptions(%v): got refused (%v), want accepted", c.opts, err)
			continue
		}
		if ro != c.wantRO {
			t.Errorf("judgeBindOptions(%v).ro = %v, want %v", c.opts, ro, c.wantRO)
		}
		if !slices.Equal(fwd, c.wantFwd) {
			t.Errorf("judgeBindOptions(%v).forward = %v, want %v", c.opts, fwd, c.wantFwd)
		}
	}

	// The refused set: everything mount(8) offers that is not ro/rw/z/Z/"" —
	// nodev/nosuid strippers, propagation modes that reach back out of the
	// container, and podman's own id-mapping options that mutate the bind
	// SOURCE on the host. judgeBindOptions' own comment names the class.
	refused := []string{
		"suid", "dev", "exec", "nosuid", "nodev", "noexec",
		"shared", "rshared", "slave", "rslave", "private", "rprivate",
		"unbindable", "runbindable", "bind", "rbind",
		"U", "idmap",
	}
	for _, o := range refused {
		ro, fwd, err := judgeBindOptions([]string{"ro", o})
		if err == nil {
			t.Errorf("judgeBindOptions([ro %s]): got accepted (ro=%v forward=%v), want refused", o, ro, fwd)
			continue
		}
		if !strings.Contains(err.Error(), o) {
			t.Errorf("judgeBindOptions([ro %s]) error %q does not name the refused option", o, err)
		}
		// On refusal forward must be nil, not whatever was accumulated before
		// the bad option was reached — a caller that forwarded a non-nil
		// slice on an error return would be forwarding a PARTIAL judgement.
		if fwd != nil {
			t.Errorf("judgeBindOptions([ro %s]): forward = %v on a refusal, want nil", o, fwd)
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
