package dockerproxy

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// advertisedSource pulls the path a bind refusal tells the user to bind
// instead. The tests below follow that advice rather than asserting a
// sentence, which is the only form that can catch advice the next check
// rejects — the defect issue #463 was filed for.
var advertisedSource = regexp.MustCompile(`Or bind (\S+) —`)

// TestBindRefusalOfASnugCreatedFilesystemDoesNotClaimItIsInvisible pins the
// FALSE half of issue #463.
//
// Measured inside a real sandbox: `docker run -v /tmp:/mnt` was refused with
// "this sandbox cannot see /tmp as writable" in the same run where `touch
// /tmp/probe-writable` succeeded and snug's own generated CLAUDE.md listed
// /tmp among the writable paths. The predicate hostPathVisible actually
// answers is "is a KindBind mount behind this name", and a tmpfs snug created
// for the run is not one — visible, writable, and still not forwardable.
func TestBindRefusalOfASnugCreatedFilesystemDoesNotClaimItIsInvisible(t *testing.T) {
	sock, eng, target := startProxyWithPolicy(t, policy.PodmanSocket,
		func(dir, target string) *policy.Policy {
			return &policy.Policy{Mounts: map[string]policy.Mount{
				// The shape of the measured run: an ephemeral filesystem the
				// payload can write, with the project bound inside it.
				dir:    {Guest: dir, Kind: policy.KindTmpfs, Access: policy.AccessRW},
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			}}
		})
	tmpfs := filepath.Dir(target)

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["`+tmpfs+`:/mnt"]}}`)
	if code != 403 {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if eng.reached.Load() != 0 {
		t.Error("the request reached the engine; it should have been refused here")
	}
	msg := denyMessage(resp)

	if strings.Contains(msg, "cannot see "+tmpfs) {
		t.Errorf("the refusal claims the sandbox cannot see a path it can write:\n  %s", msg)
	}
	if !strings.Contains(msg, "not a bind of a host directory") {
		t.Errorf("the refusal does not give the real reason (no host directory behind the "+
			"name):\n  %s", msg)
	}
	// The remedy arm that must not regress: this run DOES have an acceptable
	// source, so the message names it.
	m := advertisedSource.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("no source advertised, but this run has one (%s):\n  %s", target, msg)
	}
	if m[1] != target {
		t.Errorf("advertised %q, want the target %q:\n  %s", m[1], target, msg)
	}
}

// TestBindRefusalAdviceIsAcceptedByTheVeryNextRequest is the control that
// makes the sentence above worth writing: it TAKES the advice.
//
// Issue #463's second defect was that the advertised remedy ("mount a path
// inside <target>") is refused by the anchored-source rule one line further
// down — a name inside the target sits in a directory the payload can write.
// Asserting on the text could never have caught that; sending the advertised
// source back does.
func TestBindRefusalAdviceIsAcceptedByTheVeryNextRequest(t *testing.T) {
	sock, eng, _ := startProxy(t)

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["/etc:/x"]}}`)
	if code != 403 {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	msg := denyMessage(resp)
	m := advertisedSource.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("the refusal advertises no source at all:\n  %s", msg)
	}

	before := eng.reached.Load()
	code, resp = post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["`+m[1]+`:/x"]}}`)
	if code != 200 {
		t.Fatalf("snug refused the source its own refusal told the user to bind.\n"+
			"  advised: %s\n  status %d: %s", m[1], code, denyMessage(resp))
	}
	if eng.reached.Load() == before {
		t.Error("the advised bind was answered without reaching the engine")
	}
}

// TestBindRefusalNamesNoSourceWhenNoneIsAcceptable is the other half of the
// same defect: where the run has NO acceptable source, the refusal must say so
// rather than name one the next check rejects.
//
// The shape is the measured one — a target three levels below an ephemeral
// filesystem, so the anchored-source rule refuses the target itself at the
// first plain directory name under the tmpfs.
func TestBindRefusalNamesNoSourceWhenNoneIsAcceptable(t *testing.T) {
	var tmpfs string
	sock, eng, target := startProxyWithPolicy(t, policy.PodmanSocket,
		func(dir, target string) *policy.Policy {
			tmpfs = filepath.Dir(dir)
			return &policy.Policy{Mounts: map[string]policy.Mount{
				// dir itself is a plain name inside the tmpfs — not a mount
				// root — so no ancestor of the target is anchored.
				tmpfs:  {Guest: tmpfs, Kind: policy.KindTmpfs, Access: policy.AccessRW},
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			}}
		})

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["`+tmpfs+`:/mnt"]}}`)
	if code != 403 {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if eng.reached.Load() != 0 {
		t.Error("the request reached the engine; it should have been refused here")
	}
	msg := denyMessage(resp)

	if !strings.Contains(msg, "Bind mounts are unavailable in this run") {
		t.Errorf("the refusal does not say bind mounts are unavailable:\n  %s", msg)
	}
	if strings.Contains(msg, "Or bind ") {
		t.Errorf("the refusal advertises a source in a run that has none:\n  %s", msg)
	}
	// The precise failure issue #463 recorded: the target named as the remedy,
	// and the next refusal calling it impossible.
	if strings.Contains(msg, target) {
		t.Errorf("the refusal names the target, which the anchored-source rule refuses:\n  %s", msg)
	}

	// POSITIVE CONTROL: the target really is unacceptable here, so the absence
	// above is the rule firing and not a fixture that never had a source.
	code, resp = post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["`+target+`:/x"]}}`)
	if code != 403 {
		t.Fatalf("control: the target was ACCEPTED (status %d), so this fixture does not "+
			"reproduce the no-acceptable-source condition at all: %s", code, resp)
	}
}
