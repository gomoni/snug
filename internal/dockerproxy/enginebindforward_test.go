package dockerproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// The proxy half of issue #376: `-v <declared source>:<anything>` is forwarded
// as the GRAFT ROOT, and everything else about the anchored-source rule stays
// exactly as it was.
//
// Every test here drives the REAL create handler over a unix socket and asserts
// on the BODY that reached the engine, not on the status code. A 201 proves only
// that the request was allowed; what this ticket is about is WHICH STRING went
// upstream — the same reason issue #304's regression test asserts on the
// forwarded URI.

// declaredBindProxy starts a proxy whose policy carries one declared engine
// bind at <target>/data, with the graft that declaration produces, and creates
// the host directory so nothing here depends on a path that is not there.
//
// The GRAFT is in the policy on purpose even though checkOne's declared-bind arm
// runs before any graft check: it is the real shape of a run, and it is what
// makes the negative cases below meaningful — with the graft present,
// CheckEngineForwardedPath and CheckEngineBindSource both refuse anything under
// /snug/engine/binds, so a test that passes here cannot be passing because the
// graft was missing.
func declaredBindProxy(t *testing.T, access policy.Access) (sock string, eng *fakeEngine, target, declared string) {
	t.Helper()
	sock, eng, target = startProxyWithPolicy(t, policy.PodmanSocket,
		func(dir, target string) *policy.Policy {
			declared = filepath.Join(target, "data")
			if err := os.MkdirAll(declared, 0o755); err != nil {
				t.Fatal(err)
			}
			guest := policy.EngineBindsDir + "/data"
			return &policy.Policy{
				Mounts: map[string]policy.Mount{
					target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
					"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind, Access: policy.AccessRO},
				},
				EngineBinds: []policy.EngineBind{{
					Host: declared, Guest: guest, Access: access, From: []string{"work"},
				}},
				Grafts: map[string]policy.Graft{guest: {
					Mount: policy.Mount{Guest: guest, Host: declared, Kind: policy.KindGraft,
						Access: access, From: []string{"(snug)"}, Authored: true},
					Why: "bind this host tree into a container of its own choosing",
				}},
			}
		})
	return sock, eng, target, declared
}

// TestDeclaredBindInsideTheTargetIsForwardedAsTheGraftRoot is the ticket's own
// motivating case: `podman run -v ./data:/data` with the target at any depth.
//
// Before this, the same request was a 403 in every layout — the target is a
// read-write bind, so `data` is a plain name in a directory the payload can
// write, and the engine re-resolves the forwarded string at container START.
// Now snug forwards a path on its own read-only root instead, and the assertion
// is that BOTH halves happened: the graft path went upstream AND the host path
// did not.
func TestDeclaredBindInsideTheTargetIsForwardedAsTheGraftRoot(t *testing.T) {
	sock, eng, _, declared := declaredBindProxy(t, policy.AccessRW)

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+declared+`:/data"]}}`)
	if code != 200 {
		t.Fatalf("a declared engine bind was refused (status %d): %s", code, resp)
	}
	body := eng.lastBody.Load().(string)
	if !strings.Contains(body, policy.EngineBindsDir+"/data") {
		t.Errorf("the forwarded body does not name the graft root %s:\n%s",
			policy.EngineBindsDir+"/data", body)
	}
	if strings.Contains(body, declared) {
		t.Errorf("the forwarded body still carries the HOST path %s — the engine would re-resolve "+
			"that string at container start, which is the whole of issue #284:\n%s", declared, body)
	}
}

// TestOnlyDeclaredSourcesAreForwarded is the negative that bounds the grant.
// Fork A widens nothing except the exact paths a profile named.
//
//   - a relative source stays a 403. `-v ./data:/data` reaches the proxy as
//     the literal "./data" from a client that did not resolve it, and there is
//     nothing to resolve it against here.
//   - a SIBLING of the declaration is refused: the declaration is not a licence
//     over the target.
//   - the declared root plus a tail the REQUEST supplied is refused, and this is
//     the one that matters. open_tree(OPEN_TREE_CLONE) pins the inode at the
//     graft's root; crun re-resolves the whole forwarded string at container
//     start, so a relative symlink planted inside the grafted directory would be
//     followed in the engine's namespace. Declaring the subdirectory is the
//     answer; extending the match is not.
func TestOnlyDeclaredSourcesAreForwarded(t *testing.T) {
	sock, eng, target, declared := declaredBindProxy(t, policy.AccessRW)
	if err := os.MkdirAll(filepath.Join(declared, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "other"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		source string
	}{
		{"a relative source", "./data"},
		{"a sibling of the declaration", filepath.Join(target, "other")},
		{"the declared root plus a request-supplied tail", filepath.Join(declared, "sub")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.reached.Load()
			code, resp := post(t, sock, "/v1.41/containers/create",
				`{"Image":"alpine","HostConfig":{"Binds":["`+tc.source+`:/x"]}}`)
			if code != 403 {
				t.Fatalf("status %d, want 403 — Fork A grants only DECLARED sources: %s", code, resp)
			}
			if eng.reached.Load() != before {
				t.Error("the request reached the engine; it should have been refused here")
			}
			if strings.Contains(resp, policy.EngineBindsDir) {
				t.Errorf("the refusal names a graft path, so something matched the declaration "+
					"when nothing should have:\n%s", resp)
			}
		})
	}
}

// TestDeclaredBindThroughASymlinkIsJudgedResolved. A client naming a symlink
// that resolves TO the declared path is honoured, because checkOne resolves
// before it decides and the declaration is stored resolved — so both sides of
// the comparison are canonical, which is what stops the match being a string
// game.
//
// The negative in the same test is the one that would be a hole: a symlink
// pointing SOMEWHERE ELSE must not be forwarded as the declaration merely
// because its own name sits inside the declaration's parent. It asks for /usr
// READ-ONLY, which this run genuinely grants and genuinely forwards, so the
// case ends in a 200 and the assertion is on the SOURCE that went upstream — a
// refusal here would prove nothing, because a refusal is what a hole would also
// look like if the visibility check happened to fire first.
func TestDeclaredBindThroughASymlinkIsJudgedResolved(t *testing.T) {
	sock, eng, target, declared := declaredBindProxy(t, policy.AccessRW)

	toDeclared := filepath.Join(target, "link-ok")
	if err := os.Symlink(declared, toDeclared); err != nil {
		t.Fatal(err)
	}
	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+toDeclared+`:/data"]}}`)
	if code != 200 {
		t.Fatalf("a symlink resolving to the declared path was refused (status %d): %s", code, resp)
	}
	if body := eng.lastBody.Load().(string); !strings.Contains(body, policy.EngineBindsDir+"/data") {
		t.Errorf("the forwarded body does not name the graft root:\n%s", body)
	}

	toUsr := filepath.Join(target, "link-usr")
	if err := os.Symlink("/usr", toUsr); err != nil {
		t.Fatal(err)
	}
	code, resp = post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+toUsr+`:/x:ro"]}}`)
	if code != 200 {
		t.Fatalf("a read-only bind of /usr through a symlink was refused (status %d), so this "+
			"half measures nothing about which source is forwarded: %s", code, resp)
	}
	body := eng.lastBody.Load().(string)
	if strings.Contains(body, policy.EngineBindsDir) {
		t.Fatalf("a symlink to /usr was forwarded as the DECLARED bind's graft: %s", body)
	}
	if !strings.Contains(body, `"Source":"/usr"`) {
		t.Errorf("the forwarded body does not carry the resolved /usr:\n%s", body)
	}
}

// TestDeclaredBindRefusesAWritableRequestOnAReadOnlyDeclaration. A declaration's
// access is the sandbox's own, so the read-only case must not become writable by
// going through the graft. hostPathVisible refuses first here — the declaration
// and that predicate answer the same question about the same host path — and
// this test pins that the graft path is NOT what the client gets instead.
func TestDeclaredBindRefusesAWritableRequestOnAReadOnlyDeclaration(t *testing.T) {
	sock, eng, _, declared := declaredBindProxy(t, policy.AccessRO)

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+declared+`:/data"]}}`)
	if code == 200 {
		body := eng.lastBody.Load().(string)
		t.Fatalf("a writable bind of a read-only declaration was forwarded: %s", body)
	}
	if eng.reached.Load() != 0 {
		t.Error("the request reached the engine; it should have been refused here")
	}
	// The read-only spelling of the same request IS honoured, which is what
	// makes the refusal above about the access rather than about the path.
	code, resp = post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+declared+`:/data:ro"]}}`)
	if code != 200 {
		t.Fatalf("the read-only spelling was also refused (status %d), so the test above proves "+
			"nothing about access: %s", code, resp)
	}
	if body := eng.lastBody.Load().(string); !strings.Contains(body, policy.EngineBindsDir+"/data") {
		t.Errorf("the forwarded body does not name the graft root:\n%s", body)
	}
}

// TestBindRefusalNamesEngineBindsAsTheRemedy. The refusal a user meets when
// their `-v` is inside the target had, for a whole milestone, no remedy to offer
// at depth — the message said so and stopped (issue #463's own fix, and the
// sentence policy.swappableFix carried). It now names the grant, and the test
// asserts the WORD rather than a sentence, because the word is what a user can
// act on.
func TestBindRefusalNamesEngineBindsAsTheRemedy(t *testing.T) {
	sock, eng, target := startProxyWithPolicy(t, policy.PodmanSocket,
		func(dir, target string) *policy.Policy {
			return &policy.Policy{Mounts: map[string]policy.Mount{
				dir:    {Guest: dir, Kind: policy.KindTmpfs, Access: policy.AccessRW},
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			}}
		})
	inside := filepath.Join(target, "data")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+inside+`:/data"]}}`)
	if code != 403 {
		t.Fatalf("status %d, want 403 — an UNDECLARED path inside the target is still refused: %s",
			code, resp)
	}
	if eng.reached.Load() != 0 {
		t.Error("the request reached the engine")
	}
	if !strings.Contains(resp, "engine_binds") {
		t.Errorf("the refusal does not name engine_binds, so a user at this depth is told there "+
			"is no way forward when there is one:\n%s", resp)
	}
}
