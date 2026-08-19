package dockerproxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// fakeEngine stands in for podman and records whether it was reached. "snug
// refused" and "the engine refused" look alike to a client; only this tells
// them apart, and the difference is the entire point of the proxy.
type fakeEngine struct {
	reached  atomic.Int32
	lastBody atomic.Value
}

func startProxy(t *testing.T) (sock string, eng *fakeEngine, target string) {
	t.Helper()
	return startProxyMode(t, policy.PodmanSocket)
}

// startProxyMode is startProxy with the engine surface the case needs. Building
// is gated on policy.PodmanBuild, so the build tests ask for it explicitly and
// every other test keeps the container-only mode.
func startProxyMode(t *testing.T, mode policy.PodmanMode) (sock string, eng *fakeEngine, target string) {
	t.Helper()
	dir := t.TempDir()
	target = filepath.Join(dir, "proj")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}

	eng = &fakeEngine{}
	up := filepath.Join(dir, "engine.sock")
	ln, err := net.Listen("unix", up)
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eng.reached.Add(1)
		// io.ReadAll, not a single Read: a short read would record a TRUNCATED
		// body, and every "the escape field did not reach the engine" assertion
		// that inspects lastBody would then be satisfied by truncation rather
		// than by filtering.
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		eng.lastBody.Store(string(b))
		w.WriteHeader(200)
		w.Write([]byte(`{"Id":"deadbeef"}`))
	}))
	t.Cleanup(func() { ln.Close() })

	pol := &policy.Policy{
		Target: target,
		Podman: mode,
		Mounts: map[string]policy.Mount{
			target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind, Access: policy.AccessRO},
		},
	}
	sock = filepath.Join(dir, "proxy.sock")
	p, err := New(pol, up, sock, "snug.run=test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return sock, eng, target
}

func post(t *testing.T, sock, path, body string) (int, string) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest("POST", "http://d"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Write(conn)
	resp, err := http.ReadResponse(bufReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(buf)
}

// refuse asserts that a create body is refused HERE, by the reason we think, and
// never reaches the engine.
//
// wantMsg is not decoration. Without it a table entry only establishes "something
// refused this", and a case can silently stop exercising the rule it was written
// for while still passing — which is exactly what happened to the two entries
// below that named /tmp and a relative path: both were refused by the visibility
// check, so deleting the option parser and the absolute-path check changed
// nothing and the suite stayed green. Naming the reason pins each case to one
// mechanism.
func refuse(t *testing.T, sock string, eng *fakeEngine, path, body, wantMsg string) {
	t.Helper()
	before := eng.reached.Load()
	code, resp := post(t, sock, path, body)
	if code != http.StatusForbidden {
		t.Errorf("status %d, want 403: %s", code, resp)
	}
	if eng.reached.Load() != before {
		t.Error("the request reached the engine; it should have been refused here")
	}
	if msg := denyMessage(resp); !strings.Contains(msg, wantMsg) {
		t.Errorf("refused, but not for the reason this case exists to test.\n"+
			"  want the message to contain: %q\n  got: %s", wantMsg, msg)
	}
}

// denyMessage pulls the human-readable reason out of a 403 body. The body is
// JSON, so quotes inside the message arrive escaped and a raw substring match
// against a quoted path or option would never fire.
func denyMessage(resp string) string {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(resp), &body); err != nil || body.Message == "" {
		return resp
	}
	return body.Message
}

// THE rule: a container may bind a host path only if the sandbox can see it.
func TestContainerCannotMountWhatTheSandboxCannot(t *testing.T) {
	sock, eng, target := startProxy(t)

	for _, tc := range []struct{ name, body, wantMsg string }{
		{"the whole host filesystem", `{"HostConfig":{"Binds":["/:/host"]}}`,
			"cannot see / as writable"},
		{"/etc, which sys grants read-only", `{"HostConfig":{"Binds":["/etc:/etc"]}}`,
			"cannot see /etc as writable"},
		{"/usr writable, granted only read-only", `{"HostConfig":{"Binds":["/usr:/u"]}}`,
			"cannot see /usr as writable"},

		// The absolute-path rule, pinned by its own message. As `../..` this case
		// was refused by the VISIBILITY check instead — the proxy resolves a
		// relative source against snug's cwd, which is never a granted path — so
		// deleting filepath.IsAbs left it passing.
		{"a relative source", `{"HostConfig":{"Binds":["../..:/x"]}}`,
			"must be an absolute path"},
		{"a bare relative source", `{"HostConfig":{"Binds":["build:/x"]}}`,
			"must be an absolute path"},

		// The structured Mounts form, which nothing covered at all: every escape
		// below can equally be written this way, and `docker run --mount` does.
		{"a volume mount, whose backing store is not knowable here",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"v","Target":"/v"}]}}`,
			`mount type "volume" is not permitted`},
		{"a tmpfs mount",
			`{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t"}]}}`,
			`mount type "tmpfs" is not permitted`},
		{"the host filesystem via the structured form",
			`{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]}}`,
			"cannot see / as writable"},
		{"a read-only bind of a path the sandbox never got",
			`{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/x","ReadOnly":true}]}}`,
			"cannot see /etc as read-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, "/v1.41/containers/create", tc.body, tc.wantMsg)
		})
	}

	// The target IS visible, so this one can only be refused by the option
	// parser. Written against /tmp it was refused by visibility instead, and the
	// option parser could be deleted without failing anything.
	t.Run("propagation smuggled through bind options on a PERMITTED path", func(t *testing.T) {
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["`+target+`:/src:rshared"]}}`,
			`bind option "rshared" is not permitted`)
	})
	// Control for the case above: the same bind without the smuggled option is
	// accepted, so the refusal is attributable to `rshared` alone.
	t.Run("control: the same bind without the option is allowed", func(t *testing.T) {
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["`+target+`:/src:ro"]}}`)
		if code != 200 {
			t.Fatalf("status %d, want 200 — if this cannot be accepted, the case above "+
				"proves nothing about the option parser: %s", code, resp)
		}
	})
}

// The common legitimate case must still work, or nobody will use the profile.
func TestContainerMayMountTheTarget(t *testing.T) {
	sock, eng, target := startProxy(t)
	code, body := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":["`+target+`:/src"]}}`)
	if code != 200 {
		t.Fatalf("status %d, want 200: %s", code, body)
	}
	if eng.reached.Load() == 0 {
		t.Fatal("a legitimate mount never reached the engine")
	}
	sent, _ := eng.lastBody.Load().(string)
	if !strings.Contains(sent, target) {
		t.Errorf("the approved mount was not forwarded:\n%s", sent)
	}
	// Hardening must be injected regardless of what the client asked for.
	if !strings.Contains(sent, "no-new-privileges") {
		t.Errorf("SecurityOpt was not injected:\n%s", sent)
	}
}

func TestEscapeFieldsAreRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, tc := range []struct{ name, body, wantMsg string }{
		{"privileged", `{"HostConfig":{"Privileged":true}}`,
			"HostConfig.Privileged is not permitted"},
		{"added capabilities", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
			"HostConfig.CapAdd is not permitted"},
		{"device passthrough", `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`,
			"HostConfig.Devices is not permitted"},
		{"an alternate runtime", `{"HostConfig":{"Runtime":"/tmp/evil"}}`,
			"HostConfig.Runtime is not permitted"},
		// NetworkMode="host" is NOT in this table any more (issue #63, Tier
		// B): the container engine now runs INSIDE this sandbox's own
		// network namespace N, so "join the engine's current netns" joins
		// N, not the real host's — see TestNetworkModeHostIsAllowedButOtherHostModesAreNot.
		{"another container's netns", `{"HostConfig":{"NetworkMode":"container:abc"}}`,
			"naming a namespace snug did not author"},
		{"host pid namespace", `{"HostConfig":{"PidMode":"host"}}`,
			"There is no flag that enables it"},
		{"a raw netns path", `{"HostConfig":{"NetworkMode":"ns:/proc/1/ns/net"}}`,
			"naming a namespace snug did not author"},
		{"the host user namespace", `{"HostConfig":{"UsernsMode":"host"}}`,
			"snug decides a container's user namespace"},
		{"published ports", `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostPort":"8080"}]}}}`,
			"HostConfig.PortBindings is not permitted"},
		{"mounts inherited from another container", `{"HostConfig":{"VolumesFrom":["other"]}}`,
			"HostConfig.VolumesFrom is not permitted"},
		{"a security-opt of its own", `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`,
			"HostConfig.SecurityOpt is not permitted"},
		{"anonymous volumes", `{"Volumes":{"/data":{}}}`,
			"Volumes is not permitted"},

		// REGRESSION, confirmed by the redteam agent (M4): podman's k8s-file and
		// json-file log drivers honour a `path` option, and conmon then creates
		// and writes that file ON THE HOST, as your uid, needing no privileges.
		// It was used to plant a file in a $HOME the sandbox itself sees only as
		// an empty tmpfs — an arbitrary host-file write through a field nobody
		// reads as dangerous. LogConfig was on the denylist from the fix onwards
		// and had no test until this one: deleting the entry failed nothing.
		{"a log driver writing to a host path (redteam M4)",
			`{"HostConfig":{"LogConfig":{"Type":"k8s-file","Config":{"path":"/home/user/.bashrc"}}}}`,
			"HostConfig.LogConfig is not permitted"},
		{"annotations, which podman routes to the OCI runtime",
			`{"HostConfig":{"Annotations":{"run.oci.keep_original_groups":"1"}}}`,
			"HostConfig.Annotations is not permitted"},
		{"a cgroup outside this sandbox's own", `{"HostConfig":{"CgroupParent":"/"}}`,
			"HostConfig.CgroupParent is not permitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, "/v1.41/containers/create", tc.body, tc.wantMsg)
		})
	}
}

// REGRESSION, confirmed by the redteam agent (M4): the proxy understands the
// DOCKER-COMPAT create schema. podman's native libpod SpecGenerator body is a
// different shape — lowercase top-level `mounts`, `privileged`, `netns`,
// `cap_add`, `devices` — and an earlier normalise() collapsed the `libpod`
// segment and forgot it, so /v5.0.0/libpod/containers/create routed into
// handleCreate, which inspected none of those fields and forwarded the body
// verbatim. The agent bound the host's ~/.ssh into a privileged container with
// host networking and read a private key out.
//
// A filter that understands one schema must never be handed the other, so
// body-bearing libpod endpoints are refused outright rather than forwarded.
func TestLibpodNativeBodyIsRefusedRatherThanForwardedUnexamined(t *testing.T) {
	sock, eng, _ := startProxy(t)

	// The exact escape: everything dangerous, in libpod spelling.
	escape := `{"image":"alpine","privileged":true,"netns":{"nsmode":"host"},
	            "cap_add":["SYS_ADMIN"],
	            "mounts":[{"type":"bind","source":"/","destination":"/host"}]}`

	for _, path := range []string{
		"/v5.0.0/libpod/containers/create",
		"/libpod/containers/create",
		"/v4.0.0/libpod/volumes/create",
		"/v5.0.0/libpod/images/pull",
		"/v5.0.0/libpod/pods/create",
		"/v5.0.0/libpod/play/kube",
	} {
		t.Run(path, func(t *testing.T) {
			refuse(t, sock, eng, path, escape, "the libpod-native API is not supported")
		})
	}

	// CONTROL, and it is the half that keeps the test honest: the same escape on
	// the DOCKER-COMPAT path reaches handleCreate and is refused there, by a
	// different message. Without this, "libpod is refused" would be satisfied by
	// a proxy that refused every create request, and the test would still pass if
	// the docker-compat path stopped working.
	t.Run("control: the docker-compat path is judged, not blanket-refused", func(t *testing.T) {
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"Privileged":true}}`,
			"HostConfig.Privileged is not permitted")
	})

	// CONTROL: read-only libpod routes stay usable. If this stopped being true
	// the refusal above would be a blanket ban on libpod and would prove nothing
	// about schema confusion.
	t.Run("control: a read-only libpod route still works", func(t *testing.T) {
		before := eng.reached.Load()
		segs, libpod, ok := normaliseFull("/v5.0.0/libpod/containers/json")
		if !ok || !libpod {
			t.Fatalf("normaliseFull did not recognise the libpod prefix: %v %v %v", segs, libpod, ok)
		}
		if bodyBearing(segs, http.MethodGet) {
			t.Error("a GET carries no body to misread and must not be refused as libpod")
		}
		if !allowed(segs) {
			t.Error("listing containers over libpod should still be allowed")
		}
		_ = before
	})
}

// REGRESSION, confirmed by the redteam agent (M4): the visibility check was
// applied to the literal string the client sent. The sandbox's writable target
// is attacker-controlled, so `ln -s /etc $TARGET/link` produced a bind source
// that passed the check — it is inside the target — while podman resolved it on
// the HOST and mounted /etc.
//
// The fix resolves symlinks before deciding AND forwards the resolved path, so
// podman is asked for the thing that was actually approved.
func TestSymlinkedBindSourceIsJudgedAfterResolution(t *testing.T) {
	sock, eng, target := startProxy(t)

	// A symlink inside the writable target, pointing at a path the sandbox was
	// never granted. This is exactly what a payload can create.
	escape := filepath.Join(target, "innocent")
	if err := os.Symlink("/etc", escape); err != nil {
		t.Fatal(err)
	}
	// A second one, one level deeper, because the check has to survive resolution
	// of an ANCESTOR component and not just of the leaf.
	deep := filepath.Join(target, "sub")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(deep, "link")); err != nil {
		t.Fatal(err)
	}

	// CONTROL: a plain path inside the target is accepted, so a refusal below is
	// attributable to where the link points and not to the target being unusable.
	if code, resp := post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["`+filepath.Join(target, "sub")+`:/src"]}}`); code != 200 {
		t.Fatalf("control: a real directory inside the target must be mountable "+
			"(status %d): %s", code, resp)
	}

	for _, src := range []string{escape, filepath.Join(deep, "link"), filepath.Join(escape, "hosts")} {
		t.Run(src, func(t *testing.T) {
			refuse(t, sock, eng, "/v1.41/containers/create",
				`{"HostConfig":{"Binds":["`+src+`:/x"]}}`, "cannot see /etc")
		})
	}

	// And the RESOLVED path is what gets forwarded, so podman is asked for the
	// thing that was approved rather than for a link it will re-resolve itself.
	// A link inside the target pointing at another place inside the target is
	// legitimate and must still work.
	inner := filepath.Join(target, "real")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(target, "alias")
	if err := os.Symlink(inner, alias); err != nil {
		t.Fatal(err)
	}
	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"HostConfig":{"Binds":["`+alias+`:/src"]}}`)
	if code != 200 {
		t.Fatalf("a symlink to a permitted path inside the target should be allowed "+
			"(status %d): %s", code, resp)
	}
	sent, _ := eng.lastBody.Load().(string)
	if !strings.Contains(sent, inner) {
		t.Errorf("the RESOLVED path was not what reached the engine; podman would "+
			"re-resolve the link itself, which is the TOCTOU this fix closes:\n%s", sent)
	}
	if strings.Contains(sent, `"Source":"`+alias+`"`) {
		t.Errorf("the unresolved symlink was forwarded as the mount source:\n%s", sent)
	}
}

// A local volume with driver options is how a host path gets planted under a
// name, to be referenced innocently later.
func TestVolumeDriverOptionsAreRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, body, wantMsg string }{
		{"a local volume that is really a host bind",
			`{"Name":"v","Driver":"local","Options":{"type":"none","o":"bind","device":"/"}}`,
			"volume Options is not permitted"},
		{"the same thing spelled DriverOpts",
			`{"Name":"v","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}}`,
			"volume DriverOpts is not permitted"},
		{"an NFS share",
			`{"Name":"v","Options":{"type":"nfs","o":"addr=10.0.0.1","device":":/export"}}`,
			"volume Options is not permitted"},
		{"a non-local driver",
			`{"Name":"v","Driver":"sshfs"}`,
			`volume driver "sshfs" is not permitted`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, "/v1.41/volumes/create", tc.body, tc.wantMsg)
		})
	}

	// CONTROL: a plain local volume with no options is still allowed, so the
	// refusals above are attributable to the options and not to volume creation
	// being blocked outright.
	code, resp := post(t, sock, "/v1.41/volumes/create", `{"Name":"plain","Driver":"local"}`)
	if code != 200 {
		t.Errorf("control: an ordinary local volume must still be creatable "+
			"(status %d): %s", code, resp)
	}
}

// `docker cp` stays refused — CONTAINER-CLIENT.md §9 found the equivalence
// argument for allowing it unsound: archive/export run on the ENGINE, outside
// the sandbox, as the host uid, and archive path resolution is the home of
// the CVE-2018-15664 symlink-escape class. This pins the refusal AND that its
// message names the alternative that IS bounded by the sandbox's own mount
// namespace, rather than the generic "endpoint ... is not permitted".
func TestDockerCpStaysRefusedWithTheExecTarAlternativeNamed(t *testing.T) {
	sock, eng, _ := startProxy(t)
	refuse(t, sock, eng, "/v1.41/containers/abc/archive", "", "docker exec")
}

func TestEndpointAllowlist(t *testing.T) {
	for _, tc := range []struct {
		path string
		segs []string
		want bool
	}{
		{"/v1.41/_ping", nil, true},
		{"/v1.41/containers/json", nil, true},
		{"/v5.0.0/libpod/containers/json", nil, true},
		{"/v1.41/containers/abc/start", nil, true},
		// attach and exec are permitted: the container is already the sandbox's
		// own, created under this policy, so a shell in it grants nothing that
		// running it did not. Refusing attach broke `docker run` outright.
		{"/v1.41/containers/abc/exec", nil, true},
		{"/v1.41/containers/abc/attach", nil, true},
		// These are host-filesystem channels and stay refused.
		{"/v1.41/containers/abc/archive", nil, false},
		{"/v1.41/containers/abc/export", nil, false},
		{"/v1.41/containers/abc/commit", nil, false},
		{"/v1.41/build", nil, false},
		{"/v1.41/images/load", nil, false},
		{"/v1.41/commit", nil, false},
	} {
		segs, ok := normalise(tc.path)
		if !ok {
			t.Errorf("%s failed to normalise", tc.path)
			continue
		}
		if got := allowed(segs); got != tc.want {
			t.Errorf("%s -> allowed=%v, want %v (segs %v)", tc.path, got, tc.want, segs)
		}
	}
}

// Without this, /containers/../build reaches the build endpoint while matching
// an allowed prefix.
func TestPathTraversalIsRejected(t *testing.T) {
	for _, p := range []string{"/v1.41/containers/../build", "/../build", "/v1.41/./build"} {
		if _, ok := normalise(p); ok {
			t.Errorf("%s was accepted; it must be rejected outright", p)
		}
	}
}

func bufReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// postHdr is post with extra request headers, which is the whole subject of the
// hijack regression below.
func postHdr(t *testing.T, sock, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest("POST", "http://d"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(buf)
}

// ── the two escapes found by mutation-testing the suite (M4 review) ──────────

// REGRESSION: an `Upgrade:` header made the client, not snug, decide whether
// the filter ran.
//
// isHijack returned true on Upgrade/Connection: upgrade for ANY path, and
// ServeHTTP consults it BEFORE handleCreate — so a create request carrying the
// header went straight to hijack(), which writes it to podman byte for byte.
// {"Privileged":true,"Binds":["/:/host"]} reached the engine, 200 OK. Verified
// against a real engine before the fix.
//
// The hijack set is now decided by PATH. A header may narrow it (a detached
// start is an ordinary POST) but can never widen it.
func TestUpgradeHeaderCannotBypassTheFilter(t *testing.T) {
	const escape = `{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/host"]}}`

	// CONTROL 1: without the header this body is refused. If it were not, the
	// assertion below would pass on a proxy that filters nothing at all.
	t.Run("control: the body is refused on the ordinary path", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		refuse(t, sock, eng, "/v1.41/containers/create", escape, "HostConfig.Privileged")
	})

	// CONTROL 2: a real streaming endpoint still upgrades and still reaches the
	// engine. Without it, "the header no longer hijacks" would be equally true
	// of a proxy that had simply lost the ability to attach — and `docker run`
	// in the foreground would be broken with the suite green.
	t.Run("control: attach still streams to the engine", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		before := eng.reached.Load()
		code, resp := postHdr(t, sock, "/v1.41/containers/abc/attach", "",
			map[string]string{"Upgrade": "tcp", "Connection": "Upgrade"})
		if eng.reached.Load() == before {
			t.Fatalf("attach did not reach the engine (status %d): %s", code, resp)
		}
	})

	// THE ESCAPE, in every spelling of the header that used to work.
	for _, hdr := range []map[string]string{
		{"Upgrade": "tcp"},
		{"Connection": "Upgrade"},
		{"Connection": "keep-alive, Upgrade"},
		{"Upgrade": "tcp", "Connection": "Upgrade"},
		{"Upgrade": "h2c"},
	} {
		t.Run("create with headers "+fmt.Sprint(hdr), func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			before := eng.reached.Load()
			code, resp := postHdr(t, sock, "/v1.41/containers/create", escape, hdr)
			if eng.reached.Load() != before {
				t.Fatalf("the create request reached the engine unfiltered; "+
					"the client chose whether snug's filter ran. body seen by engine: %v",
					eng.lastBody.Load())
			}
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, resp)
			}
			if msg := denyMessage(resp); !strings.Contains(msg, "HostConfig.Privileged") {
				t.Errorf("refused, but not by the create filter: %s", msg)
			}
		})
	}
}

// A detached start must NOT be hijacked — it is an ordinary POST whose response
// the client parses. Pins the one direction in which the header still counts.
func TestDetachedStartIsNotHijacked(t *testing.T) {
	segs, _ := normalise("/v1.41/containers/abc/start")
	plain, _ := http.NewRequest("POST", "http://d/", nil)
	if isHijack(segs, plain) {
		t.Error("a start with no upgrade header was treated as a stream")
	}
	up, _ := http.NewRequest("POST", "http://d/", nil)
	up.Header.Set("Upgrade", "tcp")
	if !isHijack(segs, up) {
		t.Error("a start WITH an upgrade header must stream, or foreground `docker run` breaks")
	}
}

// REGRESSION: a case-variant JSON key bypassed every denylist.
//
// encoding/json matches struct fields case-INSENSITIVELY, so podman reads
// {"privileged":true} as Privileged — while snug's exact-key map lookups did
// not. json.Marshal then sorts map keys, so snug's injected "Privileged":false
// was emitted first and the attacker's lowercase variant, arriving last, won
// the decode. Verified reaching a real engine:
// {"hostconfig":{"privileged":true,"binds":["/:/host"]}} started a privileged
// container with the host root bound.
func TestCaseVariantKeysCannotBypassTheDenylist(t *testing.T) {
	t.Run("control: the canonical spelling is refused", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"HostConfig":{"Privileged":true}}`, "HostConfig.Privileged")
	})

	t.Run("control: an ordinary create still succeeds", func(t *testing.T) {
		sock, _, target := startProxy(t)
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"Binds":["`+target+`:/w"]}}`)
		if code != 200 {
			t.Fatalf("a legitimate create must still work (status %d): %s", code, resp)
		}
	})

	// The top-level key, the nested keys, and the mount keys — each was a
	// separate way through.
	for name, body := range map[string]string{
		"lowercase HostConfig":  `{"hostconfig":{"privileged":true,"binds":["/:/host"]}}`,
		"uppercase HostConfig":  `{"HOSTCONFIG":{"PRIVILEGED":true}}`,
		"mixed-case Privileged": `{"HostConfig":{"pRiViLeGeD":true}}`,
	} {
		t.Run(name, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			refuse(t, sock, eng, "/v1.41/containers/create", body, "HostConfig.Privileged")
		})
	}

	// A lowercase Binds must be CHECKED, not ignored: the mount rule has to see
	// the same field podman will.
	t.Run("lowercase Binds is checked against visibility", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"HostConfig":{"binds":["/etc:/etc"]}}`, "this sandbox cannot see")
	})

	// Two spellings at once is refused rather than resolved. Any rule for
	// picking a winner is a rule about JSON text order, and getting it wrong is
	// silent.
	for name, body := range map[string]string{
		"nested collision":    `{"HostConfig":{"Privileged":false,"privileged":true}}`,
		"top-level collision": `{"HostConfig":{},"hostconfig":{"Privileged":true}}`,
	} {
		t.Run(name, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			refuse(t, sock, eng, "/v1.41/containers/create", body, "differ only in case")
		})
	}

	// And the injected hardening must be the only spelling in what is forwarded.
	// This is the assertion that would have caught the marshal-ordering half.
	t.Run("exactly one Privileged reaches the engine, and it is false", func(t *testing.T) {
		sock, eng, target := startProxy(t)
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"Binds":["`+target+`:/w"]}}`)
		if code != 200 {
			t.Fatalf("status %d: %s", code, resp)
		}
		sent, _ := eng.lastBody.Load().(string)
		if n := strings.Count(strings.ToLower(sent), `"privileged"`); n != 1 {
			t.Errorf("%d spellings of Privileged in the forwarded body, want exactly 1: %s", n, sent)
		}
		if !strings.Contains(sent, `"Privileged":false`) {
			t.Errorf("the forwarded body does not pin Privileged false: %s", sent)
		}
	})
}

// Every denylist entry must be case-proof, not just the one the escape used.
// A new entry added to refusedHostConfig is covered the moment it is added,
// which is the property that keeps this from rotting.
func TestEveryRefusedHostConfigKeyIsCaseProof(t *testing.T) {
	for _, k := range refusedHostConfig {
		lower := strings.ToLower(k)
		if lower == k {
			continue // no variant to test
		}
		t.Run(k, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			// A non-empty value of a shape isEmptyJSON does not swallow.
			refuse(t, sock, eng, "/v1.41/containers/create",
				`{"HostConfig":{"`+lower+`":["x"]}}`, "HostConfig."+k)
		})
	}
}

// The namespace-mode checks are a separate loop and were separately exposed.
//
// NetworkMode uses a value that stays refused regardless of issue #63 Tier
// B's own NetworkMode="host" exception (container:x joins ANOTHER
// container's netns, not the engine's own N) — every other key still uses
// "host", which stays refused for all of them.
func TestNamespaceModesAreCaseProof(t *testing.T) {
	for _, k := range namespaceModeKeys {
		value := "host"
		if k == "NetworkMode" {
			value = "container:x"
		}
		t.Run(k, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			refuse(t, sock, eng, "/v1.41/containers/create",
				`{"HostConfig":{"`+strings.ToLower(k)+`":"`+value+`"}}`,
				"HostConfig."+k)
		})
	}
}

// TestNetworkModeHostIsAllowedButOtherHostModesAreNot is the settled Tier B
// inversion (TIER-B.md, the NET_ADMIN decision; internal/dockerproxy/
// create.go's own comment on namespaceModeKeys): the container engine now
// runs INSIDE this sandbox's own network namespace N (setns'd there by the
// stage), so HostConfig.NetworkMode="host" joins N — exactly the "share N
// host-mode" design — not the real host's. Every OTHER "host" namespace mode
// stays refused: PidMode="host" above all. Since issue #125's C0 that refusal
// is CONSERVATIVE rather than the whole boundary — the engine holds its own
// pid namespace now, so PidMode="host" would join the ENGINE's, not the real
// host's — and create.go's own comment on namespaceModeKeys carries the
// measurement and names issue #145 as where the policy question belongs. What
// this test asserts is unchanged either way: the set of modes that reach the
// engine is exactly {NetworkMode=host}.
//
// Positive control is the loop itself: if NetworkMode ever stopped being the
// one exception, this test would catch it turning into a refusal; if a
// DIFFERENT key ever started being silently allowed, the loop's own refusal
// assertion catches that too.
func TestNetworkModeHostIsAllowedButOtherHostModesAreNot(t *testing.T) {
	sock, eng, _ := startProxy(t)
	code, body := post(t, sock, "/v1.41/containers/create", `{"HostConfig":{"NetworkMode":"host"}}`)
	if code != 200 {
		t.Fatalf("NetworkMode=host: status %d, want 200: %s", code, body)
	}
	if eng.reached.Load() == 0 {
		t.Fatal("NetworkMode=host never reached the engine")
	}

	for _, k := range []string{"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"} {
		t.Run(k, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			refuse(t, sock, eng, "/v1.41/containers/create",
				`{"HostConfig":{"`+k+`":"host"}}`, "HostConfig."+k)
		})
	}
}

// TestNamespaceModeRefusalsAreExhaustive is the redteam's own standing gate
// on issue #63 Tier B's `NetworkMode="host"` inversion (6a2ddb2): the redteam
// confirmed the inversion BY HAND and found no single committed test proving
// the whole set together — TestNamespaceModesAreCaseProof and
// TestNetworkModeHostIsAllowedButOtherHostModesAreNot cover most of it, split
// across two tests and neither one includes `container:<id>` for a key OTHER
// than NetworkMode, or Privileged/CapAdd alongside the namespace-mode set.
// This is the one place all of it is asserted together, with the live
// inversion in place.
//
// This doc comment used to carry a SEVERITY claim: "PidMode="host" being
// refused is the ONLY thing standing between a container and a full
// host-pidns escape; there is no second mechanism behind it the way there is
// for network." Severity claims decay when the mechanism moves, and issue
// #125's C0 moved it — it gave the engine its own pid namespace
// (CLONE_NEWPID, internal/stage/enginefork.go) and a fresh procfs
// (internal/stage/inengine.go), so "the ONLY thing standing between" stopped
// being true the moment C0 landed, silently, because nothing here re-read it.
//
// Replaced with a RULE claim (issue #145's decision), which does not decay
// the same way, because it names the test that has to fail before the row
// could ever be safely relaxed:
//
//   - An inversion — turning a refused "host" mode into an allowed one, the
//     way NetworkMode="host" was turned into "joins N" — is safe only when the
//     namespace's MEMBERSHIP SET is a SUBSET of what the sandbox already has.
//     N contains the sandbox's own network and nothing else, which is why the
//     network row alone could invert. A pid namespace fails that test even
//     with an engine-owned one on offer: pid namespace membership is not
//     "seeing more pids", it is the only kind of membership that is a HANDLE
//     to every other namespace a member holds — /proc/<pid>/root and
//     /proc/<pid>/cwd dereference into the member's own MOUNT namespace,
//     /proc/<pid>/fd/N reopens its open descriptors — and the engine's pid
//     namespace contains THE ENGINE: pid 1, root-in-U,
//     policy.EngineCapBounding, the full delegated subuid range, and a mount
//     namespace that is a private COPY of the entire host tree. Joining it is
//     a superset of the sandbox's authority, not a subset, so PidMode="host"
//     stays refused PERMANENTLY, not provisionally — and Tier C (issue #125)
//     makes the row MORE load-bearing, not less, because the graft
//     descriptors the derived view is built from now pass through the engine
//     child too. MEASURED (issue #145, podman 6.0.2, yama ptrace_scope=1): a
//     container placed in a sibling container's pid namespace read the
//     sibling's whole filesystem through /proc/<pid>/root and listed its open
//     file descriptions through /proc/<pid>/fd, at plain uid, no capability
//     and no ptrace — exactly the shape PidMode="host" would reproduce
//     against the engine.
//   - CgroupnsMode="host" fails the same subset test the same way: it names
//     the engine's own cgroup namespace (CLONE_NEWCGROUP), disclosing the
//     engine's cgroup path and the placement of every other container this
//     sandbox started — placement snug authors, not the client.
//   - IpcMode="host" and UTSMode="host" still name the MACHINE's namespaces,
//     because neither the stage (internal/stage/fds.go's stageCloneflags) nor
//     the engine fork (internal/stage/enginefork.go's Cloneflags) unshares
//     IPC or UTS — so for these two keys "host" is not even an inversion
//     candidate yet, it is the pre-Tier-B case, unchanged. If that ever
//     changes (issue #182 proposes exactly this), these two rows — and their
//     refusal reasons — change with it; TestIpcAndUtsReasonsMatchTheEnginesActualCloneflags
//     (refusalreason_test.go) is the tripwire that keeps that true rather than
//     assumed.
//   - UsernsMode="host" names U, the engine's own user namespace, and is
//     refused on a narrower ground than the subset test: snug decides a
//     container's user namespace, full stop, whether or not naming U would
//     have changed anything.
//   - The `container:<id>` and `ns:<path>` spellings of every key above are
//     the same rule applied sibling-to-sibling rather than sibling-to-engine:
//     a sibling container's namespace is exactly as much a superset of this
//     sandbox's authority as "host" is, so there is no narrower spelling that
//     gets around any of this.
//
// No row here is relaxed by this rewrite. It is a comment change and a
// severity-to-rule change only; every case in the table below refuses exactly
// what it refused before.
//
// Positive control: NetworkMode="host" is accepted (reaches the fake engine)
// in the SAME test, so a refusal-shaped bug that accidentally caught
// NetworkMode too would show up here rather than only in a different test
// file.
func TestNamespaceModeRefusalsAreExhaustive(t *testing.T) {
	t.Run("control: NetworkMode=host is allowed (joins N)", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		code, body := post(t, sock, "/v1.41/containers/create", `{"HostConfig":{"NetworkMode":"host"}}`)
		if code != 200 {
			t.Fatalf("NetworkMode=host: status %d, want 200: %s", code, body)
		}
		if eng.reached.Load() == 0 {
			t.Fatal("NetworkMode=host never reached the engine — the control itself is broken, " +
				"so every refusal below proves nothing about a REAL inversion")
		}
	})

	for _, tc := range []struct {
		name, body, wantMsg string
	}{
		{"PidMode=host", `{"HostConfig":{"PidMode":"host"}}`, "HostConfig.PidMode"},
		{"IpcMode=host", `{"HostConfig":{"IpcMode":"host"}}`, "HostConfig.IpcMode"},
		{"UTSMode=host", `{"HostConfig":{"UTSMode":"host"}}`, "HostConfig.UTSMode"},
		{"CgroupnsMode=host", `{"HostConfig":{"CgroupnsMode":"host"}}`, "HostConfig.CgroupnsMode"},
		{"UsernsMode=host", `{"HostConfig":{"UsernsMode":"host"}}`, "HostConfig.UsernsMode"},
		{"NetworkMode=container:<id>", `{"HostConfig":{"NetworkMode":"container:abc123"}}`,
			"HostConfig.NetworkMode"},
		{"PidMode=container:<id>", `{"HostConfig":{"PidMode":"container:abc123"}}`,
			"HostConfig.PidMode"},
		{"NetworkMode=ns:/proc/1/ns/net", `{"HostConfig":{"NetworkMode":"ns:/proc/1/ns/net"}}`,
			"HostConfig.NetworkMode"},
		{"PidMode=ns:/proc/1/ns/pid", `{"HostConfig":{"PidMode":"ns:/proc/1/ns/pid"}}`,
			"HostConfig.PidMode"},
		{"Privileged:true", `{"HostConfig":{"Privileged":true}}`, "HostConfig.Privileged"},
		{"CapAdd", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, "HostConfig.CapAdd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			refuse(t, sock, eng, "/v1.41/containers/create", tc.body, tc.wantMsg)
		})
	}
}

// REGRESSION (redteam, M4 review): the ASCII case fix above was not enough,
// and its own comment stated the false premise that caused it.
//
// encoding/json folds field names with EqualFold semantics, which unify LONG S
// (U+017F) with `s`. strings.ToLower does not — ſ is already lowercase — so
// `{"HostConfig":{"Bindſ":["/:/host"]}}` missed the canonical lookup AND the
// collision check, was re-marshalled verbatim, and podman folded it back to
// Binds. The engine runs as the host uid outside bwrap, so that is host `/`
// mounted into the container with checkedMounts never having seen a mount.
// Confirmed by the bytes reaching a real engine.
//
// The fix refuses non-ASCII keys outright, which is why this test asserts the
// CLASS rather than the rune.
func TestNonASCIIKeysCannotSmuggleAField(t *testing.T) {
	t.Run("the escape as found", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		refuse(t, sock, eng, "/v1.41/containers/create",
			"{\"Image\":\"alpine\",\"HostConfig\":{\"Bindſ\":[\"/:/host\"]}}", "not ASCII")
	})

	// Every canonical key containing an s or a k is spellable this way, so the
	// table is generated from the same list the checks use: a key added to
	// refusedHostConfig is covered the moment it is added.
	for fold, canon := range canonicalKey {
		if !strings.ContainsAny(fold, "sk") {
			continue
		}
		t.Run(canon, func(t *testing.T) {
			sock, eng, _ := startProxy(t)
			// Long s for every s, Kelvin sign for every k — the two runes
			// encoding/json folds onto ASCII letters.
			for _, variant := range []string{
				strings.ReplaceAll(canon, "s", "ſ"),
				strings.ReplaceAll(canon, "S", "ſ"),
				strings.ReplaceAll(canon, "k", "K"),
				strings.ReplaceAll(canon, "K", "K"),
			} {
				if variant == canon {
					continue
				}
				body := `{"HostConfig":{"` + variant + `":["x"]}}`
				if canon == "HostConfig" || canon == "Volumes" {
					body = `{"` + variant + `":{"Privileged":true}}`
				}
				refuse(t, sock, eng, "/v1.41/containers/create", body, "not ASCII")
			}
		})
	}

	// CONTROL: an ordinary ASCII body still works. Without it, "non-ASCII is
	// refused" would be equally true of a proxy that refuses everything.
	t.Run("control: an ASCII create still succeeds", func(t *testing.T) {
		sock, _, target := startProxy(t)
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"Binds":["`+target+`:/w"]}}`)
		if code != 200 {
			t.Fatalf("a legitimate create must still work (status %d): %s", code, resp)
		}
	})
}

// The premise decodeObject rests on, asserted directly against encoding/json
// rather than trusted — because trusting it is precisely what went wrong.
//
// The property is NOT "snug's fold equals podman's". Refusing a spelling podman
// would accept is fine: nothing reaches the engine, and fail-closed is the
// direction this project errs in. What must never happen is the third case —
// snug forwards a key under a name it did NOT inspect while encoding/json folds
// that same key onto a field it acts on. That is the long-s escape exactly, and
// this assertion fails on it.
//
// Written by asking encoding/json itself, so it tracks whatever the standard
// library's folding does in a future Go rather than a rule copied from its docs.
func TestSnugNeverForwardsAFieldItDidNotInspect(t *testing.T) {
	// Binds stands in for every canonical key: the fold is a property of
	// encoding/json's field matching, not of the field.
	type probe struct {
		Binds []string
	}
	for _, spelling := range []string{
		"Binds", "binds", "BINDS", "BiNdS",
		"Bindſ", "ſinds", "BINDſ", // long s: folded by encoding/json, not by ToLower
		"Unrelated",
	} {
		body := []byte(`{"` + spelling + `":["x"]}`)

		var got probe
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		podmanReadsItAsBinds := len(got.Binds) == 1

		m, err := decodeObject(body)
		switch {
		case err != nil:
			// Refused outright: nothing is forwarded, so nothing can be acted on.
			continue
		case !podmanReadsItAsBinds:
			continue
		default:
			if _, inspected := m["Binds"]; !inspected {
				t.Errorf("spelling %q: encoding/json reads it as the Binds field, but snug "+
					"neither canonicalised it nor refused the request — so it is forwarded "+
					"under a name no mount check ever looks at, and podman acts on it",
					spelling)
			}
		}
	}
}

// REGRESSION (redteam, M4 review): Privileged was refused at create and then
// available again on the way in. Low severity — the exec body reaches no host
// resource — but create-time and exec-time must not disagree about one word.
func TestPrivilegedExecIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)

	refuse(t, sock, eng, "/v1.41/containers/abc/exec",
		`{"Privileged":true,"Cmd":["id"]}`, "exec Privileged is not permitted")

	// The same body in the spelling the ASCII fix was about.
	refuse(t, sock, eng, "/v1.41/containers/abc/exec",
		`{"privileged":true,"Cmd":["id"]}`, "exec Privileged is not permitted")

	// CONTROL: an ordinary exec still works, or `docker exec` is broken and the
	// refusals above would be equally true of a proxy that blocks exec entirely.
	before := eng.reached.Load()
	code, resp := post(t, sock, "/v1.41/containers/abc/exec",
		`{"Cmd":["id"],"AttachStdout":true}`)
	if code != 200 || eng.reached.Load() == before {
		t.Fatalf("an ordinary exec must still reach the engine (status %d): %s", code, resp)
	}
}

// The docker CLI sends HostConfig.LogConfig {"Type":"","Config":{}} on EVERY
// create. isEmptyJSON does not see that as empty, so the LogConfig denylist
// refused every `docker run` this proxy had ever seen — the profile's whole
// purpose, failing with a message about log drivers.
//
// The hazard is the `path` option (conmon writes it on the HOST as your uid),
// so that is what must stay refused, and both halves are asserted here.
func TestTheDefaultLogConfigIsAccepted(t *testing.T) {
	sock, eng, target := startProxy(t)

	t.Run("the docker CLI default passes", func(t *testing.T) {
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"LogConfig":{"Type":"","Config":{}},"Binds":["`+target+`:/w"]}}`)
		if code != 200 {
			t.Fatalf("`docker run` sends this on every create; refusing it refuses "+
				"everything (status %d): %s", code, resp)
		}
		// And it must not arrive at the engine as an empty driver spec that
		// podman then has to interpret.
		//
		// Decoded rather than substring-matched, which is not fastidiousness:
		// the first version looked for "LogConfig" in the forwarded bytes and
		// failed, because t.TempDir() names the directory after the test and
		// this test is called ...LogConfig..., so the bind source matched.
		sent, _ := eng.lastBody.Load().(string)
		var got struct {
			HostConfig map[string]json.RawMessage
		}
		if err := json.Unmarshal([]byte(sent), &got); err != nil {
			t.Fatalf("the engine did not receive JSON: %s", sent)
		}
		if _, ok := got.HostConfig["LogConfig"]; ok {
			t.Errorf("the default LogConfig was forwarded rather than dropped: %s", sent)
		}
	})

	// The hazard, in both fields.
	for name, body := range map[string]string{
		"a named driver": `{"HostConfig":{"LogConfig":{"Type":"k8s-file","Config":{}}}}`,
		"a path option":  `{"HostConfig":{"LogConfig":{"Type":"","Config":{"path":"/home/u/pwned"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			refuse(t, sock, eng, "/v1.41/containers/create", body, "HostConfig.LogConfig")
		})
	}
}

// HostConfig.Tmpfs used to be deleted without a word, two comments below the
// paragraph saying nothing is silently dropped. It is container-internal — a
// tmpfs has no source, so there is no host path for the mount rule to judge —
// so it is forwarded.
func TestTmpfsIsForwardedNotSilentlyDropped(t *testing.T) {
	sock, eng, _ := startProxy(t)
	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Tmpfs":{"/run":"rw,size=64m"}}}`)
	if code != 200 {
		t.Fatalf("status %d: %s", code, resp)
	}
	sent, _ := eng.lastBody.Load().(string)
	if !strings.Contains(sent, `"Tmpfs"`) || !strings.Contains(sent, "/run") {
		t.Errorf("Tmpfs did not reach the engine, so `docker run --tmpfs` silently "+
			"does nothing: %s", sent)
	}
}

// Teardown stops the containers THIS run started, and it can only do that if
// every container carries this run's label.
//
// The store is shared with any concurrent sandbox that resolved to the same key
// — deliberately, so a warm start is warm — so the `stop --all` that teardown
// used to run was collateral damage on a sibling that was still working.
func TestEveryContainerIsStampedWithTheRunLabel(t *testing.T) {
	labels := func(t *testing.T, eng *fakeEngine) map[string]string {
		t.Helper()
		sent, _ := eng.lastBody.Load().(string)
		var got struct{ Labels map[string]string }
		if err := json.Unmarshal([]byte(sent), &got); err != nil {
			t.Fatalf("the engine did not receive JSON: %s", sent)
		}
		return got.Labels
	}

	t.Run("a plain create", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		if code, resp := post(t, sock, "/v1.41/containers/create", `{"Image":"alpine"}`); code != 200 {
			t.Fatalf("status %d: %s", code, resp)
		}
		if got := labels(t, eng)["snug.run"]; got != "test" {
			t.Errorf("snug.run = %q, want %q — teardown cannot find this container", got, "test")
		}
	})

	// The client's own labels survive. Dropping them would be the silent-strip
	// mistake this file already learned once with Binds.
	t.Run("the client's labels are kept", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		if code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","Labels":{"mine":"yes"}}`); code != 200 {
			t.Fatalf("status %d: %s", code, resp)
		}
		got := labels(t, eng)
		if got["mine"] != "yes" {
			t.Errorf("the client's own label was dropped: %v", got)
		}
		if got["snug.run"] != "test" {
			t.Errorf("snug.run = %q, want %q", got["snug.run"], "test")
		}
	})

	// And the sandbox cannot disown its container by claiming another run.
	t.Run("a client value for snug.run loses", func(t *testing.T) {
		sock, eng, _ := startProxy(t)
		if code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","Labels":{"snug.run":"somebody-else"}}`); code != 200 {
			t.Fatalf("status %d: %s", code, resp)
		}
		if got := labels(t, eng)["snug.run"]; got != "test" {
			t.Errorf("snug.run = %q: the sandbox chose its own owner, so it would either "+
				"survive its own teardown or be stopped by a sibling's", got)
		}
	})
}

// Volume create decodes its own body and had the same hole.
func TestVolumeCreateIsCaseProof(t *testing.T) {
	sock, eng, _ := startProxy(t)
	refuse(t, sock, eng, "/v1.41/volumes/create",
		`{"Name":"v","driver":"local-persist"}`, "volume driver")
	refuse(t, sock, eng, "/v1.41/volumes/create",
		`{"Name":"v","options":{"device":"/","o":"bind","type":"none"}}`, "not permitted")
}
