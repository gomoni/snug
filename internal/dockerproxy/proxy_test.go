package dockerproxy

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"snug/internal/policy"
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
		b := make([]byte, 64*1024)
		n, _ := r.Body.Read(b)
		eng.lastBody.Store(string(b[:n]))
		w.WriteHeader(200)
		w.Write([]byte(`{"Id":"deadbeef"}`))
	}))
	t.Cleanup(func() { ln.Close() })

	pol := &policy.Policy{
		Target: target,
		Mounts: map[string]policy.Mount{
			target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
			"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind, Access: policy.AccessRO},
		},
	}
	sock = filepath.Join(dir, "proxy.sock")
	p, err := New(pol, up, sock, nil, nil)
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
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

// THE rule: a container may bind a host path only if the sandbox can see it.
func TestContainerCannotMountWhatTheSandboxCannot(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, body string }{
		{"the whole host filesystem", `{"HostConfig":{"Binds":["/:/host"]}}`},
		{"/etc, which sys grants read-only", `{"HostConfig":{"Binds":["/etc:/etc"]}}`},
		{"/usr writable, granted only read-only", `{"HostConfig":{"Binds":["/usr:/u"]}}`},
		{"a relative source", `{"HostConfig":{"Binds":["../..:/x"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.reached.Load()
			code, body := post(t, sock, "/v1.41/containers/create", tc.body)
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, body)
			}
			if eng.reached.Load() != before {
				t.Error("the request reached the engine; it should have been refused here")
			}
		})
	}
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
	for _, tc := range []struct{ name, body string }{
		{"privileged", `{"HostConfig":{"Privileged":true}}`},
		{"added capabilities", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`},
		{"device passthrough", `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`},
		{"an alternate runtime", `{"HostConfig":{"Runtime":"/tmp/evil"}}`},
		{"host networking", `{"HostConfig":{"NetworkMode":"host"}}`},
		{"another container's netns", `{"HostConfig":{"NetworkMode":"container:abc"}}`},
		{"host pid namespace", `{"HostConfig":{"PidMode":"host"}}`},
		{"published ports", `{"HostConfig":{"PortBindings":{"80/tcp":[{"HostPort":"8080"}]}}}`},
		{"mounts inherited from another container", `{"HostConfig":{"VolumesFrom":["other"]}}`},
		{"a security-opt of its own", `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`},
		{"anonymous volumes", `{"Volumes":{"/data":{}}}`},
		{"propagation smuggled through bind options", `{"HostConfig":{"Binds":["/tmp:/tmp:rshared"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.reached.Load()
			code, body := post(t, sock, "/v1.41/containers/create", tc.body)
			if code != http.StatusForbidden {
				t.Errorf("status %d, want 403: %s", code, body)
			}
			if eng.reached.Load() != before {
				t.Error("request reached the engine")
			}
		})
	}
}

// A local volume with driver options is how a host path gets planted under a
// name, to be referenced innocently later.
func TestVolumeDriverOptionsAreRefused(t *testing.T) {
	sock, _, _ := startProxy(t)
	code, _ := post(t, sock, "/v1.41/volumes/create",
		`{"Name":"v","Driver":"local","Options":{"type":"none","o":"bind","device":"/"}}`)
	if code != http.StatusForbidden {
		t.Errorf("status %d, want 403", code)
	}
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
