package dockerproxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// startProxyWithPolicy is startProxyAudited with the resolved *policy.Policy
// supplied by the caller rather than the package's own fixed fixture. Every
// test in this file needs a mount shape (a divergent bind, a graft) that
// fixture cannot express.
func startProxyWithPolicy(t *testing.T, mode policy.PodmanMode, mkPolicy func(dir, target string) *policy.Policy) (sock string, eng *fakeEngine, target string) {
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
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		eng.lastBody.Store(string(b))
		eng.lastURI.Store(r.URL.RequestURI())
		w.WriteHeader(200)
		w.Write([]byte(`{"Id":"deadbeef"}`))
	}))
	t.Cleanup(func() { ln.Close() })

	pol := mkPolicy(dir, target)
	pol.Target = target
	pol.Podman = mode

	sock = filepath.Join(dir, "proxy.sock")
	p, err := New(pol, up, sock, "snug.run=test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return sock, eng, target
}

// TestCreateRefusesADivergentBindSpelling drives the REAL create handler
// (issue #371) against a policy carrying @claude's own shape: a read-only
// bind whose Host and Guest are two unrelated trees
// ("{home}/.local/bin/claude:/snug/bin/claude"). A client naming the mount's
// HOST spelling as a bind source is refused, because CheckEngineForwardedPath
// judges the string in GUEST space and this mount's Guest
// ("/snug/bin/claude") never covers it — so the name means nothing to the
// engine's own derived view, whatever hostPathVisible (a HOST-space check)
// says about it.
func TestCreateRefusesADivergentBindSpelling(t *testing.T) {
	var claudeBin string
	sock, eng, _ := startProxyWithPolicy(t, policy.PodmanSocket, func(dir, target string) *policy.Policy {
		claudeSrcDir := filepath.Join(dir, "home", ".local", "bin")
		if err := os.MkdirAll(claudeSrcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		claudeBin = filepath.Join(claudeSrcDir, "claude")
		if err := os.WriteFile(claudeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return &policy.Policy{
			Mounts: map[string]policy.Mount{
				target:             {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
				"/usr":             {Guest: "/usr", Host: "/usr", Kind: policy.KindBind, Access: policy.AccessRO},
				"/snug/bin/claude": {Guest: "/snug/bin/claude", Host: claudeBin, Kind: policy.KindBind, Access: policy.AccessRO},
			},
		}
	})

	t.Run("the HOST spelling of the divergent bind is refused", func(t *testing.T) {
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["`+claudeBin+`:/x:ro"]}}`)
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if eng.reached.Load() != before {
			t.Fatal("the request reached the engine; it should have been refused here")
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "issue #371") {
			t.Errorf("refused, but not for the #371 reason this case exists to test:\n%s", msg)
		}
	})

	// POSITIVE CONTROL: an ordinary /usr-rooted source, granted with an
	// identical Host==Guest spelling, is ACCEPTED — proving the refusal
	// above is about the divergence, not a proxy that refuses everything or
	// a policy nothing can pass.
	t.Run("control: an ordinary Host==Guest source is accepted", func(t *testing.T) {
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["/usr:/u:ro"]}}`)
		if code != 200 {
			t.Fatalf("status %d, want 200: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the control request never reached the engine")
		}
	})
}

// TestSeccompProfileIsJudgedInTheSpaceTheEngineReadsIt is issue #371 §3.3's
// own regression: checkSeccompProfile used to hand CheckEngineBindSource a
// HOST path under the parameter name `guest`, discharging none of that
// function's documented precondition. This drives the real build endpoint.
func TestSeccompProfileIsJudgedInTheSpaceTheEngineReadsIt(t *testing.T) {
	var profilePath string
	sock, eng, _ := startProxyWithPolicy(t, policy.PodmanBuild, func(dir, target string) *policy.Policy {
		profileSrcDir := filepath.Join(dir, "home", ".config", "containers")
		if err := os.MkdirAll(profileSrcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		profilePath = filepath.Join(profileSrcDir, "seccomp.json")
		if err := os.WriteFile(profilePath, []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return &policy.Policy{
			Mounts: map[string]policy.Mount{
				target: {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
				"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind, Access: policy.AccessRO},
				// The @claude shape again, this time for the seccomp profile
				// itself: readable, not writable, Host and Guest disjoint.
				"/snug/seccomp/custom.json": {
					Guest: "/snug/seccomp/custom.json", Host: profilePath,
					Kind: policy.KindBind, Access: policy.AccessRO,
				},
			},
		}
	})

	t.Run("negative: the HOST spelling of the divergent profile bind is refused", func(t *testing.T) {
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL("seccomp="+url.QueryEscape(profilePath)), "")
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if eng.reached.Load() != before {
			t.Fatal("the request reached the engine; it should have been refused here")
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "issue #371") {
			t.Errorf("refused, but not for the #371 reason this case exists to test:\n%s", msg)
		}
	})

	// POSITIVE CONTROL, MANDATORY: the CLI sends a profile on EVERY build, so
	// a wrong tightening here breaks every ordinary build rather than
	// announcing itself. The exact spelling TestSeccompProfileMustNotBeSandboxAuthored
	// already controls against (build_test.go).
	t.Run("control: the CLI's own default seccomp profile is still accepted", func(t *testing.T) {
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL("seccomp="+url.QueryEscape("/usr/share/containers/seccomp.json")), "")
		if code != 200 {
			t.Fatalf("the CLI's default seccomp profile was refused (status %d): %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the control build never reached the engine")
		}
	})
}

// TestCheckSeccompProfileOrderIsResolveVisibleWritableForwardedRepointable
// pins the ORDER of checkSeccompProfile's five checks — load-bearing, because
// CheckEngineBindSource's own doc comment states its caller must FIRST
// establish the path is what the engine sees (CheckEngineForwardedPath), and
// an order that ran CheckEngineBindSource earlier would silently stop
// discharging that precondition again.
func TestCheckSeccompProfileOrderIsResolveVisibleWritableForwardedRepointable(t *testing.T) {
	src, err := os.ReadFile("build.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	fn := funcBody(t, text, "func checkSeccompProfile(p *Proxy, v string) (string, error) {")
	// CONTROL: the extraction found the real function.
	if fn == "" {
		t.Fatal("control: extracted an empty body — the signature this test greps for has " +
			"drifted from build.go's own")
	}

	markers := []string{
		"resolveForwardable(",
		"hostPathVisible(real, false)",
		"hostPathVisible(real, true)",
		"CheckEngineForwardedPath(",
		"CheckEngineBindSource(",
	}
	last := -1
	for _, m := range markers {
		i := strings.Index(fn, m)
		if i < 0 {
			t.Fatalf("checkSeccompProfile no longer contains %q — the order this test pins cannot "+
				"be checked; update both the function and this test together", m)
		}
		if i <= last {
			t.Errorf("checkSeccompProfile's checks are out of order: %q appears before or at the "+
				"same position as the previous marker. Want resolve -> visible -> not-writable -> "+
				"forwarded-path -> re-pointable, in that order, because CheckEngineBindSource's own "+
				"doc comment requires CheckEngineForwardedPath to have run first", m)
		}
		last = i
	}
}

// TestTheWideningStillEnforcesAccess is issue #371's widening, checked end to
// end: a source under a sandbox-visible directory that ALSO carries a
// toolchain graft whose Host covers it is now ACCEPTED by
// CheckEngineForwardedPath (policy row 8, engineforwardedpath_test.go),
// where it used to be refused via EngineGuestPath's graft arm. The safety
// argument for that widening is that authorization stays a HOST-space
// question (hostPathVisible) and the access join is unchanged — an argument
// that only holds while hostPathVisible actually runs on this route. This
// drives the real create handler to prove it does.
func TestTheWideningStillEnforcesAccess(t *testing.T) {
	var bundleDir string
	sock, eng, _ := startProxyWithPolicy(t, policy.PodmanSocket, func(dir, target string) *policy.Policy {
		bundleDir = filepath.Join(dir, "bundle")
		if err := os.MkdirAll(filepath.Join(bundleDir, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, "lib", "libfoo.so"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		return &policy.Policy{
			Mounts: map[string]policy.Mount{
				target:    {Guest: target, Host: target, Kind: policy.KindBind, Access: policy.AccessRW},
				bundleDir: {Guest: bundleDir, Host: bundleDir, Kind: policy.KindBind, Access: policy.AccessRO},
			},
			Grafts: map[string]policy.Graft{
				"/snug/engine/toolchain": {Mount: policy.Mount{
					Guest: "/snug/engine/toolchain", Host: bundleDir,
					Kind: policy.KindGraft, Access: policy.AccessRO,
				}},
			},
		}
	})

	t.Run("ro request under the widened source is accepted, forwarded read-only, unrewritten path", func(t *testing.T) {
		before := eng.reached.Load()
		libDir := filepath.Join(bundleDir, "lib")
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["`+libDir+`:/x:ro"]}}`)
		if code != 200 {
			t.Fatalf("status %d, want 200: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the request never reached the engine")
		}
		sent, _ := eng.lastBody.Load().(string)
		var body struct {
			HostConfig struct {
				Mounts []mount `json:"Mounts"`
			} `json:"HostConfig"`
		}
		if err := json.Unmarshal([]byte(sent), &body); err != nil {
			t.Fatalf("could not decode the forwarded body: %v\n%s", err, sent)
		}
		if len(body.HostConfig.Mounts) != 1 {
			t.Fatalf("forwarded %d mounts, want 1:\n%s", len(body.HostConfig.Mounts), sent)
		}
		got := body.HostConfig.Mounts[0]
		if got.Source != libDir {
			t.Errorf("forwarded Source = %q, want %q — the widening accepts the NAME, it does not "+
				"rewrite it to the graft's guest spelling (\"refuse, never translate\")", got.Source, libDir)
		}
		if !got.ReadOnly {
			t.Errorf("forwarded ReadOnly = false, want true — a ro request over the widened source " +
				"must still forward ro, or the widening silently promoted access")
		}
	})

	// THE ENFORCEMENT CHECK. Same source, but WITHOUT :ro — a writable
	// request. The bind granting bundleDir is read-only, so this must be
	// refused by hostPathVisible(source, needWrite=true), exactly as it
	// would be for any other read-only grant. If this ever starts passing,
	// the widening has silently turned a read-only grant into a writable
	// one for anything a toolchain graft also happens to cover.
	t.Run("rw request under the same source is refused by hostPathVisible(needWrite=true)", func(t *testing.T) {
		before := eng.reached.Load()
		libDir := filepath.Join(bundleDir, "lib")
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["`+libDir+`:/x"]}}`)
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if eng.reached.Load() != before {
			t.Fatal("the writable request reached the engine; it should have been refused here")
		}
		if msg := denyMessage(resp); !strings.Contains(msg, "cannot see") || !strings.Contains(msg, "writable") {
			t.Errorf("refused, but not for the hostPathVisible(needWrite=true) reason this case "+
				"exists to test:\n%s", msg)
		}
	})
}
