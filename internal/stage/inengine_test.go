package stage

import (
	"reflect"
	"strings"
	"testing"
)

// enterEngineRoundTripReq is a "start" request carrying enough of every
// field parseEnterEngineArgv decodes to catch a positional shift: a
// non-empty env block (so RUNSIZE/VARTMPSIZE cannot be mistaken for an env
// pair), non-default size values (so a bug that read DefaultTmpfsSize or
// zero instead would still be caught), and a nonzero graft count (so the
// insert of the two size fields ahead of NGRAFTS is asserted not to have
// shifted graft parsing).
func enterEngineRoundTripReq() request {
	return request{
		EnginePodman: "/snug/engine/podman",
		EngineArgv:   []string{"system", "service", "--time", "300", "unix:///tmp/engine.sock"},
		EngineEnv:    []string{"PATH=/snug/bin", "HOME=/snug/home"},
		EngineSock:   "/tmp/engine.sock",
		EngineGrafts: []EngineGraft{
			{Host: "/host/store", Guest: "/snug/engine/store", ReadOnly: false},
			{Host: "/host/config", Guest: "/snug/engine/config", ReadOnly: true},
		},
		EngineRunSizeBytes:    1234567,
		EngineVarTmpSizeBytes: 8 << 30,
	}
}

// TestEnterEngineArgvRoundTrip builds a request with buildEnterEngineArgv —
// the same encoder startEngine uses — and decodes it with
// parseEnterEngineArgv, so a change to either side that breaks the other
// fails here rather than only inside a namespace this host cannot create
// (see TestEngineTmpfsAreBounded).
func TestEnterEngineArgvRoundTrip(t *testing.T) {
	req := enterEngineRoundTripReq()
	argv := buildEnterEngineArgv(req)
	// argv[0] is the exec verb "__inengine"; EnterEngine's own caller
	// (exec.Command's cmd.Args[0] aside) hands parseEnterEngineArgv the argv
	// AFTER that verb, exactly as EnterEngine itself does.
	got, err := parseEnterEngineArgv(argv[1:])
	if err != nil {
		t.Fatalf("parseEnterEngineArgv: %v", err)
	}

	if got.netnsFD != 3 {
		t.Errorf("netnsFD = %d, want 3", got.netnsFD)
	}
	if got.mntFD != 4 {
		t.Errorf("mntFD = %d, want 4", got.mntFD)
	}
	if !reflect.DeepEqual(got.env, req.EngineEnv) {
		t.Errorf("env = %#v, want %#v", got.env, req.EngineEnv)
	}
	if got.runSize != req.EngineRunSizeBytes {
		t.Errorf("runSize = %d, want %d", got.runSize, req.EngineRunSizeBytes)
	}
	if got.varTmpSize != req.EngineVarTmpSizeBytes {
		t.Errorf("varTmpSize = %d, want %d", got.varTmpSize, req.EngineVarTmpSizeBytes)
	}
	if len(got.grafts) != len(req.EngineGrafts) {
		t.Fatalf("got %d grafts, want %d", len(got.grafts), len(req.EngineGrafts))
	}
	for i, g := range req.EngineGrafts {
		if got.grafts[i].host != g.Host || got.grafts[i].guest != g.Guest || got.grafts[i].readOnly != g.ReadOnly {
			t.Errorf("graft %d = %+v, want {host:%q guest:%q readOnly:%v}",
				i, got.grafts[i], g.Host, g.Guest, g.ReadOnly)
		}
	}
	wantPodmanArgv := append([]string{req.EnginePodman}, req.EngineArgv...)
	if !reflect.DeepEqual(got.podmanArgv, wantPodmanArgv) {
		t.Errorf("podmanArgv = %#v, want %#v", got.podmanArgv, wantPodmanArgv)
	}
}

// TestEnterEngineArgvRefusesAZeroOrGarbageSize is the test that matters for
// invariant 5 on this protocol: EnterEngine must never read a zero or
// unparseable size field as "use the kernel default", because bwrap.Mount's
// own empty-data-string tmpfs is exactly that default — half of host RAM.
func TestEnterEngineArgvRefusesAZeroOrGarbageSize(t *testing.T) {
	cases := []struct {
		name       string
		runSize    string
		varTmpSize string
		wantField  string
	}{
		{"run zero", "0", "8589934592", "/run"},
		{"run garbage", "not-a-number", "8589934592", "/run"},
		{"vartmp zero", "1234567", "0", "/var/tmp"},
		{"vartmp garbage", "1234567", "not-a-number", "/var/tmp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := enterEngineRoundTripReq()
			argv := buildEnterEngineArgv(req)
			// The two size fields sit right after the env block: argv[0] is
			// "__inengine", argv[1..3] are the fd/fd/nEnv triple, then
			// len(req.EngineEnv) env pairs, then RUNSIZE, VARTMPSIZE.
			sizeAt := 1 + 3 + len(req.EngineEnv)
			argv[sizeAt] = tc.runSize
			argv[sizeAt+1] = tc.varTmpSize

			_, err := parseEnterEngineArgv(argv[1:])
			if err == nil {
				t.Fatalf("parseEnterEngineArgv: got no error for %s=%q", tc.wantField, argv[sizeAt])
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Errorf("error %q does not name the field %q", err.Error(), tc.wantField)
			}
		})
	}
}
