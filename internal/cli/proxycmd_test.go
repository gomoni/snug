package cli

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestSplitPortSpecAcceptsTheDockerShapedSpellings fails if `snug proxy -p`
// stops accepting any of the three spellings its own doc comment promises: a
// bare host port (docker's own shape), PORT:DOOR naming which of several
// declared doors that host port opens, and :DOOR taking a door on its own
// default port. splitPortSpec had zero test sites before this.
func TestSplitPortSpecAcceptsTheDockerShapedSpellings(t *testing.T) {
	for _, tc := range []struct {
		spec     string
		wantPort int
		wantName string
	}{
		{"8080", 8080, ""},
		{"8080:api", 8080, "api"},
		{":api", 0, "api"},
	} {
		port, name, err := splitPortSpec(tc.spec)
		if err != nil {
			t.Errorf("splitPortSpec(%q) = _, _, %v; want no error", tc.spec, err)
			continue
		}
		if port != tc.wantPort || name != tc.wantName {
			t.Errorf("splitPortSpec(%q) = (%d, %q), want (%d, %q)", tc.spec, port, name, tc.wantPort, tc.wantName)
		}
	}
}

// TestSplitPortSpecRefusesNeitherAPortNorADoor is splitPortSpec's negative:
// an empty spec, a bare colon, and a port half that is not a number in
// 1..65535 name neither a host port nor a door, and must fail rather than
// silently resolve as port 0 — the sentinel splitPortSpec's own callers use
// for "no port given" (":api" above).
func TestSplitPortSpecRefusesNeitherAPortNorADoor(t *testing.T) {
	for _, spec := range []string{"", ":", "0", "65536", "-1", "api"} {
		port, name, err := splitPortSpec(spec)
		if err == nil {
			t.Errorf("splitPortSpec(%q) = (%d, %q), nil; want a refusal", spec, port, name)
		}
	}
}

// TestPlanHTTPDoorsAssignsSequentialPorts fails if a run declaring several
// doors stops giving each the next port after httpDoorBasePort — the
// arrangement that is the whole reason two of a run's doors can be open at
// once, rather than the second dying on EADDRINUSE against the first.
func TestPlanHTTPDoorsAssignsSequentialPorts(t *testing.T) {
	pol := &policy.Policy{ListenNames: []string{"web", "admin", "metrics"}}
	doors, err := planHTTPDoors(pol, func(name string) (string, error) { return "/tmp/" + name, nil })
	if err != nil {
		t.Fatalf("planHTTPDoors: %v", err)
	}
	if len(doors) != len(pol.ListenNames) {
		t.Fatalf("planHTTPDoors returned %d doors for %d declared names", len(doors), len(pol.ListenNames))
	}
	for i, wantName := range pol.ListenNames {
		if doors[i].Name != wantName {
			t.Errorf("door %d = %q, want %q", i, doors[i].Name, wantName)
		}
		wantPort := uint16(httpDoorBasePort + i)
		if got := doors[i].Addr.Port(); got != wantPort {
			t.Errorf("door %q got port %d, want httpDoorBasePort+%d = %d", doors[i].Name, got, i, wantPort)
		}
	}
	// The doors share one address by design (one sandbox, one trust domain),
	// so the sequential PORT above is the only thing actually keeping two
	// doors of the same run from colliding — this is the positive control
	// that the port, not some other field, is what varies between them.
	for i := 1; i < len(doors); i++ {
		if doors[i].Addr.Addr() != doors[0].Addr.Addr() {
			t.Errorf("door %d has a different address than door 0; every door of one run shares one", i)
		}
	}
}

// TestPlanHTTPDoorsNamesNoneWhenNoneAreDeclared is the boundary planHTTPDoors
// exists to short-circuit on: a policy naming no doors must plan nothing,
// rather than the base port with no name to attach it to.
func TestPlanHTTPDoorsNamesNoneWhenNoneAreDeclared(t *testing.T) {
	pol := &policy.Policy{}
	doors, err := planHTTPDoors(pol, func(name string) (string, error) { return "/tmp/" + name, nil })
	if err != nil || doors != nil {
		t.Errorf("planHTTPDoors(no ListenNames) = %v, %v; want nil, nil", doors, err)
	}
}
