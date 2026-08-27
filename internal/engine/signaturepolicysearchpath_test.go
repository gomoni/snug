package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheSearchPathIsPodmansOwn pins the list against what podman 6.0.2 prints
// when it finds nothing, which is the only oracle that cannot go stale
// silently.
//
// MEASURED by hiding /usr/share/containers behind a bind mount inside
// `unshare -U -r -m` and letting podman name its own candidates:
//
//	Error: config file not found: no policy.json file found; searched paths:
//	  ["<config>/containers/policy.json" "/etc/containers/policy.json"
//	   "/usr/share/containers/policy.json"]
//
// The third entry is the one this test exists for. snug read only the first
// two, which on any distribution shipping a default under /usr/share — openSUSE
// does — made it conclude "the host configured no policy" about a host that had
// one.
func TestTheSearchPathIsPodmansOwn(t *testing.T) {
	got, err := hostSignaturePolicyPaths("/home/u", "")
	if err != nil {
		t.Fatalf("hostSignaturePolicyPaths: %v", err)
	}
	want := []string{
		"/home/u/.config/containers/policy.json",
		"/etc/containers/policy.json",
		"/usr/share/containers/policy.json",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate %d is %q, want %q — the order is podman's own and a "+
				"different one projects a file the engine would not load", i, got[i], want[i])
		}
	}
}

// TestXDGConfigHomeDisplacesTheHomeCandidate pins the other half of the
// per-user path. Measured on 6.0.2: with XDG_CONFIG_HOME set, podman's own
// candidate list names <XDG_CONFIG_HOME>/containers/policy.json and not
// $HOME/.config. Reading HOME where they diverge projects a file podman never
// loads and misses the one it does.
func TestXDGConfigHomeDisplacesTheHomeCandidate(t *testing.T) {
	got, err := hostSignaturePolicyPaths("/home/u", "/elsewhere/cfg")
	if err != nil {
		t.Fatalf("hostSignaturePolicyPaths: %v", err)
	}
	if got[0] != "/elsewhere/cfg/containers/policy.json" {
		t.Errorf("first candidate is %q, want the XDG one", got[0])
	}
	for _, p := range got {
		if strings.HasPrefix(p, "/home/u/") {
			t.Errorf("candidate %q still reads $HOME/.config while XDG_CONFIG_HOME is set", p)
		}
	}
	// CONTROL: unset, and the home candidate comes back — so the assertion
	// above is XDG displacing it rather than the home path never being built.
	got, err = hostSignaturePolicyPaths("/home/u", "")
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if got[0] != "/home/u/.config/containers/policy.json" {
		t.Fatalf("control: with XDG_CONFIG_HOME unset the first candidate is %q, want the "+
			"home one", got[0])
	}
}

// TestARelativeXDGConfigHomeRefuses. Falling back to $HOME/.config would read a
// DIFFERENT file than the engine, so the sandbox would enforce a posture its
// own screen does not describe (invariant 5). The same hazard the home
// parameter's doc comment records, without @home's validation behind it.
func TestARelativeXDGConfigHomeRefuses(t *testing.T) {
	_, err := hostSignaturePolicyPaths("/home/u", "relative/cfg")
	if err == nil {
		t.Fatal("a relative XDG_CONFIG_HOME was accepted; it must refuse rather than fall " +
			"back to $HOME/.config")
	}
	for _, want := range []string{"XDG_CONFIG_HOME", "absolute", "Fix:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not contain %q, so it does not name the fix:\n%v",
				want, err)
		}
	}
}

// TestAPolicyOnlyInUsrShareIsProjected is the defect itself, end to end: a host
// whose ONLY signature policy is the distribution's. Before the third candidate
// existed snug reported Source == "" for this host and generated an
// accept-anything policy, while --dry-run told the human "this host has no
// policy.json where podman looks, so a podman here refuses every pull outright"
// — and a pull on that host in fact SUCCEEDS.
func TestAPolicyOnlyInUsrShareIsProjected(t *testing.T) {
	dir := t.TempDir()
	savedSystem, savedShare := systemSignaturePolicyPath, usrShareSignaturePolicyPath
	t.Cleanup(func() {
		systemSignaturePolicyPath, usrShareSignaturePolicyPath = savedSystem, savedShare
	})
	systemSignaturePolicyPath = filepath.Join(dir, "no-system-policy.json")
	usrShareSignaturePolicyPath = filepath.Join(dir, "usrshare-policy.json")

	// openSUSE's own file, byte for byte in shape: a default plus the
	// empty-scope docker-daemon entry, which checkScope accepts.
	body := `{"default":[{"type":"reject"}],` +
		`"transports":{"docker-daemon":{"":[{"type":"insecureAcceptAnything"}]}}}`
	if err := os.WriteFile(usrShareSignaturePolicyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	sp, err := ProjectHostSignaturePolicy(t.TempDir(), "")
	if err != nil {
		t.Fatalf("projecting a host whose only policy is the distribution's: %v", err)
	}
	if sp.Source != usrShareSignaturePolicyPath {
		t.Fatalf("Source is %q, want %q — an empty Source is snug reporting \"your host "+
			"configured nothing\" about a host that configured this", sp.Source,
			usrShareSignaturePolicyPath)
	}
	if !sp.demandsSomething() {
		t.Error("the projected policy demands nothing, though the host file's default is " +
			"\"reject\" — the host's posture was not reproduced")
	}
}
