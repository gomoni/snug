package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// noSignaturePolicy is what every Spec test in this package passes: the host
// configured nothing. Without it the suite's verdict would depend on whether
// the developer's machine enforces image signatures, which is the trap
// $SNUG_PODMAN is and the reason the golden tests clear that too.
func noSignaturePolicy(t *testing.T) *SignaturePolicy {
	t.Helper()
	return hostConfiguredNoSignaturePolicy()
}

// hostWithPolicy plants a host policy.json under a temporary home, points the
// SYSTEM candidate at a path that does not exist, and returns the home.
//
// Pointing the system candidate away is not tidiness: /etc/containers/policy.json
// is a real file on some hosts, and a test asserting "this host configured
// none" would otherwise pass or fail by which machine ran it.
func hostWithPolicy(t *testing.T, body string) string {
	t.Helper()
	saved := systemSignaturePolicyPath
	t.Cleanup(func() { systemSignaturePolicyPath = saved })
	systemSignaturePolicyPath = filepath.Join(t.TempDir(), "no-system-policy.json")

	home := t.TempDir()
	if body == "" {
		return home
	}
	dir := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// requirementTypes is what the assertions below compare: the shape of the
// generated file rather than its bytes. "default" first, then every transport
// scope in sorted order, each as "transport/scope: type".
func requirementTypes(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Default []struct {
			Type string `json:"type"`
		} `json:"default"`
		Transports map[string]map[string][]struct {
			Type string `json:"type"`
		} `json:"transports"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the generated policy.json is not valid JSON (%v); podman would refuse every "+
			"pull with a parse error:\n%s", err, body)
	}
	var out []string
	for _, r := range doc.Default {
		out = append(out, "default: "+r.Type)
	}
	for _, transport := range sortedKeys(doc.Transports) {
		for _, scope := range sortedKeys(doc.Transports[transport]) {
			for _, r := range doc.Transports[transport][scope] {
				out = append(out, transport+"/"+scope+": "+r.Type)
			}
		}
	}
	return out
}

// projectAndWrite runs the WHOLE pipeline the way a run does: project from a
// host file, then materialise into a config directory. It returns the generated
// policy.json's bytes and the directory everything landed in, so a test can
// assert both what was written and — on a refusal — that nothing was.
//
// The guest mapper is the identity on a prefix, which is enough to exercise the
// substitution without a resolved Policy; imageprovenance_test.go asserts the
// real mapping through Spec.
func projectAndWrite(t *testing.T, hostBody string) ([]byte, string, error) {
	t.Helper()
	home := hostWithPolicy(t, hostBody)
	sp, err := ProjectHostSignaturePolicy(home)
	if err != nil {
		return nil, "", err
	}
	confDir := t.TempDir()
	containersDir := filepath.Join(confDir, "home", ".config", "containers")
	if err := os.MkdirAll(containersDir, 0o700); err != nil {
		t.Fatal(err)
	}
	err = sp.write(confDir, containersDir, func(_, host string) (string, error) {
		return "/snug/engine/conf" + strings.TrimPrefix(host, confDir), nil
	})
	if err != nil {
		return nil, confDir, err
	}
	body, rerr := os.ReadFile(filepath.Join(containersDir, "policy.json"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	return body, confDir, nil
}

// nothingWasWritten is the assertion that goes with every refusal: "refused,
// but wrote a permissive file anyway" is clause 3's exact shape and no source
// grep sees it.
func nothingWasWritten(t *testing.T, confDir string) {
	t.Helper()
	if confDir == "" {
		return
	}
	for _, glob := range []string{
		filepath.Join(confDir, "home", ".config", "containers", "policy.json"),
		filepath.Join(confDir, SignatureKeyDir, "*"),
	} {
		hits, err := filepath.Glob(glob)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) > 0 {
			t.Errorf("a refused projection still wrote %v", hits)
		}
	}
}

// TestTheGeneratedPolicyReproducesTheHostsRequirements is clause 1, asserted as
// a SHAPE rather than as bytes: every requirement the host wrote appears in the
// generated file, in its position, with its type.
//
// Comparing types rather than the whole document is what makes this a check on
// the PROJECTION rather than on the emitter's formatting — the emitter may
// rewrite a key path (it must) and may not change what is required of an image.
func TestTheGeneratedPolicyReproducesTheHostsRequirements(t *testing.T) {
	key := filepath.Join(t.TempDir(), "k.gpg")
	if err := os.WriteFile(key, []byte("not really a key, but a regular file"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		host string
		want []string
	}{{
		name: "podman's own default",
		host: `{"default":[{"type":"insecureAcceptAnything"}]}`,
		want: []string{"default: insecureAcceptAnything"},
	}, {
		name: "podman's shipped file, with a docker-daemon transport",
		host: `{"default":[{"type":"insecureAcceptAnything"}],
		        "transports":{"docker-daemon":{"":[{"type":"insecureAcceptAnything"}]}}}`,
		want: []string{"default: insecureAcceptAnything", "docker-daemon/: insecureAcceptAnything"},
	}, {
		// The one that matters: a host that rejects by default and trusts one
		// registry. Today's code answered insecureAcceptAnything to all of it.
		name: "reject by default, one signed registry",
		host: `{"default":[{"type":"reject"}],
		        "transports":{"docker":{"registry.example.internal":[
		          {"type":"signedBy","keyType":"GPGKeys","keyPath":"` + key + `"}]}}}`,
		want: []string{"default: reject", "docker/registry.example.internal: signedBy"},
	}, {
		name: "several requirements in one list keep their order",
		host: `{"default":[{"type":"reject"},{"type":"insecureAcceptAnything"}]}`,
		want: []string{"default: reject", "default: insecureAcceptAnything"},
	}, {
		// keyData names no path, so nothing is copied and the requirement
		// carries through untouched.
		name: "a signedBy with inline key data",
		host: `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB",
		        "signedIdentity":{"type":"remapIdentity","prefix":"a.example","signedPrefix":"b.example"}}]}`,
		want: []string{"default: signedBy"},
	}, {
		// All four keyTypes take the identical key shape, so all four are
		// equally projectable. Refusing three of them would refuse a host
		// configuration that is exactly as reproducible as the one accepted.
		name: "an X.509 trust root",
		host: `{"default":[{"type":"signedBy","keyType":"X509Certificates","keyData":"QUFB"}]}`,
		want: []string{"default: signedBy"},
	}, {
		// A docker-daemon scope is algo:digest, not a path.
		name: "a docker-daemon scope with a digest",
		host: `{"default":[{"type":"reject"}],
		        "transports":{"docker-daemon":{"sha256:0000":[{"type":"insecureAcceptAnything"}]}}}`,
		want: []string{"default: reject", "docker-daemon/sha256:0000: insecureAcceptAnything"},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _, err := projectAndWrite(t, tc.host)
			if err != nil {
				t.Fatalf("a host policy snug should project was refused: %v", err)
			}
			got := requirementTypes(t, body)
			if strings.Join(got, " | ") != strings.Join(tc.want, " | ") {
				t.Errorf("the generated policy requires\n  %v\nand the host's requires\n  %v\n"+
					"— a projection that changes what is required of an image is the silent "+
					"downgrade this file exists to prevent:\n%s", got, tc.want, body)
			}
		})
	}
}

// TestAnUnprojectableRequirementRefusesTheRun is clause 2. Every case here is a
// host policy that is STRICTER than accept-anything in a way snug cannot
// reproduce, and the only acceptable answer is an error.
//
// The error must name the position, because a policy.json with four transports
// and one sigstoreSigned in it is otherwise a file the reader has to search.
func TestAnUnprojectableRequirementRefusesTheRun(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		wantName string
	}{{
		name:     "a schema snug transcribes rather than compiles against",
		host:     `{"default":[{"type":"sigstoreSigned","keyPath":"/etc/pki/k.pub"}]}`,
		wantName: "sigstoreSigned",
	}, {
		name: "a sigstore requirement buried in one transport scope",
		host: `{"default":[{"type":"insecureAcceptAnything"}],
		        "transports":{"docker":{"registry.example.internal":[{"type":"sigstoreSigned"}]}}}`,
		wantName: "registry.example.internal",
	}, {
		// Upstream accepts the type and enforces nothing for it, so "reproduce
		// it" has no meaning snug can act on.
		name:     "signedBaseLayer, named rather than swept into the default arm",
		host:     `{"default":[{"type":"signedBaseLayer","baseLayerIdentity":{"type":"matchRepository"}}]}`,
		wantName: "signedBaseLayer",
	}, {
		name:     "a requirement type snug has never heard of",
		host:     `{"default":[{"type":"someFutureRequirement"}]}`,
		wantName: "someFutureRequirement",
	}, {
		name:     "an unknown key inside a known requirement",
		host:     `{"default":[{"type":"insecureAcceptAnything","unlessTuesday":true}]}`,
		wantName: "unlessTuesday",
	}, {
		name:     "an unknown key inside signedBy",
		host:     `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB","viaHelper":"x"}]}`,
		wantName: "viaHelper",
	}, {
		name:     "a keyType outside the four containers/image defines",
		host:     `{"default":[{"type":"signedBy","keyType":"sha256","keyData":"QUFB"}]}`,
		wantName: "sha256",
	}, {
		// Upstream requires keyType. snug neither accepts an absent one nor
		// invents "GPGKeys" for it: a keyType names a kind of trust root.
		name:     "signedBy with no keyType",
		host:     `{"default":[{"type":"signedBy","keyData":"QUFB"}]}`,
		wantName: "no keyType",
	}, {
		// Upstream: "Exactly one of keyPath, keyPaths and keyData must be
		// specified". Carrying both would emit a file the engine then rejects
		// at every pull.
		name:     "signedBy naming two key sources",
		host:     `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB","keyPaths":["/k"]}]}`,
		wantName: "names 2 of keyPath",
	}, {
		name:     "signedBy naming no key at all",
		host:     `{"default":[{"type":"signedBy","keyType":"GPGKeys"}]}`,
		wantName: "names 0 of keyPath",
	}, {
		name:     "a signedIdentity match snug does not know",
		host:     `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB","signedIdentity":{"type":"matchWhatever"}}]}`,
		wantName: "matchWhatever",
	}, {
		// Upstream decodes each match type with an EXACT field set, so a
		// dockerReference inside a matchExact is a file podman refuses.
		name:     "a field the match type does not admit",
		host:     `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB","signedIdentity":{"type":"matchExact","dockerReference":"x"}}]}`,
		wantName: "dockerReference",
	}, {
		name:     "a match type missing the field it requires",
		host:     `{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB","signedIdentity":{"type":"exactReference"}}]}`,
		wantName: "exactReference",
	}, {
		// THE PROJECTION'S OWN DOWNGRADE HAZARD. A dir scope is a host path,
		// and the engine's view is derived — carrying it verbatim would leave a
		// rule that never matches, so the image falls through to `default` and
		// a rule stricter than the default has been dropped by the projection.
		name:     "a transport whose scope is a host path",
		host:     `{"default":[{"type":"insecureAcceptAnything"}],"transports":{"dir":{"/mnt/untrusted":[{"type":"reject"}]}}}`,
		wantName: "/mnt/untrusted",
	}, {
		name:     "a docker scope that begins with a slash",
		host:     `{"default":[{"type":"reject"}],"transports":{"docker":{"/etc":[{"type":"reject"}]}}}`,
		wantName: "begins with '/'",
	}, {
		name:     "a top-level key snug does not know",
		host:     `{"default":[{"type":"reject"}],"defaultDockerDaemon":[{"type":"reject"}]}`,
		wantName: "defaultDockerDaemon",
	}, {
		// Upstream: "Default policy is missing". Being looser than the thing
		// being projected for is how a projection stops being one.
		name:     "no default requirement list",
		host:     `{"transports":{"docker":{"a.example":[{"type":"reject"}]}}}`,
		wantName: `no "default"`,
	}, {
		// Upstream: "List of verification policy requirements must not be
		// empty".
		name:     "an empty requirement list",
		host:     `{"default":[]}`,
		wantName: "empty list",
	}, {
		name:     "not JSON at all",
		host:     `this is not a policy`,
		wantName: "cannot parse",
	}, {
		name:     "a requirement with no type",
		host:     `{"default":[{}]}`,
		wantName: "no \"type\"",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, confDir, err := projectAndWrite(t, tc.host)
			if err == nil {
				t.Fatalf("a host policy snug cannot reproduce was projected anyway, which is "+
					"the downgrade this file exists to prevent:\n%s", body)
			}
			if !strings.Contains(err.Error(), tc.wantName) {
				t.Errorf("the refusal never says %q, so the reader cannot tell which "+
					"requirement stopped the run: %v", tc.wantName, err)
			}
			nothingWasWritten(t, confDir)
		})
	}
}

// TestNothingFallsBackToAcceptAnything is clause 3, and it is the one a
// reviewer greps for.
//
// TWO INSTRUMENTS, because either alone is weak. The behavioural half asserts
// that a stricter host policy never produces the token; the source half asserts
// that the token has exactly one site in the package that is not carrying a
// host requirement, so a future "keep builds working" patch cannot add a
// second one and pass the first half by covering only the inputs it thought of.
func TestNothingFallsBackToAcceptAnything(t *testing.T) {
	t.Run("a stricter host policy never yields the token", func(t *testing.T) {
		body, _, err := projectAndWrite(t, `{"default":[{"type":"reject"}]}`)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), reqAcceptAnything) {
			t.Fatalf("a host policy that rejects everything produced a generated policy "+
				"carrying %s:\n%s", reqAcceptAnything, body)
		}
		// CONTROL: the token IS produced when the host wrote it, so the check
		// above is not passing because nothing ever emits it.
		permissive, _, err := projectAndWrite(t, `{"default":[{"type":"insecureAcceptAnything"}]}`)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(permissive), reqAcceptAnything) {
			t.Fatalf("control: a host policy that accepts anything did not produce %s, so the "+
				"assertion above proves nothing:\n%s", reqAcceptAnything, permissive)
		}
	})

	t.Run("exactly one site builds the requirement out of nothing", func(t *testing.T) {
		// The sweep counts CONSTRUCTIONS, not mentions. Carrying a host
		// requirement whose own type is insecureAcceptAnything is the
		// projection working; building one where the host wrote something else
		// is the fallback clause 3 forbids, and every spelling of it has to
		// name the type on the right of a field assignment.
		src, err := os.ReadFile("signaturepolicy.go")
		if err != nil {
			t.Fatal(err)
		}
		var built []string
		var literals []string
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			at := "signaturepolicy.go:" + strconv.Itoa(i+1) + ": " + trimmed
			if strings.Contains(line, "Type: reqAcceptAnything") ||
				strings.Contains(line, "Type = reqAcceptAnything") {
				built = append(built, at)
			}
			if strings.Contains(line, `"`+reqAcceptAnything+`"`) {
				literals = append(literals, at)
			}
		}
		if len(built) != 1 {
			t.Errorf("%d places build an %s requirement, want exactly 1 "+
				"(hostConfiguredNoSignaturePolicy, where the host configured nothing). A "+
				"second is a fallback to accepting any image, which is the whole thing this "+
				"file refuses to do:\n  %s",
				len(built), reqAcceptAnything, strings.Join(built, "\n  "))
		}
		if len(built) == 1 && !strings.Contains(built[0], "reqAcceptAnything") {
			t.Errorf("unexpected construction site: %s", built[0])
		}
		// The literal must live only in the const, or a fallback could spell it
		// out and the count above would not see it.
		if len(literals) != 1 {
			t.Errorf("the literal %q appears at %d places in code, want exactly 1 (the "+
				"const). A second spelling is a fallback the construction count cannot "+
				"see:\n  %s", reqAcceptAnything, len(literals), strings.Join(literals, "\n  "))
		}
	})
}

// TestAHostWithNoPolicySaysSoInTheGeneratedFile is the absent case, and the
// assertion is on the SENTENCE as much as on the bytes.
//
// A human reading this file after an image was accepted needs to know whether
// their host asked for verification and snug dropped it, or their host asked
// for nothing. Both produce insecureAcceptAnything; only one of them is a
// decision snug made.
func TestAHostWithNoPolicySaysSoInTheGeneratedFile(t *testing.T) {
	sp, err := ProjectHostSignaturePolicy(hostWithPolicy(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if sp.Source != "" {
		t.Fatalf("the projection claims a source (%s) on a host with no policy.json", sp.Source)
	}
	body, confDir, err := projectAndWrite(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := requirementTypes(t, body); len(got) != 1 || got[0] != "default: insecureAcceptAnything" {
		t.Fatalf("a host with no policy.json produced %v; an empty requirement list satisfies "+
			"no image, so every pull would fail on a host that asked for nothing", got)
	}
	// The SENTENCE lives in the sidecar, because policy.json's own schema has
	// no room for one — see TestTheGeneratedPolicyCarriesNoKeyContainersImageRefuses.
	side, err := os.ReadFile(filepath.Join(confDir, "home", ".config", "containers",
		"policy.json.snug"))
	if err != nil {
		t.Fatalf("no sidecar beside the generated policy: %v", err)
	}
	if !strings.Contains(string(side), "no policy.json") {
		t.Errorf("the sidecar does not say the HOST configured nothing, so the generated file "+
			"reads as though snug decided not to verify:\n%s", side)
	}
}

// TestTheGeneratedPolicyCarriesNoKeyContainersImageRefuses is the round trip
// that a comment cannot replace.
//
// containers/image parses policy.json with a resolver that returns a
// destination for "default" and "transports" and nil for everything else, and
// its helper turns a nil destination into `Unknown key %q`. So an explanatory
// key inside the generated file — the obvious way to write a comment into JSON —
// would make EVERY pull in EVERY sandbox fail. The explanation goes in a sidecar
// instead, and this asserts the machine file stayed machine-readable.
//
// CONTROL: the sidecar must exist and carry the sentence, or "no extra keys"
// would pass on a projection that explained nothing anywhere.
func TestTheGeneratedPolicyCarriesNoKeyContainersImageRefuses(t *testing.T) {
	body, confDir, err := projectAndWrite(t,
		`{"default":[{"type":"reject"}],"transports":{"docker-daemon":{"":[{"type":"reject"}]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range sortedKeys(doc) {
		if k != "default" && k != "transports" {
			t.Errorf("the generated policy.json carries the top-level key %q. "+
				"containers/image resolves an unknown top-level key to nil and reports "+
				"`Unknown key`, so every pull would fail with a parse error:\n%s", k, body)
		}
	}
	side, err := os.ReadFile(filepath.Join(confDir, "home", ".config", "containers",
		"policy.json.snug"))
	if err != nil {
		t.Fatalf("control: no sidecar, so the explanation is nowhere at all: %v", err)
	}
	if !strings.Contains(string(side), "PROJECTION") {
		t.Errorf("control: the sidecar does not say the file is a projection:\n%s", side)
	}
}

// TestTheEmitterAddsNoFieldTheHostDidNotWrite is what makes "projection" a true
// word.
//
// containers/image defaults an absent signedIdentity to matchRepoDigestOrExact,
// so writing one in would be snug choosing which images a signature is accepted
// for; and a keyType snug synthesised would be snug choosing a trust root.
// Neither is snug's to decide, and neither would be visible in a test that only
// checked requirement TYPES.
func TestTheEmitterAddsNoFieldTheHostDidNotWrite(t *testing.T) {
	body, _, err := projectAndWrite(t,
		`{"default":[{"type":"signedBy","keyType":"GPGKeys","keyData":"QUFB"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Default []map[string]json.RawMessage `json:"default"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Default) != 1 {
		t.Fatalf("want one default requirement, got %d", len(doc.Default))
	}
	want := map[string]bool{"type": true, "keyType": true, "keyData": true}
	for _, k := range sortedKeys(doc.Default[0]) {
		if !want[k] {
			t.Errorf("the emitter added %q, which the host did not write. A projection that "+
				"invents a field is snug deciding something the host chose not to:\n%s", k, body)
		}
	}
	for k := range want {
		if _, ok := doc.Default[0][k]; !ok {
			t.Errorf("the emitter dropped %q, which the host DID write:\n%s", k, body)
		}
	}
}

// TestAnUnreadableHostPolicyRefuses is the case hostread.Optional would fold
// into absence.
//
// "snug could not read your policy" and "you configured no policy" are
// different sentences and only one of them may produce a permissive file. A
// FIFO is the shape that also HANGS if the read is not the bounded one (issue
// #337): this test fails by timing out the package if that guard goes.
func TestAnUnreadableHostPolicyRefuses(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "policy.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("SKIP: cannot create a FIFO here: %v", err)
	}
	home := hostWithPolicy(t, "")
	if err := os.MkdirAll(filepath.Join(home, ".config", "containers"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, filepath.Join(home, ".config", "containers", "policy.json")); err != nil {
		t.Fatal(err)
	}

	type result struct {
		sp  *SignaturePolicy
		err error
	}
	done := make(chan result, 1)
	go func() {
		sp, err := ProjectHostSignaturePolicy(home)
		done <- result{sp, err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("a FIFO at the host's policy.json path was treated as a host that "+
				"configured nothing, and the run would accept any image: %+v", r.sp)
		}
		if !strings.Contains(r.err.Error(), "not a regular file") {
			t.Errorf("the refusal does not say what was wrong with the file: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ProjectHostSignaturePolicy blocked on a FIFO: the run would hang before " +
			"anything started, with nothing on any screen")
	}
}

// TestAKeyThePolicyNamesIsProjectedOrTheRunRefuses is the key half of clauses 1
// and 2 together.
//
// The engine resolves paths in its own derived view, so a keyPath that still
// names a HOST path is a requirement the engine cannot satisfy — it would fail
// to open the key and reject the image, which is a run broken in the safe
// direction and still not what the host configured.
func TestAKeyThePolicyNamesIsProjectedOrTheRunRefuses(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "trusted.gpg")
	const marker = "PROJECTED-KEY-MARKER"
	if err := os.WriteFile(key, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	body, confDir, err := projectAndWrite(t,
		`{"default":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"`+key+`"}]}`)
	if err != nil {
		t.Fatalf("a signedBy naming a readable regular file was refused: %v", err)
	}
	if strings.Contains(string(body), key) {
		t.Errorf("the generated policy still names the HOST path %s. The engine's view is "+
			"derived from the sandbox's, so that path resolves to nothing there:\n%s", key, body)
	}
	if !strings.Contains(string(body), "/snug/engine/conf/"+SignatureKeyDir+"/") {
		t.Errorf("the generated policy names no guest path for the key, so the requirement "+
			"cannot be satisfied inside:\n%s", body)
	}
	copies, err := filepath.Glob(filepath.Join(confDir, SignatureKeyDir, "*"))
	if err != nil || len(copies) != 1 {
		t.Fatalf("want exactly one projected key in %s, got %v (%v)",
			filepath.Join(confDir, SignatureKeyDir), copies, err)
	}
	if got, _ := os.ReadFile(copies[0]); string(got) != marker {
		t.Errorf("the projected key is not a copy of the host's: %q", got)
	}
	// The copy must be read-only to everything but its owner, and it lands in
	// the config directory, which Tier C grafts read-only into the engine's
	// view: an engine talked into writing cannot rewrite the key it verifies
	// against.
	if fi, err := os.Stat(copies[0]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the projected key is mode %v, want 0600", fi.Mode().Perm())
	}

	// A key that is not there, or is not a file, refuses. Accepting the image
	// instead would drop exactly the check the host configured.
	for _, bad := range []struct {
		name string
		path string
	}{
		{"absent", filepath.Join(dir, "nope.gpg")},
		{"a directory", dir},
	} {
		t.Run(bad.name, func(t *testing.T) {
			_, confDir, err := projectAndWrite(t,
				`{"default":[{"type":"signedBy","keyType":"GPGKeys","keyPath":"`+bad.path+`"}]}`)
			if err == nil {
				t.Fatal("a signedBy naming a key snug cannot project was projected anyway")
			}
			if !strings.Contains(err.Error(), bad.path) {
				t.Errorf("the refusal does not name the key it could not project: %v", err)
			}
			nothingWasWritten(t, confDir)
		})
	}
}

// TestTheGeneratedPolicyIsByteStableAcrossRuns guards the one property Go's map
// iteration takes away for free. A generated artifact that differs run to run
// is one no golden test and no human diff can hold, and the transports map is
// two levels of it.
func TestTheGeneratedPolicyIsByteStableAcrossRuns(t *testing.T) {
	const host = `{"default":[{"type":"reject"}],
	   "transports":{"docker":{"b.example":[{"type":"reject"}],"a.example":[{"type":"reject"}]},
	                 "docker-daemon":{"":[{"type":"reject"}]},
	                 "atomic":{"z.example":[{"type":"reject"}]}}}`
	first, _, err := projectAndWrite(t, host)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := projectAndWrite(t, host)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatalf("the generated policy.json is not stable across runs:\n%s\n---\n%s",
				first, again)
		}
	}
}

// TestAProjectedKeyIsNotReachableFromTheSandbox is the abuse sentence, asserted
// rather than argued.
//
// The key copies land in this run's config directory. That directory reaches
// the ENGINE through a graft and the payload through nothing at all — the
// container proxy's bind filter is policy.HostPathVisible, which walks the
// sandbox's own KindBind mounts and never p.Grafts, so no `-v` can name a copy
// under either its host path or its guest path.
//
// The keys are public verification material, which is the WEAK half of the
// argument; "the bind filter reads mounts, not grafts" is the strong half, and
// it is the half a future change can break. So it is the half that gets a test.
//
// CONTROL: the sandbox's own target bind must be visible in the same policy, or
// this passes on a policy that hides everything.
func TestAProjectedKeyIsNotReachableFromTheSandbox(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	target := t.TempDir()
	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, target))
	if err != nil {
		t.Fatal(err)
	}
	p := &policy.Policy{
		Podman: policy.PodmanSocket,
		Mounts: map[string]policy.Mount{
			"/proj": {Guest: "/proj", Host: target, Kind: policy.KindBind,
				Access: policy.AccessRW, From: []string{"@cwd-rw"}},
			"/usr": {Guest: "/usr", Host: "/usr", Kind: policy.KindBind,
				Access: policy.AccessRO, From: []string{"@sys"}},
		},
	}
	if err := e.GraftInto(policy.OSEnviron{}, p); err != nil {
		t.Fatal(err)
	}

	// CONTROL first: the target really is bindable in this policy.
	if !p.HostPathVisible(target, true) {
		t.Fatal("control: the sandbox's own target is not visible to the bind filter, so the " +
			"refusals below would prove nothing")
	}

	keyDir := filepath.Join(e.ConfDir(), SignatureKeyDir)
	for _, path := range []string{
		keyDir,
		filepath.Join(keyDir, keyFileName(0)),
		e.ConfDir(),
		policy.EngineConfGuest + "/" + SignatureKeyDir,
	} {
		if p.HostPathVisible(path, false) {
			t.Errorf("the bind filter admits %s, so a container could mount the keys the "+
				"engine verifies images against. The config directory reaches the engine "+
				"through a GRAFT, and the filter must read mounts only", path)
		}
	}

	// And the engine really can see it, or the projection would be writing
	// keys into a directory the engine cannot open.
	if _, ok := p.EngineGuestPath(filepath.Join(keyDir, keyFileName(0))); !ok {
		t.Error("the engine cannot see its own projected key: the config graft must expose it")
	}
}

// TestTheGeneratedPolicyBytes is the review artifact: a change to these bytes
// is a change to what the engine will and will not run, and it must be read as
// one.
//
// The fixture host policy is deliberately the awkward shape rather than the
// common one — reject by default, one registry trusted against a key file, one
// transport left permissive, an identity match — because that is the shape
// where a projection can go wrong quietly. The expected bytes are inline rather
// than in testdata for the same reason a golden file would be: the diff is the
// point, and here it sits next to the requirement it renders.
func TestTheGeneratedPolicyBytes(t *testing.T) {
	key := filepath.Join(t.TempDir(), "trusted.gpg")
	if err := os.WriteFile(key, []byte("a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _, err := projectAndWrite(t, `{
	    "default": [{"type": "reject"}],
	    "transports": {
	        "docker-daemon": {"": [{"type": "insecureAcceptAnything"}]},
	        "docker": {
	            "registry.example.internal": [{
	                "type": "signedBy",
	                "keyType": "GPGKeys",
	                "keyPath": "`+key+`",
	                "signedIdentity": {"type": "matchRepository"}
	            }]
	        }
	    }
	}`)
	if err != nil {
		t.Fatal(err)
	}

	const want = `{
    "default": [
        {
            "type": "reject"
        }
    ],
    "transports": {
        "docker": {
            "registry.example.internal": [
                {
                    "type": "signedBy",
                    "keyType": "GPGKeys",
                    "keyPath": "/snug/engine/conf/sigkeys/0.key",
                    "signedIdentity": {
                        "type": "matchRepository"
                    }
                }
            ]
        },
        "docker-daemon": {
            "": [
                {
                    "type": "insecureAcceptAnything"
                }
            ]
        }
    }
}
`
	if string(body) != want {
		t.Errorf("the generated policy.json changed. This file decides which images the "+
			"engine will run, so read the diff as a change to the security boundary.\n"+
			"--- got\n%s\n--- want\n%s", body, want)
	}
}
