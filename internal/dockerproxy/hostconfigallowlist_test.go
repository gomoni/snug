package dockerproxy

import (
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the create body is an allowlist now, and this is what says so ────────────
//
// Issue #338. handleCreate was the last denylist in this package: enumerated
// danger refused, everything else forwarded verbatim — 38 of docker's 71
// HostConfig fields, five of them carrying a host path the engine stats. The
// build query (TestUnknownBuildParametersAreRefused) and the build context
// (TestBuildContextRefusesAFieldSnugDoesNotModel) had both already been
// inverted to "unmodelled is refused".
//
// The assertion whose ABSENCE was the finding: every HostConfig key snug
// forwards is one it modelled. TestSnugNeverForwardsAFieldItDidNotInspect reads
// like it and only checks that case and fold spellings of ALREADY-INSPECTED
// keys cannot slip past decodeObject; TestEveryRefusedFieldExplainsItself is a
// claim about the refusal list's CONTENTS, not its completeness.

// recordedCreateBody is the create body a stock docker CLI really sends, read
// from testdata rather than typed here. A hand-written list of 62 field names is
// prose that drifts; a recording is a measurement.
type recordedCreateBody struct {
	Recorded map[string]string          `json:"_recorded"`
	Body     map[string]json.RawMessage `json:"body"`
}

func loadRecordedCreateBody(t *testing.T) recordedCreateBody {
	t.Helper()
	raw, err := os.ReadFile("testdata/docker-run-create-body.json")
	if err != nil {
		t.Fatal(err)
	}
	var got recordedCreateBody
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Recorded["client"] == "" {
		t.Fatal("the fixture does not say which client produced it, so a future reader " +
			"cannot tell whether it still describes anything")
	}
	if len(got.Body) == 0 {
		t.Fatal("the fixture decoded to an empty body; every assertion below would be vacuous")
	}
	return got
}

func recordedHostConfig(t *testing.T, b recordedCreateBody) map[string]json.RawMessage {
	t.Helper()
	raw, ok := b.Body["HostConfig"]
	if !ok {
		t.Fatal("the recorded body has no HostConfig")
	}
	hc, err := decodeObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(hc) < 50 {
		t.Fatalf("the recorded HostConfig has only %d fields; the point of this fixture is "+
			"that a real client sends dozens, and a truncated one makes the emptiness "+
			"assertions below trivial", len(hc))
	}
	return hc
}

// TestTheCreateAllowlistAdmitsWhatDockerActuallySends pins the SET of fields a
// real client sends non-empty, because that set IS the shippability constraint.
//
// An allowlist evaluated on raw PRESENCE would refuse every `docker run` on 62
// keys. One evaluated on non-empty VALUES has to admit exactly these six, and
// isEmptyJSON is what decides which six — which makes isEmptyJSON part of the
// security boundary, not a formatting helper. The LogConfig trap is the same
// mistake at one-field scale: {"Type":"","Config":{}} is sent on every create,
// isEmptyJSON does not call it empty, and the denylist refused every `docker
// run` there had ever been with a message about log drivers.
//
// Asserted as a set rather than spot-checked: a SEVENTH key going non-empty in
// a future docker release must fail here rather than in a user's `docker run`.
func TestTheCreateAllowlistAdmitsWhatDockerActuallySends(t *testing.T) {
	hc := recordedHostConfig(t, loadRecordedCreateBody(t))

	want := map[string]bool{
		"AutoRemove":       true, // true
		"ConsoleSize":      true, // [0,0]
		"LogConfig":        true, // {"Type":"","Config":{}} — refused list, deleted by isDefaultLogConfig
		"MemorySwappiness": true, // -1, and a POINTER field, which is why it is not 0
		"NetworkMode":      true, // "default", read by the namespace loop
		"RestartPolicy":    true, // {"Name":"no","MaximumRetryCount":0}, read by checkRestartPolicy
	}

	var got []string
	for k, v := range hc {
		if !isEmptyJSON(v) {
			got = append(got, k)
		}
	}
	sort.Strings(got)

	for _, k := range got {
		if !want[k] {
			t.Errorf("the recorded body sends %s=%s non-empty and nothing here expects it. "+
				"Decide what handleCreate does with it — a new non-empty field from a stock "+
				"client is the field that will 403 every `docker run`", k, hc[k])
		}
		delete(want, k)
	}
	for k := range want {
		t.Errorf("this test claims a stock client sends %s non-empty and the recording does "+
			"not, so the claim outlived its measurement", k)
	}
}

// TestCreateAcceptsWhatTheDockerCLIActuallySends is the behavioural half, and
// the one test that would have caught the LogConfig regression at schema scale.
func TestCreateAcceptsWhatTheDockerCLIActuallySends(t *testing.T) {
	sock, eng, _ := startProxy(t)
	rec := loadRecordedCreateBody(t)
	body, err := json.Marshal(rec.Body)
	if err != nil {
		t.Fatal(err)
	}

	before := eng.reached.Load()
	code, resp := post(t, sock, "/v1.41/containers/create", string(body))
	if code != 200 {
		t.Fatalf("the body a stock %s really sends was refused (status %d). That is a ban on "+
			"`docker run`, not a filter: %s", rec.Recorded["client"], code, denyMessage(resp))
	}
	if eng.reached.Load() == before {
		t.Fatal("the create never reached the engine, so nothing above is evidence the " +
			"allowlist admits anything")
	}

	// What reached the engine must still be snug's own re-encoding: every
	// unmodelled empty field gone, and the hardening injected.
	fwd, err := decodeObject([]byte(eng.lastBody.Load().(string)))
	if err != nil {
		t.Fatal(err)
	}
	hc, err := decodeObject(fwd["HostConfig"])
	if err != nil {
		t.Fatal(err)
	}
	if string(hc["Privileged"]) != "false" {
		t.Errorf("Privileged reached the engine as %s, want false", hc["Privileged"])
	}
	// Links is the one field in the recording that is modelled NOWHERE — not
	// refused, not allowlisted — so it is the one the drop actually reaches.
	// A REFUSED field arriving empty (Cgroup "", BlkioWeightDevice []) is kept
	// and forwarded as it always was: the refusal loop skips an empty value, and
	// the sweep skips it as judged. That is unchanged behaviour and harmless —
	// the value is the zero value — but it is worth knowing which of the two
	// paths a given empty field took.
	if _, ok := hc["Links"]; ok {
		t.Error("Links survived to the engine; an unmodelled empty field is dropped, not " +
			"forwarded")
	}
	if _, ok := hc["Cgroup"]; !ok {
		t.Error("Cgroup did not survive as an empty value. It is on refusedHostConfig, so " +
			"the drop must not reach it; if this changed, say so deliberately rather than " +
			"letting the two paths blur")
	}
}

// TestUnknownHostConfigFieldIsRefused — a non-empty field nobody modelled fails
// closed. This is the inversion itself.
func TestUnknownHostConfigFieldIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, body := range []string{
		`{"Image":"alpine","HostConfig":{"FieldPodmanAddsIn2027":"anything"}}`,
		`{"Image":"alpine","HostConfig":{"FieldPodmanAddsIn2027":{"Path":"/etc/shadow"}}}`,
		`{"Image":"alpine","HostConfig":{"FieldPodmanAddsIn2027":["x"]}}`,
		`{"Image":"alpine","HostConfig":{"FieldPodmanAddsIn2027":true}}`,
	} {
		refuse(t, sock, eng, "/v1.41/containers/create", body,
			"snug allows a named set of HostConfig fields and refuses the rest")
	}
}

// TestEmptyUnknownHostConfigFieldIsDroppedNotForwarded — the half that makes
// the inversion shippable, and the half that must not become silent.
//
// Dropping inherits isDefaultLogConfig's justification rather than being an
// exception to it: docker and podman decode the create body into a struct with
// non-pointer fields, so absent and zero-valued are indistinguishable on the far
// side. Invariant 5 forbids a SILENT downgrade, not a downgrade, which is why
// the audit line names what went.
func TestEmptyUnknownHostConfigFieldIsDroppedNotForwarded(t *testing.T) {
	var lines []string
	audit := func(s string) { lines = append(lines, s) }

	sock, eng, _ := startProxyAudited(t, policy.PodmanSocket, audit)

	for _, empty := range []string{`null`, `""`, `0`, `[]`, `{}`, `false`} {
		t.Run("empty "+empty, func(t *testing.T) {
			lines = nil
			before := eng.reached.Load()
			body := `{"Image":"alpine","HostConfig":{"FieldPodmanAddsIn2027":` + empty + `}}`
			code, resp := post(t, sock, "/v1.41/containers/create", body)
			if code != 200 {
				t.Fatalf("status %d, want 200 — an empty unmodelled field is dropped, not "+
					"refused: %s", code, denyMessage(resp))
			}
			if eng.reached.Load() == before {
				t.Fatal("the create never reached the engine")
			}
			hc, err := decodeObject(json.RawMessage(mustHostConfig(t, eng)))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := hc["FieldPodmanAddsIn2027"]; ok {
				t.Error("the unmodelled field reached the engine; empty means DROPPED, and " +
					"forwarding it is the verbatim channel this change closes")
			}
			named := false
			for _, l := range lines {
				if strings.Contains(l, "FieldPodmanAddsIn2027") {
					named = true
				}
			}
			if !named {
				t.Errorf("nothing in the audit named the dropped field: %v. A downgrade the "+
					"user cannot see is the one invariant 5 forbids", lines)
			}
		})
	}

	// POSITIVE CONTROL. Without it every assertion above is satisfied by a
	// proxy that drops every field it is given, empty or not.
	t.Run("control: the same field non-empty is refused", func(t *testing.T) {
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"FieldPodmanAddsIn2027":"set"}}`,
			"snug allows a named set of HostConfig fields")
	})
}

// TestNoHostConfigFieldIsForwardedThatSnugDidNotModel is the completeness
// assertion the issue says nothing makes.
//
// The name set is COMPUTED, not typed: the recording's own 62 keys, plus every
// name snug itself holds. A key added to refusedHostConfig or to
// unexaminedCreateFields joins the sweep without anybody editing this file, and
// dockerOnlyFields carries the handful docker defines that this client omits.
func TestNoHostConfigFieldIsForwardedThatSnugDidNotModel(t *testing.T) {
	sock, eng, _ := startProxy(t)

	names := map[string]bool{}
	for k := range recordedHostConfig(t, loadRecordedCreateBody(t)) {
		names[k] = true
	}
	for _, k := range refusedHostConfig {
		names[k] = true
	}
	for _, k := range namespaceModeKeys {
		names[k] = true
	}
	for k := range unexaminedCreateFields {
		names[k] = true
	}
	// The names docker's HostConfig defines that a plain `docker run` does not
	// send, so the sweep covers the schema and not just this invocation.
	for _, k := range dockerOnlyFields {
		names[k] = true
	}
	if len(names) < 65 {
		t.Fatalf("the sweep covers only %d field names; docker's HostConfig plus its embedded "+
			"Resources is 71, and a sweep that shrank is one that stopped measuring", len(names))
	}

	sorted := make([]string, 0, len(names))
	for k := range names {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, name := range sorted {
		lower := strings.ToLower(name)
		modelled := judgedCreateField[lower] || unexaminedCreateField[lower]
		body := `{"Image":"alpine","HostConfig":{` + mustJSON(t, name) + `:"snug-probe"}}`
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create", body)

		if !modelled {
			if code != http.StatusForbidden {
				t.Errorf("HostConfig.%s is modelled nowhere and status was %d, want 403: %s",
					name, code, denyMessage(resp))
			}
			if eng.reached.Load() != before {
				t.Errorf("HostConfig.%s reached the engine unmodelled", name)
			}
			continue
		}
		// A modelled field may be refused for its own reason or forwarded; what
		// it may not be is refused by the catch-all, which would mean the two
		// halves disagree about what "modelled" means.
		if code == http.StatusForbidden &&
			strings.Contains(denyMessage(resp), "snug allows a named set of HostConfig fields") {
			t.Errorf("HostConfig.%s is modelled but the catch-all refused it, so "+
				"judgedCreateField/unexaminedCreateField and the sweep disagree", name)
		}
	}
}

// dockerOnlyFields are HostConfig names docker defines that a plain `docker run`
// omits and snug does not name either. Written out because the only other source
// would be importing docker's Go types, and snug's go.mod stays minimal — every
// dependency there runs with the authority of the thing building the sandbox.
var dockerOnlyFields = []string{
	"KernelMemory", "KernelMemoryTCP", "DiskQuota", "CpuRealtimeRuntime",
	"BlkioIOps", "NetworkingConfig", "MaximumIOps",
}

// ── the five path-bearing fields ─────────────────────────────────────────────

var blkioPathFields = []string{
	"BlkioWeightDevice", "BlkioDeviceReadBps", "BlkioDeviceWriteBps",
	"BlkioDeviceReadIOps", "BlkioDeviceWriteIOps",
}

// TestEveryBlkioPathFieldIsRefused. Measured through snug's own filter against a
// real podman 6.0.2 before the fix: /dev/../<path> returned 500 `not a block
// device` for a path that exists and 500 `no such file or directory` for one
// that does not — a two-way existence oracle, one bit per request, over paths
// resolved in the ENGINE's namespace.
func TestEveryBlkioPathFieldIsRefused(t *testing.T) {
	sock, eng, target := startProxy(t)

	for _, f := range blkioPathFields {
		for _, path := range []string{
			"/dev/../etc/shadow",  // podman's own guard is lexical and /dev/../ defeats it
			"/dev/sda",            // the spelling that would work on a host
			target,                // a path the sandbox really can see, at rw
			"relative/name",       //
			"/dev/../etc/no-such", // the other half of the oracle
		} {
			body := `{"Image":"alpine","HostConfig":{"` + f + `":[{"Path":` +
				mustJSON(t, path) + `,"Rate":1}]}}`
			refuse(t, sock, eng, "/v1.41/containers/create", body,
				"snug neither resolves nor rewrites it")
		}
	}

	// NEGATIVE CONTROL, and it is the one that matters: every one of the five
	// arrives as [] on a plain `docker run`. Refusing them on PRESENCE would ban
	// `docker run` outright, which is the trap this whole change is walking past.
	t.Run("control: the empty value a real client sends is accepted", func(t *testing.T) {
		var parts []string
		for _, f := range blkioPathFields {
			parts = append(parts, `"`+f+`":[]`)
		}
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{`+strings.Join(parts, ",")+`}}`)
		if code != 200 {
			t.Fatalf("status %d on the empty blkio values a stock client sends, want 200: %s",
				code, denyMessage(resp))
		}
		if eng.reached.Load() == before {
			t.Fatal("the create never reached the engine")
		}
	})
}

// TestBlkioRefusalDoesNotRestOnAHostPathGuard.
//
// The ruling is that a path-bearing field is allowlistable only if snug both
// RESOLVES it and FORWARDS the resolved string. checkOne does that for a bind
// source — handleCreate deletes Binds and Mounts and re-encodes only what came
// back — and there is no such rewrite for an array of objects with a .Path
// inside. So a future "just run the existing guards on it" patch must fail here
// rather than pass quietly: a path the sandbox demonstrably CAN see, which
// hostPathVisible would approve, is still refused.
func TestBlkioRefusalDoesNotRestOnAHostPathGuard(t *testing.T) {
	sock, eng, target := startProxy(t)

	// Control first: the same path, through the mechanism that DOES resolve and
	// rewrite. If this fails the case below proves nothing, because the path was
	// never acceptable to begin with.
	before := eng.reached.Load()
	if code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Binds":[`+mustJSON(t, target+":/w")+`]}}`); code != 200 {
		t.Fatalf("the control bind of a visible rw path was refused (status %d), so the "+
			"refusal below is not evidence of anything: %s", code, denyMessage(resp))
	}
	if eng.reached.Load() == before {
		t.Fatal("the control create never reached the engine")
	}

	for _, f := range blkioPathFields {
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"`+f+`":[{"Path":`+mustJSON(t, target)+`,"Rate":1}]}}`,
			"snug neither resolves nor rewrites it")
	}
}

// TestEveryBlkioPathFieldSharesOneReason — five keys, one sentence, so a future
// edit cannot weaken one of them alone.
func TestEveryBlkioPathFieldSharesOneReason(t *testing.T) {
	for _, f := range blkioPathFields {
		on := false
		for _, k := range refusedHostConfig {
			if k == f {
				on = true
			}
		}
		if !on {
			t.Errorf("%s is not on refusedHostConfig, so every sweep that iterates it skips "+
				"the field", f)
		}
		if refusalReason[f] != blkioPathField {
			t.Errorf("%s does not carry blkioPathField; the five share one reason because "+
				"they share one shape", f)
		}
	}
}

// ── Cgroup, the third spelling ───────────────────────────────────────────────

func TestCgroupSpecIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)

	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Cgroup":"container:abc"}}`,
		"which snug did not author")

	// It is NOT in namespaceModeKeys deliberately: that loop matches the
	// "host"/"container:"/"ns:" prefixes, and CgroupSpec has only the one
	// spelling, so a row there would read like the other six while covering
	// less. This pins the decision rather than the mechanism.
	for _, k := range namespaceModeKeys {
		if k == "Cgroup" {
			t.Error("Cgroup joined namespaceModeKeys; the loop there is prefix-matched and " +
				"would cover less of this field than the outright refusal does")
		}
	}

	// Control: empty is what a stock client sends.
	if code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"Cgroup":""}}`); code != 200 {
		t.Fatalf("status %d on the empty Cgroup a stock client sends, want 200: %s",
			code, denyMessage(resp))
	}
}

// ── RestartPolicy ────────────────────────────────────────────────────────────

func TestRestartPolicyOnlyPermitsNo(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, name := range []string{"always", "unless-stopped", "on-failure"} {
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"RestartPolicy":{"Name":"`+name+`"}}}`,
			"outlives the request that created it")
	}

	// Controls: the two shapes a stock client sends. The first is why this is a
	// judged check rather than an allowlist entry — isEmptyJSON does not see it
	// as empty, so an allowlist without the check refuses every `docker run`.
	for _, ok := range []string{
		`{"Name":"no","MaximumRetryCount":0}`,
		`{}`,
		`{"Name":""}`,
	} {
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","HostConfig":{"RestartPolicy":`+ok+`}}`)
		if code != 200 {
			t.Errorf("RestartPolicy %s was refused (status %d): %s", ok, code, denyMessage(resp))
		}
		if eng.reached.Load() == before {
			t.Errorf("RestartPolicy %s never reached the engine", ok)
		}
	}
}

// ── the map shape, mirroring build.go's ──────────────────────────────────────

func TestEveryUnexaminedCreateFieldCarriesAnAbuseSentence(t *testing.T) {
	if len(unexaminedCreateFields) == 0 {
		t.Fatal("unexaminedCreateFields is empty, so this sweep measures nothing")
	}
	for _, name := range sortedKeys(unexaminedCreateFields) {
		reason := unexaminedCreateFields[name]
		if !hasAbuseSentence(reason) {
			t.Errorf("HostConfig.%s is forwarded unexamined and its justification is not an "+
				"abuse sentence.\n  got: %q\n  CLAUDE.md's working agreement requires \"a "+
				"hostile process inside the sandbox can use this to ___\" — written from the "+
				"attacker's side, so it cannot be satisfied by describing what the friendly "+
				"CLI does. notYetAnalysed is the honest class when nobody has established "+
				"what it buys.", name, reason)
		}
	}
}

func TestCreateFieldMapsAreDisjoint(t *testing.T) {
	for _, name := range sortedKeys(unexaminedCreateFields) {
		if judgedCreateField[strings.ToLower(name)] {
			t.Errorf("HostConfig.%s is both judged and forwarded unexamined. The two answers "+
				"disagree about whether snug read the value, and the sweep in handleCreate "+
				"takes whichever it checks first", name)
		}
	}
}

// TestShmSizeAndTmpfsShareOneClaimAcrossBothSchemas pins the drift issue #338
// found: build.go carried the resource-limit sentence for `shmsize`, create.go
// carried it for Tmpfs in a comment nothing read, and ShmSize — the same noun on
// the same schema — carried none at all.
func TestShmSizeAndTmpfsShareOneClaimAcrossBothSchemas(t *testing.T) {
	if unexaminedCreateFields["ShmSize"] != unexaminedCreateFields["Tmpfs"] {
		t.Error("ShmSize and Tmpfs no longer share a sentence; they are the same RAM claim " +
			"and splitting them is how one of them lost its justification before")
	}
	if !hasAbuseSentence(unexaminedBuildParams["shmsize"]) {
		t.Error("build.go's shmsize lost its abuse sentence, so the two schemas have drifted " +
			"apart again in the other direction")
	}
	if !strings.Contains(unexaminedCreateFields["ShmSize"], "ShmSize") ||
		!strings.Contains(unexaminedCreateFields["ShmSize"], "Tmpfs") {
		t.Error("the shared sentence must name both fields; a class sentence that does not " +
			"name its RAM members is one a reader cannot check")
	}
}

// TestEveryModelledCreateFieldIsCanonicalised — decodeObject folds a client's
// spelling through canonicalKey, and a name missing there arrives in whatever
// case the client chose, which the refusal loops (keyed on canonical names)
// would then miss.
func TestEveryModelledCreateFieldIsCanonicalised(t *testing.T) {
	for _, name := range sortedKeys(unexaminedCreateFields) {
		if canonicalKey[strings.ToLower(name)] != name {
			t.Errorf("HostConfig.%s is not in canonicalKey, so a client spelling it "+
				"differently reaches handleCreate under its own name", name)
		}
	}
	for _, name := range append(append([]string{}, refusedHostConfig...), "RestartPolicy") {
		if canonicalKey[strings.ToLower(name)] != name {
			t.Errorf("HostConfig.%s is not in canonicalKey", name)
		}
	}
}

func mustHostConfig(t *testing.T, eng *fakeEngine) string {
	t.Helper()
	fwd, err := decodeObject([]byte(eng.lastBody.Load().(string)))
	if err != nil {
		t.Fatal(err)
	}
	return string(fwd["HostConfig"])
}
