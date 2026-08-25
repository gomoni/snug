package dockerproxy

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the create body's TOP level is an allowlist now, and this is what says so ──
//
// Issues #375 and #397. #338 inverted HostConfig and left the object CONTAINING
// it forwarding verbatim, which is the same denylist shape one level up:
// enumerated danger refused, unmodelled forwarded. Measured before this change —
// 18 top-level keys in the recorded real-client body, 6 non-empty, and exactly
// two (Volumes, HostConfig) judged.
//
// These tests are deliberately the SAME SHAPE as hostconfigallowlist_test.go's,
// because the property is the same property and a reader comparing the two
// levels should not have to compare two idioms as well. Where a test here has no
// counterpart there it says why.
//
// THE ONE RULE THESE ALL SERVE: the name sets are COMPUTED, never typed. A key
// added to refusedTopLevel, topLevelChecked or unexaminedTopLevelFields joins
// every sweep below without anybody editing this file. That is the difference
// between an assertion and a third copy of the list — and "a rule applied to one
// of its two halves" is the defect this lane was chartered to close, so shipping
// the fix as a new enumeration would have been the same mistake wearing the
// fix's clothes.

// recordedTopLevel is the top level of the body a stock docker CLI really sends.
func recordedTopLevel(t *testing.T, b recordedCreateBody) map[string]json.RawMessage {
	t.Helper()
	top, err := decodeObject(mustMarshal(t, b.Body))
	if err != nil {
		t.Fatal(err)
	}
	if len(top) < 15 {
		t.Fatalf("the recorded body has only %d top-level keys; docker's CreateRequest is "+
			"Config's 25 plus HostConfig plus NetworkingConfig, and a truncated recording "+
			"makes every emptiness assertion below trivial", len(top))
	}
	return top
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dockerOnlyTopLevelFields are the top-level names docker's CreateRequest
// defines that a plain `docker run` does not send, so the completeness sweep
// covers the SCHEMA and not just this one invocation.
//
// MEASURED, not remembered: extracted from docker's own
// api/types/container/config.go (v28.5.2) and diffed against the recording.
// docker's CreateRequest is Config's 25 fields plus HostConfig plus
// NetworkingConfig = 27 names; the recording carries 18 and NOTHING outside the
// 27, so these are exactly the 9 that remain.
//
// Written out rather than imported for the reason dockerOnlyFields already gives
// one level down: snug's go.mod stays minimal, because every dependency there
// runs with the authority of the thing building the sandbox.
var dockerOnlyTopLevelFields = []string{
	"ExposedPorts", "Healthcheck", "ArgsEscaped", "NetworkDisabled",
	"MacAddress", "OnBuild", "StopSignal", "StopTimeout", "Shell",
}

// podmanOnlyTopLevelFields are keys PODMAN's compat handler understands that
// docker's schema does not define, and that snug therefore models NOWHERE — so
// the sweep expects them to be REFUSED.
//
// THEY ARE WHAT MAKES THE SWEEP'S NEGATIVE BRANCH LIVE, and that is the reason
// this list exists rather than being tidied away. Measured while writing this
// file: with only docker's 27 names in the set, every name is modelled by
// construction, so the `!modelled -> want 403` branch never executed and the
// test asserted only its own positive half. That is precisely the "test that
// cannot fail" CLAUDE.md warns about, found by mutating the fix and watching
// this test stay green. TestTheTopLevelSweepExercisesBothBranches now asserts
// the branch runs at all.
//
// `Name` is deliberately NOT here: it is a podman-only key and it is
// ALLOWLISTED, because the compat handler overwrites body.Name from the query
// string, so a rule judging it would judge a string podman discards.
var podmanOnlyTopLevelFields = []string{
	"EnvMerge", "UnsetEnv", "UnsetEnvAll",
}

// TestTheTopLevelAllowlistAdmitsWhatDockerActuallySends pins the SET of
// top-level fields a real client sends non-empty, because that set IS the
// shippability constraint.
//
// The counterpart of TestTheCreateAllowlistAdmitsWhatDockerActuallySends, and it
// exists for the same reason: an allowlist evaluated on raw PRESENCE would 403
// every `docker run` on 18 keys. A SEVENTH key going non-empty in a future
// docker release must fail here rather than in a user's `docker run`.
func TestTheTopLevelAllowlistAdmitsWhatDockerActuallySends(t *testing.T) {
	top := recordedTopLevel(t, loadRecordedCreateBody(t))

	want := map[string]string{
		"AttachStderr":     "true — unexamined, containerProcessConfig",
		"AttachStdout":     "true — unexamined, containerProcessConfig",
		"Cmd":              `["true"] — unexamined, containerProcessConfig`,
		"HostConfig":       "the object steps 2-7 judge field by field",
		"Image":            `"alpine" — unexamined, notYetAnalysed`,
		"NetworkingConfig": "{EndpointsConfig:{default:{15 empty fields}}} — judged by checkNetworkingConfig",
	}

	var got []string
	for k, v := range top {
		if !isEmptyJSON(v) {
			got = append(got, k)
		}
	}
	sort.Strings(got)

	for _, k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("the recorded body sends top-level %s=%s non-empty and nothing here "+
				"expects it. Decide what checkTopLevel does with it — a new non-empty field "+
				"from a stock client is the field that will 403 every `docker run`",
				k, top[k])
		}
		delete(want, k)
	}
	for k, why := range want {
		t.Errorf("this test claims a stock client sends top-level %s non-empty (%s) and the "+
			"recording does not, so the claim outlived its measurement", k, why)
	}
}

// TestTheTopLevelSweepCoversDockersWholeCreateSchema is the assertion that the
// completeness sweep below is not measuring a subset by accident.
//
// It is the one test here with no counterpart one level down, and it earns its
// place because the top level is the level where the schema is CLOSED: the
// libpod gate in ServeHTTP means handleCreate only ever sees docker-compat, so
// "every name in the schema" is a set that can actually be written down. If that
// gate is ever relaxed, this test's floor is the thing that stops the inversion
// quietly becoming partial again.
func TestTheTopLevelSweepCoversDockersWholeCreateSchema(t *testing.T) {
	names := topLevelSweepNames(t)
	if len(names) < 27 {
		t.Errorf("the sweep covers only %d top-level names; docker's CreateRequest is "+
			"Config's 25 fields plus HostConfig plus NetworkingConfig = 27, and a sweep that "+
			"shrank is one that stopped measuring: %v", len(names), sortedNames(names))
	}
	// A name in the recording that is in NEITHER the schema list nor snug's own
	// maps would mean the recording has drifted past what this file models.
	for _, k := range dockerOnlyTopLevelFields {
		if names[k] {
			continue
		}
		t.Errorf("%s is in dockerOnlyTopLevelFields and not in the sweep, which cannot "+
			"happen unless the sweep stopped reading that list", k)
	}
}

// topLevelSweepNames is the COMPUTED name set every completeness assertion here
// runs over: the recording's own keys, plus every name snug itself holds, plus
// the schema names a plain `docker run` omits.
//
// Nothing is typed twice. A key added to refusedTopLevel, topLevelChecked or
// unexaminedTopLevelFields joins the sweep with no edit here.
func topLevelSweepNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for k := range recordedTopLevel(t, loadRecordedCreateBody(t)) {
		names[k] = true
	}
	for _, k := range refusedTopLevel {
		names[k] = true
	}
	for _, k := range topLevelChecked {
		names[k] = true
	}
	for k := range unexaminedTopLevelFields {
		names[k] = true
	}
	for _, k := range dockerOnlyTopLevelFields {
		names[k] = true
	}
	for _, k := range podmanOnlyTopLevelFields {
		names[k] = true
	}
	names["HostConfig"] = true
	names["Labels"] = true
	return names
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestNoTopLevelFieldIsForwardedThatSnugDidNotModel is the completeness
// assertion #375 says nothing makes — the direct counterpart of
// TestNoHostConfigFieldIsForwardedThatSnugDidNotModel.
func TestNoTopLevelFieldIsForwardedThatSnugDidNotModel(t *testing.T) {
	sock, eng, _ := startProxy(t)

	var modelledSeen, unmodelledSeen int
	for _, name := range sortedNames(topLevelSweepNames(t)) {
		lower := strings.ToLower(name)
		modelled := judgedTopLevelField[lower] || unexaminedTopLevelField[lower]

		// Image is always present: a create body without one is refused by the
		// engine for a reason that has nothing to do with this sweep, and the
		// probe would then be graded on the wrong refusal.
		body := `{"Image":"alpine",` + mustJSON(t, name) + `:"snug-probe"}`
		if name == "Image" {
			body = `{"Image":"snug-probe"}`
		}
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create", body)

		if !modelled {
			unmodelledSeen++
			if code != http.StatusForbidden {
				t.Errorf("top-level %s is modelled nowhere and status was %d, want 403: %s",
					name, code, denyMessage(resp))
			}
			if eng.reached.Load() != before {
				t.Errorf("top-level %s reached the engine unmodelled", name)
			}
			continue
		}
		modelledSeen++
		// A modelled field may be refused for its OWN reason or forwarded; what
		// it may not be is refused by the CATCH-ALL, which would mean the maps
		// and the sweep disagree about what "modelled" means.
		if code == http.StatusForbidden &&
			strings.Contains(denyMessage(resp), "snug allows a named set of top-level create fields") {
			t.Errorf("top-level %s is modelled but the catch-all refused it, so "+
				"judgedTopLevelField/unexaminedTopLevelField and the sweep disagree", name)
		}
	}

	// BOTH BRANCHES MUST HAVE RUN. Without this the test is half a test, and it
	// was exactly half a test when it was written: every name in the computed
	// set was modelled by construction, so the 403 branch never executed and
	// mutating the inversion away left this green. The podman-only names are
	// what keep the negative half alive; if they are ever modelled, this fails
	// and asks for a new unmodelled probe rather than quietly going vacuous.
	if unmodelledSeen == 0 {
		t.Error("every name in the sweep was modelled, so the `unmodelled must be refused` " +
			"branch never ran. This test then asserts only that modelled fields are not " +
			"caught by the catch-all — half of what its name claims. Add an unmodelled name " +
			"to the sweep (see podmanOnlyTopLevelFields)")
	}
	if modelledSeen == 0 {
		t.Error("no modelled name was probed, so the other half never ran either")
	}
}

// TestUnknownTopLevelFieldIsRefused — a non-empty sibling nobody modelled fails
// closed. This is the inversion itself, and the thing #375 asked for.
func TestUnknownTopLevelFieldIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, body := range []string{
		`{"Image":"alpine","FieldPodmanAddsIn2027":"anything"}`,
		`{"Image":"alpine","FieldPodmanAddsIn2027":{"Path":"/etc/shadow"}}`,
		`{"Image":"alpine","FieldPodmanAddsIn2027":["x"]}`,
		`{"Image":"alpine","FieldPodmanAddsIn2027":true}`,
		// The shape the ticket is actually about: a field that LOOKS like one of
		// the objects snug reads, at the level snug was not reading.
		`{"Image":"alpine","HealthConfig":{"Interval":30000000000}}`,
	} {
		refuse(t, sock, eng, "/v1.41/containers/create", body,
			"snug allows a named set of top-level create fields")
	}
}

// TestEmptyUnknownTopLevelFieldIsDroppedNotForwarded — the half that makes the
// inversion shippable, and the half that must not become silent.
//
// Invariant 5 forbids a SILENT downgrade, not a downgrade, which is why the
// audit line names what went.
func TestEmptyUnknownTopLevelFieldIsDroppedNotForwarded(t *testing.T) {
	var lines []string
	audit := func(s string) { lines = append(lines, s) }

	sock, eng, _ := startProxyAudited(t, policy.PodmanSocket, audit)

	for _, empty := range []string{`null`, `""`, `0`, `[]`, `{}`, `false`} {
		t.Run("empty "+empty, func(t *testing.T) {
			lines = nil
			before := eng.reached.Load()
			body := `{"Image":"alpine","FieldPodmanAddsIn2027":` + empty + `}`
			code, resp := post(t, sock, "/v1.41/containers/create", body)
			if code != 200 {
				t.Fatalf("status %d, want 200 — an empty unmodelled top-level field is "+
					"dropped, not refused: %s", code, denyMessage(resp))
			}
			if eng.reached.Load() == before {
				t.Fatal("the create never reached the engine")
			}
			fwd, err := decodeObject([]byte(eng.lastBody.Load().(string)))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := fwd["FieldPodmanAddsIn2027"]; ok {
				t.Error("the unmodelled top-level field reached the engine; empty means " +
					"DROPPED, and forwarding it is the verbatim channel this change closes")
			}
			named := false
			for _, l := range lines {
				if strings.Contains(l, "FieldPodmanAddsIn2027") {
					named = true
				}
			}
			if !named {
				t.Errorf("nothing in the audit named the dropped top-level field: %v. A "+
					"downgrade the user cannot see is the one invariant 5 forbids", lines)
			}
		})
	}

	// POSITIVE CONTROL. Without it every assertion above is satisfied by a proxy
	// that drops every top-level field it is given, empty or not.
	t.Run("control: the same field non-empty is refused", func(t *testing.T) {
		refuse(t, sock, eng, "/v1.41/containers/create",
			`{"Image":"alpine","FieldPodmanAddsIn2027":"set"}`,
			"snug allows a named set of top-level create fields")
	})
}

// ── Healthcheck: issue #397 ──────────────────────────────────────────────────

// TestHealthcheckIsRefused is #397's regression test. Every spelling that asks
// for a check is refused, INCLUDING the ones that do not name an Interval —
// because the refusal is on the object, and a gate on the one subfield that
// reaches systemd today is the shape #375 closed.
func TestHealthcheckIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, body := range []string{
		// The measured mechanism: --on-unit-inactive=<interval>.
		`{"Image":"alpine","Healthcheck":{"Test":["CMD","/bin/true"],"Interval":30000000000}}`,
		// No Interval. Refused anyway — this is the assertion that distinguishes
		// "refuse the object" from "refuse a non-zero Interval", and it is the
		// one that survives podman scheduling on a different subfield.
		`{"Image":"alpine","Healthcheck":{"Test":["CMD","/bin/true"]}}`,
		`{"Image":"alpine","Healthcheck":{"Test":["CMD-SHELL","exit 0"]}}`,
		`{"Image":"alpine","Healthcheck":{"Retries":3}}`,
		`{"Image":"alpine","Healthcheck":{"StartPeriod":5000000000}}`,
		`{"Image":"alpine","Healthcheck":{"Timeout":1000000000}}`,
		`{"Image":"alpine","Healthcheck":{"StartInterval":1000000000}}`,
	} {
		refuse(t, sock, eng, "/v1.41/containers/create", body, "a healthcheck is SCHEDULED WORK")
	}
}

// TestHealthcheckRefusalNamesTheHostSideMechanism. The message is the only thing
// a user sees, and #397's whole point is that the two things stopping the unit
// today are NOT snug's policy — so the refusal has to say what it is protecting
// rather than "not permitted".
func TestHealthcheckRefusalNamesTheHostSideMechanism(t *testing.T) {
	sock, _, _ := startProxy(t)
	_, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","Healthcheck":{"Test":["CMD","/bin/true"],"Interval":30000000000}}`)
	msg := denyMessage(resp)
	for _, want := range []string{
		"systemd-run",              // the command the engine would run
		"--on-unit-inactive",       // the flag that creates the TIMER, not just the unit
		"timer",                    // what outlives the run
		"your uid",                 // as whom
		"outlive",                  // why invariant 4 cares
		"nothing ever unschedules", // #174: teardown removes no container
		"NOT SNUG'S POLICY",        // #397's actual finding
		"/run/systemd/system",      // barrier (a), and why it lapses
		"XDG_RUNTIME_DIR",          // barrier (b), the one #397 did not name
		"systemd tag",              // barrier (c), already gone
		"poll it from inside",      // the alternative that IS bounded by the sandbox

		// THE CORRECTION #397's own proposal needed, and the reason this
		// refusal is on the object rather than on Interval. A reader who
		// arrives from the ticket will be looking for the Interval cut; the
		// message has to tell them why there isn't one.
		"THE INTERVAL IS NOT THE CUT",
		"NEGATIVE",
		"30000000000",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the Healthcheck refusal does not mention %q, so a reader cannot tell "+
				"what it protects or what to do instead:\n%s", want, msg)
		}
	}
}

// TestAnEmptyHealthcheckIsNotRefused — the ergonomic floor for the refusal
// above, and the reason it is not the LogConfig trap.
//
// MEASURED: Healthcheck is one of the 9 docker Config names a stock `docker run`
// does not send at all. So a client that asks for nothing is not refused,
// because it does not send the key — and if it sends an empty one, isEmptyJSON
// skips it exactly as it does for every other refused field.
func TestAnEmptyHealthcheckIsNotRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, empty := range []string{`null`, `{}`} {
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create",
			`{"Image":"alpine","Healthcheck":`+empty+`}`)
		if code != 200 {
			t.Errorf("Healthcheck:%s was refused (status %d); a value that asks for nothing "+
				"must not be, or this is the LogConfig trap again: %s",
				empty, code, denyMessage(resp))
		}
		if eng.reached.Load() == before {
			t.Errorf("Healthcheck:%s: the create never reached the engine", empty)
		}
	}

	// POSITIVE CONTROL: the same key asking for something is still refused, so
	// the two assertions above are not passing on a proxy that stopped reading
	// Healthcheck at all.
	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","Healthcheck":{"Test":["CMD","/bin/true"]}}`,
		"a healthcheck is SCHEDULED WORK")
}

// TestHealthcheckIsNotTranslated. "Refuse, never translate" is a standing
// ruling, and the tempting alternative here was to normalise Interval to zero
// and forward the rest. That would hand back a container whose configured
// healthcheck silently never runs, with `docker inspect` showing it configured —
// so this asserts that no Healthcheck ever reaches the engine at all.
func TestHealthcheckIsNotTranslated(t *testing.T) {
	sock, eng, _ := startProxy(t)
	code, _ := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","Healthcheck":{"Test":["CMD","/bin/true"],"Interval":30000000000}}`)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", code)
	}
	if raw := eng.lastBody.Load(); raw != nil {
		if strings.Contains(raw.(string), "Healthcheck") {
			t.Error("a Healthcheck reached the engine. It is refused, not normalised: a " +
				"healthcheck snug will not schedule is one the client is told about")
		}
	}
}

// ── NetworkingConfig: issue #375's named object ──────────────────────────────

// TestNetworkingConfigThatAsksForNothingIsAccepted is the ergonomic floor, and
// the reason NetworkingConfig is JUDGED rather than refused outright.
//
// A stock `docker run` sends it NON-EMPTY —
// {"EndpointsConfig":{"default":{...15 fields...}}} — so refusing the object for
// being present would 403 every `docker run`. This is the LogConfig trap at the
// top level, and this test is what stops it.
func TestNetworkingConfigThatAsksForNothingIsAccepted(t *testing.T) {
	sock, eng, _ := startProxy(t)

	// Read from the recording rather than typed, so it is the real client's
	// object and not an idealised one.
	top := recordedTopLevel(t, loadRecordedCreateBody(t))
	nc, ok := top["NetworkingConfig"]
	if !ok {
		t.Fatal("the recorded body has no NetworkingConfig, so this test measures nothing")
	}
	if isEmptyJSON(nc) {
		t.Fatal("the recorded NetworkingConfig is empty by isEmptyJSON, which makes this " +
			"test vacuous — the whole point is that a real client sends it NON-empty")
	}

	before := eng.reached.Load()
	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","NetworkingConfig":`+string(nc)+`}`)
	if code != 200 {
		t.Fatalf("the NetworkingConfig a stock docker CLI really sends was refused "+
			"(status %d). That is a ban on `docker run`, not a filter: %s",
			code, denyMessage(resp))
	}
	if eng.reached.Load() == before {
		t.Fatal("the create never reached the engine, so nothing above is evidence")
	}
}

// TestNetworkingConfigThatAsksForSomethingIsRefused is the other half, and the
// positive control for the test above.
//
// Driven field by field over the endpoint object rather than spot-checked,
// because checkNetworkingConfig judges by EMPTINESS and never by name — so the
// property to assert is "any non-empty field", and a test that named three
// fields would say nothing about the fourth.
func TestNetworkingConfigThatAsksForSomethingIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)

	// Every field of docker's EndpointSettings that a real client sends empty.
	// Taken from the RECORDING, so the list cannot drift from what the client
	// really has — and each one is probed with a non-empty value.
	top := recordedTopLevel(t, loadRecordedCreateBody(t))
	endpoints, err := decodeObject(top["NetworkingConfig"])
	if err != nil {
		t.Fatal(err)
	}
	eps, err := decodeObject(endpoints["EndpointsConfig"])
	if err != nil {
		t.Fatal(err)
	}
	ep, err := decodeObject(eps["default"])
	if err != nil {
		t.Fatal(err)
	}
	if len(ep) < 10 {
		t.Fatalf("the recorded endpoint has only %d fields; this sweep is meant to cover "+
			"docker's whole EndpointSettings", len(ep))
	}

	for _, field := range sortedNames(func() map[string]bool {
		m := map[string]bool{}
		for k := range ep {
			m[k] = true
		}
		return m
	}()) {
		body := `{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"default":{` +
			mustJSON(t, field) + `:"snug-probe"}}}}`
		refuse(t, sock, eng, "/v1.41/containers/create", body, "is not permitted")
	}

	// And a field docker does NOT define, which is the inversion's own case:
	// checkNetworkingConfig never consults a name, so podman's 16th endpoint
	// field is refused the day it arrives.
	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"default":{"FieldPodmanAddsIn2027":"x"}}}}`,
		"is not permitted")

	// A sibling of EndpointsConfig, which is the other door into the same object.
	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","NetworkingConfig":{"SomethingElse":"x"}}`,
		"snug reads only EndpointsConfig here")
}

// TestNetworkingConfigRefusalNamesTheNamespaceItProtects. #375's reason for
// caring about this object is that it "reaches the same subsystem by a different
// door" from NetworkMode, and the message has to say which door.
func TestNetworkingConfigRefusalNamesTheNamespaceItProtects(t *testing.T) {
	sock, _, _ := startProxy(t)
	_, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"default":{"IPAddress":"10.0.0.7"}}}}`)
	msg := denyMessage(resp)
	for _, want := range []string{"IPAddress", "10.0.0.7", "network namespace", "Tier B"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the NetworkingConfig refusal does not mention %q:\n%s", want, msg)
		}
	}
}

// ── the maps themselves ──────────────────────────────────────────────────────

// TestEveryRefusedTopLevelFieldExplainsItself mirrors
// TestEveryRefusedFieldExplainsItself one level down: a refusal with no reason
// is a 403 a user cannot act on.
func TestEveryRefusedTopLevelFieldExplainsItself(t *testing.T) {
	for _, k := range refusedTopLevel {
		reason, ok := topLevelRefusalReason[k]
		if !ok {
			t.Errorf("%s is on refusedTopLevel with no entry in topLevelRefusalReason, so "+
				"its 403 reads \"is not permitted: \" and stops", k)
			continue
		}
		if len(reason) < 40 {
			t.Errorf("topLevelRefusalReason[%q] is %d characters; that is a label, not a "+
				"reason: %q", k, len(reason), reason)
		}
	}
	for k := range topLevelRefusalReason {
		found := false
		for _, r := range refusedTopLevel {
			if r == k {
				found = true
			}
		}
		if !found {
			t.Errorf("topLevelRefusalReason has an entry for %q, which is not on "+
				"refusedTopLevel — so nothing ever renders it, and a reader would take it "+
				"for a live refusal", k)
		}
	}
}

// TestEveryUnexaminedTopLevelFieldCarriesAnAbuseSentence. The working agreement
// is "write the abuse sentence first"; a field forwarded without its value being
// looked at is exactly the case where the sentence is the ONLY guard.
func TestEveryUnexaminedTopLevelFieldCarriesAnAbuseSentence(t *testing.T) {
	if len(unexaminedTopLevelFields) == 0 {
		t.Fatal("unexaminedTopLevelFields is empty, so this sweep measures nothing")
	}
	for _, name := range sortedKeys(unexaminedTopLevelFields) {
		reason := unexaminedTopLevelFields[name]
		if reason == "" {
			t.Errorf("top-level %s is forwarded unexamined with no abuse sentence. There is "+
				"no nil here: a field snug does not judge cannot be SILENT about it", name)
			continue
		}
		if !strings.Contains(reason, "A hostile process inside the sandbox can use") {
			t.Errorf("the sentence for top-level %s does not start from the hostile process, "+
				"which is the one thing the working agreement asks of it: %q", name, reason)
		}
	}
}

// TestNoTopLevelFieldIsBothJudgedAndUnexamined. The two maps are consulted with
// an OR, so an overlap is not a crash — it is a field a reader would look up in
// the wrong place, and a judgement silently outranking a sentence.
func TestNoTopLevelFieldIsBothJudgedAndUnexamined(t *testing.T) {
	for _, name := range sortedKeys(unexaminedTopLevelFields) {
		if judgedTopLevelField[strings.ToLower(name)] {
			t.Errorf("top-level %s is in unexaminedTopLevelFields AND judged. It cannot be "+
				"both: the sentence claims nobody looks at the value, and the judgement says "+
				"somebody does", name)
		}
	}
}

// TestTopLevelChecksAgreeWithTheirKeyList closes the ONE split in this change.
//
// topLevelChecked ([]string) and topLevelChecks (map) hold the same names twice,
// and that is forced rather than chosen: canonicalKey needs the names, the
// checks reach decodeObject, and decodeObject reads canonicalKey — a genuine Go
// initialization cycle. Since the duplication cannot be removed it is asserted
// instead, in BOTH directions, so a key in either alone fails here rather than
// silently becoming unjudged (in the list but not the map: a nil call) or
// unspellable (in the map but not the list: never canonicalised, never reached).
func TestTopLevelChecksAgreeWithTheirKeyList(t *testing.T) {
	if len(topLevelChecked) == 0 {
		t.Fatal("topLevelChecked is empty, so this sweep measures nothing")
	}
	for _, k := range topLevelChecked {
		if topLevelChecks[k] == nil {
			t.Errorf("%q is in topLevelChecked with no function in topLevelChecks; "+
				"checkTopLevel would call nil", k)
		}
	}
	for k := range topLevelChecks {
		found := false
		for _, c := range topLevelChecked {
			if c == k {
				found = true
			}
		}
		if !found {
			t.Errorf("%q has a check in topLevelChecks and is not in topLevelChecked, so "+
				"checkTopLevel never calls it and canonicalKey never learns the name", k)
		}
	}
}

// TestEveryCheckedTopLevelKeyIsCanonicalised. decodeObject folds a client's
// spelling through canonicalKey before any check runs, so a name missing there
// arrives in whatever case the client chose — and the sweep would judge a key
// the engine reads as a different one. This is the top level's copy of
// TestEveryCheckedKeyIsCanonicalised, and it is driven from the same maps.
func TestEveryCheckedTopLevelKeyIsCanonicalised(t *testing.T) {
	all := append([]string{}, refusedTopLevel...)
	all = append(all, topLevelChecked...)
	all = append(all, "HostConfig", "Labels", "EndpointsConfig")
	for _, name := range sortedKeys(unexaminedTopLevelFields) {
		all = append(all, name)
	}
	for _, name := range all {
		if canonicalKey[strings.ToLower(name)] != name {
			t.Errorf("top-level %s is not in canonicalKey, so a client spelling it in "+
				"another case reaches the engine unjudged", name)
		}
	}
}

// TestTopLevelCaseSpellingsAreRefusedToo. The canonicalisation above is the
// mechanism; this is the behaviour, driven over every refused name in whatever
// case a client might pick.
func TestTopLevelCaseSpellingsAreRefusedToo(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, k := range refusedTopLevel {
		for _, spelling := range []string{strings.ToLower(k), strings.ToUpper(k)} {
			body := `{"Image":"alpine",` + mustJSON(t, spelling) + `:{"Test":["CMD","/x"]}}`
			before := eng.reached.Load()
			code, resp := post(t, sock, "/v1.41/containers/create", body)
			if code != http.StatusForbidden {
				t.Errorf("top-level %s spelled %q: status %d, want 403 — podman matches "+
					"struct fields case-insensitively, so this spelling reaches the same "+
					"field: %s", k, spelling, code, denyMessage(resp))
			}
			if eng.reached.Load() != before {
				t.Errorf("top-level %s spelled %q reached the engine", k, spelling)
			}
		}
	}
}

// ── Env: the field that was nearly allowlisted ───────────────────────────────

// TestEnvBareNameIsRefused is the regression test for the measurement in
// checkEnv's comment: a bare name asks the ENGINE to copy its own environment
// variable of that name into the container, and `*` copies all of them.
//
// Measured through snug's own proxy against podman 6.0.2: Env:["*"] copied 10
// variables out of the engine's environment, every one naming this run's graft
// paths (XDG_RUNTIME_DIR=/snug/engine/runroot,
// REGISTRY_AUTH_FILE=/snug/engine/conf/auth.json, the CONTAINERS_* set).
func TestEnvBareNameIsRefused(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, body := range []string{
		// The whole environment.
		`{"Image":"alpine","Env":["*"]}`,
		// One variable by name — the `docker run -e FOO` spelling.
		`{"Image":"alpine","Env":["HOME"]}`,
		`{"Image":"alpine","Env":["SSH_AUTH_SOCK"]}`,
		// The prefix wildcard, measured working.
		`{"Image":"alpine","Env":["CONTAINERS_*"]}`,
		`{"Image":"alpine","Env":["XDG_*"]}`,
		// Hidden among well-formed entries: the loop must judge every element,
		// not the first one.
		`{"Image":"alpine","Env":["A=1","B=2","REGISTRY_AUTH_FILE","C=3"]}`,
	} {
		refuse(t, sock, eng, "/v1.41/containers/create", body,
			"asks the ENGINE to copy its OWN environment")
	}

	// An empty NAME is its own refusal, and a separate message: "=value" is
	// well-formed by the Cut above and still nonsense.
	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","Env":["=oops"]}`, "empty variable name")
}

// TestEnvNameValueIsAccepted is the positive control for the refusals above, and
// the ergonomic floor: `docker run -e FOO=bar` is ordinary and must work.
//
// Without this, TestEnvBareNameIsRefused is satisfied by a proxy that refuses
// Env outright — which would break every containerised build that passes a
// variable, and would be the LogConfig trap a third time.
func TestEnvNameValueIsAccepted(t *testing.T) {
	sock, eng, _ := startProxy(t)
	for _, body := range []string{
		`{"Image":"alpine","Env":["FOO=bar"]}`,
		`{"Image":"alpine","Env":["FOO=bar","BAZ=qux"]}`,
		// An empty VALUE is fine — it is a value, and it asks for nothing.
		`{"Image":"alpine","Env":["FOO="]}`,
		// A value containing `=` belongs to the value.
		`{"Image":"alpine","Env":["CONNSTR=a=b;c=d"]}`,
		// A value that merely LOOKS like the dangerous spelling is still a value.
		`{"Image":"alpine","Env":["FOO=*"]}`,
		// Env absent, and Env empty.
		`{"Image":"alpine"}`,
		`{"Image":"alpine","Env":[]}`,
		`{"Image":"alpine","Env":null}`,
	} {
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v1.41/containers/create", body)
		if code != 200 {
			t.Errorf("%s was refused (status %d); NAME=VALUE is what every ordinary client "+
				"sends and refusing it is a ban on `docker run -e`: %s",
				body, code, denyMessage(resp))
		}
		if eng.reached.Load() == before {
			t.Errorf("%s: the create never reached the engine", body)
		}
	}
}

// ── MacAddress: refused at both spellings ────────────────────────────────────

// TestMacAddressIsRefusedAtBothSpellings. It is the same object in two places —
// top-level MacAddress and NetworkingConfig.EndpointsConfig[*].MacAddress — and
// this lane's whole subject is a rule applied to one of its two halves. Driven
// as a pair in ONE test on purpose, so deleting either refusal fails here.
func TestMacAddressIsRefusedAtBothSpellings(t *testing.T) {
	sock, eng, _ := startProxy(t)
	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","MacAddress":"02:42:ac:11:00:02"}`,
		"static hardware address")
	refuse(t, sock, eng, "/v1.41/containers/create",
		`{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"default":{"MacAddress":"02:42:ac:11:00:02"}}}}`,
		"is not permitted")
}

// ── the Labels canonicalisation bug, found while reading canonicalKey ─────────

// TestALowercaseLabelsKeyDoesNotDiscardTheRunLabel.
//
// A LIVE BUG this change fixes as a side effect, named rather than folded in
// silently. canonicalKey did not contain "Labels", while stampRunLabel does an
// exact-key req["Labels"] lookup. So a client sending lowercase "labels" kept
// its own un-canonicalised key; stampRunLabel saw no "Labels" and added its own;
// json.Marshal sorts "Labels" (0x4C) before "labels" (0x6C); podman folds
// case-insensitively and LAST WINS — the exact mechanism decodeObject's own
// comment records for {"privileged":true}.
//
// Result: snug's run label was DISCARDED by a lowercase spelling, so the
// container became invisible to handleContainerDelete's ownership check (#339).
// It failed closed for deletion, which is why nothing caught it — but it defeated
// the mechanism silently, and the whole point of that label is that teardown
// correctness is not the sandbox's to negotiate.
//
// The fix is one entry in canonicalKey. This is the test that keeps it there.
func TestALowercaseLabelsKeyDoesNotDiscardTheRunLabel(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, spelling := range []string{"Labels", "labels", "LABELS", "LaBeLs"} {
		before := eng.reached.Load()
		body := `{"Image":"alpine",` + mustJSON(t, spelling) + `:{"mine":"kept"}}`
		code, resp := post(t, sock, "/v1.41/containers/create", body)
		if code != 200 {
			t.Fatalf("%s spelling: status %d: %s", spelling, code, denyMessage(resp))
		}
		if eng.reached.Load() == before {
			t.Fatalf("%s spelling: the create never reached the engine", spelling)
		}

		sent := eng.lastBody.Load().(string)

		// ASSERTED ON THE RAW BYTES FIRST, and this is the assertion that names
		// the bug. Exactly one spelling of Labels may reach the engine: two is
		// the defect itself, because json.Marshal sorts "Labels" before
		// "labels" and podman's case-insensitive decode takes the LAST. Reading
		// this through decodeObject instead would report it as a generic
		// case-collision error and send a reader looking at the wrong function.
		var spellings []string
		for _, cand := range []string{`"Labels"`, `"labels"`, `"LABELS"`, `"LaBeLs"`} {
			if strings.Contains(sent, cand) {
				spellings = append(spellings, cand)
			}
		}
		if len(spellings) != 1 {
			t.Errorf("%s spelling: %d spellings of Labels reached the engine (%v). Exactly "+
				"one may: podman folds case-insensitively and reads the LAST key, while snug "+
				"wrote the first, so two spellings means snug's run label is the one that "+
				"loses. Forwarded body: %s", spelling, len(spellings), spellings, sent)
			continue
		}

		fwd, err := decodeObject([]byte(sent))
		if err != nil {
			t.Fatalf("%s spelling: %v", spelling, err)
		}
		raw, ok := fwd["Labels"]
		if !ok {
			t.Errorf("%s spelling: no canonical Labels key reached the engine, so snug's run "+
				"label went nowhere", spelling)
			continue
		}
		var labels map[string]string
		if err := json.Unmarshal(raw, &labels); err != nil {
			t.Errorf("%s spelling: Labels is not a string map: %v", spelling, err)
			continue
		}
		if labels["snug.run"] == "" {
			t.Errorf("%s spelling: snug's run label is missing from %v. A lowercase spelling "+
				"must not be able to discard it — the container would be invisible to the "+
				"ownership check a DELETE goes through (#339)", spelling, labels)
		}
		if labels["mine"] != "kept" {
			t.Errorf("%s spelling: the client's own label was dropped (%v); only snug's key "+
				"is authoritative", spelling, labels)
		}
	}
}
