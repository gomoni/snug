package dockerproxy

import (
	"encoding/json"
	"strings"
	"testing"
)

// REGRESSION, issue #305 (sev:medium, found by a redteam sweep of this proxy).
//
// refusedHostConfig carried every other field of its shape — a client-named
// path an engine component opens on snug's side of the proxy — and not this
// one. So HostConfig.ContainerIDFile survived handleCreate's re-encode and
// reached the engine verbatim.
//
// MEASURED against a real engine: a create naming
// /snug/engine/store/EVIL_CIDFILE returned 201, and `podman inspect` echoed the
// path back twice — the engine PERSISTED a host path snug never approved,
// resolved in the engine's derived view (the sandbox's own tree plus this run's
// grafts, the read-write container store among them).
//
// The issue filed the WRITE side as the open question. Measured against podman
// 6.0.2 over its own API socket, and the answer was the wrong question:
//
//	create with ContainerIDFile   201, `inspect` echoes the path back
//	start                         204, and NO file appears — podman does not
//	                              write the cidfile server-side
//	DELETE the container          THE HOST FILE AT THAT PATH IS UNLINKED
//
// Not an arbitrary-write primitive, an arbitrary-DELETE one, and cheaper than
// the write would have been: create + delete, two calls, no start, no image
// ever run. A file planted at the path beforehand was gone after removal, and
// the control — the identical sequence with no ContainerIDFile — left it
// untouched.
//
// It is a NAMED test rather than one more row in the big refusal table because
// that measurement needs somewhere to live, and a table row has no room for it.
func TestCreateRefusesAContainerIDFile(t *testing.T) {
	sock, eng, _ := startProxy(t)

	for _, tc := range []struct{ name, body string }{
		{"the measured path, under the read-write store graft",
			`{"Image":"alpine","HostConfig":{"ContainerIDFile":"/snug/engine/store/EVIL_CIDFILE"}}`},
		{"a path the sandbox itself cannot see, which the delete primitive does not need",
			`{"Image":"alpine","HostConfig":{"ContainerIDFile":"/home/u/.bashrc"}}`},
		{"a path the sandbox CAN see, which is still snug's call and not the client's",
			`{"Image":"alpine","HostConfig":{"ContainerIDFile":"/usr/cid"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, "/v1.41/containers/create", tc.body,
				"HostConfig.ContainerIDFile is not permitted")
		})
	}
}

// The other half, and the one that keeps the entry from being a ban on
// `docker run`: the CLI sends ContainerIDFile as an EMPTY STRING on ordinary
// creates, which isEmptyJSON already swallows, so no LogConfig-style
// default-value carve-out is needed. LogConfig needed one because
// {"Type":"","Config":{}} is not empty to isEmptyJSON; `""` is.
//
// This is a positive control as much as a compatibility check: without it the
// test above would also pass on a refusal that fired for every create, which is
// precisely the failure the LogConfig entry once shipped.
func TestTheEmptyContainerIDFileIsAccepted(t *testing.T) {
	sock, eng, target := startProxy(t)

	code, resp := post(t, sock, "/v1.41/containers/create",
		`{"Image":"alpine","HostConfig":{"ContainerIDFile":"","Binds":["`+target+`:/w"]}}`)
	if code != 200 {
		t.Fatalf("the CLI sends an empty ContainerIDFile on ordinary creates; refusing it "+
			"refuses everything (status %d): %s", code, resp)
	}

	// And it must not reach the engine as a field podman then has to interpret.
	//
	// Decoded rather than substring-matched, for the reason
	// TestTheDefaultLogConfigIsAccepted records: t.TempDir() names the
	// directory after the test, so the bind source in this very body contains
	// the string "ContainerIDFile" and a substring check would match it.
	sent, _ := eng.lastBody.Load().(string)
	if sent == "" {
		t.Fatal("the engine recorded no body, so this test measures nothing")
	}
	var got struct {
		HostConfig map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(sent), &got); err != nil {
		t.Fatalf("the engine did not receive JSON: %s", sent)
	}
	if raw, ok := got.HostConfig["ContainerIDFile"]; ok && !isEmptyJSON(raw) {
		t.Errorf("a non-empty ContainerIDFile reached the engine: %s", sent)
	}
}

// Case-proofing is already swept for every refusedHostConfig entry by
// TestEveryRefusedHostConfigKeyIsCaseProof, which is the property that keeps
// that sweep from rotting — a new entry is covered the moment it is added. This
// asserts the sweep actually SEES this entry, because "covered by a sweep" is a
// claim about the sweep's input, and #305 was a field missing from a list that
// several sweeps iterate.
func TestContainerIDFileIsOnTheSweptList(t *testing.T) {
	found := false
	for _, k := range refusedHostConfig {
		if k == "ContainerIDFile" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("ContainerIDFile is not on refusedHostConfig, so every sweep that iterates " +
			"that list — case-proofing, the reason-required check — silently stops covering it")
	}
	reason, ok := refusalReason["ContainerIDFile"]
	if !ok || strings.TrimSpace(reason) == "" {
		t.Error("ContainerIDFile has no refusal reason; a refusal that cannot say why is " +
			"the message a user gets when snug breaks their build")
	}
}
