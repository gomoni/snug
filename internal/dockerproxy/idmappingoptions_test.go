package dockerproxy

import (
	"net/url"
	"strings"
	"testing"
)

// The value podman actually sends, per version, recorded against a listening
// socket. 5.8.3's is one field; 6.0.2's is the whole IDMappingOptions struct,
// AutoUserNsOpts included, every field of it zero — which is the shape the
// only-empty rule is built around.
const (
	idMap583 = `{"HostUIDMapping":true}`
	idMap602 = `{"HostUIDMapping":true,"HostGIDMapping":true,"UIDMap":[],"GIDMap":[],` +
		`"AutoUserNs":false,"AutoUserNsOpts":{"Size":0,"InitialSize":0,"PasswdFile":"",` +
		`"GroupFile":"","AdditionalUIDMappings":null,"AdditionalGIDMappings":null}}`
)

// buildURLWithIDMapping is buildURL with idmappingoptions REPLACED rather than
// appended: the recorded default already carries one, and a second copy would
// test what the proxy does with a duplicate query key instead of what it does
// with the value under test.
//
// The 5.8.3 base is used deliberately, so these cases say nothing about which
// podman version is otherwise buildable and keep passing either side of #314's
// grant.
func buildURLWithIDMapping(t *testing.T, value string) string {
	t.Helper()
	q, err := url.ParseQuery(buildDefaults)
	if err != nil {
		t.Fatal(err)
	}
	q.Set("idmappingoptions", value)
	return "/v5.8.3/libpod/build?" + q.Encode()
}

// REGRESSION (redteam, issue #323). idmappingoptions was waved through as a nil
// entry — "rootless bounds this; the CLI always sends it" — which was true of
// the value 5.8.3 sent. On 6.0.2 the same parameter carries
// AutoUserNsOpts.PasswdFile and .GroupFile, HOST PATHS the engine opens:
// containers/storage userns.go:101 parseMountedFiles calls os.Open on a
// non-empty override. Measured: a planted `snugmarker:x:99123:99123::/x:/bin/sh`
// came back as "the container needs a user namespace with size 99124", the
// planted uid + 1 — the engine read and parsed a file the caller named.
//
// The rule is #311's DownloadedCache rule one field down: the NAME may be
// present, every value inside it must be zero.
func TestIDMappingOptionsRefusesEveryValueInAutoUserNsOpts(t *testing.T) {
	for _, tc := range []struct{ name, value, wantMsg string }{
		{"the measured PasswdFile",
			`{"AutoUserNs":false,"AutoUserNsOpts":{"PasswdFile":"/etc/passwd"}}`,
			"AutoUserNsOpts.PasswdFile must be empty"},
		{"a GroupFile",
			`{"AutoUserNsOpts":{"GroupFile":"/etc/group"}}`,
			"AutoUserNsOpts.GroupFile must be empty"},
		{"a PasswdFile inside snug's own engine graft",
			`{"AutoUserNsOpts":{"PasswdFile":"/snug/engine/store/passwd"}}`,
			"AutoUserNsOpts.PasswdFile must be empty"},
		{"a size", `{"AutoUserNsOpts":{"Size":65536}}`,
			"AutoUserNsOpts.Size must be empty"},
		{"an initial size", `{"AutoUserNsOpts":{"InitialSize":1}}`,
			"AutoUserNsOpts.InitialSize must be empty"},
		{"additional uid mappings",
			`{"AutoUserNsOpts":{"AdditionalUIDMappings":[{"ContainerID":0,"HostID":0,"Size":1}]}}`,
			"AutoUserNsOpts.AdditionalUIDMappings must be empty"},
		{"additional gid mappings",
			`{"AutoUserNsOpts":{"AdditionalGIDMappings":[{"ContainerID":0,"HostID":0,"Size":1}]}}`,
			"AutoUserNsOpts.AdditionalGIDMappings must be empty"},

		// AutoUserNs=true is what sends the engine looking for a passwd file at
		// all. An ordinary build sends false.
		{"--userns=auto itself", `{"AutoUserNs":true}`, "drop --userns=auto"},

		// The allowlist, at both levels.
		{"an unmodelled field", `{"MysteryFile":"/etc/shadow"}`,
			`idmappingoptions carries the field "MysteryFile"`},
		{"an unmodelled nested field",
			`{"AutoUserNsOpts":{"MysteryFile":"/etc/shadow"}}`,
			`AutoUserNsOpts carries the field "MysteryFile"`},

		// #310's last-wins trap, at BOTH levels. snug dedups with ToLower and
		// the engine decodes case-insensitively taking the LAST key after a
		// sort, so a second spelling is a way to have snug judge one value and
		// the engine use another. A rule that validated the first decoded
		// object and forwarded the raw bytes would hand the engine the second.
		{"a top-level case-variant duplicate",
			`{"AutoUserNsOpts":{"PasswdFile":""},"autousernsopts":{"PasswdFile":"/etc/passwd"}}`,
			"idmappingoptions carries AutoUserNsOpts twice"},
		{"a nested case-variant duplicate",
			`{"AutoUserNsOpts":{"PasswdFile":"","passwdfile":"/etc/passwd"}}`,
			"AutoUserNsOpts carries PasswdFile twice"},
		{"three spellings of one nested field",
			`{"AutoUserNsOpts":{"PasswdFile":"","passwdfile":"","PASSWDFILE":"/etc/passwd"}}`,
			"twice"},

		// EXACT-duplicate keys, found by the redteam round on this branch and
		// a different divergence from the case-variant one above. json.Unmarshal
		// into a map collapses a repeated key to the LAST occurrence before any
		// check can see it; the engine decodes the same bytes into a STRUCT,
		// where duplicate OBJECT fields are MERGED field by field, so the FIRST
		// occurrence's scalar survives an empty second. Measured on the payload
		// below: snug's map read AutoUserNsOpts as {} and passed it, the struct
		// read PasswdFile = "/etc/passwd", and podman 6.0.2 then parsed the
		// planted file end to end.
		//
		// Refused rather than normalised: picking a winner only works if snug
		// and the engine agree on the rule, and the bug IS that they do not.
		{"the measured exact-duplicate payload",
			`{"AutoUserNsOpts":{"PasswdFile":"/etc/passwd"},"AutoUserNsOpts":{}}`,
			`idmappingoptions carries the key "AutoUserNsOpts" twice`},
		{"the same, empty one first",
			`{"AutoUserNsOpts":{},"AutoUserNsOpts":{"PasswdFile":"/etc/passwd"}}`,
			`idmappingoptions carries the key "AutoUserNsOpts" twice`},
		{"an exact-duplicate nested key",
			`{"AutoUserNsOpts":{"PasswdFile":"/etc/passwd","PasswdFile":""}}`,
			`AutoUserNsOpts carries the key "PasswdFile" twice`},
		// A repeated SCALAR is refused too, though both decoders happen to agree
		// on last-wins for one: the rule is "send it once", not "send it once
		// where we have checked that it matters".
		{"an exact-duplicate scalar", `{"AutoUserNs":false,"AutoUserNs":true}`,
			`idmappingoptions carries the key "AutoUserNs" twice`},

		{"a value that is not the object podman sends", `["not","an","object"]`,
			"is not the JSON object podman sends"},
		{"a nested value that is not an object", `{"AutoUserNsOpts":"/etc/passwd"}`,
			"AutoUserNsOpts is not the JSON object podman sends"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, buildURLWithIDMapping(t, tc.value), "", tc.wantMsg)
		})
	}
}

// THE CONTROLS, and they carry the weight of every refusal above: what a real
// podman sends must still build, on BOTH recorded versions. Without them,
// "snug refuses host paths in idmappingoptions" would be equally true of a snug
// that refuses every build, and #323's fix would be #314 one level down.
//
// The forwarded value is asserted VERBATIM as well. This check resolves nothing
// and rewrites nothing — a value that arrived at the engine altered would mean
// snug had authored an id-mapping request nobody made.
func TestIDMappingOptionsAcceptsWhatPodmanActuallySends(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"podman 5.8.3's value", idMap583},
		{"podman 6.0.2's value, AutoUserNsOpts and all", idMap602},
		{"an empty sub-object", `{"HostUIDMapping":true,"AutoUserNsOpts":{}}`},
		{"a null sub-object", `{"HostUIDMapping":true,"AutoUserNsOpts":null}`},

		// UIDMap/GIDMap keep their content: integers only, no path, and the
		// build container's userns is a child of the sandbox's. REASONED FROM
		// SOURCE AND FROM THE USERNS HIERARCHY, not measured inside snug's own
		// U — this case pins today's behaviour, it does not certify the bound.
		{"a populated UIDMap",
			`{"HostUIDMapping":false,"UIDMap":[{"ContainerID":0,"HostID":100000,"Size":65536}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			before := eng.reached.Load()
			code, resp := post(t, sock, buildURLWithIDMapping(t, tc.value), "")
			if code != 200 {
				t.Fatalf("a value a real podman sends was refused (status %d): %s\n"+
					"Every refusal in this file is meaningless if this cannot pass.", code, resp)
			}
			if eng.reached.Load() == before {
				t.Fatal("the build never reached the engine")
			}

			uri, _ := eng.lastURI.Load().(string)
			fwd, err := url.Parse(uri)
			if err != nil {
				t.Fatalf("the forwarded request-URI does not parse: %q", uri)
			}
			if got := fwd.Query().Get("idmappingoptions"); got != tc.value {
				t.Errorf("idmappingoptions reached the engine altered.\n  sent:      %s\n"+
					"  forwarded: %s", tc.value, got)
			}
		})
	}
}

// The refusal has to be READABLE by the client, not just correct: libpod/build
// is the endpoint where the client streams a large body and only reads the
// response after its upload finishes, so a refusal that answers with the body
// unread surfaces as EPIPE and the message never arrives (issue #255). The
// refusal path drains first, and this asserts a body-bearing refused build
// still gets the reason.
func TestIDMappingRefusalSurvivesAStreamedBody(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	before := eng.reached.Load()
	body := strings.Repeat("x", 1<<20) // a stand-in build context tar
	code, resp := post(t, sock,
		buildURLWithIDMapping(t, `{"AutoUserNsOpts":{"PasswdFile":"/etc/passwd"}}`), body)
	if code != 403 {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if eng.reached.Load() != before {
		t.Error("the request reached the engine; it should have been refused here")
	}
	if msg := denyMessage(resp); !strings.Contains(msg, "must be empty") {
		t.Errorf("the client got a 403 without the reason it was owed: %s", msg)
	}
}

// The exact-duplicate payload must not reach the engine in ANY form. The
// refusal above is the mechanism; this asserts the outcome the redteam measured
// against — with the bug, snug returned 200 and forwarded both keys byte for
// byte, so the engine received a PasswdFile snug had judged empty.
//
// It reads the forwarded URI rather than only the status code: a fix that
// accepted the value and re-marshalled it would pass a status check while the
// question "what did the engine actually get" went unasked.
func TestIDMappingExactDuplicateNeverReachesTheEngine(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	before := eng.reached.Load()

	code, resp := post(t, sock, buildURLWithIDMapping(t,
		`{"AutoUserNs":true,"AutoUserNsOpts":{"PasswdFile":"/etc/passwd"},"AutoUserNsOpts":{}}`), "")
	if code != 403 {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if eng.reached.Load() != before {
		t.Fatal("the request reached the engine; it should have been refused here")
	}
	if uri, ok := eng.lastURI.Load().(string); ok && strings.Contains(uri, "PasswdFile") {
		t.Errorf("a PasswdFile reached the engine: %s", uri)
	}
}
