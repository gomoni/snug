package dockerproxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// buildContextQuery is the additionalbuildcontexts parameter for one entry
// named "x", written from raw JSON so a case a real client would never send
// can still be expressed — which is the whole point: the threat model is an
// agent POSTing to the socket directly, not the CLI.
func buildContextQuery(entry string) string {
	return "additionalbuildcontexts=" + url.QueryEscape(`{"x":`+entry+`}`)
}

// engineEffectiveValue decodes a forwarded additionalbuildcontexts exactly as
// the ENGINE does — encoding/json into the same shape buildah unmarshals — and
// returns entry "x"'s effective Value.
//
// This is the assertion issue #310 turns on. Looking for the raw path as a
// SUBSTRING of the forwarded URI is necessary but not sufficient: the hole was
// that snug and the engine disagreed about WHICH of two keys counts, so the
// only honest question is what the engine ends up with. encoding/json is
// case-insensitive and takes the LAST matching key, which is why a sorted
// re-marshal put "value" after "Value" and handed the engine the raw one.
func engineEffectiveValue(t *testing.T, requestURI string) string {
	t.Helper()
	i := strings.Index(requestURI, "?")
	if i < 0 {
		t.Fatalf("the forwarded request has no query at all: %s", requestURI)
	}
	q, err := url.ParseQuery(requestURI[i+1:])
	if err != nil {
		t.Fatalf("the forwarded query does not parse: %v", err)
	}
	raw := q.Get("additionalbuildcontexts")
	if raw == "" {
		t.Fatalf("the forwarded query carries no additionalbuildcontexts: %s", requestURI)
	}
	var m map[string]struct {
		IsURL           bool
		IsImage         bool
		Value           string
		DownloadedCache string
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("the forwarded additionalbuildcontexts is not JSON the engine could read: %v", err)
	}
	return m["x"].Value
}

// REGRESSION, issue #310 (sev:high, found by redteam post-merge on #306 — the
// #304 build-path fix, which left this spelling open).
//
// #306 wrote the resolved path back "under the key spelling actually present",
// looping `for k := range fields` and taking the first key EqualFold "Value".
// With TWO case-variant spellings in one entry the loop rewrites one and
// leaves the other holding the client's raw path; json.Marshal then sorts, so
// "value" lands after "Value", and the engine's encoding/json is
// case-insensitive LAST-WINS and takes the raw one. Measured ~38/40 trials.
// The range order is a coin flip and the request is freely retriable, so the
// odds do not matter.
//
// The fix refuses the duplicate outright rather than picking a winner, because
// picking one only works if snug and the engine agree on the rule — and the
// bug WAS that they do not.
func TestBuildContextRefusesADuplicateFieldSpelling(t *testing.T) {
	for _, tc := range []struct{ name, entry, wantMsg string }{
		{"Value twice, the measured #310 input",
			`{"IsURL":false,"IsImage":false,"Value":"/usr","value":"/usr"}`,
			"carries Value twice"},
		// The general form. #310 was filed against Value, but the same
		// divergence works on any field snug reads and the engine reads: snug
		// judges one spelling, the engine takes the other.
		{"IsImage twice, so snug judges a path and the engine pulls an image",
			`{"IsURL":false,"IsImage":false,"isimage":true,"Value":"/usr"}`,
			"carries IsImage twice"},
		{"IsURL twice",
			`{"IsURL":false,"isurl":true,"IsImage":false,"Value":"/usr"}`,
			"carries IsURL twice"},
		{"three spellings of Value",
			`{"IsURL":false,"IsImage":false,"Value":"/usr","value":"/usr","VALUE":"/usr"}`,
			"twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, buildURL(buildContextQuery(tc.entry)), "", tc.wantMsg)
		})
	}
}

// The behavioural half: drive the ALLOWED single-Value case repeatedly and
// assert what the ENGINE ends up with, not merely that a substring is absent.
//
// SAY WHAT THIS DOES AND DOES NOT CATCH, because overstating it is how #310
// happened. It passes on #306's code too — a single Value key is the one case
// that loop rewrote completely, which is exactly why
// TestBuildForwardsTheResolvedPathNotTheClientsSymlink missed the hole. The
// test that catches #310 is the duplicate-spelling refusal above. What this
// one pins is the CANONICAL form: after the fix there is exactly one Value
// key, spelled "Value", carrying the resolved path — so a future rewrite that
// reintroduced per-key preservation would have to answer to the engine's own
// decode.
//
// Repeated 40 times because the defect it guards the edge of was
// range-over-map nondeterministic, and a single iteration of a
// map-order-dependent bug passes roughly half the time. A green suite
// coexisted with a sev:high hole for a merge on exactly that.
func TestBuildContextForwardsOneCanonicalResolvedValue(t *testing.T) {
	const iterations = 40

	sock, eng, target := startBuildProxy(t)
	link := filepath.Join(target, "link")
	if err := os.Symlink("/usr", link); err != nil {
		t.Fatal(err)
	}

	entry := `{"IsURL":false,"IsImage":false,"Value":` + mustJSON(t, link) + `,"DownloadedCache":""}`
	for i := 0; i < iterations; i++ {
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL(buildContextQuery(entry)), "")
		if code != 200 {
			t.Fatalf("iteration %d: the build was refused (status %d), so this test measures "+
				"nothing: %s", i, code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatalf("iteration %d: the build never reached the engine", i)
		}
		uri, _ := eng.lastURI.Load().(string)
		if got := engineEffectiveValue(t, uri); got != "/usr" {
			t.Fatalf("iteration %d: the ENGINE's effective context Value is %q, want the "+
				"resolved \"/usr\". The client's symlink can be re-pointed after the check, "+
				"so a raw path here is #304's primitive reopened (issue #310).\nforwarded: %s",
				i, got, uri)
		}
		if strings.Contains(uri, "value") && !strings.Contains(uri, `"Value"`) {
			t.Fatalf("iteration %d: the forwarded entry does not carry a canonical \"Value\" "+
				"key:\n%s", i, uri)
		}
	}
}

// REGRESSION, issue #311 (sev:medium, engine consumption unverified). #306
// preserved every field snug does not model, byte for byte, so DownloadedCache
// — a path-bearing field with no check behind it — reached the engine raw.
// Its documented role is the materialised local directory for a URL or archive
// context, so if buildah honours one supplied over the API it is a direct
// host-path read: no symlink, no race.
//
// snug does not resolve it and does not model what the engine does with it, so
// the only honest answer is that it may be empty and nothing else.
func TestBuildContextRefusesANonEmptyDownloadedCache(t *testing.T) {
	sock, eng, target := startBuildProxy(t)
	for _, tc := range []struct{ name, value string }{
		{"a path beside a clean Value", target},
		{"a path the sandbox cannot see", "/etc"},
		{"one of snug's own engine grafts", "/snug/engine/store"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := `{"IsURL":false,"IsImage":false,"Value":"/usr","DownloadedCache":` +
				mustJSON(t, tc.value) + `}`
			refuse(t, sock, eng, buildURL(buildContextQuery(entry)), "", "which names a host directory")
		})
	}
}

// An entry's fields are a DEFAULT-DENY ALLOWLIST, the same rule buildParams
// applies to the query one level up. #311's root cause was that #306 applied
// the opposite rule inside an allowed parameter.
func TestBuildContextRefusesAFieldSnugDoesNotModel(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	for _, tc := range []struct{ name, entry string }{
		{"an invented path-bearing field",
			`{"IsURL":false,"IsImage":false,"Value":"/usr","ContextDir":"/etc"}`},
		{"a field that may exist in a future buildah",
			`{"IsURL":false,"IsImage":false,"Value":"/usr","Whatever":"/etc"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuse(t, sock, eng, buildURL(buildContextQuery(tc.entry)), "",
				"which snug does not model")
		})
	}
}

// POSITIVE CONTROL, and the one that stops all of the above from becoming a
// ban on --build-context.
//
// RECORDED, not guessed: `podman 6.0.2 build --build-context extra=<dir>`
// against a listening socket sends exactly
//
//	{"extra":{"IsURL":false,"IsImage":false,"Value":"<dir>","DownloadedCache":""}}
//
// — four fields, DownloadedCache EMPTY. So the allowlist must carry all four
// and must accept an empty DownloadedCache, or snug refuses the real client.
func TestBuildContextAcceptsWhatPodmanActuallySends(t *testing.T) {
	sock, eng, target := startBuildProxy(t)

	entry := `{"IsURL":false,"IsImage":false,"Value":` + mustJSON(t, target) + `,"DownloadedCache":""}`
	before := eng.reached.Load()
	code, resp := post(t, sock, buildURL(buildContextQuery(entry)), "")
	if code != 200 {
		t.Fatalf("the shape podman 6.0.2 really sends was refused (status %d), which is a ban "+
			"on --build-context rather than on escaping it: %s", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("the build never reached the engine")
	}

	// An image reference is the other legitimate shape and carries no path.
	imageEntry := `{"IsURL":false,"IsImage":true,"Value":"alpine:latest","DownloadedCache":""}`
	if code, resp := post(t, sock, buildURL(buildContextQuery(imageEntry)), ""); code != 200 {
		t.Fatalf("an image-reference context was refused (status %d): %s", code, resp)
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// HARDENING, suggested by the redteam pass on this PR. It could not break the
// fix; this pins the reason it holds so a plausible future edit cannot quietly
// remove it.
//
// snug dedups field names with strings.ToLower. Go's encoding/json matches
// them with its own SIMPLE FOLD, and the two agree on ASCII and DIVERGE ON
// NON-ASCII. Measured against Go's encoding/json:
//
//	json.Unmarshal(`{"IsImage":false,"IſImage":true,...}`)  -> IsImage=true
//	strings.ToLower("IſImage") == "isimage"                 -> FALSE
//	strings.EqualFold("IſImage", "IsImage")                 -> TRUE
//	strings.EqualFold("\u212aeyPath", "keyPath")            -> TRUE  (Kelvin sign)
//
// U+017F LATIN SMALL LETTER LONG S folds to 's' for encoding/json and for
// EqualFold, and does NOT lower to 's' for ToLower. So today "IſImage" misses
// the allowlist entirely and is refused as a field snug does not model — the
// divergence lands FAIL-CLOSED, which is why the redteam found nothing.
//
// The edit to guard against is switching the dedup or the lookup to
// strings.EqualFold, which reads like a tidy-up and would make snug agree with
// the engine about ſ — at which point whether this stays closed depends
// entirely on the duplicate rule still being there. This test asserts the
// OUTCOME rather than which rule produces it, so it holds across that edit and
// fails only if both are relaxed together.
//
// POSITIVE CONTROL, run by hand before committing, because "still refused" is
// the kind of pass that can mean nothing. Adding "iſimage"/"iſurl" to
// additionalContextFields ALONE does not fail this test — the duplicate rule
// catches it instead, which is the defence in depth working. Disabling BOTH
// (allowlist the fold spellings and short-circuit the duplicate check) DOES
// fail it:
//
//	--- FAIL: TestBuildContextRefusesAUnicodeFoldFieldSpelling/IsImage,_long-s_variant_last
//
// So the test measures the outcome, not one mechanism, and it can fail.
//
// ONLY TWO OF THE FOUR FIELDS CAN HAVE A FOLD VARIANT AT ALL, and saying so is
// the difference between a table that tests something and one that looks like
// it does. A fold variant needs a letter with a non-ASCII fold partner: ſ
// stands in for 's', U+212A (Kelvin) for 'k'. IsURL and IsImage carry an 's';
// Value and DownloadedCache contain neither an 's' nor a 'k', so no spelling
// of either folds — "Valuſe" is a DIFFERENT WORD, not a variant, and a case
// built on it would be refused for its length and prove nothing about folding.
func TestBuildContextRefusesAUnicodeFoldFieldSpelling(t *testing.T) {
	for _, tc := range []struct{ name, entry string }{
		// The fold variant AFTER the real key, which is the ordering that
		// wins under encoding/json's last-wins.
		{"IsImage, long-s variant last",
			`{"IsURL":false,"IsImage":false,"I\u017fImage":true,"Value":"/etc/shadow"}`},
		{"IsImage, long-s variant first",
			`{"IsURL":false,"I\u017fImage":true,"IsImage":false,"Value":"/etc/shadow"}`},
		{"IsURL, long-s variant",
			`{"I\u017fURL":true,"IsURL":false,"IsImage":false,"Value":"/etc/shadow"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			// No wantMsg beyond the shared stem: WHICH rule refuses this is
			// the thing that may legitimately change (today the allowlist,
			// after an EqualFold switch the duplicate rule). Pinning the
			// message would make a safe refactor fail and teach whoever hits
			// it to loosen the test.
			refuse(t, sock, eng, buildURL(buildContextQuery(tc.entry)), "", "context \"x\"")
		})
	}
}

// TestAdditionalBuildContextFieldsAreAllScalars is issue #335's item 3 and
// issue #327's item 2 — one test, because they are the same property.
//
// The premise it guards is stated at checkAdditionalContexts' struct decode:
// snug unmarshals the ORIGINAL entry bytes with the same encoding/json
// semantics buildah uses, so for these fields what snug judges is
// definitionally what the engine computes. That holds ONLY while every field is
// a scalar. A map route collapses a repeated key to the last occurrence; a
// struct route merges duplicate OBJECT fields field by field. The two can
// disagree only where a field is an object, so an all-scalar struct is what
// makes the disagreement unrepresentable rather than merely unlikely.
//
// The assumption was load-bearing and unstated before this test existed, and it
// is a future BUILDAH release that breaks it, not a change in this repository —
// which is exactly why it needs a guard here rather than a comment.
func TestAdditionalBuildContextFieldsAreAllScalars(t *testing.T) {
	rt := reflect.TypeOf(additionalContextEntry{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		switch f.Type.Kind() {
		case reflect.Bool, reflect.String,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
		default:
			t.Errorf("additionalContextEntry.%s is %s, not a scalar. A map route takes the "+
				"LAST of a repeated key and a struct route MERGES duplicate object fields, "+
				"so a non-scalar field here lets snug and the engine read one request two "+
				"ways (issue #323). Either keep the field scalar, or refuse a repeated key "+
				"outright the way #326 did for idmappingoptions",
				f.Name, f.Type.Kind())
		}
	}
}

// TestEveryModelledContextFieldIsAccountedFor pins the two lists against each
// other, so a field added to one and not the other cannot pass unnoticed.
// additionalContextFields is the default-deny allowlist; additionalContextEntry
// is the subset snug decodes and acts on. DownloadedCache is in the first and
// deliberately not the second — it is refused unless empty rather than used.
func TestEveryModelledContextFieldIsAccountedFor(t *testing.T) {
	canon := map[string]bool{}
	for _, v := range additionalContextFields {
		canon[v] = true
	}
	want := map[string]bool{"IsURL": true, "IsImage": true, "Value": true, "DownloadedCache": true}
	if !reflect.DeepEqual(canon, want) {
		t.Errorf("additionalContextFields' canonical names are %v, want %v. A fifth field is "+
			"a field snug has not been taught about reaching the engine unexamined; if it is "+
			"genuinely harmless, add it here with the note saying why", canon, want)
	}

	rt := reflect.TypeOf(additionalContextEntry{})
	for i := 0; i < rt.NumField(); i++ {
		if !canon[rt.Field(i).Name] {
			t.Errorf("additionalContextEntry.%s is decoded and acted on but is not in "+
				"additionalContextFields, so the allowlist would refuse the very field the "+
				"decode depends on", rt.Field(i).Name)
		}
	}
}

// TestARepeatedContextFieldCannotReachTheEngine is issue #327's guard for the
// BUILD site. checkAdditionalContexts is duplicate-key-safe only because it
// re-marshals from its own decoded map — a side effect of #313's rewrite,
// never chosen as a duplicate-key defence and, until #327, never stated.
//
// MUTATION THAT MUST REDDEN IT: replace the `json.Marshal(fields)` re-marshal
// with a verbatim forward of the client's original bytes. Do NOT check this by
// deleting the field-level dedup — that is a different check, and deleting it
// would leave this test passing for the wrong reason.
func TestARepeatedContextFieldCannotReachTheEngine(t *testing.T) {
	sock, eng, target := startBuildProxy(t)
	// Same key twice, exactly — not two case variants, which the field-level
	// dedup refuses on its own and which would therefore never reach the
	// re-marshal this test is about.
	entry := `{"IsURL":false,"IsImage":false,"Value":"` + target + `","Value":"` + target + `"}`
	code, resp := post(t, sock, buildURL(buildContextQuery(entry)), "")
	if code == http.StatusForbidden {
		t.Fatalf("a repeated scalar key was refused; this test is about the re-marshal that "+
			"COLLAPSES it, so it needs a request that is forwarded (status %d): %s",
			code, denyMessage(resp))
	}
	uri := eng.lastURI.Load().(string)
	i := strings.Index(uri, "?")
	if i < 0 {
		t.Fatalf("the forwarded request has no query at all: %s", uri)
	}
	q, err := url.ParseQuery(uri[i+1:])
	if err != nil {
		t.Fatalf("the forwarded query does not parse: %v", err)
	}
	raw := q.Get("additionalbuildcontexts")
	if n := strings.Count(raw, `"Value"`); n != 1 {
		t.Errorf("the forwarded entry carries %q %d times, want exactly 1: %s\n"+
			"A repeated key reached the engine. snug decoded it into a map (last wins) and "+
			"the engine decodes into a struct, so the two can read one request two ways "+
			"(issue #323). The re-marshal is what collapses it — forwarding the client's "+
			"original bytes here reopens the class with nothing else failing",
			`"Value"`, n, raw)
	}
}
