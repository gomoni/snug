package dockerproxy

import (
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// startBuildProxy is startProxy with the build surface switched on.
func startBuildProxy(t *testing.T) (sock string, eng *fakeEngine, target string) {
	t.Helper()
	return startProxyMode(t, policy.PodmanBuild)
}

// The query strings below are VERBATIM from a recording of the real podman CLI
// (5.8.3) against a listening socket — not composed from the API docs, which
// disagree with it. That is why they carry the whole default parameter set:
// each case is what actually arrives, so a case that stops being refused is a
// real client getting through.
const (
	// `podman build -t probe:x .`
	buildDefaults = `dockerfile=%5B%22Dockerfile%22%5D&forcerm=1&httpproxy=1&` +
		`idmappingoptions=%7B%22HostUIDMapping%22%3Atrue%7D&inheritannotations=1&` +
		`isolation=0&jobs=1&layers=1&networkmode=0&` +
		`nsoptions=%5B%7B%22Name%22%3A%22user%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%5D&` +
		`omithistory=0&output=probe%3Ax&outputformat=application%2Fvnd.oci.image.manifest.v1%2Bjson&` +
		`pullpolicy=missing&retry=3&retry-delay=2s&rewritetimestamp=0&rm=1&` +
		`seccomp=%2Fusr%2Fshare%2Fcontainers%2Fseccomp.json&shmsize=67108864&t=probe%3Ax`
)

func buildURL(extra string) string {
	if extra == "" {
		return "/v5.8.3/libpod/build?" + buildDefaults
	}
	return "/v5.8.3/libpod/build?" + buildDefaults + "&" + extra
}

// buildDefaults602 is the same recording one podman major later: VERBATIM from
// `podman --remote --url unix://<sock> build -t probe:x .` on podman 6.0.2
// against a listening recorder, the recorder answering /_ping as 6.0.2 — a
// client that believes it is talking to an older engine sends an older
// parameter set, so the version on BOTH sides is part of the recording.
//
// It is a SECOND oracle, not a replacement for buildDefaults: snug may meet
// either version and the allowlist has to hold against both. Three things
// changed, and each is why keeping both is worth the duplication:
//
//   - two parameters 5.8.3 never sent at all: compressionFormat and
//     forceCompressionFormat. The second is not in buildParams, so an ORDINARY
//     6.0.2 build is refused today (issue #314). Whether it belongs there is a
//     grant decision and is NOT taken here — see
//     TestRecordedDefaultsAreKnownParameters, which pins the pending set.
//   - podman's own spelling is MIXED CASE. filterBuildQuery lowercases before
//     the lookup, so the spelling a real client sends is part of what this
//     fixture checks. The 5.8.3 fixture is all-lowercase by accident and
//     exercises none of that folding.
//   - idmappingoptions grew from {"HostUIDMapping":true} to the whole
//     IDMappingOptions struct, AutoUserNsOpts included. It is forwarded
//     unexamined (buildParams["idmappingoptions"] is nil), so what that struct
//     now carries is recorded here rather than described.
const buildDefaults602 = `compressionFormat=gzip&dockerfile=%5B%22Dockerfile%22%5D&forceCompressionFormat=1&` +
	`forcerm=1&httpproxy=1&` +
	`idmappingoptions=%7B%22HostUIDMapping%22%3Atrue%2C%22HostGIDMapping%22%3Atrue%2C%22UIDMap%22%3A%5B%5D%2C%22GIDMap%22%3A%5B%5D%2C%22AutoUserNs%22%3Afalse%2C%22AutoUserNsOpts%22%3A%7B%22Size%22%3A0%2C%22InitialSize%22%3A0%2C%22PasswdFile%22%3A%22%22%2C%22GroupFile%22%3A%22%22%2C%22AdditionalUIDMappings%22%3Anull%2C%22AdditionalGIDMappings%22%3Anull%7D%7D&` +
	`inheritannotations=1&isolation=0&jobs=1&layers=1&networkmode=0&` +
	`nsoptions=%5B%7B%22Name%22%3A%22user%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%5D&` +
	`omithistory=0&output=probe%3Ax&` +
	`outputformat=application%2Fvnd.oci.image.manifest.v1%2Bjson&pullpolicy=missing&` +
	`retry=3&retry-delay=2s&rewritetimestamp=0&rm=1&` +
	`seccomp=%2Fusr%2Fshare%2Fcontainers%2Fseccomp.json&shmsize=67108864&t=probe%3Ax`

func buildURL602(extra string) string {
	if extra == "" {
		return "/v6.0.2/libpod/build?" + buildDefaults602
	}
	return "/v6.0.2/libpod/build?" + buildDefaults602 + "&" + extra
}

// Building is gated on the profile, not on the endpoint being reachable.
// `@podman-socket` runs containers; building is a second, larger option surface
// and needs `@podman-build`.
func TestBuildNeedsItsOwnProfile(t *testing.T) {
	sock, eng, _ := startProxy(t) // PodmanOff in the fake policy
	refuse(t, sock, eng, buildURL(""), "", "building images is not permitted")
}

// The escapes, each in the exact spelling the podman CLI produces for the flag
// named in the case. Every one was recorded, not guessed.
func TestBuildRefusesTheHostReachingOptions(t *testing.T) {
	for _, tc := range []struct{ name, flag, query, wantMsg string }{
		{"a host bind", "-v /etc:/x",
			"volume=%2Fetc%3A%2Fx", "cannot see /etc as writable"},
		{"a host path as a named context", "--build-context extra=/etc",
			`additionalbuildcontexts=%7B%22extra%22%3A%7B%22IsURL%22%3Afalse%2C%22IsImage%22%3Afalse%2C%22Value%22%3A%22%2Fetc%22%7D%7D`,
			"cannot see /etc"},
		{"a URL as a named context", "--build-context extra=https://evil/x",
			`additionalbuildcontexts=%7B%22extra%22%3A%7B%22IsURL%22%3Atrue%2C%22IsImage%22%3Afalse%2C%22Value%22%3A%22https%3A%2F%2Fevil%2Fx%22%7D%7D`,
			"the ENGINE fetches"},
		{"a host device", "--device /dev/fuse",
			"devices=%5B%22%2Fdev%2Ffuse%22%5D", "no host device nodes"},
		{"a cgroup outside the sandbox", "--cgroup-parent foo",
			"cgroupparent=foo", "outside this sandbox"},
		{"name redirection", "--add-host h:1.2.3.4",
			"extrahosts=%5B%22h%3A1.2.3.4%22%5D", "name redirection"},
		{"an alternate isolation", "--isolation chroot",
			"isolation=2", "isolation mode is a runtime selector"},
		{"seccomp turned off", "--security-opt seccomp=unconfined",
			"seccomp=unconfined", "does not get to"},
		{"a remote context", "(a git/URL context)",
			"remote=https%3A%2F%2Fevil%2Frepo.git", "the ENGINE"},
		{"a Dockerfile outside the context", "--file ../../etc/passwd",
			`dockerfile=%5B%22..%2F..%2Fetc%2Fpasswd%22%5D`, "escapes the build context"},
		{"an absolute Dockerfile", "--file /etc/passwd",
			`dockerfile=%5B%22%2Fetc%2Fpasswd%22%5D`, "must name a file inside the build context"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, buildURL(tc.query), "", tc.wantMsg)
		})
	}
}

// REGRESSION (redteam, M5): `secrets` was waved through, on the reasoning that
// the podman CLI reads a --secret's file itself and ships the bytes in the tar.
// True of the CLI, and not a security argument — the threat model is an agent
// that POSTs to the socket directly and sends whatever it likes.
//
// buildah resolves src= against the context dir without clamping `..`, so a
// traversing source read a host file the sandbox is not granted and streamed it
// back. Verified end to end: the same file was FileNotFoundError to a direct
// open() inside the sandbox and TOP-SECRET on the build stream.
func TestBuildSecretsCannotEscapeTheContext(t *testing.T) {
	for _, tc := range []struct{ name, src, wantMsg string }{
		{"a traversing source", "../../../../etc/hostname", "escapes the build context"},
		{"a deeply traversing source",
			"../../../../../../../../home/u/.ssh/id_ed25519", "escapes the build context"},
		{"an absolute source", "/etc/hostname", "must name a file inside the build context"},
		{"a URL source", "https://evil/x", "is a URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			q := "secrets=" + url.QueryEscape(`["id=leak,src=`+tc.src+`"]`)
			refuse(t, sock, eng, buildURL(q), "", tc.wantMsg)
		})
	}

	// CONTROL: the shape the real CLI sends — a name inside the context — must
	// still build, or this is a ban on --secret rather than on escaping.
	t.Run("control: a context-relative secret still builds", func(t *testing.T) {
		sock, eng, _ := startBuildProxy(t)
		before := eng.reached.Load()
		q := "secrets=" + url.QueryEscape(`["id=s,src=podman-build-secret-4284765652"]`)
		if code, resp := post(t, sock, buildURL(q), ""); code != 200 {
			t.Fatalf("the CLI's own secret form was refused (status %d): %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the build never reached the engine")
		}
	})

	// An env-form secret names no path at all.
	t.Run("control: an env secret is untouched", func(t *testing.T) {
		sock, _, _ := startBuildProxy(t)
		q := "secrets=" + url.QueryEscape(`["id=s,env=MY_TOKEN"]`)
		if code, resp := post(t, sock, buildURL(q), ""); code != 200 {
			t.Fatalf("an env-form secret was refused (status %d): %s", code, resp)
		}
	})
}

// REGRESSION (redteam, M5): the seccomp check applied the ordinary mount rule —
// "a path the sandbox can see" — and the sandbox's own target is both visible
// AND writable. So the agent wrote an allow-all profile into its own project and
// passed that: `unconfined` by another name, straight through the check meant to
// prevent it.
//
// Visibility is the right test for a MOUNT. For a file the engine applies AS THE
// SECURITY POLICY the question is not what the container may reach but who wrote
// it.
func TestSeccompProfileMustNotBeSandboxAuthored(t *testing.T) {
	sock, eng, target := startBuildProxy(t)

	refuse(t, sock, eng, buildURL("seccomp="+url.QueryEscape(target+"/allow.json")), "",
		"could have written itself")
	refuse(t, sock, eng, buildURL("seccomp=unconfined"), "", "does not get to")
	refuse(t, sock, eng, buildURL("seccomp="+url.QueryEscape("/etc/shadow")), "",
		"not a path this sandbox can see")

	// CONTROL: the read-only system profile the CLI actually sends still passes.
	// /usr is granted read-only in the test policy, which is the real shape.
	before := eng.reached.Load()
	if code, resp := post(t, sock, buildURL("seccomp="+
		url.QueryEscape("/usr/share/containers/seccomp.json")), ""); code != 200 {
		t.Fatalf("the CLI's default seccomp profile was refused (status %d): %s", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("the build never reached the engine")
	}
}

// `--network=host` sets TWO parameters, and either one alone re-opens the host
// network. This is the shape of the pasta bug this project already paid for
// once: three of four closing flags were passed and every host loopback service
// stayed reachable. So both are asserted, separately, with the other left at
// its default.
func TestBuildRefusesHostNetworkingInBothSpellings(t *testing.T) {
	// The full recorded pair, then each half on its own.
	hostNS := `nsoptions=%5B%7B%22Name%22%3A%22network%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%2C%7B%22Name%22%3A%22user%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%5D`

	// Each half is pinned to ITS OWN message. A shared substring would let one
	// check cover for the other's absence, which is exactly the failure mode
	// this test exists to prevent.
	for _, tc := range []struct{ name, q, wantMsg string }{
		{"networkmode alone", "networkmode=2", "may not join the host's network namespace"},
		{"nsoptions alone", hostNS, `asks for the HOST's network namespace`},
		{"both, as the CLI sends them", "networkmode=2&" + hostNS, "network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			// The recorded default already carries networkmode=0 and a user
			// nsoptions entry, so the override has to replace them rather than
			// be appended — build the query from scratch for this one.
			base, err := url.ParseQuery(buildDefaults)
			if err != nil {
				t.Fatal(err)
			}
			over, err := url.ParseQuery(tc.q)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range over {
				base[k] = v
			}
			refuse(t, sock, eng, "/v5.8.3/libpod/build?"+base.Encode(), "", tc.wantMsg)
		})
	}
}

// An option snug has not been taught about must fail closed. This is the whole
// reason the filter is an allowlist: build options are a large and fast-moving
// set, and podman gains new ones between releases.
func TestUnknownBuildParametersAreRefused(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	for _, q := range []string{"somethingnew=1", "mountfromhost=%2Fetc"} {
		refuse(t, sock, eng, buildURL(q), "", "is not permitted")
	}
}

// THE CONTROL, and it carries the weight of every refusal above: the exact
// query the podman CLI sends for a plain `podman build -t probe:x .` must be
// ACCEPTED and reach the engine. Without it, "snug refuses host binds in builds"
// would be equally true of a snug that refuses every build, and the profile
// would be useless with the suite green.
func TestAnOrdinaryBuildIsAllowed(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	before := eng.reached.Load()
	code, resp := post(t, sock, buildURL(""), "")
	if code != 200 {
		t.Fatalf("the podman CLI's own default build was refused (status %d): %s\n"+
			"Every refusal in this file is meaningless if this cannot pass.", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("the build never reached the engine")
	}
}

// A bind the sandbox CAN see is allowed, which is what makes the refusals above
// about visibility rather than about `-v` being banned outright.
func TestBuildMayBindWhatTheSandboxCanSee(t *testing.T) {
	sock, eng, target := startBuildProxy(t)
	before := eng.reached.Load()
	code, resp := post(t, sock, buildURL("volume="+url.QueryEscape(target+":/src")), "")
	if code != 200 {
		t.Fatalf("a bind of the sandbox's own target was refused (status %d): %s", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("the build never reached the engine")
	}
}

// The compat endpoint is the same filter. snug targets podman, whose CLI uses
// /libpod/build — but a docker client posting to /v1.41/build must not find a
// different set of rules.
func TestBothBuildPathsAreFiltered(t *testing.T) {
	for _, p := range []string{"/v1.41/build", "/build", "/v5.8.3/libpod/build"} {
		t.Run(p, func(t *testing.T) {
			segs, _, ok := normaliseFull(p)
			if !ok || !isBuild(segs) {
				t.Fatalf("%s is not recognised as the build endpoint (segs %v)", p, segs)
			}
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, p+"?volume=%2Fetc%3A%2Fx", "", "cannot see /etc")
		})
	}
}

// `version` selects the BUILDER, not a capability — the classic one (1, or
// unsent) is what `docker build` uses once DOCKER_BUILDKIT=0 forces the
// legacy path (internal/cli/container.go), and it is the endpoint this filter
// actually reads. `2` selects BuildKit, whose options are a different set
// from the ones buildParams enumerates, so it is refused by name rather than
// silently accepted — accepting it would make this whole allowlist not the
// full story for a request that took that path.
func TestBuildVersionSelectorAllowsClassicOnly(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)

	for _, v := range []string{"", "1"} {
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL("version="+v), "")
		if code != 200 {
			t.Fatalf("version=%q (the classic builder) was refused (status %d): %s", v, code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatalf("version=%q never reached the engine", v)
		}
	}

	refuse(t, sock, eng, buildURL("version=2"), "", "BuildKit")
}

// Every validator in the allowlist must be exercised by a case above. A check
// nothing tests is a check that can rot, and this file's whole claim is that
// the dangerous parameters are judged rather than merely listed.
func TestEveryBuildValidatorIsExercised(t *testing.T) {
	// The validators with a real decision to make, each covered above.
	covered := map[string]bool{
		"volume": true, "volumes": true, "additionalbuildcontexts": true,
		"networkmode": true, "nsoptions": true, "seccomp": true,
		"isolation": true, "dockerfile": true, "secrets": true, "version": true,
		"idmappingoptions": true,
	}
	for name, check := range buildParams {
		if check == nil || isFlatRefusal(name) {
			continue
		}
		if !covered[name] {
			t.Errorf("build parameter %q has a validator that no test exercises", name)
		}
	}
}

// isFlatRefusal reports whether a parameter is refused outright rather than
// judged. Those are one line each and are covered where they matter.
func isFlatRefusal(name string) bool {
	switch name {
	case "devices", "cgroupparent", "extrahosts", "dnsservers", "dnsoptions",
		"dnssearch", "addcapabilities", "runtime", "remote", "cachefrom",
		"cacheto", "annotations":
		return true
	}
	return false
}

// recordedBuildDefaults is every plain-build parameter set snug may actually
// meet, each one recorded against its own podman rather than composed from the
// docs. A third recording is one more entry.
var recordedBuildDefaults = map[string]string{
	"5.8.3": buildDefaults,
	"6.0.2": buildDefaults602,
}

// unmodelledBuildParams pins, per recorded version, the parameters an ORDINARY
// build sends that buildParams does not know — the ones that make a plain build
// fail closed with nobody having asked for anything unusual. The healthy value
// is no entry at all; an entry is a compatibility break, and it carries the
// issue where the grant decision for it is being taken.
//
// It is asserted as an EXACT set rather than as a floor, so it fails in both
// directions: a newer podman sending a second unmodelled parameter fails it,
// and so does #314's grant landing without this line being removed. Neither is
// something to find out from a user's broken build.
//
// It is EMPTY, which is the healthy value: every parameter both recorded
// podmans send on a plain build is modelled. It stays here as a map rather than
// becoming an assertion of emptiness so that the next version whose defaults
// outrun buildParams has somewhere to be recorded with its issue number, and so
// the exact-set comparison below keeps failing in both directions.
//
// It carried {"6.0.2": {"forcecompressionformat"}} until that grant was ruled
// on (issue #314).
var unmodelledBuildParams = map[string][]string{}

// Every parameter a real podman sends on a PLAIN build must be one buildParams
// knows about, or that podman cannot build at all — the allowlist doing its job
// in the wrong direction. The check is mechanical over the recordings so it
// keeps holding as versions are added.
func TestRecordedDefaultsAreKnownParameters(t *testing.T) {
	for version, defaults := range recordedBuildDefaults {
		t.Run("podman "+version, func(t *testing.T) {
			q, err := url.ParseQuery(defaults)
			if err != nil {
				t.Fatal(err)
			}
			if len(q) == 0 {
				t.Fatal("the recorded defaults parsed to no parameters at all")
			}
			var unknown []string
			for name := range q {
				if _, known := buildParams[strings.ToLower(name)]; !known {
					unknown = append(unknown, strings.ToLower(name))
				}
			}
			want := append([]string(nil), unmodelledBuildParams[version]...)
			sort.Strings(unknown)
			sort.Strings(want)
			if !slices.Equal(unknown, want) {
				t.Errorf("podman %s's plain build sends parameters buildParams does not "+
					"model:\n  unmodelled now:  %v\n  pinned as known: %v\n"+
					"An addition here breaks ordinary builds on that podman. A removal "+
					"means the grant landed: delete the entry from unmodelledBuildParams.",
					version, unknown, want)
			}
		})
	}
}

// The end-to-end half of the same fact, and the one that says what a user sees:
// podman 6.0.2's own default build is ACCEPTED and reaches the engine.
//
// It is the 6.0.2 twin of TestAnOrdinaryBuildIsAllowed and carries the same
// weight — every refusal in this file would be equally true of a snug that
// refuses every 6.0.2 build, and the fixture would then say nothing about the
// version most users are on. This was a TRIPWIRE asserting the refusal until
// forceCompressionFormat was ruled on (issue #314); the flip is deliberate.
func TestPodman602DefaultBuildIsAllowed(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)

	before := eng.reached.Load()
	code, resp := post(t, sock, buildURL602(""), "")
	if code != 200 {
		t.Fatalf("podman 6.0.2's own default build was refused (status %d): %s\n"+
			"Every refusal in this file is meaningless if this cannot pass.", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("the build never reached the engine")
	}

	// The granted parameter must arrive AT THE ENGINE, not merely survive the
	// filter: a check that dropped it would leave this test green while the
	// engine built with a different compression decision than the client asked
	// for. lastURI exists for exactly this class of mistake (issue #304).
	uri, _ := eng.lastURI.Load().(string)
	fwd, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("the forwarded request-URI does not parse: %q", uri)
	}
	if got := fwd.Query().Get("forceCompressionFormat"); got != "1" {
		t.Errorf("forceCompressionFormat reached the engine as %q, want \"1\"\n  forwarded: %s", got, uri)
	}
}

// NEGATIVE CONTROL for the grant: allowing forceCompressionFormat must not have
// made the 6.0.2 path permissive in general. The same recorded query with one
// unmodelled parameter added is still refused, and a host-reaching one is still
// judged — on the 6.0.2 base, not only on 5.8.3's.
func TestPodman602BaseStillFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, query, wantMsg string }{
		{"an unmodelled parameter", "somethingnew=1", "is not permitted"},
		{"a host bind", "volume=%2Fetc%3A%2Fx", "cannot see /etc as writable"},
		{"a host device", "devices=%5B%22%2Fdev%2Ffuse%22%5D", "no host device nodes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, buildURL602(tc.query), "", tc.wantMsg)
		})
	}
}

// The mixed-case spelling a real 6.0.2 client sends must reach the same
// decision as the lowercase one — filterBuildQuery lowercases before the
// lookup, and the 5.8.3 fixture is all-lowercase by accident, so nothing else
// in this file would notice that folding being dropped.
//
// Both halves are asserted: a checked parameter is still CHECKED under podman's
// own spelling (not merely known), and a flatly refused one is still refused.
func TestBuildParameterLookupFoldsCase(t *testing.T) {
	for _, tc := range []struct{ name, query, wantMsg string }{
		{"a checked parameter, camel-cased", "Volume=%2Fetc%3A%2Fx", "cannot see /etc as writable"},
		{"a refused parameter, camel-cased", "CgroupParent=foo", "outside this sandbox"},
		{"a refused parameter, upper-cased", "DEVICES=%5B%22%2Fdev%2Ffuse%22%5D", "no host device nodes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, buildURL(tc.query), "", tc.wantMsg)
		})
	}
}
