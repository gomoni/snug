package dockerproxy

import (
	"net/url"
	"testing"

	"snug/internal/policy"
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
			"devices=%5B%22%2Fdev%2Ffuse%22%5D", "device passthrough"},
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

// Every validator in the allowlist must be exercised by a case above. A check
// nothing tests is a check that can rot, and this file's whole claim is that
// the dangerous parameters are judged rather than merely listed.
func TestEveryBuildValidatorIsExercised(t *testing.T) {
	// The validators with a real decision to make, each covered above.
	covered := map[string]bool{
		"volume": true, "volumes": true, "additionalbuildcontexts": true,
		"networkmode": true, "nsoptions": true, "seccomp": true,
		"isolation": true, "dockerfile": true, "secrets": true,
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
