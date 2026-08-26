package dockerproxy

import (
	"encoding/json"
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

// nsOption is the JSON shape checkNSOptions decodes. Building nsoptions
// entries through json.Marshal, rather than by hand-writing more
// percent-escaped literals like noneNS/hostNS above, is what makes the
// per-branch cases below (refs #369) readable as a table instead of as a
// wall of URL-encoding.
type nsOption struct {
	Name string
	Host bool
	Path string
}

// nsOptionsQuery encodes one nsoptions entry as the query parameter podman
// sends.
func nsOptionsQuery(o nsOption) string {
	b, err := json.Marshal([]nsOption{o})
	if err != nil {
		panic(err)
	}
	return "nsoptions=" + url.QueryEscape(string(b))
}

// buildURLOverride is the pattern TestBuildRefusesAPrivateNetworkNamespaceInBothSpellings
// established, pulled out for reuse: `extra` REPLACES the recorded default's
// own value for any key it shares, rather than being appended alongside a
// second copy of the same key.
func buildURLOverride(t *testing.T, extra string) string {
	t.Helper()
	base, err := url.ParseQuery(buildDefaults)
	if err != nil {
		t.Fatal(err)
	}
	over, err := url.ParseQuery(extra)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range over {
		base[k] = v
	}
	return "/v5.8.3/libpod/build?" + base.Encode()
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
		{"a client-named cgroup parent", "--cgroup-parent foo",
			"cgroupparent=foo", "the engine's own cgroup namespace"},
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

// `--network=none` sets TWO parameters, and either one alone asks for a
// network namespace of the BUILD STEP's own — the thing the containers.conf
// pin (issue #401) makes unconditionally dead, MEASURED on podman 6.0.2:
// `ioctl SIOCSIFFLAGS: Operation not permitted` regardless of which of the two
// spellings carried the request. This is the shape of the pasta bug this
// project already paid for once: three of four closing flags were passed and
// every host loopback service stayed reachable. So both are asserted,
// separately, with the other left at its default — and `--network=host`,
// which since Tier B means the ENGINE's own netns rather than the machine's,
// is the positive control: it is what a build with no --network flag already
// gets, and it must still be accepted rather than refused by a check written
// for the pre-#401 reading.
func TestBuildRefusesAPrivateNetworkNamespaceInBothSpellings(t *testing.T) {
	// `--network=none` sends networkmode=1 and an nsoptions entry naming
	// `network` with Host:false, Path:"" — both spellings of "give this build
	// step a network namespace of its own".
	noneNS := `nsoptions=%5B%7B%22Name%22%3A%22network%22%2C%22Host%22%3Afalse%2C%22Path%22%3A%22%22%7D%2C%7B%22Name%22%3A%22user%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%5D`

	// Each half is pinned to ITS OWN message. A shared substring would let one
	// check cover for the other's absence, which is exactly the failure mode
	// this test exists to prevent.
	for _, tc := range []struct{ name, q, wantMsg string }{
		{"networkmode alone", "networkmode=1", "ioctl SIOCSIFFLAGS"},
		{"nsoptions alone", noneNS, "Host:false"},
		{"both, as --network=none sends them", "networkmode=1&" + noneNS, "ioctl SIOCSIFFLAGS"},
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

// TestBuildAcceptsHostNetworkingInBothSpellings is the positive control for
// the test above: `--network=host` sends the same two parameters, and since
// Tier B "host" means the ENGINE's own network namespace, which is this
// sandbox's — the same place a build with no --network flag already lands,
// via the containers.conf pin (issue #401). A check still reading the
// pre-#401 rule would refuse exactly this pair.
func TestBuildAcceptsHostNetworkingInBothSpellings(t *testing.T) {
	hostNS := `nsoptions=%5B%7B%22Name%22%3A%22network%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%2C%7B%22Name%22%3A%22user%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%5D`

	for _, tc := range []struct{ name, q string }{
		{"networkmode alone", "networkmode=2"},
		{"nsoptions alone", hostNS},
		{"both, as the CLI sends them", "networkmode=2&" + hostNS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
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
			before := eng.reached.Load()
			code, resp := post(t, sock, "/v5.8.3/libpod/build?"+base.Encode(), "")
			if code != 200 {
				t.Fatalf("--network=host build refused (status %d): %s", code, resp)
			}
			if eng.reached.Load() == before {
				t.Fatal("the build never reached the engine")
			}
		})
	}
}

// TestCheckNetworkModeRecordedSpellings is a table over every literal
// networkmode SPELLING checkNetworkMode's own switch names (issue #401),
// each with the message it must carry — not merely accept/refuse, per
// CLAUDE.md's rule that a table entry without its message can silently stop
// exercising the rule it was written for while staying green.
//
// This is deliberately BROADER than the libpod CLI's own recorded query
// (TestBuildAcceptsHostNetworkingInBothSpellings /
// TestBuildRefusesAPrivateNetworkNamespaceInBothSpellings, which drive
// networkmode=1/2 the way `podman build` actually encodes them alongside an
// nsoptions entry): the literal words ("none", "bridge", "private",
// "slirp4netns", "pasta") are what a docker-compat client sends for the SAME
// key, per build.go's own doc comment distinguishing the two encodings, and
// checkNetworkMode is the one function judging both. "" and "default" are
// accepted for robustness (checkNetworkMode's own comment: no measured
// client sends either), not because a real caller does.
func TestCheckNetworkModeRecordedSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, value, wantMsg string
		accept               bool
	}{
		{"empty (no --network flag at all)", "", "", true},
		{"explicit 0", "0", "", true},
		{"the word default", "default", "", true},
		{"the libpod int for host", "2", "", true},
		{"the word host", "host", "", true},
		{"the word HOST, case-folded", "HOST", "", true},
		{"the libpod int for a private netns", "1",
			"ioctl SIOCSIFFLAGS", false},
		{"the word none", "none", "ioctl SIOCSIFFLAGS", false},
		{"the word private", "private", "ioctl SIOCSIFFLAGS", false},
		{"the word bridge", "bridge", "ioctl SIOCSIFFLAGS", false},
		{"the word slirp4netns", "slirp4netns", "ioctl SIOCSIFFLAGS", false},
		{"the word pasta", "pasta", "ioctl SIOCSIFFLAGS", false},
		{"a joined container namespace", "container:abc",
			"snug did not author", false},
		{"a joined namespace by path", "ns:/proc/123/ns/net",
			"snug did not author", false},
		{"an unrecognised value", "some-future-mode",
			"a value it has not been taught about fails closed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			base, err := url.ParseQuery(buildDefaults)
			if err != nil {
				t.Fatal(err)
			}
			base.Set("networkmode", tc.value)
			u := "/v5.8.3/libpod/build?" + base.Encode()
			if tc.accept {
				before := eng.reached.Load()
				code, resp := post(t, sock, u, "")
				if code != 200 {
					t.Fatalf("networkmode=%q was refused (status %d): %s", tc.value, code, resp)
				}
				if eng.reached.Load() == before {
					t.Fatal("the build never reached the engine")
				}
				return
			}
			refuse(t, sock, eng, u, "", tc.wantMsg)
		})
	}

	// CONTROLS: neither recorded ordinary build (each already carrying its
	// own networkmode=0) was disturbed by anything above — TestAnOrdinaryBuildIsAllowed
	// and TestPodman602DefaultBuildIsAllowed are the tests that actually pin
	// this; repeated here as an explicit precondition for this table's own
	// claim, since a table that judges networkmode in isolation says nothing
	// if the ordinary case it is a special case OF has quietly stopped
	// passing.
	t.Run("control: podman 5.8.3's own default build still passes unchanged", func(t *testing.T) {
		sock, eng, _ := startBuildProxy(t)
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL(""), "")
		if code != 200 {
			t.Fatalf("podman 5.8.3's own default build was refused (status %d): %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the build never reached the engine")
		}
	})
	t.Run("control: podman 6.0.2's own default build still passes unchanged", func(t *testing.T) {
		sock, eng, _ := startBuildProxy(t)
		before := eng.reached.Load()
		code, resp := post(t, sock, buildURL602(""), "")
		if code != 200 {
			t.Fatalf("podman 6.0.2's own default build was refused (status %d): %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the build never reached the engine")
		}
	})
}

// TestCheckNetworkModeOnTheCompatEndpoint is the docker-compat half of the
// same table, issue #401: /v1.41/build is the SAME filter
// (TestBothBuildPathsAreFiltered already pins that generally), so the
// literal-word spellings a docker client sends for networkmode must be
// judged identically there.
//
// MEASURED on podman 6.0.2 (this repository's own development host, see
// go-implementer's coverage note): the compat build endpoint's own handler
// does not read networkmode as a build-time option at all — a container's
// network is a RUN-time question on that endpoint, not a build-time one — so
// this refusal is entirely snug's OWN semantics, judged before the request
// ever reaches podman, not a property the engine also happens to enforce.
// That is exactly why this belongs in the allowlist rather than being left
// for the engine to sort out: an engine that silently ignores a parameter is
// indistinguishable, from the client's side, from one that honours it.
func TestCheckNetworkModeOnTheCompatEndpoint(t *testing.T) {
	compatURL := func(extra string) string {
		if extra == "" {
			return "/v1.41/build?" + buildDefaults
		}
		return "/v1.41/build?" + buildDefaults + "&" + extra
	}

	// networkmode ABSENT must still pass: the recorded default carries
	// networkmode=0 already (buildDefaults), so this asserts that overriding
	// nothing does not, by itself, break the compat path.
	t.Run("networkmode absent", func(t *testing.T) {
		sock, eng, _ := startBuildProxy(t)
		before := eng.reached.Load()
		code, resp := post(t, sock, compatURL(""), "")
		if code != 200 {
			t.Fatalf("the compat endpoint's own default build was refused (status %d): %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("the build never reached the engine")
		}
	})

	for _, tc := range []struct{ name, value, wantMsg string }{
		{"the numeric private mode", "1", "ioctl SIOCSIFFLAGS"},
		{"bridge", "bridge", "ioctl SIOCSIFFLAGS"},
		{"none", "none", "ioctl SIOCSIFFLAGS"},
		{"private", "private", "ioctl SIOCSIFFLAGS"},
		{"pasta", "pasta", "ioctl SIOCSIFFLAGS"},
		{"container:abc", "container:abc", "snug did not author"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			base, err := url.ParseQuery(buildDefaults)
			if err != nil {
				t.Fatal(err)
			}
			base.Set("networkmode", tc.value)
			refuse(t, sock, eng, "/v1.41/build?"+base.Encode(), "", tc.wantMsg)
		})
	}

	// POSITIVE CONTROL for the row above: the accepted spellings must reach
	// the engine on THIS endpoint too, at the numeric AND the word spelling —
	// a docker client asking for --network=host must not meet a stricter rule
	// than the podman CLI's own libpod endpoint does (refs #369).
	for _, v := range []string{"2", "host", "default", ""} {
		t.Run("accept networkmode="+v, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			base, err := url.ParseQuery(buildDefaults)
			if err != nil {
				t.Fatal(err)
			}
			base.Set("networkmode", v)
			before := eng.reached.Load()
			code, resp := post(t, sock, "/v1.41/build?"+base.Encode(), "")
			if code != 200 {
				t.Fatalf("networkmode=%q on the compat endpoint was refused (status %d): %s", v, code, resp)
			}
			if eng.reached.Load() == before {
				t.Fatal("the build never reached the engine")
			}
		})
	}
}

// TestCheckNSOptionsRefusesAnUntaughtName pins the NAME-axis fix (refs #369):
// before it, any Name with Host:false and an empty Path fell through the
// loop's Host/Path checks straight to the accept, and what actually refused
// "net" was buildah's own mapStrToNamespace — not because snug judged it, and
// not by case: "net" simply is not one of the names that table accepts, so it
// was refused by luck of spelling. "mount" and "time" ARE both in that table,
// and buildah's setupNamespaces has no default: arm, so those two were
// configured into the OCI spec verbatim. This
// fails if the NAME axis is ever again left to fall through to an accept for
// any name outside the six podman is measured to send.
//
// Each row asserts eng.reached did not move: a refusal message that happened
// to be right for the wrong reason (e.g. the build failing for an unrelated
// cause) must not be mistaken for this check having fired.
func TestCheckNSOptionsRefusesAnUntaughtName(t *testing.T) {
	const wantMsg = "names a namespace snug has not been taught about"
	for _, tc := range []struct{ name, nsName string }{
		{"net — refused today only because buildah's name table happens not to list it", "net"},
		{"mount — buildah accepts this and configures it verbatim; snug did not check it until now", "mount"},
		{"time — the second name buildah accepts that snug never checked", "time"},
		{"the empty name", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			u := buildURLOverride(t, nsOptionsQuery(nsOption{Name: tc.nsName, Host: false, Path: ""}))
			refuse(t, sock, eng, u, "", wantMsg)
		})
	}
}

// TestCheckNSOptionsStillAcceptsRealClients is the positive control for the
// refusal above: none of the entries a real podman CLI actually sends may
// have started being refused by the new NAME switch. Without this, "unknown
// names are refused" would be equally true of a check that refuses every
// name.
func TestCheckNSOptionsStillAcceptsRealClients(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  nsOption
	}{
		{"the recorded default: user, Host:true — the rootless default, sent with no flag at all",
			nsOption{Name: "user", Host: true, Path: ""}},
		{"--userns=container: user, Host:false, Path empty",
			nsOption{Name: "user", Host: false, Path: ""}},
		{"--pid=private", nsOption{Name: "pid", Host: false, Path: ""}},
		{"--ipc=private", nsOption{Name: "ipc", Host: false, Path: ""}},
		{"--uts=private", nsOption{Name: "uts", Host: false, Path: ""}},
		{"--cgroupns=private", nsOption{Name: "cgroup", Host: false, Path: ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			u := buildURLOverride(t, nsOptionsQuery(tc.opt))
			before := eng.reached.Load()
			code, resp := post(t, sock, u, "")
			if code != 200 {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if eng.reached.Load() == before {
				t.Fatal("the build never reached the engine")
			}
		})
	}
}

// TestNetworkHostFalseKeepsItsOwnMessage guards the new name-axis switch
// against silently covering for the OLDER network-specific refusal it now
// sits in front of: "network" is a taught name, so it must still fall
// through the switch to the check that names WHY Host:false is refused
// (needs CAP_NET_ADMIN the engine does not have), not stop at the generic
// "not been taught about" message the switch produces for an unknown name.
// TestBuildRefusesAPrivateNetworkNamespaceInBothSpellings already pins this
// via the compound --network=none query; this is the same fact reached
// directly through checkNSOptions' own inputs.
func TestNetworkHostFalseKeepsItsOwnMessage(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	u := buildURLOverride(t, nsOptionsQuery(nsOption{Name: "network", Host: false, Path: ""}))
	refuse(t, sock, eng, u, "", "Host:false")
}

// TestCheckNSOptionsHostTrueOnNonNetworkName pins a branch that predates
// #369 and that no test before this one ever executed:
// TestEveryBuildValidatorIsExercised reports nsoptions "covered" purely
// because SOME case drives it, and every existing nsoptions case either
// names "network" or "user" — none put Host:true on pid/ipc/uts/cgroup. This
// fails if that arm is ever changed to admit the engine's pid/ipc/uts/cgroup
// namespace under a name other than user or network.
//
// The asserted phrase names the ENGINE's namespace, not the machine's, and
// that is the same correction issue #372 made to the archive refusal: the
// engine clones all four for itself (internal/stage/enginefork.go's
// Cloneflags), so a message calling Host:true "the HOST's namespace" describes
// a boundary C0 and #182 removed. TestNoRefusalTextPlacesTheEngineOutsideTheSandbox
// guards the class.
func TestCheckNSOptionsHostTrueOnNonNetworkName(t *testing.T) {
	for _, name := range []string{"pid", "ipc", "uts", "cgroup"} {
		t.Run(name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			u := buildURLOverride(t, nsOptionsQuery(nsOption{Name: name, Host: true, Path: ""}))
			refuse(t, sock, eng, u, "", "the ENGINE's own and not the machine's")
		})
	}
}

// TestCheckNSOptionsNetworkPathNamesTheMode pins the `network`+non-empty-Path
// branch, the second spelling of --network=<mode> (the first being
// networkmode, checkNetworkMode's own table): a namespace NAME in Path is how
// --network=pasta/bridge/ns:/p arrive here. This fails if that branch is ever
// changed to accept a network mode name through nsoptions after
// checkNetworkMode already refuses the same word under networkmode.
func TestCheckNSOptionsNetworkPathNamesTheMode(t *testing.T) {
	for _, path := range []string{"pasta", "bridge", "slirp4netns", "/proc/self/ns/net"} {
		t.Run(path, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			u := buildURLOverride(t, nsOptionsQuery(nsOption{Name: "network", Host: false, Path: path}))
			refuse(t, sock, eng, u, "", "names the network")
		})
	}
}

// TestCheckNSOptionsPathOnNonNetworkName pins the non-`network`,
// non-empty-Path branch — `--pid=/proc/self/ns/pid` joining a namespace snug
// did not create. This fails if a namespace path on any name other than
// `network` is ever accepted.
func TestCheckNSOptionsPathOnNonNetworkName(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	u := buildURLOverride(t, nsOptionsQuery(nsOption{Name: "pid", Host: false, Path: "/proc/self/ns/pid"}))
	refuse(t, sock, eng, u, "", "names an existing namespace at")
}

// TestCheckNSOptionsRejectsMalformedJSON pins the json.Unmarshal failure
// path, unexecuted by any case before this one — every existing nsoptions
// query is well-formed JSON, so this arm has only ever been read, never run.
func TestCheckNSOptionsRejectsMalformedJSON(t *testing.T) {
	sock, eng, _ := startBuildProxy(t)
	u := buildURLOverride(t, "nsoptions="+url.QueryEscape("not a json list"))
	refuse(t, sock, eng, u, "", "is not the JSON list podman sends")
}

// TestNSOptionsIsFilteredOnEveryBuildPath is the nsoptions half of
// TestBothBuildPathsAreFiltered's claim (that claim is driven by `volume`
// alone): a docker-compat client posting nsoptions to /v1.41/build or the
// bare /build path must meet the same NAME-axis and network-Host:false
// refusals as the podman CLI's own /libpod/build. These paths carry no other
// query parameter, which is enough — filterBuildQuery refuses on the first
// bad parameter it finds, so the recorded defaults are not needed to reach
// checkNSOptions here, matching the precedent TestBothBuildPathsAreFiltered
// already set for `volume`.
func TestNSOptionsIsFilteredOnEveryBuildPath(t *testing.T) {
	for _, p := range []string{"/v1.41/build", "/build", "/v5.8.3/libpod/build"} {
		t.Run(p+"/untaught name", func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			q := nsOptionsQuery(nsOption{Name: "mount", Host: false, Path: ""})
			refuse(t, sock, eng, p+"?"+q, "", "names a namespace snug has not been taught about")
		})
		t.Run(p+"/private network", func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			q := nsOptionsQuery(nsOption{Name: "network", Host: false, Path: ""})
			refuse(t, sock, eng, p+"?"+q, "", "Host:false")
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
			segs, _, _, ok := normaliseFull(p)
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
//
// WHAT THIS DOES NOT ASSERT (refs #369): "exercised" here means the
// validator's NAME is in `covered`, which whoever adds the first case for it
// sets by hand — it says nothing about how many of that validator's own
// branches the covering case actually reaches. nsoptions was "covered" by
// this accounting for the whole of #369's finding: checkNSOptions had (and,
// for four of them, still has) branches — Host:true on a name other than
// user/network, the network+Path and non-network+Path arms, and the
// malformed-JSON arm — that no case in this file executed, and this loop
// was and remains green throughout. The name axis itself was the fifth: any
// unrecognised Name with Host:false and an empty Path fell through to the
// accept, and nothing here noticed. Those five now have their own tests
// (TestCheckNSOptionsRefusesAnUntaughtName,
// TestCheckNSOptionsHostTrueOnNonNetworkName,
// TestCheckNSOptionsNetworkPathNamesTheMode,
// TestCheckNSOptionsPathOnNonNetworkName,
// TestCheckNSOptionsRejectsMalformedJSON) — this loop does not, and cannot,
// confirm they exist; a per-branch check would need a coverage hook this
// package does not have, and this comment is the substitute for one.
func TestEveryBuildValidatorIsExercised(t *testing.T) {
	// The validators with a real decision to make, each covered above.
	covered := map[string]bool{
		"volume": true, "volumes": true, "additionalbuildcontexts": true,
		"networkmode": true, "nsoptions": true, "seccomp": true,
		"isolation": true, "dockerfile": true, "secrets": true, "version": true,
		"idmappingoptions": true,
	}
	// `check == nil` is not skipped: buildParams has no nil entry, and a
	// parameter forwarded unexamined lives in unexaminedBuildParams with its
	// abuse sentence (issue #331). isFlatRefusal's exemption is KEPT — a
	// refuseBuildParam entry carries its reason in the 403 the client reads,
	// which is a stronger record than a comment, and a flat refusal has no
	// value-dependent behaviour to exercise.
	for name, check := range buildParams {
		if isFlatRefusal(name) {
			continue
		}
		if check == nil {
			t.Errorf("build parameter %q has a nil check; it belongs in "+
				"unexaminedBuildParams with its abuse sentence", name)
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
				if !knownBuildParam(name) {
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
		{"a refused parameter, camel-cased", "CgroupParent=foo", "the engine's own cgroup namespace"},
		{"a refused parameter, upper-cased", "DEVICES=%5B%22%2Fdev%2Ffuse%22%5D", "no host device nodes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, eng, _ := startBuildProxy(t)
			refuse(t, sock, eng, buildURL(tc.query), "", tc.wantMsg)
		})
	}
}
