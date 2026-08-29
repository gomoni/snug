package dockerproxy

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// imagepull.go is POST /libpod/images/pull — the podman CLI's own pull route,
// and the reason `podman run` was refused while `podman build` worked (issue
// #459).
//
// WHY THIS ROUTE CAN BE READ WHEN libpod/containers/create CANNOT. Every
// parameter travels in the QUERY STRING; the body is empty. That is the same
// property that let /libpod/build share handleBuild with /build, and it is
// where the libpod/compat split actually bites: on routes carrying a JSON body.
// containers/create carries a SpecGenerator and stays refused.
//
// MEASURED, podman 6.0.2 CLI against a socket that logs the request. `podman
// pull alpine:3.20` posts exactly:
//
//	POST /v6.0.2/libpod/images/pull?alltags=false&arch=&authfile=&os=&
//	     policy=always&quiet=false&reference=alpine%3A3.20&variant=
//
// and `podman run --rm alpine:3.20 true` posts the same with `policy=missing`
// BEFORE it posts containers/create — even with the image already in the store,
// which is why refusing this route refuses `podman run` outright and why
// `--pull=never` is not a workaround.
//
// THE ABUSE SENTENCE. A hostile process inside the sandbox can use this to make
// the ENGINE read a filesystem tree or tarball of the payload's choosing and
// turn it into an image, because `reference` carries a containers/image
// TRANSPORT and not just a registry name. Measured, all four forwarded verbatim
// by the CLI:
//
//	reference=docker-archive%3A%2Ftmp%2Fx.tar
//	reference=oci-archive%3A%2Ftmp%2Fx.tar
//	reference=dir%3A%2Fetc
//	reference=docker%3A%2F%2Falpine%3A3.20
//
// The first three are an IMPORT, which the docker-compat path refuses by name
// (handleImageCreate's `fromSrc`), and they are refused here for the same
// reason: the bytes come from a path snug never resolved and never judged, in
// the engine's mount namespace rather than the sandbox's.
//
// PARAMETER SURFACE, and it is default-deny because it must stay complete as
// podman adds parameters: an unrecognised one is a 403 that names it. The
// allowlist below is the measured set — the eight the CLI always sends, plus
// tlsVerify (`--tls-verify`), retry and retrydelay (`--retry`,
// `--retry-delay`). A newer podman sending a tenth parameter refuses loudly
// rather than forwarding it unread, which is invariant 5 and the same trade
// issue #478's ruling makes for the engine version itself.
//
// pullMetadata is the half that needs no judgement: booleans and platform
// selectors that name nothing outside the registry request.
var pullMetadata = map[string]string{
	"alltags":    "pull every tag of the named repository (`--all-tags`)",
	"arch":       "the architecture to pull (`--arch`)",
	"os":         "the OS to pull (`--os`)",
	"variant":    "the architecture variant to pull (`--variant`)",
	"policy":     "when to consult the registry: always, missing, newer, never (`--pull`)",
	"quiet":      "suppress the progress stream (`--quiet`)",
	"tlsVerify":  "whether to verify the registry's TLS certificate (`--tls-verify`)",
	"retry":      "how many times to retry a failed pull (`--retry`)",
	"retrydelay": "how long to wait between retries (`--retry-delay`)",
}

// pullJudged is the other half: a parameter whose VALUE decides the verdict.
// Named separately from pullMetadata so that a parameter cannot be silently
// moved from judged to waved through — the two maps are disjoint and
// TestEveryPullParameterIsEitherJudgedOrMetadata asserts it.
var pullJudged = map[string]func(*Proxy, string) error{
	"reference": checkPullReference,
	"authfile":  checkPullAuthfile,
}

func (p *Proxy) handleImagePull(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		p.deny(w, "the query string of %s is malformed: %v", r.URL.Path, err)
		return
	}

	// A BODY on this route is refused, and the reason is honesty about what was
	// measured: the podman 6.0.2 CLI sends NO body here (Content-Length absent
	// in every capture), every parameter travels in the query string, and
	// whether podman's own handler would read a body on this route was NOT
	// measured — this host cannot run the engine tier. Forwarding bytes whose
	// effect is unknown is the thing libpodExamined exists to prevent, so the
	// entry is earned for the query string only.
	if r.ContentLength != 0 {
		p.deny(w, "images/pull with a request body is not permitted: the podman CLI sends "+
			"none, every pull parameter travels in the query string, and snug does not "+
			"forward bytes it has not read. Drop the body.")
		return
	}

	var unknown []string
	for name := range q {
		if _, ok := pullMetadata[name]; ok {
			continue
		}
		if check, ok := pullJudged[name]; ok {
			if err := check(p, q.Get(name)); err != nil {
				p.deny(w, "%v", err)
				return
			}
			continue
		}
		unknown = append(unknown, name)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		p.deny(w, "the pull parameter %s is one snug's filter has not read, so it refuses the "+
			"request rather than forwarding it unexamined. snug reads this route's whole "+
			"parameter set (%s) and judges `reference` and `authfile`; a parameter outside "+
			"that set may name a host path, a credential or an image source, and it cannot "+
			"be waved through on the strength of not being recognised. Drop it, or pull with "+
			"`docker pull` over the docker-compat endpoint.",
			quoteList(unknown), strings.Join(pullParameterNames(), ", "))
		return
	}
	if q.Get("reference") == "" {
		p.deny(w, "images/pull without a `reference` names no image to pull")
		return
	}
	p.forward(w, r, nil)
}

// pullTransports is every containers/image transport that reads its bytes from
// somewhere other than a registry. It is a list of the DANGEROUS spellings and
// therefore has to stay complete, which is the shape CLAUDE.md's invariant 2
// calls a smell — so it is not the defence. checkPullReference refuses on the
// SHAPE first (anything whose scheme is followed by a slash) and consults this
// list only to name the transport in the refusal. A transport podman adds
// tomorrow is caught by the shape rule if it names a path, and by the
// registry-reference rule otherwise.
var pullTransports = map[string]string{
	"docker-archive":     "a tarball written by `docker save`",
	"oci-archive":        "an OCI layout tarball",
	"oci":                "an OCI layout directory",
	"dir":                "a directory of blobs",
	"containers-storage": "another local image store",
	"docker-daemon":      "a docker daemon's own store",
	"tarball":            "a rootfs tarball",
}

// checkPullReference keeps `reference` to a REGISTRY reference.
//
// The refusal is on shape, not on a name: a reference whose first colon is
// followed by `/` is a path or a URL, and no legitimate registry reference has
// that form — a tag cannot begin with `/` and a digest is `@sha256:…`. So
// `dir:/etc`, `docker-archive:/tmp/x.tar` and `oci-archive:/tmp/x.tar` all
// refuse without the transport list being consulted for the verdict.
//
// `docker://` is the one scheme-with-slashes that is a registry pull, and it is
// what `podman pull docker://alpine:3.20` sends. It is allowed by naming it,
// which is the enumerate half of invariant 2's corollary rather than an
// exception to the rule above.
//
// A transport whose argument carries no slash (`containers-storage:alpine`)
// survives the shape test, so the list is consulted second — for the verdict
// this time, and it is complete for podman 6.0.2's own transport set.
func checkPullReference(_ *Proxy, ref string) error {
	if ref == "" {
		return nil // handleImagePull refuses an absent reference by itself
	}
	if !isASCII(ref) {
		return fmt.Errorf("the pull reference %q is not printable ASCII, so snug refuses it "+
			"rather than reasoning about how the engine will read it", ref)
	}
	scheme, rest, found := strings.Cut(ref, ":")
	if !found {
		return nil // a bare repository name, no tag: `podman pull alpine`
	}
	if scheme == "docker" && strings.HasPrefix(rest, "//") {
		return nil // the explicit registry spelling
	}
	if strings.HasPrefix(rest, "/") {
		return refusePullTransport(ref, scheme)
	}
	if _, ok := pullTransports[scheme]; ok {
		return refusePullTransport(ref, scheme)
	}
	return nil
}

func refusePullTransport(ref, scheme string) error {
	what := pullTransports[scheme]
	if what == "" {
		what = "something other than a registry"
	}
	return fmt.Errorf("pulling %q is not permitted: `%s:` names %s, so the image's bytes "+
		"would come from a path this sandbox never granted and snug never resolved — read "+
		"by the ENGINE, in the engine's mount namespace, not by the payload in the "+
		"sandbox's. That is an IMPORT wearing a pull's spelling, and the docker-compat path "+
		"refuses it by name too (`images/create?fromSrc=`). Pull from a registry instead: "+
		"`podman pull <registry>/<repo>:<tag>`, or build the image with `podman build`, "+
		"which reads its context through this proxy where it can be judged.",
		ref, scheme, what)
}

// checkPullAuthfile refuses a non-empty `authfile`, and the measurement is why
// it is judged rather than metadata: `podman pull --authfile /etc/passwd` sends
// `authfile=%2Fetc%2Fpasswd` to the SERVER, so the path is opened by the engine
// and not by the client.
//
// snug already answers the credentials question, in the direction that keeps
// issue #142's regression closed: REGISTRY_AUTH_FILE names snug's own generated
// auth.json, so a pull authenticates as nobody and the host's registry
// credentials stay unreachable. An authfile parameter is a request to replace
// that answer with a path of the payload's choosing.
func checkPullAuthfile(_ *Proxy, path string) error {
	if path == "" {
		return nil // what the CLI always sends
	}
	return fmt.Errorf("the pull parameter `authfile=%q` is not permitted: the path is read by "+
		"the ENGINE, not by your client, and this sandbox's registry credentials are snug's "+
		"own generated auth.json (REGISTRY_AUTH_FILE) — deliberately empty, so a pull "+
		"authenticates as nobody and the host's credentials stay out of reach. Pull a public "+
		"image, or ask the sandbox's author for a profile that grants a registry identity.",
		path)
}

func pullParameterNames() []string {
	names := make([]string, 0, len(pullMetadata)+len(pullJudged))
	for n := range pullMetadata {
		names = append(names, n)
	}
	for n := range pullJudged {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func quoteList(names []string) string {
	q := make([]string, 0, len(names))
	for _, n := range names {
		q = append(q, fmt.Sprintf("%q", n))
	}
	return strings.Join(q, ", ")
}
