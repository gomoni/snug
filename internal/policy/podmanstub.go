package policy

import (
	"path/filepath"
	"strings"
)

// HasStagedBin reports whether anything was staged in StagedBinDir, and is what
// decides whether that directory joins PATH at all.
//
// Strictly UNDER the directory, never the directory itself: a mount AT
// StagedBinDir would be a grant of the whole directory rather than of one
// executable in it, which is the shape this rule exists to refuse.
//
// Stays on p.Mounts and is NOT lifted onto a View (issue #55). It decides
// whether StagedBinDir joins the PAYLOAD's PATH, and a graft cannot affect
// that — the payload's mount namespace never sees a graft at all, and G1
// refuses any graft that covers StagedBinDir in the engine's namespace either.
// Do not "fix" this to consult p.Grafts or EngineView(); there is no question
// here for the engine's view to answer.
func (p *Policy) HasStagedBin() bool {
	for guest := range p.Mounts {
		if strings.HasPrefix(guest, StagedBinDir+"/") {
			return true
		}
	}
	return false
}

// PodmanStubGuest is the podman stub: a link to WrapperGuest, staged when
// podman on the host resolves to a host-escape helper and a podman profile is
// selected. internal/wrapper.IsPodmanStub is what turns snug's image into the
// stub when it runs under this name.
const PodmanStubGuest = StagedBinDir + "/podman"

// PodmanStubClients is the order the stub tries clients in, every PATH
// directory for the first before any for the second. docker first: the
// container proxy speaks the compat API it was written for, and a foreground
// `docker run` works there. podman-remote is podman's own CLI, so the stub
// forwards to it verbatim.
var PodmanStubClients = []string{"docker", "podman-remote"}

// PodmanStubClient is the client the stub will exec in this sandbox, judged
// from outside for --dry-run: the first of PodmanStubClients that the
// payload's PATH, minus StagedBinDir and relative entries as the stub skips
// them, reaches as an executable regular file. It follows guest and host links
// through walkLinks, so it is the kernel's answer rather than a lexical one.
// name is "" when there is none, which is the stub refusing every command.
//
// writable is the first PATH directory the stub searches before reaching that
// answer that the payload can write a command into (IsShadowSlot). When it is
// set the answer is the payload's to change: a `docker` dropped there is what
// the stub execs, whatever is on disk now.
func (p *Policy) PodmanStubClient(host HostLinks) (name, guest, writable string) {
	path, _ := p.EnvValue("PATH")
	v := p.SandboxView()
	for _, name := range PodmanStubClients {
		for _, dir := range filepath.SplitList(path) {
			if !filepath.IsAbs(dir) || filepath.Clean(dir) == StagedBinDir {
				continue
			}
			if writable == "" && v.IsShadowSlot(host, dir) {
				writable = dir
			}
			g := filepath.Join(dir, name)
			_, _, _, end, hostAt := v.walkLinks(host, g)
			if end != walkLanded || hostAt == "" {
				continue
			}
			if fi, err := host.Lstat(hostAt); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				return name, g, writable
			}
		}
	}
	return "", "", writable
}
