package policy

import (
	"path/filepath"
	"strings"
)

// EngineTargetGraft is the SINGLE producer of the target graft's destination
// and access. Three consumers read it - the --dir loop in BwrapFlags, G3's
// fourth disjunct, and the Tier C installer - so they cannot disagree about
// which directory the graft lands in or at what access.
//
// ok == false means NO GRAFT, never a refusal: nothing was requested, so
// nothing was silently downgraded. The two ways it is false are a target no
// KindBind grant exposes in HOST space (a divergent host:guest grant satisfies
// Validate's Guest-side target check and not this one - and such a target
// cannot be forwarded as a string either, engineforwardedpath.go's Host!=Guest
// clause, so no capability is lost), and a target whose base name is not a
// single path component. The second is the one that would produce a WRONG
// MOUNT rather than a refusal: filepath.Base("/") is "/", so the join collapses
// to EngineBindsDir itself and the graft would clone the host root onto the
// directory snug pre-creates for this - admitted by G1b, which permits anything
// under EngineDir. Refuse to produce instead.
func (p *Policy) EngineTargetGraft() (guest string, access Access, ok bool) {
	if p.Podman == PodmanOff {
		return "", AccessNone, false
	}
	t := filepath.Clean(p.Target)
	if !filepath.IsAbs(t) || t == "/" {
		return "", AccessNone, false
	}
	base := filepath.Base(t)
	if base == "/" || base == "." || base == ".." || strings.Contains(base, "/") {
		return "", AccessNone, false
	}
	switch {
	case p.HostPathVisible(t, true):
		return EngineBindsDir + "/" + base, AccessRW, true
	case p.HostPathVisible(t, false):
		return EngineBindsDir + "/" + base, AccessRO, true
	}
	return "", AccessNone, false
}

// EngineTargetForwarded reports the guest path the container proxy should
// forward source to, if source is an exact match (after filepath.Clean) for
// the installed target graft's Host at the requested access.
//
// Reads the INSTALLED graft rather than recomputing from p.Target: the answer
// is then "what snug actually cloned", so a policy Tier C never ran over
// forwards nothing at all. Exact match, never a prefix - a graft root plus a
// payload-supplied tail reopens #284 through the graft, because
// open_tree(OPEN_TREE_CLONE) pins the root inode and says nothing about names
// beneath it, and crun re-resolves the whole forwarded string at container
// start in a namespace this sandbox is not in. A client asking for a
// subdirectory falls through to CheckEngineBindSource and is refused; the
// answer is `-v .:/x` plus /x/<sub> inside the container.
func (p *Policy) EngineTargetForwarded(source string, needWrite bool) (string, bool) {
	guest, _, ok := p.EngineTargetGraft()
	if !ok {
		return "", false
	}
	g, installed := p.Grafts[guest]
	if !installed || g.Kind != KindGraft {
		return "", false
	}
	if g.Host != filepath.Clean(source) {
		return "", false
	}
	if needWrite && g.Access != AccessRW {
		return "", false
	}
	return g.Guest, true
}
