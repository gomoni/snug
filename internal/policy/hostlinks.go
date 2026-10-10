package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"syscall"
)

// maxAuthorableHops bounds authorableLinks. It matches the kernel's own limit
// on symlinks followed in one resolution (see maxGuestLinkHops for the
// measurement), so a chain the kernel would refuse is refused here too.
const maxAuthorableHops = 40

// authoredLink is a host symlink on a granted path that a sandbox could have
// written: At is the link's own path, Text its unresolved text, Owner its uid.
// OwnerKnown is false when the host gave no owner to read, and Owner is then 0
// without meaning root.
//
// Parent is the directory the link sits in, as it is now. A link keeps its
// owner when it is renamed, so a root-owned link moved into a directory a
// sandbox can write is still root-owned; the directory is the other half of
// whether root put it there.
type authoredLink struct {
	At, Text   string
	Owner      uint32
	OwnerKnown bool

	ParentOwner uint32
	ParentMode  fs.FileMode
	ParentKnown bool
}

// trustedParent reports whether a directory is one only root can change: owned
// by uid 0 with no group or other write. The sticky bit does not help, it
// only stops deleting someone else's entry and not renaming one's own into
// place.
func trustedParent(owner uint32, mode fs.FileMode) bool {
	return owner == 0 && mode.Perm()&0o022 == 0
}

// authorableLinks walks p component by component from "/" on the host, the way
// the kernel resolves it, and returns where it ended up plus every symlink on
// the way that a sandbox could have planted. EVERY hop is judged, including the
// final component and the links reached through another link's text: a
// root-owned /opt/x -> /home/u/y followed by a user-owned y -> / is only caught
// because the second hop is looked at too.
//
// A link is authorable unless it is owned by uid 0, the directory it sits in is
// owned by uid 0 with no group or other write permission, and snug itself is
// not uid 0. A sandbox can create links owned by the invoking uid or by a
// subuid, never by uid 0, but rename(2) keeps the owner: a root-owned link
// sitting in a directory the invoking user (or a subuid) can write could have
// been moved there from somewhere root wrote it, so ownership alone does not
// say who chose its place. Root ownership of both is the trace of "a human or
// a package manager wrote this" that survives past targets and deleted
// profiles. Under uid 0 no link is trusted, because a root-run snug cannot
// tell its own links from planted ones. A Sys() that is not a *syscall.Stat_t,
// on the link or on its parent, carries no owner and is treated as authorable.
//
// A component that does not exist is plain (fs.ErrNotExist), so a grant or an
// identity key that is merely absent stays legal. Any other Lstat or Readlink
// error is returned: the caller cannot say who wrote the path and must refuse.
func authorableLinks(h HostLinks, uid int, p string) (resolved string, links []authoredLink, err error) {
	rest := strings.Split(p, "/")
	resolved = "/"
	hops := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		cand := path.Join(resolved, c)
		fi, err := h.Lstat(cand)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				resolved = cand
				continue
			}
			return "", nil, err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = cand
			continue
		}
		hops++
		if hops > maxAuthorableHops {
			return "", nil, &fs.PathError{Op: "readlink", Path: p, Err: syscall.ELOOP}
		}
		text, err := h.Readlink(cand)
		if err != nil {
			return "", nil, err
		}
		l := authoredLink{At: cand, Text: text}
		authorable := true
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			l.Owner, l.OwnerKnown = st.Uid, true
			if l.Owner == 0 && uid != 0 {
				pfi, err := h.Lstat(resolved)
				if err != nil {
					return "", nil, err
				}
				if pst, ok := pfi.Sys().(*syscall.Stat_t); ok {
					l.ParentOwner, l.ParentMode, l.ParentKnown = pst.Uid, pfi.Mode(), true
					authorable = !trustedParent(l.ParentOwner, l.ParentMode)
				}
			}
		}
		if authorable {
			links = append(links, l)
		}
		if strings.HasPrefix(text, "/") {
			resolved = "/"
		}
		rest = append(strings.Split(text, "/"), rest...)
	}
	return resolved, links, nil
}

// ownerPhrase is the parenthesis in a refusal naming an authorable link.
func ownerPhrase(l authoredLink, uid int) string {
	if uid == 0 {
		return "snug is running as root, so no link on this path is trusted"
	}
	if !l.OwnerKnown {
		return "whose owner snug could not read, so it is not trusted"
	}
	if l.Owner == 0 {
		if !l.ParentKnown {
			return "owned by root, but snug could not read who owns the directory it is in, so it is not trusted"
		}
		if l.ParentOwner != 0 {
			if int(l.ParentOwner) == uid {
				return fmt.Sprintf("owned by root but in a directory uid %d owns, so it could have been moved there", uid)
			}
			return fmt.Sprintf("owned by root but in a directory owned by uid %d, not root", l.ParentOwner)
		}
		return fmt.Sprintf("owned by root but in a directory that group or other users can write (mode %04o), so it could have been moved there",
			l.ParentMode.Perm())
	}
	return fmt.Sprintf("owned by uid %d, not root", l.Owner)
}

// divertedGrant is a bind grant whose path went through an authorable link,
// held until the fold is done because whether another grant covers the
// destination cannot be known while the fold is still running.
type divertedGrant struct {
	profile   ProfileName
	key       string
	requested string
	real      string
	link      authoredLink
	access    Access
	uid       int
}

// literalGrant is a bind grant that resolved through no authorable link.
type literalGrant struct {
	real   string
	access Access
}

// refuseAuthorableRedirects refuses a diverted grant unless some literal grant
// already exposes its destination with at least its access. Only literal grants
// cover, so two diverted grants cannot vouch for each other, and a tmpfs never
// covers because it exposes nothing of the host. The failure reported is the
// first by (requested, profile), so the verdict does not depend on fold order.
func refuseAuthorableRedirects(diverted []divertedGrant, literal []literalGrant) error {
	var failed []divertedGrant
next:
	for _, d := range diverted {
		for _, l := range literal {
			if _, ok := under(l.real, d.real); ok && l.access >= d.access {
				continue next
			}
		}
		failed = append(failed, d)
	}
	if len(failed) == 0 {
		return nil
	}
	sort.Slice(failed, func(i, j int) bool {
		if failed[i].requested != failed[j].requested {
			return failed[i].requested < failed[j].requested
		}
		return failed[i].profile < failed[j].profile
	})
	d := failed[0]
	return fmt.Errorf("profile %q grants %s, which resolves through the link %s -> %s (%s), "+
		"so a sandbox run that once had write access there could have planted it; "+
		"snug will not follow it to %s, which no other grant in this run exposes as %s or wider. "+
		"If you made that link, grant the destination yourself (%s = [\"%s\"], or \"%s:%s\" to keep the path); "+
		"if you did not, delete the link and treat everything near it as sandbox-written.",
		string(d.profile), VisibleText(d.requested), VisibleText(d.link.At), VisibleText(d.link.Text),
		ownerPhrase(d.link, d.uid), VisibleText(d.real), d.key,
		d.key, VisibleText(d.real), VisibleText(d.real), VisibleText(d.requested))
}
