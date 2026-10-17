package policy

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// fsLoc is a place on a filesystem rather than a place in a path namespace:
// Dev is the mountinfo "major:minor", Rel the directory within that
// filesystem. Two spellings that reach the same bytes through different mounts
// (a bind, a distrobox /run/host/... copy of /home) have different paths and
// the same fsLoc, which is the only thing a string comparison cannot see.
type fsLoc struct{ Dev, Rel string }

// mountTable answers "where on its filesystem is this canonical path" from the
// host's mountinfo, which is what lets the protected-root refusals compare
// locations. Comparing (dev, inode) instead would miss both a grant inside a
// root reached by a subdirectory bind and a grant containing a root reached by
// a submount (bwrap's bind is recursive), because neither shares an inode with
// the root.
type mountTable struct {
	ms   []HostMount
	root int // index of the tree's root mount, -1 when the table is unusable
}

// newMountTable reads env.HostMounts. A read error is returned, and so is a
// non-empty table with no root entry: a real /proc/self/mountinfo always has
// one, so a table without it cannot be walked and answering "no overlap"
// would be a silent downgrade. Only a nil or empty table (a test fake that
// models no mount table; OSEnviron refuses to return an empty one) is unusable
// without being an error, and every alias question then answers no.
func newMountTable(env Environ) (*mountTable, error) {
	ms, err := env.HostMounts()
	if err != nil {
		return nil, err
	}
	t := &mountTable{ms: ms, root: -1}
	ids := make(map[int]bool, len(ms))
	for _, m := range ms {
		ids[m.ID] = true
	}
	for i, m := range ms {
		if m.Root != "" && m.Path == "/" && !ids[m.Parent] {
			t.root = i
		}
	}
	if len(ms) > 0 && t.root < 0 {
		return nil, errors.New("the table has no root entry (a mount with an empty root-within-filesystem, at /, whose parent is not in the table)")
	}
	return t, nil
}

// usable reports whether the table has a root mount to walk from. A nil table
// is unusable.
func (t *mountTable) usable() bool { return t != nil && t.root >= 0 }

// loc returns the filesystem location of the canonical, absolute path p.
//
// It walks from the root mount, at each step descending into the child mount
// whose mount point covers p. Of several such children it takes the SHALLOWEST,
// later line winning a tie: siblings /a and /a/b with one parent mean /a was
// mounted over /a/b, so /a/b is hidden and p reaches /a's filesystem. A mount
// stacked on another at one point is the other's child, so the walk reaches
// the top of the stack.
//
// p must exist or be a nonexistent tail under a canonical existing ancestor
// (canonExisting): no mount point can be inside the nonexistent part, so the
// answer for the ancestor plus the tail is exact.
func (t *mountTable) loc(p string) (fsLoc, bool) {
	if !t.usable() {
		return fsLoc{}, false
	}
	p = filepath.Clean(p)
	cur := t.root
	for range len(t.ms) {
		next := -1
		for i, m := range t.ms {
			if i == cur || m.Parent != t.ms[cur].ID || !covers(m.Path, p) {
				continue
			}
			if next < 0 || len(m.Path) <= len(t.ms[next].Path) {
				next = i
			}
		}
		if next < 0 {
			break
		}
		cur = next
	}
	m := t.ms[cur]
	rel := filepath.Clean(m.Root + "/" + strings.TrimPrefix(p, m.Path))
	return fsLoc{Dev: m.Dev, Rel: rel}, true
}

// locsUnder is loc(canon) plus the location of every mount whose mount point
// is at or inside canon: a bind of canon carries those submounts in, so what
// the grant reaches is each of them. Mounts hidden under another mount are
// included — a superset, which can only over-refuse. The result is sorted
// and free of duplicates, so what a caller reports does not depend on mount
// table order.
func (t *mountTable) locsUnder(canon string) []fsLoc {
	if !t.usable() {
		return nil
	}
	canon = filepath.Clean(canon)
	var out []fsLoc
	if l, ok := t.loc(canon); ok {
		out = append(out, l)
	}
	for _, m := range t.ms {
		if covers(canon, m.Path) {
			out = append(out, fsLoc{Dev: m.Dev, Rel: filepath.Clean(m.Root)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dev != out[j].Dev {
			return out[i].Dev < out[j].Dev
		}
		return out[i].Rel < out[j].Rel
	})
	return slices.Compact(out)
}

// aliasHit is one alias overlap: Grant and Root as the caller spelled them,
// the device they share, and the two filesystem directories that overlap.
type aliasHit struct{ Grant, Root, Dev, GrantRel, RootRel string }

// aliasOverlap reports whether grant and root reach overlapping places on one
// filesystem: some location under grant has the same device as some location
// under root, and one directory is an ancestor of, or equal to, the other.
// Both are canonicalised through their longest existing ancestor first, so a
// nonexistent grant or root is judged by where it would be created.
//
// It is the SECOND arm of a refusal and is only asked after the string
// comparison (covers) has said no; it answers false when the table is
// unusable, which is how a fake host without mount identity keeps today's
// result.
func (t *mountTable) aliasOverlap(env Environ, grant, root string) (aliasHit, bool) {
	if !t.usable() {
		return aliasHit{}, false
	}
	gs := t.locsUnder(canonExisting(env, grant))
	rs := t.locsUnder(canonExisting(env, root))
	for _, g := range gs {
		for _, r := range rs {
			if g.Dev == r.Dev && (covers(g.Rel, r.Rel) || covers(r.Rel, g.Rel)) {
				return aliasHit{Grant: grant, Root: root, Dev: g.Dev, GrantRel: g.Rel, RootRel: r.Rel}, true
			}
		}
	}
	return aliasHit{}, false
}

// aliasUnderNamePrefix is aliasOverlap for a NAME PREFIX such as
// "/tmp/snug-1000-": it reports whether grant reaches, through a mount of the
// same filesystem as prefix's parent directory, a directory strictly inside
// that parent whose first component starts with the prefix's final element.
// entry is that directory spelled under the parent as given.
func (t *mountTable) aliasUnderNamePrefix(env Environ, grant, prefix string) (entry string, h aliasHit, ok bool) {
	if !t.usable() {
		return "", aliasHit{}, false
	}
	prefix = filepath.Clean(prefix)
	parent, namePrefix := filepath.Dir(prefix), filepath.Base(prefix)
	p, found := t.loc(canonExisting(env, parent))
	if !found {
		return "", aliasHit{}, false
	}
	base := strings.TrimSuffix(p.Rel, "/") + "/"
	for _, g := range t.locsUnder(canonExisting(env, grant)) {
		if g.Dev != p.Dev {
			continue
		}
		rest, under := strings.CutPrefix(g.Rel, base)
		if !under {
			continue
		}
		first, _, _ := strings.Cut(rest, "/")
		if first == "" || !strings.HasPrefix(first, namePrefix) {
			continue
		}
		entry = filepath.Join(parent, first)
		return entry, aliasHit{Grant: grant, Root: entry, Dev: g.Dev, GrantRel: g.Rel, RootRel: base + first}, true
	}
	return "", aliasHit{}, false
}

// aliasNote is the sentence a refusal appends when the match was found through
// the mount table rather than by name.
func aliasNote(h aliasHit) string {
	return fmt.Sprintf("\n       %s is not under %s by name: it reaches it through a second mount of the same\n"+
		"       filesystem (device %s: %s overlaps %s).",
		VisibleText(h.Grant), VisibleText(h.Root), h.Dev, VisibleText(h.GrantRel), VisibleText(h.RootRel))
}

// mountTableUnreadable is the refusal for a mount table snug could not read,
// shared by every site that builds one.
func mountTableUnreadable(err error) error {
	return fmt.Errorf("cannot read this host's mount table (%s), so snug cannot tell whether a grant reaches its own state (configuration, runtime directory, engine store) through a second mount of it. snug reads /proc/self/mountinfo; check that /proc is mounted.", visibleErr(err))
}

// writableAliasOf returns the first writable bind of p, in sorted order of its
// guest path, whose host side reaches path through a second mount of the same
// filesystem (aliasOverlap). Callers run it after the lexical check
// (CheckEngineBinary, CheckEngineToolchainTree) has cleared, so a hit here is
// a grant the string comparison could not see. A mount table that cannot be
// read is an error, not a pass.
func (p *Policy) writableAliasOf(env Environ, path string) (Mount, aliasHit, bool, error) {
	mt, err := newMountTable(env)
	if err != nil {
		return Mount{}, aliasHit{}, false, mountTableUnreadable(err)
	}
	if !mt.usable() {
		return Mount{}, aliasHit{}, false, nil
	}
	guests := make([]string, 0, len(p.Mounts))
	for g := range p.Mounts {
		guests = append(guests, g)
	}
	sort.Strings(guests)
	for _, g := range guests {
		m := p.Mounts[g]
		if m.Kind != KindBind || m.Access != AccessRW {
			continue
		}
		if h, ok := mt.aliasOverlap(env, m.Host, path); ok {
			return m, h, true, nil
		}
	}
	return Mount{}, aliasHit{}, false, nil
}
