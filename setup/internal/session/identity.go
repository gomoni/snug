package session

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/texts"
)

// Candidate is one identity of a kind found on this host. Key is the exact
// value Pick takes for it; Label is how it is listed.
type Candidate struct {
	Key   string
	Label string
	names []string
}

// Candidates lists the host's identities of kind ("ssh", "github" or
// "git"), in the order the host reported them. The order never changes
// during a session.
func (s *Session) Candidates(kind string) []Candidate {
	var out []Candidate
	switch kind {
	case "ssh":
		for _, k := range s.keys {
			label := safe.Inline(k.Stem) + "  " + dash(safe.Inline(k.Comment))
			if k.InAgent {
				label += "  [held by the agent]"
			}
			out = append(out, Candidate{Key: k.Stem, Label: label + "  " + k.Fingerprint, names: []string{k.Stem, k.Stem + ".pub", k.Comment}})
		}
	case "github":
		for _, a := range s.gh {
			key := a.User
			if slices.ContainsFunc(s.gh, func(b hostfacts.GHAccount) bool { return b.User == a.User && b.Host != a.Host }) {
				key = a.Host + "/" + a.User
			}
			label := safe.Inline(a.Host + "/" + a.User)
			if a.Active {
				label += "  (active)"
			}
			out = append(out, Candidate{Key: key, Label: label, names: []string{a.User, a.Host + "/" + a.User}})
		}
	case "git":
		for _, a := range s.authors {
			out = append(out, Candidate{Key: a.Email, Label: safe.Inline(a.String()), names: []string{a.String(), a.Name, a.Email}})
		}
	}
	return out
}

// bestMatch returns the index of the candidate the account word most likely
// meant, or -1: first an exact match against any name, then a
// case-insensitive substring match. It only ever says whether the word names
// something on this host; it never picks.
func bestMatch(account string, cands []Candidate) int {
	account = strings.TrimSpace(account)
	if account == "" {
		return -1
	}
	words := []string{account}
	if b := strings.TrimSuffix(filepath.Base(account), ".pub"); b != account && b != "." && b != "/" {
		words = append(words, b)
	}
	for _, w := range words {
		for i, c := range cands {
			if slices.Contains(c.names, w) {
				return i
			}
		}
	}
	for _, w := range words {
		lw := strings.ToLower(w)
		for i, c := range cands {
			for _, n := range c.names {
				if n != "" && strings.Contains(strings.ToLower(n), lw) {
					return i
				}
			}
		}
	}
	return -1
}

// slotFull reports whether the draft already pins an identity of this kind,
// and its name.
func (s *Session) slotFull(kind string) (string, bool) {
	switch {
	case kind == "ssh" && s.d.SSH != nil:
		return s.d.SSH.Stem, true
	case kind == "github" && s.d.GH != nil:
		return s.d.GH.User, true
	case kind == "git" && s.d.Git != nil:
		return s.d.Git.Email, true
	}
	return "", false
}

// pinnedNames are the spellings that name the identity the draft pins.
func (s *Session) pinnedNames(kind string) []string {
	switch kind {
	case "ssh":
		for _, k := range s.keys {
			if k.Stem == s.d.SSH.Stem {
				return []string{k.Stem, k.Stem + ".pub", k.Comment}
			}
		}
		return []string{s.d.SSH.Stem}
	case "github":
		return []string{s.d.GH.User, s.d.GH.Host + "/" + s.d.GH.User}
	}
	return []string{s.d.Git.Email, s.d.Git.Name}
}

// askIdentity opens the question for a select_identity. It never pins: even a
// host with exactly one candidate gets the question, because an identity is
// the human's to name. A kind the draft already pins gets the second-profile
// question instead, unless the request names the pinned identity itself.
func (s *Session) askIdentity(kind, hint, said string, at int) []Line {
	if p, ok := s.includedPin(kind); ok {
		return []Line{info("your profile %q, which the draft includes, already pins %s. A profile pins one %s; another account needs a second profile. Nothing changed.", p.Name, pins(p.Identity), kindName(kind))}
	}
	cands := s.Candidates(kind)
	if len(cands) == 0 {
		switch kind {
		case "ssh":
			return []Line{info("no ssh public keys (~/.ssh/*.pub) were found on this host, so there is nothing to pin. Nothing written.")}
		case "github":
			return []Line{info("no GitHub logins are known to gh on this host (gh auth login, or gh is not installed), so there is nothing to pin. Nothing written.")}
		}
		return []Line{info("no global git author (git config --global user.name and user.email) was found, so there is nothing to pin. Nothing written.")}
	}
	for _, p := range s.pending {
		if (p.Kind == Identity || p.Kind == SecondProfile) && p.kind == kind {
			return []Line{info("the %s question is already open as #%d.", kindName(kind), p.N)}
		}
	}
	if cur, full := s.slotFull(kind); full {
		if hint == "" || slices.ContainsFunc(s.pinnedNames(kind), func(n string) bool { return n != "" && strings.EqualFold(n, hint) }) {
			return []Line{info("the draft already pins the %s %q; nothing changed.", kindName(kind), safe.Inline(cur))}
		}
		e, _ := texts.Note("identity_one")
		p := s.open(Pending{Kind: SecondProfile, kind: kind, hint: hint, said: said, at: at})
		return []Line{info("%s", e), p.Line()}
	}
	p := s.open(Pending{Kind: Identity, kind: kind, hint: hint, said: said, at: at})
	return []Line{p.Line()}
}

// Pick answers the open identity question of kind with the candidate whose
// Key is value, or with "none", which pins nothing. Any other value is
// refused with the list and the question stays open; nothing is matched
// loosely.
func (s *Session) Pick(ctx context.Context, kind, value string) []Line {
	i := slices.IndexFunc(s.pending, func(p Pending) bool { return p.Kind == Identity && p.kind == kind })
	if i < 0 {
		return []Line{info("there is no open %s question; ask for one first (for example \"use my %s\"). Nothing written.", kind, kindName(kind))}
	}
	p := s.pending[i]
	if value == "none" {
		before := s.snapshot()
		s.close(p.N)
		s.commit(before, fmt.Sprintf("the answer to #%d", p.N))
		return []Line{info("no %s pinned.", kindName(kind))}
	}
	cands := s.Candidates(kind)
	j := slices.IndexFunc(cands, func(c Candidate) bool { return c.Key == value })
	if j < 0 {
		keys := make([]string, len(cands))
		for k, c := range cands {
			keys[k] = safe.Inline(c.Key)
		}
		return []Line{info("%q is not a %s on this host: one of %s, or none. Nothing written; #%d stays open.",
			safe.Inline(value), kindName(kind), strings.Join(keys, ", "), p.N)}
	}
	if cur, full := s.slotFull(kind); full {
		return []Line{info("the draft already pins the %s %q; nothing written.", kindName(kind), safe.Inline(cur))}
	}
	before := s.snapshot()
	s.close(p.N)
	var out []Line
	switch kind {
	case "ssh":
		out = s.pinSSH(s.keys[j], p)
	case "github":
		out = s.pinGitHub(s.gh[j], p)
	case "git":
		a := s.authors[j]
		s.d.SetGit(a.Name, a.Email)
		s.d.RecordIdentity("git", nonEmpty(a.String(), a.Name, a.Email), p.said, p.at)
		out = []Line{info("pinned git author %s.", safe.Inline(a.String()))}
	}
	out = append(out, s.checkIdentity(ctx)...)
	s.commit(before, fmt.Sprintf("the answer to #%d", p.N))
	return out
}

// netIncluded reports whether the draft reaches the internet.
func (s *Session) netIncluded() bool {
	return slices.ContainsFunc(s.d.Includes(), func(n string) bool { return slices.Contains(draft.Closure(n), "@net") })
}

func (s *Session) pinSSH(k hostfacts.SSHKey, p Pending) []Line {
	s.d.SetSSH(k.Path)
	s.d.RecordIdentity("ssh", nonEmpty(k.Stem, k.Stem+".pub", k.Comment), p.said, p.at)
	stem := safe.Inline(k.Stem)
	out := []Line{info("pinned ssh key %s (the public half; the private key stays in your agent).", stem)}
	if !k.InAgent {
		out = append(out, warn("warning: the host ssh-agent does not hold this key. snug will refuse to start until `ssh-add` has loaded it."))
	}
	if s.netIncluded() {
		out = append(out, info("(@net is in the draft, so git can push over ssh.)"))
	} else {
		out = append(out, info("Pushing needs @net: say \"needs internet\" to add it."))
	}
	return out
}

func (s *Session) pinGitHub(a hostfacts.GHAccount, p Pending) []Line {
	s.d.SetGH(a.Host, a.User)
	s.d.RecordIdentity("github", nonEmpty(a.User, a.Host+"/"+a.User), p.said, p.at)
	out := []Line{info("pinned GitHub login %s.", safe.Inline(a.Host+"/"+a.User))}
	if path, err := s.cfg.LookPath("gh"); err == nil {
		if !strings.HasPrefix(path, "/usr/") && !strings.HasPrefix(path, "/opt/") {
			out = append(out, info("note: gh is at %s, outside /usr, so the sandbox will not have it. Say \"stage %s as gh\" to add it.", safe.Inline(path), safe.Inline(path)))
		}
	} else {
		out = append(out, info("note: gh is not installed on this host; the sandbox needs a gh binary for the pinned login to be of use."))
	}
	if s.d.SSH == nil && len(s.keys) > 0 {
		out = append(out, info("no ssh key is pinned, so git over ssh has none; ask for one (\"use my ssh key for %s\") if it should push.", safe.Inline(a.User)))
	}
	if s.d.Git == nil && len(s.authors) > 0 {
		out = append(out, info("no git author is pinned; ask for one (\"use my git author\") to pin identity.git too."))
	}
	return out
}

func nonEmpty(xs ...string) []string {
	return slices.DeleteFunc(xs, func(s string) bool { return s == "" })
}

// checkIdentity compares the pinned ssh key with the pinned GitHub login's
// keys on GitHub. It is the check snug itself cannot make: it needs the
// network.
func (s *Session) checkIdentity(ctx context.Context) []Line {
	if s.d.GH == nil || s.d.SSH == nil {
		return nil
	}
	var key *hostfacts.SSHKey
	for i := range s.keys {
		if s.keys[i].Stem == s.d.SSH.Stem {
			key = &s.keys[i]
		}
	}
	if key == nil {
		return nil
	}
	gh := s.d.GH
	stem, user := safe.Inline(key.Stem), safe.Inline(gh.User)
	if s.cfg.Offline {
		return []Line{info("offline: not checking that %s belongs to %s on GitHub.", stem, safe.Inline(gh.Host+"/"+gh.User))}
	}
	if !s.ghInstalled {
		return []Line{warn("warning: gh is not installed, so whether %s belongs to %s on GitHub was not checked.", stem, user)}
	}
	res, err := hostfacts.CheckKeyOwnership(ctx, s.cfg.Run, gh.Host, gh.User, *key)
	switch {
	case err != nil:
		return []Line{warn("warning: could not check whether %s belongs to %s on GitHub: %s\n  (this is not fatal; --offline skips the check)", stem, user, safe.Inline(err.Error()))}
	case res.Match:
		return []Line{info("checked: GitHub lists %s (%s) among %s's keys. The ssh key and the gh login are one account.", stem, safe.Inline(res.Detail), user)}
	}
	return []Line{warn("!!! SPLIT IDENTITY !!!\n"+
		"!!! GitHub account %s does not list the ssh key %s (%s).\n"+
		"!!! git over ssh would act as whoever owns that key, and gh as %s: the sandbox would push as one and comment as the other.\n"+
		"!!! Pin a key GitHub lists for %s, or pin a different login (/undo takes this pick back).",
		user, stem, safe.Inline(res.Detail), user, user)}
}

// acceptSecond saves the draft and starts an empty one, where the identity
// question the second profile was for opens. A save that does not complete
// leaves the question open.
func (s *Session) acceptSecond(ctx context.Context, p Pending) []Line {
	if s.d.Name == "" {
		return []Line{info("this profile has no name yet: /save NAME first, then /accept %d.", p.N)}
	}
	ok, out := s.Save(ctx, "")
	if !ok {
		return append(out, info("the second profile was not started; #%d stays open.", p.N))
	}
	for _, q := range s.pending {
		if q.N != p.N {
			out = append(out, info("#%d is dropped: it was about the profile just saved.", q.N))
		}
	}
	s.pending = nil
	s.undo = nil
	s.d = draft.New(s.cfg.Host)
	s.lastSaved = ""
	out = append(out, info("started a new, empty profile."))
	return append(out, s.askIdentity(p.kind, p.hint, p.said, p.at)...)
}
