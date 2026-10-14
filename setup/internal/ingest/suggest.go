package ingest

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/hostfacts"
)

// Reason is a value with the words that say where it came from.
type Reason struct {
	Value string
	Why   string
}

// IdentityPick is the identity the facts point at, field by field, each with
// its why. It is computed and never applied: the human answers the identity
// questions, and these are what those questions put first.
type IdentityPick struct {
	// Remote is the remote the pick was made for.
	Remote Remote
	// Profile is one of the human's own profiles that already pins this
	// identity, "" when none or when two do (Conflict).
	Profile  Reason
	Conflict []string
	SSH      Reason // a key stem
	Signing  Reason // a key stem
	GH       Reason // a gh login
	// Author is the commit author to pin; Value is the email.
	Author Reason
	// Name goes with Author.Value.
	AuthorName string
}

// SuggestInput is everything Suggest weighs. Every field comes from the human's
// own host except Repo, which is the target's and is therefore only ever
// compared byte for byte to the host's.
type SuggestInput struct {
	Repo     *RepoFacts
	SSH      SSHFacts
	Keys     []hostfacts.SSHKey
	Profiles []Profile
	Authors  []hostfacts.GitAuthor // global git author
	GH       []hostfacts.GHAccount
	// GitSigningKey is the global git config's user.signingkey: a path to a
	// .pub file, a key literal, or "".
	GitSigningKey string
}

// Suggest computes the identity pick. It is pure: no filesystem, no command.
//
// Abuse: a hostile repository chooses its remote url and its author lines, so
// it can steer this toward any one of the human's own keys, accounts or
// profiles, or away from the right one, and make a lie look like evidence
// ("193 of 200 commits"). Its signatures steer nothing unless they verify, and
// one that verifies under the human's key was made by that key's holder. The
// steering is bounded by what Suggest can return: only values that exist among
// the human's own keys, gh logins, profiles and git authors, matched byte for
// byte, never a value taken from the repo; and by what happens next: the pick
// is shown with its reason on the opening card, and nothing is pinned until the
// human answers that card or an identity question.
func Suggest(in SuggestInput) *IdentityPick {
	if in.Repo == nil {
		return nil
	}
	r, ok := pickRemote(in.Repo.Remotes)
	if !ok {
		return nil
	}
	p := &IdentityPick{Remote: r}
	dom, total := dominant(in.Repo)

	for _, pr := range in.Profiles {
		id := pr.Identity
		if !id.Pins() {
			continue
		}
		host := id.SSHHost
		if host == "" {
			host = "github.com"
		}
		if strings.ToLower(host) != r.Host || dom.Email == "" || id.Email != dom.Email {
			continue
		}
		p.Conflict = append(p.Conflict, pr.Name)
	}
	if len(p.Conflict) == 1 {
		p.Profile = Reason{p.Conflict[0], "it pins " + r.Host + " and the author of " + fmt.Sprint(dom.Commits) + " of the last " + fmt.Sprint(total) + " commits"}
		p.Conflict = nil
	} else if len(p.Conflict) == 0 {
		p.Conflict = nil
	}

	have := func(stem string) bool {
		return slices.ContainsFunc(in.Keys, func(k hostfacts.SSHKey) bool { return k.Stem == stem })
	}
	switch stems := StemsFor(in.SSH.Hosts, r.Host); {
	case len(stems) > 0 && have(stems[0]):
		p.SSH = Reason{stems[0], "~/.ssh/config: Host " + r.Host}
	case profileKey(in.Profiles, p.Profile.Value, have) != "":
		p.SSH = Reason{profileKey(in.Profiles, p.Profile.Value, have), "your profile " + p.Profile.Value}
	default:
		for _, k := range in.Keys {
			if strings.Contains(strings.ToLower(k.Comment), r.Host) {
				p.SSH = Reason{k.Stem, "its comment names " + r.Host}
				break
			}
		}
	}

	// A signing key: the key most of the dominant author's ssh-signed commits
	// were made with, found among the human's own .pub files by fingerprint.
	// Only a signature that verified over its commit counts: an unverified one
	// is a header the repository wrote, naming a public key anyone can copy.
	byFP := func(fp string) string {
		for _, k := range in.Keys {
			if k.Fingerprint == fp {
				return k.Stem
			}
		}
		return ""
	}
	n := map[string]int{}
	for _, s := range in.Repo.Signers {
		if s.Format == "ssh" && s.Verified && s.Email == dom.Email && byFP(s.Fingerprint) != "" {
			n[byFP(s.Fingerprint)] += s.Commits
		}
	}
	best := ""
	for stem, c := range n {
		if best == "" || c > n[best] || c == n[best] && stem < best {
			best = stem
		}
	}
	switch {
	case best != "":
		p.Signing = Reason{best, fmt.Sprintf("%d of the last %d commits carry an ssh signature that verifies with it", n[best], in.Repo.Sampled)}
	case stemOfConfigKey(in.GitSigningKey, in.Keys) != "":
		p.Signing = Reason{stemOfConfigKey(in.GitSigningKey, in.Keys), "your git config user.signingkey"}
	default:
		for _, fp := range in.SSH.Signers[dom.Email] {
			if s := byFP(fp); s != "" && dom.Email != "" {
				p.Signing = Reason{s, "~/.config/git allowed_signers lists it for " + dom.Email}
				break
			}
		}
	}

	// The author: the commits' own email, when it is also someone the human's
	// host knows by that exact email. The name shown beside it is the host's
	// spelling, never the commits': a project writes its own author names.
	known := func(email string) (why, name string) {
		for _, a := range in.Authors {
			if a.Email == email {
				return "your global git author", a.Name
			}
		}
		for _, pr := range in.Profiles {
			if pr.Identity.Email == email {
				return "your profile " + pr.Name, pr.Identity.GitName
			}
		}
		if _, ok := in.SSH.Signers[email]; ok {
			return "an allowed_signers principal", ""
		}
		return "", ""
	}
	if why, name := known(dom.Email); dom.Email != "" && why != "" {
		p.Author = Reason{dom.Email, fmt.Sprintf("%d of the last %d commits, and %s", dom.Commits, total, why)}
		p.AuthorName = name
	} else if len(in.Authors) > 0 {
		p.Author = Reason{in.Authors[0].Email, "your global git author"}
		p.AuthorName = in.Authors[0].Name
	}

	// The gh login.
	switch {
	case p.Profile.Value != "" && profileGH(in.Profiles, p.Profile.Value) != "":
		p.GH = Reason{profileGH(in.Profiles, p.Profile.Value), "your profile " + p.Profile.Value}
	default:
		for _, a := range in.GH {
			if a.Host == r.Host && r.Owner != "" && a.User == r.Owner {
				p.GH = Reason{a.User, "the owner in the remote url"}
			}
		}
		if p.GH.Value == "" {
			var active []hostfacts.GHAccount
			for _, a := range in.GH {
				if a.Active && a.Host == r.Host {
					active = append(active, a)
				}
			}
			if len(active) == 1 {
				p.GH = Reason{active[0].User, "your active gh login for " + r.Host}
			}
		}
	}
	return p
}

func pickRemote(rs []Remote) (Remote, bool) {
	for _, r := range rs {
		if r.Name == "origin" && r.Host != "" {
			return r, true
		}
	}
	for _, r := range rs {
		if r.Host != "" {
			return r, true
		}
	}
	return Remote{}, false
}

func dominant(r *RepoFacts) (Person, int) {
	total := 0
	for _, a := range r.Authors {
		total += a.Commits
	}
	if len(r.Authors) == 0 {
		return Person{}, 0
	}
	return r.Authors[0], total
}

func profileKey(ps []Profile, name string, have func(string) bool) string {
	for _, p := range ps {
		if p.Name == name && p.Identity.SSHKey != "" {
			if s := stemOfPath(p.Identity.SSHKey); have(s) {
				return s
			}
		}
	}
	return ""
}

func profileGH(ps []Profile, name string) string {
	for _, p := range ps {
		if p.Name == name {
			return p.Identity.GHUser
		}
	}
	return ""
}

func stemOfPath(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, ".pub")
}

// stemOfConfigKey maps git's user.signingkey to the stem of one of the
// human's keys: a path to a .pub (by its base name), or a literal key whose
// blob is one of theirs ("key::ssh-ed25519 AAAA..." or the bare line).
func stemOfConfigKey(v string, keys []hostfacts.SSHKey) string {
	v = strings.TrimSpace(strings.TrimPrefix(v, "key::"))
	if v == "" {
		return ""
	}
	if f := strings.Fields(v); len(f) >= 2 && strings.HasPrefix(f[0], "ssh-") {
		for _, k := range keys {
			if k.Blob == f[1] {
				return k.Stem
			}
		}
		return ""
	}
	s := stemOfPath(v)
	for _, k := range keys {
		if k.Stem == s {
			return s
		}
	}
	return ""
}
