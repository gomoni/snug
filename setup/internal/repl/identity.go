package repl

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/texts"
)

// candidate is one detected identity of a kind. names are the strings the
// model's account word is matched against.
type candidate struct {
	label string
	names []string
}

// bestMatch returns the index of the candidate the account word most likely
// meant, or -1: first an exact match against any name, then a
// case-insensitive substring match. The result is only ever a DEFAULT for the
// question put to the human, never a decision.
func bestMatch(account string, cands []candidate) int {
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

// pick lists EVERY candidate and asks the human to choose, even when there is
// exactly one. def is the default (-1 for none, which writes nothing). The
// returned index is -1 when the human declined, typed nonsense three times, or
// input ended.
func (r *REPL) pick(title string, cands []candidate, def int) int {
	r.say("%s", title)
	for i, c := range cands {
		mark := " "
		if i == def {
			mark = "*"
		}
		r.say(" %s %d) %s", mark, i+1, c.label)
	}
	defText := "none"
	if def >= 0 {
		defText = strconv.Itoa(def + 1)
	}
	for try := 0; try < 3; try++ {
		s, ok := r.prompt(fmt.Sprintf("choose 1-%d, or 'none' [default %s]: ", len(cands), defText))
		if !ok {
			r.say("no input; nothing written.")
			return -1
		}
		switch strings.ToLower(s) {
		case "":
			return def
		case "n", "no", "none", "skip", "0":
			return -1
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(cands) {
			return n - 1
		}
		r.say("not a choice: %q", s)
	}
	return -1
}

func (r *REPL) sshCands() []candidate {
	out := make([]candidate, len(r.keys))
	for i, k := range r.keys {
		held := ""
		if k.InAgent {
			held = "  [agent holds it]"
		}
		out[i] = candidate{
			label: fmt.Sprintf("%s  %s  %s%s", k.Stem, dash(k.Comment), k.Fingerprint, held),
			names: []string{k.Stem, k.Stem + ".pub", k.Comment},
		}
	}
	return out
}

func (r *REPL) ghCands() []candidate {
	out := make([]candidate, len(r.gh))
	for i, a := range r.gh {
		act := ""
		if a.Active {
			act = " (active)"
		}
		out[i] = candidate{label: a.Host + "/" + a.User + act, names: []string{a.User, a.Host + "/" + a.User}}
	}
	return out
}

func (r *REPL) gitCands() []candidate {
	out := make([]candidate, len(r.authors))
	for i, a := range r.authors {
		out[i] = candidate{label: a.String(), names: []string{a.String(), a.Name, a.Email}}
	}
	return out
}

// slotFull reports whether the draft already pins an identity of this kind,
// and its name.
func (r *REPL) slotFull(kind string) (string, bool) {
	switch {
	case kind == "ssh" && r.draft.SSH != nil:
		return r.draft.SSH.Stem, true
	case kind == "github" && r.draft.GH != nil:
		return r.draft.GH.User, true
	case kind == "git" && r.draft.Git != nil:
		return r.draft.Git.Email, true
	}
	return "", false
}

// selectIdentity never writes an identity without the human's choice. The
// model's account word only chooses which candidate is the default.
func (r *REPL) selectIdentity(ctx context.Context, kind, account string) {
	var cands []candidate
	var none string
	switch kind {
	case "ssh":
		cands, none = r.sshCands(), "no ssh public keys (~/.ssh/*.pub) were found on this host, so there is nothing to pin. Nothing written."
	case "github":
		cands, none = r.ghCands(), "no GitHub logins are known to gh on this host (gh auth login, or gh is not installed), so there is nothing to pin. Nothing written."
	case "git":
		cands, none = r.gitCands(), "no global git author (git config --global user.name and user.email) was found, so there is nothing to pin. Nothing written."
	}
	if len(cands) == 0 {
		r.say("%s", none)
		return
	}
	if cur, full := r.slotFull(kind); full {
		e, _ := texts.Note("identity_one")
		r.say("the draft already pins the %s identity %q.\n%s", kind, cur, e)
		if !r.confirm("Save this profile and start a second one for this identity?", false) {
			r.say("nothing written.")
			return
		}
		if !r.startSecondProfile(ctx) {
			return
		}
	}
	best := bestMatch(account, cands)
	title := fmt.Sprintf("Which %s identity should the sandbox act as?", kind)
	if account != "" {
		if best < 0 {
			title += fmt.Sprintf(" (nothing on this host matches %q)", account)
		} else {
			title += fmt.Sprintf(" (you said %q)", account)
		}
	}
	i := r.pick(title, cands, best)
	if i < 0 {
		r.say("nothing written.")
		return
	}
	switch kind {
	case "ssh":
		r.pinSSH(r.keys[i])
	case "github":
		r.pinGitHub(r.gh[i])
	case "git":
		r.pinGit(r.authors[i])
	}
	r.checkIdentity(ctx)
}

func (r *REPL) pinSSH(k hostfacts.SSHKey) {
	r.draft.SetSSH(k.Path)
	r.draft.RecordIdentity("ssh", nonEmpty(k.Stem, k.Stem+".pub", k.Comment), r.said, r.turn)
	r.say("pinned ssh key %s (the public half; the private key stays in your agent).", k.Stem)
	if !k.InAgent {
		r.say("warning: the host ssh-agent does not hold this key. snug will refuse to start until `ssh-add` has loaded it.")
	}
	r.say("Pushing needs the network: say \"needs internet\" to add @net.")
}

func (r *REPL) pinGit(a hostfacts.GitAuthor) {
	r.draft.SetGit(a.Name, a.Email)
	r.draft.RecordIdentity("git", nonEmpty(a.String(), a.Name, a.Email), r.said, r.turn)
	r.say("pinned git author %s.", a)
}

func (r *REPL) pinGitHub(a hostfacts.GHAccount) {
	r.draft.SetGH(a.Host, a.User)
	r.draft.RecordIdentity("github", nonEmpty(a.User, a.Host+"/"+a.User), r.said, r.turn)
	r.say("pinned GitHub login %s/%s.", a.Host, a.User)
	if p, err := r.cfg.LookPath("gh"); err == nil {
		if !strings.HasPrefix(p, "/usr/") && !strings.HasPrefix(p, "/opt/") {
			r.say("note: gh is at %s, outside /usr, so the sandbox will not have it. Say \"stage %s as gh\" to add it.", p, p)
		}
	} else {
		r.say("note: gh is not installed on this host; the sandbox needs a gh binary for the pinned login to be of use.")
	}

	if _, full := r.slotFull("ssh"); full {
		r.say("(an ssh key is already pinned: %s)", r.draft.SSH.Stem)
	} else if len(r.keys) > 0 {
		def := -1
		for i, k := range r.keys {
			if containsFold(k.Stem, a.User) || containsFold(k.Comment, a.User) {
				def = i
				break
			}
		}
		if i := r.pick(fmt.Sprintf("Which ssh key should the sandbox push %s's commits with?", a.User), r.sshCands(), def); i >= 0 {
			r.pinSSH(r.keys[i])
		} else {
			r.say("no ssh key pinned: gh will act as %s but git over ssh has no key.", a.User)
		}
	}

	if _, full := r.slotFull("git"); full {
		r.say("(a git author is already pinned: %s)", r.draft.Git.Email)
	} else if len(r.authors) > 0 {
		def := -1
		for i, au := range r.authors {
			if containsFold(au.Name, a.User) || containsFold(au.Email, a.User) {
				def = i
				break
			}
		}
		if i := r.pick("Pin a git author (identity.git) too?", r.gitCands(), def); i >= 0 {
			r.pinGit(r.authors[i])
		}
	}
}

func nonEmpty(xs ...string) []string {
	return slices.DeleteFunc(xs, func(s string) bool { return s == "" })
}

func containsFold(s, sub string) bool {
	return s != "" && sub != "" && strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// startSecondProfile saves the current draft and starts an empty one.
func (r *REPL) startSecondProfile(ctx context.Context) bool {
	if !r.save(ctx) {
		r.say("the current draft was not saved, so no second profile was started. Nothing written.")
		return false
	}
	r.undo = nil
	r.draft = draft.New(r.cfg.Host)
	r.say("started a new, empty profile.")
	return true
}

// checkIdentity compares the pinned ssh key with the pinned GitHub login's
// keys on GitHub. It is the check snug itself cannot make: it needs the network.
func (r *REPL) checkIdentity(ctx context.Context) {
	if r.draft.GH == nil || r.draft.SSH == nil {
		return
	}
	var key *hostfacts.SSHKey
	for i := range r.keys {
		if r.keys[i].Stem == r.draft.SSH.Stem {
			key = &r.keys[i]
		}
	}
	if key == nil {
		return
	}
	gh := r.draft.GH
	if r.cfg.Offline {
		r.say("offline: not checking that %s belongs to %s/%s on GitHub.", key.Stem, gh.Host, gh.User)
		return
	}
	if !r.ghInstalled {
		r.say("warning: gh is not installed, so whether %s belongs to %s on GitHub was not checked.", key.Stem, gh.User)
		return
	}
	res, err := hostfacts.CheckKeyOwnership(ctx, r.cfg.Run, gh.Host, gh.User, *key)
	switch {
	case err != nil:
		r.say("warning: could not check whether %s belongs to %s on GitHub: %v\n  (this is not fatal; --offline skips the check)", key.Stem, gh.User, err)
	case res.Match:
		r.say("checked: GitHub lists %s (%s) among %s's keys. The ssh key and the gh login are one account.", key.Stem, res.Detail, gh.User)
	default:
		r.say("!!! SPLIT IDENTITY !!!\n"+
			"!!! GitHub account %s does not list the ssh key %s (%s).\n"+
			"!!! git over ssh would act as whoever owns that key, and gh as %s: the sandbox would push as one and comment as the other.\n"+
			"!!! Pin a key GitHub lists for %s (say \"use the ssh key ...\"), or pin a different login.",
			gh.User, key.Stem, res.Detail, gh.User, gh.User)
	}
}
