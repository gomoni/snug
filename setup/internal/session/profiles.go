package session

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/ingest"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/safe"
	"github.com/gomoni/snug/setup/internal/verify"
)

func (s *Session) userProfile(name string) (ingest.Profile, bool) {
	i := slices.IndexFunc(s.facts.Profiles, func(p ingest.Profile) bool { return p.Name == name })
	if i < 0 {
		return ingest.Profile{}, false
	}
	return s.facts.Profiles[i], true
}

// profileNames are the names of the human's profiles the model may be shown
// and may name: a name include_profile would refuse is left out.
func (s *Session) profileNames() []string {
	var out []string
	for _, p := range s.facts.Profiles {
		if intent.ValidProfileName(p.Name) && !slices.Contains(out, p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}

func (s *Session) where(p ingest.Profile) string {
	path := filepath.Join(p.Dir, p.File)
	if h := filepath.Clean(s.cfg.Host.Home); h != "" && strings.HasPrefix(path, h+"/") {
		path = "~/" + strings.TrimPrefix(path, h+"/")
	}
	return safe.Inline(path)
}

// refusalOf asks the real snug whether the human's profile name resolves for
// this target, and returns snug's own message when it does not. checked is
// false when snug could not be asked (not on PATH, or no readable answer);
// the result is remembered for the session.
func (s *Session) refusalOf(ctx context.Context, name string) (msg string, checked bool) {
	if r, ok := s.resolves[name]; ok {
		return r.msg, r.checked
	}
	r := s.askSnug(ctx, name)
	if s.resolves == nil {
		s.resolves = map[string]resolveResult{}
	}
	s.resolves[name] = r
	return r.msg, r.checked
}

type resolveResult struct {
	msg     string
	checked bool
}

func (s *Session) askSnug(ctx context.Context, name string) resolveResult {
	snug, err := s.cfg.LookPath("snug")
	if err != nil {
		return resolveResult{}
	}
	res, _ := s.cfg.Run(ctx, nil, snug, "--dry-run", "--json", "-p", name, s.cfg.Host.Target)
	if len(res.Stdout) == 0 {
		return resolveResult{}
	}
	doc, err := verify.Parse(res.Stdout)
	if err != nil {
		return resolveResult{}
	}
	if doc.Snug.Outcome == "ok" && doc.Snug.PolicyResolved {
		return resolveResult{checked: true}
	}
	msg := "no message"
	if doc.Refusal != nil {
		msg = doc.Refusal.Message
	}
	msg = safe.Inline(msg)
	if r := []rune(msg); len(r) > 240 {
		msg = string(r[:237]) + "..."
	}
	return resolveResult{msg: msg, checked: true}
}

// includeRefusal is why an include_profile cannot be offered: the name is not
// one of the human's profiles, or snug refuses it today. "" when it can.
//
// Abuse: the model chooses the name and a hostile project can influence what
// the model chooses, so the name is looked up in the profiles read from the
// human's own directories and nowhere else; a name that is not there never
// reaches the draft, and one that is there still waits on a card that lists
// what it includes. snug-setup never writes to a profile it did not create.
func (s *Session) includeRefusal(ctx context.Context, name string) string {
	p, ok := s.userProfile(name)
	if !ok {
		have := s.profileNames()
		if len(have) == 0 {
			return fmt.Sprintf("you have no snug profile called %q, and no profile at all in %s.", safe.Inline(name), safe.Inline(strings.Join(s.cfg.ProfileDirs, " or ")))
		}
		return fmt.Sprintf("you have no snug profile called %q. Yours: %s.", safe.Inline(name), safe.Inline(strings.Join(have, ", ")))
	}
	if msg, checked := s.refusalOf(ctx, p.Name); checked && msg != "" {
		return fmt.Sprintf("your profile %q (%s) is there, but snug refuses it today: %s\nsnug-setup does not edit your profiles. Fix that file as snug's message says, then ask again.", p.Name, s.where(p), msg)
	}
	return ""
}

// pins says what an identity block pins, in words.
func pins(i ingest.ProfileIdentity) string {
	var out []string
	if i.GHUser != "" {
		host := i.GHHost
		if host == "" {
			host = draft.GitHubHost
		}
		out = append(out, "GitHub login "+host+"/"+i.GHUser)
	}
	if i.SSHKey != "" {
		out = append(out, "ssh key "+stemOf(i.SSHKey))
	}
	if i.SigningKey != "" {
		out = append(out, "signing key "+stemOf(i.SigningKey))
	}
	if i.Email != "" {
		a := i.Email
		if i.GitName != "" {
			a = i.GitName + " <" + i.Email + ">"
		}
		out = append(out, "git author "+a)
	}
	return safe.Inline(strings.Join(out, ", "))
}

func stemOf(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".pub")
}

// profileCost is what the card says including this profile adds: what it
// includes and what it pins. Its own grants are in a file snug reads, so the
// card names it rather than quoting it.
func profileCost(p ingest.Profile) string {
	var parts []string
	if len(p.Include) > 0 {
		parts = append(parts, "includes "+strings.Join(p.Include, ", "))
	}
	if p.Identity.Pins() {
		parts = append(parts, "pins "+pins(p.Identity))
	}
	if len(parts) == 0 {
		return "your profile is applied as written; read it with `snug profile show " + p.Name + "`"
	}
	return "your profile " + p.Name + " " + safe.Inline(strings.Join(parts, "; ")) + " (`snug profile show " + p.Name + "` has the rest)"
}

// IncludeProfile is /include NAME: the same turn "use my NAME profile" would
// give, without the model. It returns the lines to show; the card, if any, is
// open afterwards.
func (s *Session) IncludeProfile(ctx context.Context, name string) []Line {
	acts := []intent.Action{{Op: intent.OpIncludeProfile, Name: name}}
	s.turn++
	t := s.classify(ctx, s.turn, "/include "+safe.Inline(name), acts)
	return s.Defer(ctx, t)
}

// includedPin returns the user profile the draft includes that pins an
// identity of kind, if any.
func (s *Session) includedPin(kind string) (ingest.Profile, bool) {
	for _, n := range s.d.Include {
		p, ok := s.userProfile(n)
		if !ok {
			continue
		}
		i := p.Identity
		if (kind == "ssh" && i.SSHKey != "") || (kind == "github" && i.GHUser != "") || (kind == "git" && (i.Email != "" || i.GitName != "")) {
			return p, true
		}
	}
	return ingest.Profile{}, false
}

// checkFiles are the human's profile files the save check must have beside
// the draft: none unless the draft includes one of their profiles, and never
// a file that defines the profile being saved.
func (s *Session) checkFiles() []verify.File {
	if !slices.ContainsFunc(s.d.Include, func(n string) bool { return !strings.HasPrefix(n, "@") }) {
		return nil
	}
	var out []verify.File
	for i, f := range s.facts.Files {
		if slices.Contains(f.Defines, s.d.Name) {
			continue
		}
		out = append(out, verify.File{Name: strconv.Itoa(i) + "-" + f.Name, Body: f.Body})
	}
	return out
}

// profileLines tells the human which profiles of theirs exist and, for the
// ones that pin an identity, whether snug accepts them today.
func (s *Session) profileLines(ctx context.Context) []Line {
	var out []Line
	for _, w := range s.facts.Warnings {
		out = append(out, warn("%s", w))
	}
	names := s.profileNames()
	if len(names) == 0 {
		return out
	}
	out = append(out, info("Your snug profiles: %s. \"use my NAME profile\" or /include NAME adds one.", strings.Join(names, ", ")))
	for _, p := range s.facts.Profiles {
		if !p.Identity.Pins() || !intent.ValidProfileName(p.Name) {
			continue
		}
		line := fmt.Sprintf("Your profile %q (%s) pins %s", p.Name, s.where(p), pins(p.Identity))
		if msg, checked := s.refusalOf(ctx, p.Name); checked && msg != "" {
			line += fmt.Sprintf(", but snug refuses it today: %s\nsnug-setup does not edit your profiles; fix that file as snug's message says.", msg)
		} else {
			line += "."
		}
		out = append(out, info("%s", line))
	}
	return out
}
