// Package rules reads a request into snug-setup actions without a model:
// the request is split into clauses, each word is compared with a fixed
// lexicon (a typo within a small edit distance counts as the word), and each
// clause is read by which word sets it touches. Slots are filled only from
// what the request spells exactly (a path, an environment variable name, a
// value after "to") and from what the host already knows (built-in names, the
// human's profile names, ssh key stems, gh logins, git authors).
//
// It is pure: no filesystem, no command, no state between calls. A request it
// cannot read is never mapped to the nearest action it resembles; it returns
// *intent.Unclear with the closest readings as choices for the human.
package rules

import (
	"context"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/intent"
)

// Interpreter is the rules reader as a session interpreter.
type Interpreter struct{}

// Interpret is Read.
func (Interpreter) Interpret(_ context.Context, c intent.Context, request string) ([]intent.Action, error) {
	return Read(c, request)
}

// Read returns the actions of request in the context c. It returns
// *intent.Unclear, and no actions, when no clause of the request could be
// read, or when a part of it that is not filler could not be read; the
// Unclear carries what the rest was read as and up to three choices.
func Read(c intent.Context, request string) ([]intent.Action, error) {
	if name, email, rest, first, ok := typedAuthor(request); ok {
		pin := pick("git", name+" <"+email+">")
		r := &reader{c: c}
		if !slices.ContainsFunc(split(rest, r.slot), func(cl clause) bool { return !r.filler(cl) }) {
			return []intent.Action{pin}, nil
		}
		acts, err := Read(c, rest)
		var u *intent.Unclear
		// The pin keeps its place in what was said.
		with := func(acts []intent.Action) []intent.Action {
			if first {
				return append([]intent.Action{pin}, acts...)
			}
			return append(slices.Clone(acts), pin)
		}
		switch {
		case err == nil:
			return with(acts), nil
		case errors.As(err, &u):
			u.Understood = with(u.Understood)
			for i := range u.Choices {
				u.Choices[i].Actions = with(u.Choices[i].Actions)
			}
			return nil, u
		}
		return nil, err
	}
	r := &reader{c: c}
	clauses := split(request, r.slot)
	type part struct {
		cl   clause
		acts []intent.Action
	}
	var done []part
	var unknown []string
	var carry clause
	for _, cl := range clauses {
		if len(carry.toks) > 0 {
			merged := clause{toks: append(slices.Clone(carry.toks), cl.toks...)}
			alone := r.clause(cl)
			acts := r.clause(merged)
			if len(acts) > 0 {
				if len(acts) == len(alone) && r.unknown(carry) {
					unknown = append(unknown, carry.text())
				}
				done = append(done, part{merged, acts})
				carry = clause{}
				continue
			}
			cl = merged
		}
		acts := r.clause(cl)
		if len(acts) == 0 {
			carry = cl
			continue
		}
		carry = clause{}
		done = append(done, part{cl, acts})
	}
	if len(carry.toks) > 0 {
		switch {
		case len(done) > 0:
			last := done[len(done)-1]
			merged := clause{toks: append(slices.Clone(last.cl.toks), carry.toks...)}
			if acts := r.clause(merged); len(acts) > len(last.acts) {
				done[len(done)-1] = part{merged, acts}
			} else if r.unknown(carry) {
				unknown = append(unknown, carry.text())
			}
		case !r.filler(carry):
			unknown = append(unknown, carry.text())
		}
	}
	var acts, literal, sure []intent.Action
	var doubted, fixes []string
	for _, p := range done {
		acts = append(acts, p.acts...)
		if lit, fx := r.doubt(p.cl, p.acts); fx != "" {
			doubted = append(doubted, p.cl.text())
			fixes = append(fixes, fx)
			literal = append(literal, lit...)
			continue
		}
		sure = append(sure, p.acts...)
		literal = append(literal, p.acts...)
	}
	acts = r.finish(acts)
	if slices.Contains(acts, refuse("out_of_scope")) {
		return []intent.Action{refuse("out_of_scope")}, nil
	}
	if len(doubted) > 0 {
		return nil, doubtful(r.finish(sure), r.finish(literal), acts, doubted, fixes, unknown)
	}
	if len(acts) == 0 && r.missing != "" {
		return nil, r.noSuchProfile(request)
	}
	if len(acts) == 0 || len(unknown) > 0 {
		u := &intent.Unclear{Unknown: strings.Join(unknown, "; "), Understood: acts}
		if len(acts) == 0 {
			u.Unknown = strings.TrimSpace(request)
		}
		u.Choices = choices(u.Unknown, acts)
		return nil, u
	}
	return acts, nil
}

// doubt reports whether reading c with its corrections adds a widening
// action that reading the words as typed does not: "mount ~/notes unwritable"
// corrected to "writable" asks for rw, "it calls an internal service"
// corrected to "internet" for @net. It returns the literal reading and the
// corrections as `"typed" read as "word"`, or "" when the corrections widen
// nothing.
func (r *reader) doubt(c clause, acts []intent.Action) ([]intent.Action, string) {
	if !c.fixed() {
		return nil, ""
	}
	last, missing := r.last, r.missing
	lit := r.clause(c.literal())
	r.last, r.missing = last, missing
	if !slices.ContainsFunc(acts, func(a intent.Action) bool { return widens(a) && !slices.Contains(lit, a) }) {
		return nil, ""
	}
	// A filler fixed ("plz" read as "please") is not worth naming unless
	// it is all there is.
	var fx, all []string
	for _, t := range c.toks {
		if t.fixed {
			w := t.w
			if t.w == t.typed {
				w = strings.Join(t.parts, "-")
			}
			all = append(all, "\""+t.raw+"\" read as \""+w+"\"")
			if !fillers[t.w] {
				fx = append(fx, all[len(all)-1])
			}
		}
	}
	if len(fx) == 0 {
		fx = all
	}
	return lit, strings.Join(fx, ", ")
}

// widens reports whether a makes the sandbox see or do more, or puts a value
// into it: the ops that go on a card.
func widens(a intent.Action) bool {
	switch a.Op {
	case intent.OpUseProfile, intent.OpIncludeProfile, intent.OpStageBinary, intent.OpOpenDoor, intent.OpSetEnv, intent.OpGrantPath:
		return true
	}
	return false
}

// doubtful is the question for a request a correction would widen: the
// reading of the words as typed first, then the corrected one, each beside
// what the rest of the request was read as. Nothing is applied from either
// until the human picks.
func doubtful(sure, literal, corrected []intent.Action, doubted, fixes, unknown []string) *intent.Unclear {
	u := &intent.Unclear{Unknown: strings.Join(append(doubted, unknown...), "; "), Understood: sure,
		Why: strings.Join(fixes, ", ") + "? a typo fix that would widen the sandbox is never applied unasked"}
	if len(sure) == 0 {
		u.Understood = nil
	}
	if len(literal) > 0 && !slices.Equal(literal, sure) {
		u.Choices = append(u.Choices, intent.Choice{Actions: literal})
	} else if len(sure) > 0 {
		u.Choices = append(u.Choices, intent.Choice{Actions: sure})
	}
	u.Choices = append(u.Choices, intent.Choice{Actions: corrected})
	return u
}

// authorREs find a git author the request spells out: "commit as NAME
// <EMAIL>", "author NAME EMAIL", "my git name is NAME, email EMAIL". The
// values are the human's own words, so they are taken as typed rather than
// matched against the host's authors; the session checks their shape.
var authorREs = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:\b(?:pin|set|use)\s+)?(?:\b(?:the|my)\s+)?(?:\bgit\s+)?\b(?:commit(?:s|ting)?\s+as|author(?:ed)?(?:\s+as)?|as\s+the\s+author)\s+(.+?)\s*<\s*([^<>]*?)\s*>`),
	regexp.MustCompile(`(?i)(?:\b(?:pin|set|use)\s+)?(?:\b(?:the|my)\s+)?(?:\bgit\s+)?\b(?:commit(?:s|ting)?\s+as|author(?:ed)?(?:\s+as)?)\s+((?:[^\s<>@,]+\s+){0,4}?[^\s<>@,]+)\s+<?([^\s<>,]+@[^\s<>,]+?)>?(?:[\s,;]|[.!]?$)`),
	regexp.MustCompile(`(?i)(?:\bmy\s+)?(?:\bgit\s+)?(?:\bauthor\s+)?\bname\s+is\s+(.+?)\s*(?:,|;|\band\b)\s*(?:(?:my|the)\s+)?(?:e-?mail|address)(?:\s+is)?\s+<?([^\s<>,]+@[^\s<>,]+?)>?(?:[\s,;]|[.!]?$)`),
}

// typedAuthor returns the name and email a request spells out for the git
// author, the request without them, and whether they came before anything
// else in it; ok is false when it spells none.
func typedAuthor(request string) (name, email, rest string, first, ok bool) {
	for _, re := range authorREs {
		m := re.FindStringSubmatchIndex(request)
		if m == nil {
			continue
		}
		name = strings.Trim(strings.TrimSpace(request[m[2]:m[3]]), "\"'“”")
		email = strings.TrimRight(request[m[4]:m[5]], ".")
		if name == "" {
			continue
		}
		before := request[:m[0]]
		return name, email, before + " " + request[m[1]:], strings.Trim(before, " \t,;+&") == "", true
	}
	return "", "", "", false, false
}

type reader struct {
	c intent.Context
	// missing is a profile name a request asked to include that the human
	// does not have.
	missing string
	// last is the last path an earlier clause spelled, for "put it on the
	// path" in the next.
	last *pathTok
}

// hit is an action with the index of the word that produced it, so a clause
// lists its actions in the order they were said.
type hit struct {
	pos int
	a   intent.Action
}

type hits []hit

func (h *hits) add(pos int, a intent.Action) { *h = append(*h, hit{pos, a}) }

func (h hits) actions() []intent.Action {
	slices.SortStableFunc(h, func(a, b hit) int { return a.pos - b.pos })
	out := make([]intent.Action, len(h))
	for i, x := range h {
		out[i] = x.a
	}
	return out
}

func use(name string) intent.Action { return intent.Action{Op: intent.OpUseProfile, Name: name} }
func drop(name string) intent.Action {
	return intent.Action{Op: intent.OpDropProfile, Name: name}
}
func refuse(code string) intent.Action { return intent.Action{Op: intent.OpRefuse, Code: code} }
func note(topic string) intent.Action  { return intent.Action{Op: intent.OpNote, Topic: topic} }
func pick(kind, account string) intent.Action {
	return intent.Action{Op: intent.OpSelectIdentity, Kind: kind, Account: account}
}

// notAName are the words before "profile" that do not name one.
var notAName = set("my the a an this that your our own new snug same other existing old usual default sandbox")

// noSuchProfile is the answer to a request to include a profile the human
// does not have: their own profiles, closest name first, as the choices.
func (r *reader) noSuchProfile(request string) *intent.Unclear {
	u := &intent.Unclear{Unknown: strings.TrimSpace(request), Why: "you have no snug profile called \"" + r.missing + "\""}
	names := slices.Clone(r.c.Profiles)
	w := strings.ToLower(r.missing)
	slices.SortStableFunc(names, func(a, b string) int { return distance(w, strings.ToLower(a)) - distance(w, strings.ToLower(b)) })
	for i, n := range names {
		if i == 3 {
			break
		}
		u.Choices = append(u.Choices, intent.Choice{Actions: []intent.Action{{Op: intent.OpIncludeProfile, Name: n}}})
	}
	if len(names) == 0 {
		u.Why += ", and no profile at all"
	}
	return u
}

// slot reports whether raw is a word the request spells exactly and that must
// not be corrected: a host name the session knows, or an environment variable
// name. A word holding anything but letters is never corrected anyway.
func (r *reader) slot(raw string) bool {
	return envName(raw) || r.profile(raw) != "" || r.stem(raw) != "" || r.login(raw) != ""
}

// unknown reports whether c, left over beside parts that were understood,
// asks for something the rules could not read: a word that asks for
// something (meaningful), or a host name the request spells, that produced
// no action.
func (r *reader) unknown(c clause) bool {
	if r.filler(c) {
		return false
	}
	for _, t := range c.toks {
		if t.is(meaningful) || r.slot(t.raw) {
			return true
		}
	}
	return false
}

// filler reports whether every word of c is one that carries no request.
func (r *reader) filler(c clause) bool {
	for _, t := range c.toks {
		if !fillers[t.w] && !negWords[t.w] && !offWords[t.w] && !modifiers[t.w] && !onlyRead[t.w] && !readWords[t.w] && !tmpWords[t.w] && !hereWords[t.w] {
			return false
		}
	}
	return true
}

func (r *reader) draftHas(name string) bool { return slices.Contains(r.c.Draft.Include, name) }

// wantsDropped reports whether a request to turn name off has something to
// act on: the draft has it, or an open question proposes it.
func (r *reader) wantsDropped(name string) bool {
	return r.draftHas(name) || slices.Contains(r.c.Proposed, name)
}

func (r *reader) profile(raw string) string {
	for _, p := range r.c.Profiles {
		if strings.EqualFold(p, raw) {
			return p
		}
	}
	return ""
}

// stem returns the ssh key stem raw names: the stem itself, its .pub file or
// the key's comment.
func (r *reader) stem(raw string) string {
	for _, k := range r.c.SSH {
		if strings.EqualFold(raw, k.Stem) || strings.EqualFold(raw, k.Stem+".pub") || (k.Comment != "" && strings.EqualFold(raw, k.Comment)) {
			return k.Stem
		}
	}
	return ""
}

// keyWord reports whether w is part of the name or comment of a key on the
// host, so "the work key" can say which one when a stem holds "work".
func (r *reader) keyWord(w string) bool {
	if len(w) < 3 || keyNotName[w] {
		return false
	}
	for _, k := range r.c.SSH {
		if strings.Contains(strings.ToLower(k.Stem), w) || strings.Contains(strings.ToLower(k.Comment), w) {
			return true
		}
	}
	return false
}

// keyHint is the first word of c that is part of a key's name or comment on
// this host, "" when none is.
func (r *reader) keyHint(c clause) string {
	for _, t := range c.toks {
		if r.keyWord(t.w) {
			return t.raw
		}
	}
	return ""
}

// keyNotName are words next to "key" that say nothing about which key.
var keyNotName = set("the my your our this that ssh key keys use using with for signing sign private public new old any one")

func (r *reader) login(raw string) string {
	for _, a := range r.c.GitHub {
		if strings.EqualFold(raw, a.User) || strings.EqualFold(raw, a.Host+"/"+a.User) {
			return a.User
		}
	}
	return ""
}

// author returns the host's git author whose email raw is, "".
func (r *reader) author(raw string) string {
	email := strings.Trim(raw, "<>")
	for _, a := range r.c.Git {
		if i := strings.LastIndex(a, "<"); i >= 0 && strings.EqualFold(strings.Trim(a[i:], "<> "), email) {
			return a
		}
	}
	return ""
}

var (
	envRE      = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	doorRE     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	portPairRE = regexp.MustCompile(`^\d{2,5}:\d{2,5}$`)
	emailRE    = regexp.MustCompile(`^<?[^@<>\s]+@[^@<>\s]+\.[a-z]{2,}>?$`)
)

// acronyms are upper-case words that are not environment variables.
var acronyms = set("API APIS SSH GUI CLI URL HTTP HTTPS IDE CPU GPU AWS GCP NPM PIP OK PR PRS CI CD DNS TLS SSL VPN LAN USB JSON YAML TOML README MD UI UX DB SQL OS GH IP TCP UDP X11 I AI LLM ID SDK")

// knownEnv are lower-case-free names that are environment variables even
// without an underscore.
func envName(raw string) bool {
	name, _, _ := strings.Cut(raw, "=")
	if !envRE.MatchString(name) || len(name) < 2 || len(name) > 64 || acronyms[name] {
		return false
	}
	return true
}

// secretEnv reports whether an environment variable name says it holds a
// credential.
func secretEnv(name string) bool {
	for _, s := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "CREDENTIAL", "PRIVATE", "AUTH"} {
		if strings.Contains(name, s) {
			return true
		}
	}
	return strings.HasSuffix(name, "_KEY") || strings.HasSuffix(name, "_PASS") || name == "PAT" || strings.HasSuffix(name, "_PAT") || strings.Contains(name, "_PAT_")
}

// pathTok is a path the request spells, in the spelling grant_path takes.
type pathTok struct {
	pos  int
	path string
	dir  bool // spelled with a trailing slash, or ending in bin
}

// paths returns the paths c spells. A relative path is under the target;
// "../x" is under its parent. A URL, a host/name pair and "read/write" are not
// paths.
func (r *reader) paths(c clause) []pathTok {
	var out []pathTok
	for i, t := range c.toks {
		raw := t.raw
		if strings.Contains(raw, "://") || writeWords[t.w] || strings.ContainsAny(raw, "@:<>") && !strings.HasPrefix(raw, "/") {
			continue
		}
		p := ""
		switch {
		case raw == "~" || raw == "~/" || raw == "$HOME" || raw == "$HOME/":
			p = "~"
		case strings.HasPrefix(raw, "$HOME/"):
			p = "~/" + strings.TrimPrefix(raw, "$HOME/")
		case strings.HasPrefix(raw, "/"), strings.HasPrefix(raw, "~/"), strings.HasPrefix(raw, "{home}"), strings.HasPrefix(raw, "{target}"), strings.HasPrefix(raw, "{target_parent}"):
			p = raw
		case raw == ".." || raw == "../":
			continue
		case strings.HasPrefix(raw, "../"):
			p = "{target_parent}/" + strings.TrimPrefix(raw, "../")
		case strings.HasPrefix(raw, "./"):
			p = "{target}/" + strings.TrimPrefix(raw, "./")
		case strings.Contains(raw, "/"):
			first, _, _ := strings.Cut(raw, "/")
			if first == "" || strings.Contains(first, ".") || !wordLike(strings.ReplaceAll(strings.ReplaceAll(first, "_", "-"), ".", "-")) {
				continue
			}
			p = "{target}/" + raw
		default:
			continue
		}
		dir := strings.HasSuffix(p, "/") && p != "/"
		if p != "/" {
			p = strings.TrimRight(p, "/")
		}
		if b := path.Base(p); b == "bin" || b == "sbin" {
			dir = true
		}
		out = append(out, pathTok{pos: i, path: p, dir: dir})
	}
	return out
}

// sensitive reports whether p is under a home directory snug-setup never
// grants, and which identity kind lists the narrow version of it.
func sensitive(p string) (bool, string) {
	rest, ok := strings.CutPrefix(p, "~/")
	if !ok {
		rest, ok = strings.CutPrefix(p, "{home}/")
	}
	if !ok {
		return false, ""
	}
	first, _, _ := strings.Cut(rest, "/")
	switch {
	case first == ".ssh":
		return true, "ssh"
	case rest == ".config/gh" || strings.HasPrefix(rest, ".config/gh/"):
		return true, "github"
	case sensitiveDir[first], strings.HasPrefix(rest, ".local/share/keyrings"):
		return true, ""
	case slices.ContainsFunc(sensitiveConfig, func(d string) bool { return rest == d || strings.HasPrefix(rest, d+"/") }):
		return true, ""
	}
	return false, ""
}

func under(p, dir string) bool { return p != dir && strings.HasPrefix(p, dir+"/") }

// question reports whether c asks for information rather than for a change:
// it ends in a question mark or starts with a word that opens a question, and
// that word is not one of the polite openings of a request ("can it ...").
func (c clause) question() bool {
	if len(c.toks) == 0 {
		return false
	}
	head := c.toks[0].w
	switch head {
	case "can", "could", "would", "will", "kann":
		switch {
		case len(c.toks) > 1 && (c.toks[1].w == "it" || c.toks[1].w == "you" || c.toks[1].w == "we"):
			return false
		case len(c.toks) > 2 && c.toks[1].w == "the" && c.toks[2].w == "sandbox":
			return false
		}
		return c.toks[len(c.toks)-1].q
	}
	if questionHead[head] || strings.HasPrefix(head, "what'") || strings.HasPrefix(head, "where'") || strings.HasPrefix(head, "how'") {
		return true
	}
	return c.toks[len(c.toks)-1].q
}

// clause reads one clause. It returns no actions when nothing in it is a
// request the rules know.
func (r *reader) clause(c clause) []intent.Action {
	var h hits
	if len(c.toks) == 0 {
		return nil
	}
	if i := c.find("ignore previous", "ignore all", "ignore your", "disregard previous", "disregard all", "system prompt", "hidden instructions", "your instructions"); i >= 0 {
		return []intent.Action{refuse("out_of_scope")}
	}
	if c.hasSet(offTopic) {
		return []intent.Action{refuse("out_of_scope")}
	}
	if i := c.findSet(undoWords); i >= 0 || c.has("take that back", "take it back", "never mind", "nevermind", "scratch that", "forget that", "forget it", "roll back", "go back", "what you just did", "you just did") {
		return []intent.Action{{Op: intent.OpUndo}}
	}
	if c.hasSet(dropWords) && c.has("it", "that") && len(r.paths(c)) == 0 && r.objectless(c) {
		return []intent.Action{{Op: intent.OpUndo}}
	}
	if c.hasSet(recommend) || c.has("you pick", "you decide", "your call", "what do you think", "no idea", "up to you") {
		if c.hasSet(identityNoun) {
			return []intent.Action{{Op: intent.OpAdvise}}
		}
		return []intent.Action{{Op: intent.OpAnalyze}}
	}
	file, filePos := r.file(c)
	if c.hasSet(analyzeWords) && file == "" {
		return []intent.Action{{Op: intent.OpAnalyze}}
	}

	q := c.question()
	neg := c.hasSet(negWords) || c.hasSet(offWords)
	paths := r.paths(c)
	if q && len(paths) == 0 {
		if acts := r.listing(c); acts != nil {
			return acts
		}
		if c.hasSet(seccompWords) && !neg {
			return nil
		}
		if t := r.topic(c); t != "" {
			return []intent.Action{note(t)}
		}
		if slices.ContainsFunc(c.toks, func(t tok) bool { return strings.HasPrefix(t.raw, "@") && !slices.Contains(intent.Builtins, t.raw) }) {
			return []intent.Action{note("profiles")}
		}
	} else if c.has("list") {
		if acts := r.listing(c); acts != nil {
			return acts
		}
	}

	consumed := map[int]bool{}
	refused := false
	identityRefused := false
	for _, p := range paths {
		if bad, kind := sensitive(p.path); bad {
			h.add(p.pos, refuse("sensitive_home"))
			if kind != "" {
				h.add(p.pos, intent.Action{Op: intent.OpListIdentities, Kind: kind})
			}
			consumed[p.pos], refused, identityRefused = true, true, true
			continue
		}
		if p.path == "~/.claude" || under(p.path, "~/.claude") {
			h.add(p.pos, use("@claude"))
			consumed[p.pos] = true
			continue
		}
		if p.path == "~" || p.path == "/home" || p.path == "{home}" {
			h.add(p.pos, refuse("whole_home"))
			consumed[p.pos], refused = true, true
		}
		if strings.HasSuffix(p.path, "docker.sock") || strings.HasSuffix(p.path, "podman.sock") {
			h.add(p.pos, refuse("docker_sock"))
			consumed[p.pos], refused = true, true
		}
	}
	if i := c.find("ssh folder", "ssh directory", "ssh dir", "aws credentials", "my keyring", "the keyring"); i >= 0 {
		h.add(i, refuse("sensitive_home"))
		if c.has("ssh") {
			h.add(i, intent.Action{Op: intent.OpListIdentities, Kind: "ssh"})
		}
		refused, identityRefused = true, true
	}
	if i := c.find("gh config", "github config", "gh directory", "gh folder"); i >= 0 {
		h.add(i, refuse("sensitive_home"))
		h.add(i, intent.Action{Op: intent.OpListIdentities, Kind: "github"})
		refused, identityRefused = true, true
	}
	if i := c.find("whole home", "entire home", "home directory", "home dir", "home folder", "my home", "all of home"); i >= 0 {
		h.add(i, refuse("whole_home"))
		refused = true
	}
	sock := false
	if i := c.find("docker socket", "docker.sock", "podman.sock", "host docker", "docker daemon's"); i >= 0 || c.has("docker") && c.has("socket", "sock") {
		i = max(i, c.find("docker"))
		h.add(i, refuse("docker_sock"))
		refused, sock = true, true
	}
	if slices.ContainsFunc(h, func(x hit) bool { return x.a.Code == "docker_sock" }) {
		sock = true
	}
	hostNet := false
	if i := c.find("host network", "host's network", "host networking", "network namespace", "host net", "network of the host", "network of the machine", "machine's network", "same network"); i >= 0 || c.has("namespace") && c.hasSet(netWords) {
		i = max(i, c.findSet(netWords))
		h.add(i, refuse("host_network"))
		refused, hostNet = true, true
	}
	for i, t := range c.toks {
		if !hostNet && (strings.HasSuffix(t.w, "=host") || t.w == "--network=host") {
			h.add(i, refuse("host_network"))
			refused, hostNet = true, true
		}
	}
	if i := c.findSet(desktopWords); i >= 0 {
		h.add(i, refuse("desktop_socket"))
		refused = true
	}
	publish := false
	portish := c.has("port", "ports", "-p") || slices.ContainsFunc(c.toks, func(t tok) bool { return portPairRE.MatchString(t.w) })
	if (c.has("publish") || c.has("-p")) && (portish || c.hasSet(podmanWords)) || portish && c.hasSet(podmanWords) && c.has("expose", "publish", "-p") {
		h.add(max(c.find("publish", "-p", "expose"), 0), refuse("port_publish"))
		refused, publish = true, true
	}
	// "keep my BROWSER" names a variable, not a browser to serve a page to.
	browser := c.find("host browser", "my browser", "the browser", "laptop browser")
	if browser >= 0 && envName(c.toks[browser+1].raw) {
		browser = -1
	}
	door := !publish && (c.hasSet(doorWords) || browser >= 0 || c.has("reachable from", "from outside", "from the outside")) && !(c.has("expose") && len(paths) > 0)
	if !door && !publish {
		hp := -1
		for i, t := range c.toks {
			if strings.HasPrefix(t.w, "localhost") || strings.HasPrefix(t.raw, "127.") || strings.HasPrefix(t.raw, "0.0.0.0") || t.raw == "[::1]" {
				hp = i
				break
			}
		}
		if hp < 0 {
			hp = c.find("my laptop", "host port", "host's port", "on my machine", "local postgres", "local redis", "local mysql",
				"local mongo", "local database", "local db", "local service", "local server", "local frontend", "local backend", "local api")
		}
		if hp >= 0 {
			h.add(hp, refuse("host_port"))
			refused = true
		}
	}
	for i, t := range c.toks {
		if t.w == ".snug" || t.w == ".snug/" || t.w == "snug.toml" {
			h.add(i, refuse("repo_profile"))
			refused = true
			break
		}
	}
	if !slices.ContainsFunc(h, func(x hit) bool { return x.a.Code == "repo_profile" }) {
		if i := c.find("repo ships", "project ships", "repo provides", "repo's profile", "repo's config", "repository ships", "comes with the repo"); i >= 0 {
			h.add(i, refuse("repo_profile"))
			refused = true
		}
	}
	if i := c.findSet(seccompWords); i >= 0 && (neg || c.has("turn off", "disable")) {
		h.add(i, refuse("no_seccomp"))
		refused = true
	}
	secret := false
	for i, t := range c.toks {
		name, _, _ := strings.Cut(t.raw, "=")
		if envName(t.raw) && secretEnv(name) {
			h.add(i, refuse("secret_in_env"))
			refused, secret = true, true
			break
		}
	}
	if !secret && !q && c.has("token", "password", "api key", "secret") && c.has("env", "environment", "variable", "export", "set") {
		h.add(c.find("token", "password", "api key", "secret"), refuse("secret_in_env"))
		refused, secret = true, true
	}
	deny := false
	if neg && c.has("reachable", "visible", "see", "read", "access", "readable") && (len(paths) > 0 || c.has("directory", "folder", "dir")) && !c.hasSet(writeWords) {
		h.add(max(c.find("reachable", "visible", "see", "read", "access", "readable"), 0), refuse("deny_rule"))
		refused, deny = true, true
	} else if i := c.findSet(denyWords); i >= 0 || c.has("leave") && c.has("out") || c.has("keep") && c.has("out") || c.has("mount nothing", "not exist", "shouldn't exist") {
		i = max(i, c.find("leave", "keep", "mount nothing", "not exist", "shouldn't exist"))
		h.add(i, refuse("deny_rule"))
		refused, deny = true, true
	}

	// Paths.
	pathVar := c.has("to path", "on the path", "to the path", "on path", "in path", "into path", "$path") ||
		slices.ContainsFunc(c.toks, func(t tok) bool { return t.raw == "PATH" || t.raw == "$PATH" })
	if len(paths) > 0 {
		last := paths[len(paths)-1]
		r.last = &last
	} else if pathVar && r.last != nil && c.has("it", "that", "them") {
		p := *r.last
		p.pos = c.find("it", "that", "them")
		paths = []pathTok{p}
	}
	stage := c.hasSet(stageWords) || c.has("run") && !c.hasSet(tmpWords) && !c.hasSet(writeWords) && !c.hasSet(readWords)
	access := "ro"
	switch {
	case c.hasSet(tmpWords) || c.has("in memory", "thrown away", "throw away"):
		access = "tmpfs"
	case c.hasSet(writeWords) && !(neg && !c.hasSet(onlyRead)) && !c.hasSet(onlyRead):
		access = "rw"
	}
	layered := c.has("except", "but")
	var granted []pathTok
	for _, p := range paths {
		if consumed[p.pos] || deny {
			continue
		}
		switch {
		case c.hasSet(dropWords):
			h.add(p.pos, intent.Action{Op: intent.OpDropPath, Path: p.path})
		case (pathVar || stage) && p.dir:
			h.add(p.pos, intent.Action{Op: intent.OpGrantPath, Path: p.path, Access: "ro"})
			if pathVar || stage {
				h.add(p.pos, intent.Action{Op: intent.OpSetEnv, Name: "PATH", Verb: "prepend", Value: p.path, HasValue: true})
			}
		case pathVar || stage:
			name := path.Base(p.path)
			if i := c.find("as"); i > p.pos && i+1 < len(c.toks) {
				name = c.toks[i+1].raw
			}
			h.add(p.pos, intent.Action{Op: intent.OpStageBinary, Host: p.path, Name: name})
		default:
			a := access
			if layered && len(granted) > 0 && under(p.path, granted[0].path) && a == "ro" {
				a = "rw"
			}
			h.add(p.pos, intent.Action{Op: intent.OpGrantPath, Path: p.path, Access: a})
			granted = append(granted, p)
		}
	}

	// The project and its parent, when no path says where.
	if len(paths) == 0 {
		parent := c.findSet(parentWords)
		if parent < 0 {
			parent = c.find("next to", "other projects", "the folder above", "the directory above", "one level up", "..", "../", "@parent-ro")
		}
		here := c.findSet(hereWords)
		if here < 0 {
			here = c.find("this directory", "this dir", "this folder", "my files", "current directory", "working dir", "working directory", "work dir", "workdir", "@target-rw")
		}
		ro := c.hasSet(onlyRead) || c.has("only read", "read only") || neg && c.hasSet(writeWords)
		switch {
		case parent >= 0 && (neg || c.hasSet(dropWords)):
			h.add(parent, drop("@parent-ro"))
		case parent >= 0:
			h.add(parent, use("@parent-ro"))
		case here >= 0 && ro:
			h.add(here, intent.Action{Op: intent.OpGrantPath, Path: "{target}", Access: "ro"})
		case here >= 0 && (c.hasSet(writeWords) || c.toks[here].w == "@target-rw"):
			h.add(here, use("@target-rw"))
		}
	}

	off := neg || c.hasSet(dropWords)
	if i := c.find("@claude"); i >= 0 || c.hasSet(claudeWords) {
		if i < 0 {
			i = c.findSet(claudeWords)
		}
		if off {
			h.add(i, drop("@claude"))
		} else {
			h.add(i, use("@claude"))
		}
	}

	reading := file != "" && (c.hasSet(readWords) || c.hasSet(analyzeWords) || c.has("check", "through", "figure", "open", "have a look"))
	// "share ~/.docker with the container" names a container as where a
	// refused path would go, not as a wish for one.
	if !sock && !publish && !reading && !hostNet && !identityRefused {
		img := c.findSet(imageWords)
		if img < 0 {
			img = c.find("@podman-build")
		}
		pod := c.findSet(podmanWords)
		if pod < 0 {
			pod = c.find("@podman-socket")
		}
		build := img >= 0 || pod >= 0 && c.hasSet(buildWords)
		at := min(nonNeg(img, pod), nonNeg(pod, img))
		switch {
		case build && off:
			h.add(at, drop("@podman-build"))
		case pod >= 0 && off:
			h.add(at, drop("@podman-socket"))
		case build && !(img >= 0 && pod < 0 && !c.hasSet(buildWords) && file != ""):
			h.add(at, use("@podman-build"))
		case pod >= 0:
			h.add(at, use("@podman-socket"))
		}
	}

	// "offline is fine" accepts what another part asks for; it is not a
	// request to drop the internet.
	content := c.hasSet(offWords) && c.has("fine", "ok", "okay", "acceptable", "enough")
	if !hostNet && !content {
		ni := c.findSet(netWords)
		if ni < 0 {
			ni = c.find("@net", "go get", "go mod", "go modules", "openai")
		}
		if ni < 0 {
			if i := c.findSet(netTools); i >= 0 && c.has("install", "installs", "build", "fetch", "download", "update", "add", "work") {
				ni = i
			}
		}
		if ni < 0 && !door {
			if i := c.find("api", "apis"); i >= 0 && c.has("call", "calls", "uses", "talks", "reach", "hit", "hits", "query") {
				ni = i
			}
		}
		switch {
		case ni >= 0 && (neg || c.hasSet(offWords)):
			if r.wantsDropped("@net") {
				h.add(ni, drop("@net"))
			} else {
				h.add(ni, note("net"))
			}
		case ni < 0 && c.hasSet(offWords):
			i := c.findSet(offWords)
			if r.wantsDropped("@net") {
				h.add(i, drop("@net"))
			} else {
				h.add(i, note("net"))
			}
		case ni >= 0 && c.hasSet(dropWords):
			h.add(ni, drop("@net"))
		case ni >= 0:
			h.add(ni, use("@net"))
		}
	}

	// "refuse my work profile", "commits are unsigned": a negated clause
	// never asks for an identity or a profile.
	negated := c.hasSet(negWords)
	if !identityRefused && !negated {
		r.identity(c, &h)
	}

	r.env(c, &h, paths, secret)

	if name, i := profileName(c); name != "" {
		h.add(i, intent.Action{Op: intent.OpNameProfile, Name: name})
	}
	if !negated {
		r.include(c, &h)
	}

	if i := nonNeg(c.findSet(showWords), c.find("current state", "let me see", "so far", "what we have")); i >= 0 && !c.hasSet(identityNoun) && len(paths) == 0 {
		h.add(i, intent.Action{Op: intent.OpShow})
	}
	if i := nonNeg(c.findSet(saveWords), c.find("profiles.d", "write it out", "schreib es raus")); i >= 0 {
		h.add(i, intent.Action{Op: intent.OpSave})
	} else if i := c.find("write it", "write the profile", "write the file", "write it out", "done", "fertig", "hotovo"); i >= 0 && len(paths) == 0 && !c.hasSet(hereWords) {
		h.add(i, intent.Action{Op: intent.OpSave})
	}

	if door {
		h.add(max(c.findSet(doorWords), 0), intent.Action{Op: intent.OpOpenDoor, Name: doorName(c)})
	}
	if reading {
		h.add(filePos, intent.Action{Op: intent.OpReadFile, Path: file})
	}

	if len(h) == 0 && !refused {
		if i := c.findSet(helpWords); i >= 0 || c.has("what can you do", "who are you", "how does this work") {
			return []intent.Action{note("help")}
		}
		if i := c.findSet(langWords); i >= 0 {
			return []intent.Action{{Op: intent.OpToolchain, Name: toolchain[c.toks[i].w]}}
		}
	}
	return h.actions()
}

// toolchain names the language a word of langWords is about, in the names
// ingest uses.
var toolchain = map[string]string{"go": "go", "golang": "go", "node": "node", "nodejs": "node", "javascript": "node",
	"typescript": "node", "npm": "node", "python": "python", "pip": "python", "rust": "rust", "cargo": "rust"}

func nonNeg(a, b int) int {
	if a < 0 {
		return b
	}
	return a
}

// objectless reports whether c names nothing besides dropping: "remove it".
func (r *reader) objectless(c clause) bool {
	for _, t := range c.toks {
		if !fillers[t.w] && !negWords[t.w] && !dropWords[t.w] {
			return false
		}
	}
	return true
}

// listing reads a request to list identities: "which ssh keys do I have",
// "list my github logins". It returns nil for anything else.
func (r *reader) listing(c clause) []intent.Action {
	if !c.hasSet(listWords) && !c.has("do i have") {
		return nil
	}
	if c.hasSet(bothWords) {
		return nil
	}
	kind := ""
	switch {
	case c.hasSet(signWords):
		kind = "signing"
	case c.has("github", "gh") || c.hasSet(accountWords):
		kind = "github"
	case c.has("author") || c.has("git") && c.has("configured", "identity", "name", "email"):
		kind = "git"
	case c.hasSet(keyWords) || c.has("ssh", "agent"):
		kind = "ssh"
	}
	if kind == "" {
		return nil
	}
	return []intent.Action{{Op: intent.OpListIdentities, Kind: kind}}
}

// topic is the note a question about snug's rules is answered with, "" when
// the question is not about one.
func (r *reader) topic(c clause) string {
	switch {
	case c.hasSet(bothWords) && (c.hasSet(accountWords) || c.has("github", "identities")):
		return "identity_one"
	case c.has("profiles") && !c.hasSet(podmanWords):
		return "profiles"
	case c.hasSet(podmanWords) && (c.has("pull") || c.hasSet(netWords) || c.has("@net")):
		return "podman_offline"
	case c.hasSet(podmanWords) && c.hasSet(buildWords):
		return "podman_build"
	case c.has("token", "password", "secret", "secrets", "api key", "credentials"):
		return "secrets_file"
	case c.hasSet(netWords) || c.has("@net"):
		return "net"
	case c.has("@git") || c.has("git") && !c.has("github"):
		return "git"
	case c.has("@claude") || c.hasSet(claudeWords):
		return "claude"
	case c.hasSet(parentWords) || c.has("@parent-ro"):
		return "parent_ro"
	case c.has("publish") || c.has("port", "ports") && c.hasSet(podmanWords):
		return "port_publish"
	case c.has("except") || c.has("but") && c.hasSet(writeWords):
		return "layering"
	case c.hasSet(onlyRead) && c.hasSet(hereWords):
		return "readonly_target"
	case c.has("default", "defaults", "by default", "out of the box", "without adding") || c.hasSet(hereWords) && c.hasSet(writeWords):
		return "defaults"
	case c.has("what can you do", "help"):
		return "help"
	}
	return ""
}

// identity reads the identity part of a clause: a GitHub login, an ssh key, a
// signing key, a git author. Account words are taken only when they name
// something on this host.
func (r *reader) identity(c clause, h *hits) {
	if c.hasSet(bothWords) && (c.hasSet(accountWords) || c.has("github", "identities", "konten", "konto", "účty")) {
		h.add(c.findSet(bothWords), note("identity_one"))
		return
	}
	login, loginAt := "", -1
	stem, stemAt := "", -1
	authorAt, author := -1, ""
	for i, t := range c.toks {
		if l := r.login(t.raw); l != "" && login == "" && !(r.profile(t.raw) != "" && r.including(c)) {
			login, loginAt = l, i
		}
		if r.stem(t.raw) != "" && stem == "" {
			stem, stemAt = t.raw, i
		}
		if authorAt < 0 && emailRE.MatchString(t.raw) {
			authorAt, author = i, r.author(t.raw)
		}
	}
	gh := c.find("github", "gh")
	push := c.findSet(pushWords)
	sign := c.findSet(signWords)
	ssh := c.find("ssh")
	key := c.findSet(keyWords)

	if gh >= 0 || login != "" || push >= 0 {
		at := min(nonNeg(gh, nonNeg(loginAt, push)), nonNeg(loginAt, nonNeg(gh, push)))
		h.add(at, pick("github", login))
		if push >= 0 && ssh < 0 && key < 0 && stem == "" {
			h.add(at, pick("ssh", ""))
		}
	}
	if sign >= 0 {
		s := stem
		if s == "" {
			s = r.keyHint(c)
		}
		h.add(sign, pick("signing", s))
		if ssh >= 0 && (key < 0 || ssh < sign-2 || ssh > sign+2) {
			h.add(ssh, pick("ssh", ""))
		}
		return
	}
	if authorAt >= 0 && (c.has("commit", "commits", "author", "authored", "as") || c.has("git")) {
		h.add(authorAt, pick("git", author))
		if stem == "" && key < 0 && ssh < 0 {
			return
		}
	} else if g := c.find("git", "@git"); g >= 0 && push < 0 {
		h.add(g, use("@git"))
	}
	if ssh >= 0 || key >= 0 || stem != "" {
		hint := stem
		if hint == "" {
			hint = r.keyHint(c)
		}
		h.add(nonNeg(stemAt, nonNeg(ssh, key)), pick("ssh", hint))
	}
}

// env reads environment variables: "set EDITOR to vim", "EDITOR=vim",
// "keep my PAGER". A credential's name has been refused already.
func (r *reader) env(c clause, h *hits, paths []pathTok, secret bool) {
	if secret {
		return
	}
	for i, t := range c.toks {
		if !envName(t.raw) {
			continue
		}
		name, value, hasEq := strings.Cut(t.raw, "=")
		if name == "PATH" && len(paths) > 0 {
			continue
		}
		if !hasEq {
			j := i + 1
			for j < len(c.toks) && (c.toks[j].w == "to" || c.toks[j].w == "should" || c.toks[j].w == "be" || c.toks[j].w == "auf" ||
				c.toks[j].w == "=" || c.toks[j].w == "is" || c.toks[j].w == "na" || c.toks[j].w == "as") {
				j++
			}
			if j > i+1 && j < len(c.toks) {
				value, hasEq = c.toks[j].raw, true
			}
		}
		if hasEq && value != "" {
			h.add(i, intent.Action{Op: intent.OpSetEnv, Name: name, Verb: "set", Value: value, HasValue: true})
		} else {
			h.add(i, intent.Action{Op: intent.OpSetEnv, Name: name, Verb: "inherit"})
		}
	}
}

// profileName returns the name a clause gives the profile: "call it NAME",
// "name the profile NAME", "pojmenuj to NAME", "a profile named NAME".
func profileName(c clause) (string, int) {
	for i, t := range c.toks {
		j := -1
		switch {
		case nameVerbs[t.w]:
			j = i + 1
			for j < len(c.toks) && (c.toks[j].w == "the" || c.toks[j].w == "sandbox" || c.toks[j].w == "profile") {
				j++
			}
			if j == i+1 {
				if j < len(c.toks) && (c.toks[j].w == "it" || c.toks[j].w == "to" || c.toks[j].w == "es" || c.toks[j].w == "this") {
					j++
				} else if t.w != "pojmenuj" {
					j = -1
				}
			}
		case t.w == "named" && i > 0 && c.toks[i-1].w == "profile":
			j = i + 1
		}
		if j > 0 && j < len(c.toks) && intent.ValidProfileName(c.toks[j].raw) && c.toks[j].w != "door" {
			return c.toks[j].raw, i
		}
	}
	return "", -1
}

// include reads a request to include one of the human's own profiles. The
// name must be one of theirs, and the clause must say profile or use an
// including verb, so a profile called "work" is not included by "make it
// work".
func (r *reader) include(c clause, h *hits) {
	if !r.including(c) {
		return
	}
	for i, t := range c.toks {
		if p := r.profile(t.raw); p != "" {
			h.add(i, intent.Action{Op: intent.OpIncludeProfile, Name: p})
			return
		}
	}
	if i := c.find("profile", "profiles", "profil"); i > 0 && c.hasSet(includeVerbs) || i > 0 && c.has("use", "add", "apply", "load") {
		if w := c.toks[i-1]; !notAName[w.w] && intent.ValidProfileName(w.raw) {
			r.missing = w.raw
		}
	}
}

func (r *reader) including(c clause) bool {
	return c.has("profile", "profiles", "profil") || c.hasSet(includeVerbs) || c.has("start from", "bring in", "based on", "base it on", "build on", "on top of")
}

// doorName is the name a clause gives a door, "web" when it gives none.
func doorName(c clause) string {
	for i, t := range c.toks {
		if t.w != "door" {
			continue
		}
		j := i + 1
		for j < len(c.toks) && (c.toks[j].w == "named" || c.toks[j].w == "called" || c.toks[j].w == "is") {
			j++
		}
		if j < len(c.toks) && doorRE.MatchString(c.toks[j].raw) && len(c.toks[j].raw) <= 32 && !fillers[c.toks[j].w] {
			return c.toks[j].raw
		}
	}
	return "web"
}

// file returns the project file a clause names for reading, and where.
func (r *reader) file(c clause) (string, int) {
	for i, t := range c.toks {
		switch low := strings.ToLower(t.raw); {
		case low == "readme" || strings.HasPrefix(low, "readme."):
			if low == "readme" {
				return "README.md", i
			}
			return t.raw, i
		case low == "dockerfile" || low == "containerfile" || strings.HasPrefix(low, "dockerfile.") || strings.HasPrefix(low, "containerfile."):
			return t.raw, i
		case strings.Contains(low, "/"):
		case strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".json") ||
			strings.HasSuffix(low, ".toml") || strings.HasSuffix(low, ".md") || strings.HasSuffix(low, ".txt") || strings.HasSuffix(low, ".lock"):
			if low != "snug.toml" {
				return t.raw, i
			}
		}
	}
	if i := c.find("compose file"); i >= 0 {
		return "docker-compose.yml", i
	}
	return "", -1
}

// finish adds the notes that go with what a request asked for, takes the
// default door when a named one was asked for too, and drops repeats. A
// second GitHub login cannot be pinned, so a request that also says so pins
// none.
func (r *reader) finish(acts []intent.Action) []intent.Action {
	has := func(a intent.Action) bool { return slices.Contains(acts, a) }
	named := slices.ContainsFunc(acts, func(a intent.Action) bool { return a.Op == intent.OpOpenDoor && a.Name != "web" })
	one := has(note("identity_one"))
	netTurn := has(use("@net"))
	if has(refuse("host_network")) {
		acts = slices.DeleteFunc(slices.Clone(acts), func(a intent.Action) bool { return a == use("@net") })
		netTurn = false
	}
	var out []intent.Action
	add := func(a intent.Action) {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, a := range acts {
		switch {
		case a.Op == intent.OpOpenDoor && a.Name == "web" && named:
			continue
		case one && a.Op == intent.OpSelectIdentity && a.Kind == "github":
			continue
		case a.Op == intent.OpNote && slices.Contains(out, a):
			continue
		}
		add(a)
		switch {
		case a == use("@net"):
			add(note("net"))
		case a == use("@target-rw"):
			add(note("defaults"))
		case a.Op == intent.OpGrantPath && a.Path == "{target}" && a.Access == "ro":
			add(note("readonly_target"))
		case a == use("@parent-ro"):
			add(note("parent_ro"))
		case a == use("@podman-socket") || a == use("@podman-build"):
			if !netTurn && !r.draftHas("@net") {
				add(note("podman_offline"))
			}
			if a.Name == "@podman-build" {
				add(note("podman_build"))
			}
		case a == refuse("deny_rule"):
			add(note("layering"))
		case a == refuse("secret_in_env"):
			add(note("secrets_file"))
		case a.Op == intent.OpGrantPath && a.Access == "rw":
			if slices.ContainsFunc(acts, func(b intent.Action) bool {
				return b.Op == intent.OpGrantPath && b.Access == "ro" && under(a.Path, b.Path)
			}) {
				add(note("layering"))
			}
		}
	}
	return out
}
