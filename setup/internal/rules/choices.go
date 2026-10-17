package rules

import (
	"regexp"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/intent"
)

// option is one reading offered when a request was not understood, with the
// words that bring it to mind.
type option struct {
	acts  []intent.Action
	words []string
}

var options = []option{
	{[]intent.Action{{Op: intent.OpAnalyze}}, strings.Fields("analyze analyse project files repo look check scan go golang node npm python pip rust cargo language toolchain setup needs")},
	{[]intent.Action{use("@net"), note("net")}, strings.Fields("internet network net online download downloads web reach fetch go modules npm pip cargo install")},
	{[]intent.Action{use("@podman-socket")}, strings.Fields("docker podman container containers compose daemon run")},
	{[]intent.Action{use("@podman-build")}, strings.Fields("build image images dockerfile containerfile")},
	{[]intent.Action{{Op: intent.OpGrantPath, Path: "{target}", Access: "ro"}, note("readonly_target")}, strings.Fields("read-only readonly read only protect touch modify")},
	{[]intent.Action{use("@parent-ro"), note("parent_ro")}, strings.Fields("parent sibling siblings other projects next")},
	{[]intent.Action{pick("github", "")}, strings.Fields("github gh account login logins")},
	{[]intent.Action{pick("ssh", "")}, strings.Fields("ssh key keys push clone")},
	{[]intent.Action{pick("signing", "")}, strings.Fields("sign signing signature signed commit commits")},
	{[]intent.Action{use("@git")}, strings.Fields("git author name email identity commit")},
	{[]intent.Action{use("@claude")}, strings.Fields("claude anthropic agent")},
	{[]intent.Action{{Op: intent.OpAdvise}}, strings.Fields("recommend suggest identity identities advice which who")},
	{[]intent.Action{{Op: intent.OpListIdentities, Kind: "ssh"}}, strings.Fields("list keys have show")},
	{[]intent.Action{{Op: intent.OpShow}}, strings.Fields("show print display config draft profile")},
	{[]intent.Action{{Op: intent.OpSave}}, strings.Fields("save write done finish")},
	{[]intent.Action{{Op: intent.OpUndo}}, strings.Fields("undo revert back")},
	{[]intent.Action{note("help")}, strings.Fields("help what can do how hello")},
}

// fallback is what is offered when no option shares a word with the request.
var fallback = []int{0, 11, 16}

// choices returns up to three readings for the part of a request that was not
// understood, best first. With actions understood from the rest, the first
// choice is those alone and every other choice adds to them. A choice is
// offered, never applied: only the human's pick submits one.
func choices(unknown string, understood []intent.Action) []intent.Choice {
	if name := bareName(unknown); name != "" {
		path := "{target}/" + name
		return []intent.Choice{
			{Actions: append(slices.Clone(understood), intent.Action{Op: intent.OpGrantPath, Path: path, Access: "rw"})},
			{Actions: append(slices.Clone(understood), intent.Action{Op: intent.OpGrantPath, Path: path, Access: "ro"})},
		}
	}
	var words []string
	for _, cl := range split(unknown, func(string) bool { return false }) {
		for _, t := range cl.toks {
			if !fillers[t.w] {
				words = append(words, t.w)
			}
		}
	}
	type scored struct {
		i     int
		score float64
	}
	var ranked []scored
	for i, o := range options {
		s := 0.0
		for _, w := range words {
			best := 0.0
			for _, k := range o.words {
				switch d := distance(w, k); {
				case d == 0:
					best = 1
				case d <= limit(len([]rune(w))) && best < 0.5:
					best = 0.5
				}
			}
			s += best
		}
		if s > 0 && !covered(o.acts, understood) && !(len(understood) > 0 && control(o.acts)) {
			ranked = append(ranked, scored{i, s})
		}
	}
	slices.SortStableFunc(ranked, func(a, b scored) int {
		switch {
		case a.score > b.score:
			return -1
		case a.score < b.score:
			return 1
		}
		return 0
	})
	n := 3
	var out []intent.Choice
	if len(understood) > 0 {
		out = append(out, intent.Choice{Actions: slices.Clone(understood)})
		n = 2
	}
	var picked []int
	for _, r := range ranked {
		if len(picked) == n {
			break
		}
		picked = append(picked, r.i)
	}
	for _, i := range fallback {
		if len(picked) == n || len(understood) > 0 {
			break
		}
		if !slices.Contains(picked, i) && !covered(options[i].acts, understood) {
			picked = append(picked, i)
		}
	}
	for _, i := range picked {
		out = append(out, intent.Choice{Actions: append(slices.Clone(understood), options[i].acts...)})
	}
	return out
}

// control reports whether acts only steer the session (analysis, advice, a
// listing, show, save, undo, help). Beside a request understood in part they
// are noise: the human asked for a change.
func control(acts []intent.Action) bool {
	for _, a := range acts {
		switch a.Op {
		case intent.OpAnalyze, intent.OpAdvise, intent.OpListIdentities, intent.OpShow, intent.OpSave, intent.OpUndo, intent.OpNote:
		default:
			return false
		}
	}
	return true
}

// covered reports whether every action of acts is already in understood.
func covered(acts, understood []intent.Action) bool {
	for _, a := range acts {
		if !slices.Contains(understood, a) {
			return false
		}
	}
	return len(understood) > 0
}

var bareNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// bareName returns the name in a clause that asks to write or read something
// by a bare word ("write to docs"): the last word after a write or read word
// that is not a filler, a preposition or a word of the lexicon. A bare word is
// too likely to be prose to be a path, so the request is not read as a grant;
// the readings offered are the two grants it could mean, under the target.
func bareName(unknown string) string {
	for _, cl := range split(unknown, func(string) bool { return false }) {
		verb := slices.IndexFunc(cl.toks, func(t tok) bool { return writeWords[t.w] || readWords[t.w] })
		if verb < 0 {
			continue
		}
		last := cl.toks[len(cl.toks)-1]
		if len(cl.toks)-1 <= verb || fillers[last.w] || lexicon[last.w] || prepositions[last.w] || !bareNameRE.MatchString(last.raw) {
			continue
		}
		return last.raw
	}
	return ""
}

var prepositions = set("to into in on for at of onto")
