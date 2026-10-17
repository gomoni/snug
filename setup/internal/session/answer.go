package session

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// reply is a line that answers a question rather than asking for something:
// yes, no, or the numbers of what to keep.
type reply struct {
	yes, no bool
	nums    []int
}

var (
	yesWords  = set("y yes yep yeah ok okay sure all accept apply agreed go-ahead ano jo ja")
	noWords   = set("n no nope skip decline none nothing neither ne nein")
	numsRE    = regexp.MustCompile(`^(?:(?:only|just|jen|nur|keep)\s+)?\d+(?:\s*(?:,|and|&|a|und|\s)\s*\d+)*$`)
	numRE     = regexp.MustCompile(`\d+`)
	yesPhrase = []string{"yes please", "ok all", "all of it", "go ahead", "do it", "yes all", "sure go ahead", "apply all", "accept all"}
	noPhrase  = []string{"no thanks", "no thank you", "none of it", "skip it", "not now"}
)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// parseAnswer reads text as an answer to the open question, false when it is
// a request. Only whole lines count: "no network" is a request, "no" is an
// answer.
func parseAnswer(text string) (reply, bool) {
	t := strings.ToLower(strings.TrimSpace(text))
	t = strings.Trim(t, ".!?")
	t = strings.ReplaceAll(t, "#", "")
	t = strings.Join(strings.Fields(t), " ")
	switch {
	case t == "":
		return reply{}, false
	case yesWords[t] || slices.Contains(yesPhrase, t):
		return reply{yes: true}, true
	case noWords[t] || slices.Contains(noPhrase, t):
		return reply{no: true}, true
	case numsRE.MatchString(t):
		var r reply
		for _, m := range numRE.FindAllString(t, -1) {
			n, err := strconv.Atoi(m)
			if err != nil {
				return reply{}, false
			}
			r.nums = append(r.nums, n)
		}
		return r, true
	}
	return reply{}, false
}

// answerWords are the words an answer is made of: parseAnswer's yes and no
// words and the words that join numbers.
var answerWords = func() []string {
	var ws []string
	for w := range yesWords {
		ws = append(ws, w)
	}
	for w := range noWords {
		ws = append(ws, w)
	}
	return append(ws, "only", "just", "keep", "and", "nur", "jen", "und")
}()

// fixAnswer reads text as an answer with typos in its words: each word that is
// not an answer word and is one edit (a transposition counts as one) from
// exactly one kind of answer word becomes that word. It returns the corrected
// line and whether it changed anything and now parses as an answer. When words
// of different kinds are equally close, the ones starting with the same letter
// as the typo are the candidates. A word of two letters is never corrected,
// and neither is a digit.
func fixAnswer(text string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(text))
	t = strings.Trim(t, ".!?")
	toks := strings.Fields(strings.ReplaceAll(t, "#", ""))
	if len(toks) == 0 {
		return "", false
	}
	changed := false
	for i, w := range toks {
		if yesWords[w] || noWords[w] || numRE.MatchString(w) || slices.Contains(answerWords, w) {
			continue
		}
		if len([]rune(w)) < 3 {
			return "", false
		}
		var cands []string
		for _, a := range answerWords {
			if len([]rune(a)) >= 2 && editDistance(w, a) == 1 {
				cands = append(cands, a)
			}
		}
		if same := slices.DeleteFunc(slices.Clone(cands), func(c string) bool { return c[0] != w[0] }); len(same) > 0 {
			cands = same
		}
		kinds := map[string]bool{}
		for _, c := range cands {
			switch {
			case yesWords[c]:
				kinds["yes"] = true
			case noWords[c]:
				kinds["no"] = true
			default:
				kinds[c] = true
			}
		}
		if len(kinds) != 1 {
			return "", false
		}
		slices.Sort(cands)
		toks[i] = cands[0]
		changed = true
	}
	fixed := strings.Join(toks, " ")
	if _, ok := parseAnswer(fixed); !ok || !changed {
		return "", false
	}
	return fixed, true
}

// editDistance is the optimal string alignment distance in runes: an
// insertion, a deletion, a substitution or a swap of two neighbours is one.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			c := 1
			if ra[i-1] == rb[j-1] {
				c = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+c)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

// answerTypo handles a line the interpreter did not understand but that is an
// answer with typos, for the question printed just before it. A "no" is a
// narrowing, so it is applied and the reading is said. Anything else (yes, a
// list of items to keep) would widen, so it is only asked: nothing changes
// until the human types the corrected line, which then answers the same
// question. The answer line is attributed to the question with Q.
func (s *Session) answerTypo(ctx context.Context, text string) (*Turn, []Line, bool) {
	p, ok := s.find(s.before)
	if !ok {
		return nil, nil, false
	}
	fixed, ok := fixAnswer(text)
	if !ok {
		return nil, nil, false
	}
	r, _ := parseAnswer(fixed)
	if r.no {
		t, lines := s.answer(ctx, r)
		return t, append([]Line{info("(read %s as %s)", quote(text), quote(fixed))}, lines...), true
	}
	l := info("%s is not an answer I know. Did you mean %s to #%d? Nothing changed; type %s to confirm (#%d: %s).",
		quote(text), quote(fixed), p.N, quote(fixed), p.N, p.Answer)
	l.Q = p.N
	return nil, []Line{l}, true
}

// answer applies r to the question the front end printed last in answer to
// the line before this one (Heard, Shown), and says which it answered. With no
// such question still open it applies nothing and lists what is open: a "yes"
// typed under a refusal or a listing must not land on a card printed further
// up. A pick from a choice is returned as a turn, the same as a request.
func (s *Session) answer(ctx context.Context, r reply) (*Turn, []Line) {
	if len(s.pending) == 0 {
		return nil, []Line{info("there is no open question to answer; say what the sandbox needs, or /help.")}
	}
	p, ok := s.find(s.before)
	if !ok {
		out := []Line{info("a bare yes, no or number answers the question printed just before it, and the last thing printed asked none; nothing changed. Open:")}
		for _, q := range s.pending {
			out = append(out, info("  #%d: %s", q.N, q.Answer))
		}
		return nil, out
	}
	lead := info("(answering #%d)", p.N)
	with := func(lines []Line) []Line {
		if _, open := s.find(p.N); open {
			// The answer did not close it, so it is still the question
			// the human last read about.
			lead.Q = p.N
		}
		return append([]Line{lead}, lines...)
	}
	switch p.Kind {
	case Card:
		switch {
		case r.yes:
			return nil, with(s.Accept(ctx, p.N))
		case r.no:
			return nil, with(s.Decline(p.N))
		}
		return nil, with(s.AcceptSome(ctx, p.N, r.nums))
	case Identity:
		switch {
		case r.no:
			return nil, with(s.Pick(ctx, p.kind, "none"))
		case len(r.nums) == 1 && r.nums[0] >= 1 && r.nums[0] <= len(p.shown):
			return nil, with(s.Pick(ctx, p.kind, p.shown[r.nums[0]-1]))
		}
		return nil, with([]Line{info("#%d is answered with the number of one listed %s, or no: %s.", p.N, kindName(p.kind), p.Answer)})
	case Choice:
		switch {
		case r.no:
			return nil, with(s.Decline(p.N))
		case r.yes && len(p.unclear.Choices) == 1:
			r.nums = []int{1}
		}
		if len(r.nums) == 1 && r.nums[0] >= 1 && r.nums[0] <= len(p.unclear.Choices) {
			s.close(p.N)
			t, out := s.understood(ctx, p.said, p.unclear.Choices[r.nums[0]-1].Actions)
			return t, with(out)
		}
		return nil, with([]Line{info("#%d is answered with one number from 1 to %d.", p.N, len(p.unclear.Choices))})
	}
	switch {
	case r.yes:
		return nil, with(s.Accept(ctx, p.N))
	case r.no:
		return nil, with(s.Decline(p.N))
	}
	return nil, with([]Line{info("#%d is answered with yes or no: %s.", p.N, p.Answer)})
}
