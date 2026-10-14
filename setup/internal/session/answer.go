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

// answer applies r to the newest open question, the one the human last saw.
// A pick from a choice is returned as a turn, the same as a request.
func (s *Session) answer(ctx context.Context, r reply) (*Turn, []Line) {
	if len(s.pending) == 0 {
		return nil, []Line{info("there is no open question to answer; say what the sandbox needs, or /help.")}
	}
	p := s.pending[len(s.pending)-1]
	lead := info("(answering #%d)", p.N)
	if len(s.pending) == 1 {
		lead = Line{}
	}
	with := func(lines []Line) []Line {
		if lead.Text == "" {
			return lines
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
		case len(r.nums) == 1 && r.nums[0] >= 1 && r.nums[0] <= len(p.unclear.Choices):
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
