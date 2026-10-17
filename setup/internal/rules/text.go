package rules

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// tok is one word of a request. raw is as typed with the punctuation around it
// trimmed, for slots (a path, an env value, a profile name); w is the word the
// rules compare, lowercased and corrected to the lexicon when it is not a
// slot.
type tok struct {
	raw string
	w   string
	// q is true when the word ended in a question mark.
	q bool
	// parts are the corrected pieces of a hyphenated word that is not a
	// slot ("ssh-schlüssel"), each matched like a word of its own.
	parts []string
	// typed is w before any correction; fixed is true when a correction
	// changed w or a part into another word (not merely its plural).
	typed string
	fixed bool
}

// literal is c with every correction taken back: the words as typed.
func (c clause) literal() clause {
	out := clause{toks: make([]tok, len(c.toks))}
	for i, t := range c.toks {
		if !t.fixed {
			out.toks[i] = t
			continue
		}
		out.toks[i] = tok{raw: t.raw, w: t.typed, q: t.q, typed: t.typed}
		if t.parts != nil {
			for _, p := range strings.Split(t.typed, "-") {
				if p != "" {
					out.toks[i].parts = append(out.toks[i].parts, p)
				}
			}
		}
	}
	return out
}

// plural reports whether a and b are one word with and without a plural or
// third-person s: "edits" corrected to "edit" is the same word, not a guess.
func plural(a, b string) bool {
	return a == b+"s" || b == a+"s" || a == b+"es" || b == a+"es"
}

// fixed reports whether a correction changed any word of c.
func (c clause) fixed() bool {
	return slices.ContainsFunc(c.toks, func(t tok) bool { return t.fixed })
}

// is reports whether t is one of the words in m, as a whole or by a part.
func (t tok) is(m map[string]bool) bool {
	if m[t.w] {
		return true
	}
	for _, p := range t.parts {
		if m[p] {
			return true
		}
	}
	return false
}

// clause is a stretch of a request between separators.
type clause struct {
	toks []tok
}

func (c clause) text() string {
	raws := make([]string, len(c.toks))
	for i, t := range c.toks {
		raws[i] = t.raw
	}
	return strings.Join(raws, " ")
}

// separators end a clause. "a" is not one, although it is Czech for "and": it
// is also the English article, and a clause holding two requests is read as
// two anyway.
var separators = set("and also then plus und dann but aber ale")

// symbolSeparators join two requests as "and" does: "write here + internet".
var symbolSeparators = set("+ & — – / |")

// shortWords are frequent misspellings of short words, which the edit
// distance does not correct: below four letters one edit turns most words
// into others, so these are listed rather than guessed.
var shortWords = map[string]string{"nd": "and", "cal": "call", "giv": "give", "th": "the", "teh": "the",
	"plz": "please", "pls": "please", "u": "you", "ur": "your", "wth": "with", "w/": "with", "jut": "just", "nto": "not", "nott": "not", "dnot": "don't"}

// trimPunct strips what surrounds a word but cannot be part of a path, a name
// or a value, and reports whether it ended its clause: a comma, a semicolon,
// or the dot, question or exclamation mark that ends a sentence ("vim.").
func trimPunct(s string) (string, bool) {
	end := false
	s = strings.TrimLeft(s, "\"'(`[{“‘«")
	for len(s) > 0 {
		r, n := utf8.DecodeLastRuneInString(s)
		if !strings.ContainsRune(",;!?.:\"')`]}”’»", r) {
			break
		}
		if r == ',' || r == ';' || r == '.' || r == '!' || r == '?' {
			end = true
		}
		s = s[:len(s)-n]
	}
	return s, end
}

// lower is the comparison form of a raw word: lowercase, with an apostrophe
// spelled one way so "don't" and "don’t" are one word.
func lower(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "’", "'")
}

// split cuts a request into clauses: at a comma or semicolon, and at a
// separator word. A word is corrected unless keep says it is a slot.
func split(request string, keep func(raw string) bool) []clause {
	var out []clause
	var cur clause
	flush := func() {
		if len(cur.toks) > 0 {
			out = append(out, cur)
		}
		cur = clause{}
	}
	for _, f := range strings.Fields(request) {
		raw, end := trimPunct(f)
		if f == ".." {
			raw, end = f, false
		}
		q := strings.HasSuffix(f, "?")
		if raw == "" {
			if end {
				flush()
			}
			continue
		}
		low := lower(raw)
		typed := low
		if !keep(raw) {
			if s, ok := shortWords[low]; ok {
				low = s
			}
		}
		if separators[low] || symbolSeparators[raw] {
			flush()
			continue
		}
		t := tok{raw: raw, w: low, q: q, typed: typed}
		if !keep(raw) {
			t.w = correct(low)
			if strings.Contains(low, "-") && !lexicon[low] && wordLike(low) {
				for _, p := range strings.Split(low, "-") {
					if p != "" {
						c := correct(p)
						t.parts = append(t.parts, c)
						t.fixed = t.fixed || c != p
					}
				}
			}
		}
		t.fixed = t.fixed || t.w != typed && !plural(typed, t.w)
		cur.toks = append(cur.toks, t)
		if end {
			flush()
		}
	}
	flush()
	return out
}

// limit is how far a word may be from the lexicon word it is corrected to:
// none below four letters, where one edit turns most words into others.
func limit(n int) int {
	switch {
	case n < 4:
		return 0
	case n < 8:
		return 1
	}
	return 2
}

// correct returns the lexicon word w is a typo of, or w. A word already in the
// lexicon, a real word listed in notTypos, and a word holding anything but
// letters, an apostrophe or a dash stays as it is. When two lexicon words are
// equally close the one starting with the same letter wins; when that does
// not decide, w stays, because a guess between two words is not a correction.
func correct(w string) string {
	if lexicon[w] || notTypos[w] || !wordLike(w) {
		return w
	}
	n := utf8.RuneCountInString(w)
	max := limit(n)
	if max == 0 {
		return w
	}
	best, bestD, tie := "", max+1, false
	for _, v := range lexiconWords {
		m := utf8.RuneCountInString(v)
		if m-n > max || n-m > max {
			continue
		}
		d := distance(w, v)
		switch {
		case d < bestD:
			best, bestD, tie = v, d, false
		case d == bestD && best != "":
			bf, vf, wf := firstRune(best), firstRune(v), firstRune(w)
			switch {
			case vf == wf && bf != wf:
				best, tie = v, false
			case (vf == wf) == (bf == wf):
				tie = true
			}
		}
	}
	if best == "" || tie {
		return w
	}
	return best
}

func firstRune(s string) rune { r, _ := utf8.DecodeRuneInString(s); return r }

func wordLike(w string) bool {
	for _, r := range w {
		if !unicode.IsLetter(r) && r != '\'' && r != '-' {
			return false
		}
	}
	return true
}

// distance is the optimal string alignment distance between a and b, in
// runes: insertions, deletions, substitutions and transpositions of two
// adjacent runes each cost one, and no substring is edited twice.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[len(rb)]
}

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// find returns the index of the first token of c that is one of keys, -1 when
// none is. A key of several words matches that run of tokens.
func (c clause) find(keys ...string) int {
	best := -1
	for _, k := range keys {
		parts := strings.Fields(k)
		for i := 0; i+len(parts) <= len(c.toks); i++ {
			if best >= 0 && i >= best {
				break
			}
			ok := true
			for j, p := range parts {
				if t := c.toks[i+j]; t.w != p && !(len(parts) == 1 && slices.Contains(t.parts, p)) {
					ok = false
					break
				}
			}
			if ok {
				best = i
				break
			}
		}
	}
	return best
}

func (c clause) has(keys ...string) bool { return c.find(keys...) >= 0 }

// findSet is find for a set of single words.
func (c clause) findSet(m map[string]bool) int {
	for i, t := range c.toks {
		if t.is(m) {
			return i
		}
	}
	return -1
}

func (c clause) hasSet(m map[string]bool) bool { return c.findSet(m) >= 0 }

// lexiconWords is the lexicon in a fixed order, so a correction never depends
// on map iteration.
var lexiconWords []string

func init() {
	for w := range lexicon {
		lexiconWords = append(lexiconWords, w)
	}
	slices.Sort(lexiconWords)
}
