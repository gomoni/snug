package rules

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/intent"
)

// goldCase is one line of testdata/*.jsonl.
type goldCase struct {
	ID       string                                 `json:"id"`
	Tags     []string                               `json:"tags"`
	Tag      string                                 `json:"tag"`
	Context  intent.Context                         `json:"context"`
	Request  string                                 `json:"request"`
	Expected *struct{ Actions []map[string]string } `json:"expected"`
	Actions  []map[string]string                    `json:"actions"`
}

// canon is the action as a JSON object with sorted keys,
// the text of an ask blanked.
func canon(m map[string]string) string {
	m = maps(m)
	if m["op"] == "ask" {
		m["question"] = ""
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func maps(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// fields is an action in the shape of schema.json: the fields its op has.
func fields(a intent.Action) map[string]string {
	m := map[string]string{"op": a.Op}
	switch a.Op {
	case intent.OpUseProfile, intent.OpDropProfile, intent.OpIncludeProfile, intent.OpOpenDoor, intent.OpNameProfile:
		m["name"] = a.Name
	case intent.OpGrantPath:
		m["path"], m["access"] = a.Path, a.Access
	case intent.OpDropPath, intent.OpReadFile:
		m["path"] = a.Path
	case intent.OpStageBinary:
		m["host"], m["name"] = a.Host, a.Name
	case intent.OpSetEnv:
		m["name"], m["verb"] = a.Name, a.Verb
		if a.HasValue {
			m["value"] = a.Value
		}
	case intent.OpListIdentities:
		m["kind"] = a.Kind
	case intent.OpSelectIdentity:
		m["kind"], m["account"] = a.Kind, a.Account
	case intent.OpRefuse:
		m["code"] = a.Code
	case intent.OpNote:
		m["topic"] = a.Topic
	case intent.OpAsk:
		m["question"] = a.Question
	}
	return m
}

type score struct {
	n, exact, set, core int
	fails               []string
}

func (s score) String() string {
	f := func(k int) float64 { return float64(k) / float64(s.n) }
	return fmt.Sprintf("n=%d exact=%.3f set=%.3f core=%.3f", s.n, f(s.exact), f(s.set), f(s.core))
}

func multiset(xs []string) map[string]int {
	m := map[string]int{}
	for _, x := range xs {
		m[x]++
	}
	return m
}

func sameMultiset(a, b []string) bool {
	ma, mb := multiset(a), multiset(b)
	if len(ma) != len(mb) {
		return false
	}
	for k, v := range ma {
		if mb[k] != v {
			return false
		}
	}
	return true
}

func noNotes(xs []string) []string {
	return slices.DeleteFunc(slices.Clone(xs), func(s string) bool { return strings.Contains(s, `"op":"note"`) })
}

// scoreFile runs every case of a gold file through Read. An *intent.Unclear
// is scored as `ask`: it is the rules' way of asking the human, and an ask's
// text is not compared.
func scoreFile(t *testing.T, file string) (score, []map[string]any) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var s score
	var rows []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var c goldCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		want := c.Actions
		if c.Expected != nil {
			want = c.Expected.Actions
		}
		acts, err := Read(c.Context, c.Request)
		var u *intent.Unclear
		if errors.As(err, &u) {
			acts = []intent.Action{{Op: intent.OpAsk}}
		} else if err != nil {
			t.Fatal(err)
		}
		var g, w []string
		for _, a := range acts {
			g = append(g, canon(fields(a)))
		}
		for _, a := range want {
			w = append(w, canon(a))
		}
		exact, set, core := slices.Equal(g, w), sameMultiset(g, w), sameMultiset(noNotes(g), noNotes(w))
		s.n++
		if exact {
			s.exact++
		}
		if set {
			s.set++
		}
		if core {
			s.core++
		} else {
			s.fails = append(s.fails, fmt.Sprintf("%s %q\n    want %s\n    got  %s", c.ID, c.Request, strings.Join(noNotes(w), " "), strings.Join(noNotes(g), " ")))
		}
		id := c.ID
		if id == "" {
			id = c.Tag
		}
		rows = append(rows, map[string]any{"id": id, "request": c.Request, "exact": exact, "set": set, "core": core, "want": w, "got": g})
	}
	return s, rows
}

// TestGoldScores scores the rules on the gold sets: exact (the same action
// list), set (the same actions in any order) and core (the same, notes left
// out).
// The floors are the scores measured when the rules were written, so a change
// that loses a case fails here; one that gains should raise them. Set
// SNUG_SETUP_GOLD_REPORT to a directory to write each set's rows there.
func TestGoldScores(t *testing.T) {
	for _, g := range []struct {
		file             string
		exact, set, core float64
	}{
		{"gold.jsonl", 0.868, 0.868, 0.868},
		// Two typos that widen ("giv it acess to the internt", "let it wirte
		// to this projcet") are a question now, by design: a correction
		// never grants unasked.
		{"gold-v4.jsonl", 0.72, 0.72, 0.72},
		{"val-v4.jsonl", 0.666, 0.666, 0.666},
	} {
		s, rows := scoreFile(t, filepath.Join("testdata", g.file))
		t.Logf("%s: %s", g.file, s)
		if testing.Verbose() {
			for _, f := range s.fails {
				t.Log(f)
			}
		}
		f := func(k int) float64 { return float64(k) / float64(s.n) }
		if f(s.exact) < g.exact || f(s.set) < g.set || f(s.core) < g.core {
			t.Errorf("%s: %s, below the floor exact=%.3f set=%.3f core=%.3f", g.file, s, g.exact, g.set, g.core)
		}
		if dir := os.Getenv("SNUG_SETUP_GOLD_REPORT"); dir != "" {
			sum := map[string]any{"n": s.n, "exact": round(f(s.exact)), "set": round(f(s.set)), "core": round(f(s.core))}
			b, _ := json.MarshalIndent(map[string]any{"summary": sum, "rows": rows}, "", " ")
			name := "rules-" + strings.TrimSuffix(filepath.Base(g.file), ".jsonl") + ".json"
			if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func round(x float64) float64 { return float64(int(x*1000+0.5)) / 1000 }
