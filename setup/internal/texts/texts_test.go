package texts

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/intent"
)

var ws = regexp.MustCompile(`\s+`)

// normalise reduces a source file to the words a reader would see: comment
// markers removed, Go string-literal fragments joined, whitespace collapsed.
func normalise(path, s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "//"):
			l = strings.TrimPrefix(l, "//")
		case strings.HasPrefix(l, "#"):
			l = strings.TrimPrefix(l, "#")
		case strings.HasSuffix(path, ".go") && strings.HasPrefix(l, `"`):
			l = strings.TrimSuffix(l, "+")
			l = strings.TrimSuffix(l, ",")
			l = strings.TrimSuffix(strings.TrimPrefix(l, `"`), `"`)
			l = strings.ReplaceAll(strings.ReplaceAll(l, `\n`, ""), `\"`, `"`)
		}
		out = append(out, l)
	}
	return ws.ReplaceAllString(strings.Join(out, " "), " ")
}

func TestQuotesAreStillInSnugSources(t *testing.T) {
	cache := map[string]string{}
	n := 0
	for _, e := range All() {
		for _, q := range e.Quotes {
			n++
			src, ok := cache[q.Src]
			if !ok {
				raw, err := os.ReadFile(filepath.Join("..", "..", "..", q.Src))
				if err != nil {
					t.Fatal(err)
				}
				src = normalise(q.Src, string(raw))
				cache[q.Src] = src
			}
			if !strings.Contains(src, ws.ReplaceAllString(q.Text, " ")) {
				t.Errorf("not in %s any more: %q", q.Src, q.Text)
			}
		}
	}
	if n == 0 {
		t.Fatal("no quotes checked")
	}
}

func TestEveryCodeAndTopicHasText(t *testing.T) {
	for _, c := range append(append([]string{}, intent.Refusals...),
		draft.CodeKernelPath, draft.CodeReservedEnv, draft.CodeBadValue, draft.CodeNotGranted,
		draft.CodeUnknownList, draft.CodeNoVerb, draft.CodeNoSuchEntry, draft.CodeHostPointer) {
		if e, ok := Refusal(c); !ok || e.String() == "" {
			t.Errorf("no text for refusal %s", c)
		}
	}
	for _, c := range intent.Topics {
		if e, ok := Note(c); !ok || e.String() == "" {
			t.Errorf("no text for note %s", c)
		}
	}
}
