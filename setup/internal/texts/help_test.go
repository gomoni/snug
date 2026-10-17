package texts

import (
	"strings"
	"testing"
)

// TestHelpIsTrueInRulesMode fails if the help text claims a model is running.
// The default mode reads requests by fixed rules, so "the model remembers"
// and "commands that skip the model" describe a process that is not there.
func TestHelpIsTrueInRulesMode(t *testing.T) {
	e, ok := Note("help")
	if !ok {
		t.Fatal("no help note")
	}
	s := e.String()
	for _, bad := range []string{"the model remembers", "skip the model"} {
		if strings.Contains(s, bad) {
			t.Errorf("help says %q:\n%s", bad, s)
		}
	}
	for _, want := range []string{"fixed rules", "--model", "--openai-url", "/save"} {
		if !strings.Contains(s, want) {
			t.Errorf("help lacks %q:\n%s", want, s)
		}
	}
}
