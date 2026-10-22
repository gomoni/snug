package policy

import "testing"

// TestVisibleTextKeepsAnEscapedTrailingQuote: VisibleText used to trim every
// `"` off both ends of %q's output, so text that needed escaping and ended in
// a quote lost the escaped quote too. A tab-indented gitconfig line is exactly
// that text.
func TestVisibleTextKeepsAnEscapedTrailingQuote(t *testing.T) {
	for in, want := range map[string]string{
		"\tx = \"a\"":     `\tx = \"a\"`,
		"\"\t\"":          `\"\t\"`,
		"\ty = \"b\\\"\"": `\ty = \"b\\\"\"`,
	} {
		if got := VisibleText(in); got != want {
			t.Errorf("VisibleText(%q) = %s, want %s", in, got, want)
		}
	}
}
