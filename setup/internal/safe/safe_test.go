package safe

import (
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                    "plain",
		"a\nb":                     "a\nb",
		"a\tb":                     "a  b",
		"x\x1b]0;title\x07y":       "x]0;titley",
		"x\x1b[2Jy":                "x[2Jy",
		"x\u009b31my":              "x31my",
		"x\x7fy":                   "xy",
		"evil\u202etxt.exe":        "eviltxt.exe",
		"a\u2066b\u2069c":          "abc",
		"zero\u200bwidth\ufeff":    "zerowidth",
		"tag\U000E0041\U000E0001s": "tags",
		"soft\u00adhyphen":         "softhyphen",
		"rlm\u200f\u061c":          "rlm",
		"line\u2028sep\u2029":      "linesep",
		"bad\xffutf8":              "bad\ufffdutf8",
		"\r\nwindows":              "\nwindows",
		"keeps é, ž and 漢字 intact": "keeps é, ž and 漢字 intact",
	} {
		if got := string(Clean(in)); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInlineCannotStartALine(t *testing.T) {
	got := Inline("id_x\nchecked: GitHub lists id_x\x1b[1A")
	if strings.Contains(got, "\n") || strings.Contains(got, "\x1b") {
		t.Errorf("%q", got)
	}
}
