package profile

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// ── the runnable-example sweep (issue #44 follow-up) ────────────────────────
//
// README.md's five-verb example and VERIFY.md's §6j wrote
// `[profile.mytools.environ.inherit] COLORTERM = true` with no `declare`
// block. COLORTERM has no roster row (internal/policy/envtypes.go), so once
// the roster flip landed, the WHOLE profile was refused at parse time — and
// nothing caught it: VERIFY.md "earns its place by being executable" but
// nothing runs it except a human, and README's examples are never run at all.
// VERIFY.md's own §6j exited 77 before its expected-output fence was ever
// printed. Both documents now carry a `declare` block; this file is what
// makes the NEXT such change fail `go test` instead of a human's terminal.
//
// THE EXTRACTION RULE, mechanical rather than a hand-maintained list of line
// ranges — each step is load-bearing and is exercised by a case in the two
// documents themselves, not a hypothetical:
//
//  1. Every fenced code block (``` … ```) in the document, whatever its
//     language tag. README spells its profiles in ```toml fences; VERIFY.md
//     mostly does not — most of its examples are plain ```bash.
//  2. Within each fenced block, look for shell heredocs: a line matching
//     `<<-?['"]?WORD['"]?` opens one, a later line that is EXACTLY `WORD`
//     closes it. If a block contains at least one heredoc, ONLY the heredoc
//     BODIES are candidates — the `cat > …toml <<EOF` line, the closing
//     delimiter, and any shell that runs afterwards are discarded outright,
//     because they are not TOML and parsing them as TOML would fail for a
//     reason that has nothing to do with the profile inside. This is what
//     pulls VERIFY §6j's `[profile.mytools]` out of a ```bash fence that
//     also contains `COLORTERM=truecolor … | sed -n …` on the next line.
//  3. Of what step 1/2 produced, skip leading blank and `#`-comment lines,
//     then require the very next line to be a COMPLETE `[profile.NAME]`
//     table header (nothing after the closing `]` but whitespace). Anything
//     that fails this is out of scope, and the rule is deliberately blind to
//     WHY: a bare `[profile.NAME.identity]` sub-table with no top-level
//     header before it, a `defaults = [...]` config.toml line, a JSON
//     heredoc (`<<EOF` … a `.claude/settings.json` body), a Python heredoc
//     (`<<'EOF'` … `probe.py`), and — the case that would otherwise be a
//     false positive — VERIFY §6h's `one() { … }` shell function, whose
//     FIRST line is `one() {  # one <name> <toml-body>` even though a later
//     line inside a single-quoted argument reads `[profile.c]` for one of
//     its three DELIBERATELY-REFUSED fixtures. All five fail "is the first
//     substantive line a complete profile header", and for all five that is
//     the right verdict, not a gap — §6h's fixtures are refused ON PURPOSE
//     (bad verb, forbidden name) and asserting parse() succeeds on them would
//     be asserting the wrong thing.
//
// WHAT THIS DELIBERATELY DOES NOT COVER: a profile spelled through
// `printf '[profile.x]\n...'` rather than a heredoc or a fenced ```toml
// block — VERIFY.md does this over a dozen times. It is excluded by
// construction rather than by a special case: the physical line always reads
// `printf '...' '[profile.x]' ...`, never `[profile.x]` alone, so step 3's
// exact-header-line test already says no. Reconstructing these would mean
// interpreting printf's OWN escaping rules — a second parser this sweep would
// then have to keep correct — for examples that are shell-escaping
// demonstrations first and profile text second. The two examples this sweep
// exists to protect (README's five-verb block, VERIFY §6j) are both
// heredoc/fenced-block spelled, not printf-spelled.
//
// Lives in internal/profile, not cmd/snug or internal/policy: `parse` (below)
// is what already runs a profile file through BOTH the profile grammar and
// policy.ValidateEnvGrants (file.go's parse calls it directly) — one call is
// the real path a file on disk goes through, not a reimplementation of it.
// internal/policy stays pure; this test only reads the two committed
// markdown files, which is no different from Load reading profiles.d.

var (
	heredocStart  = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*$`)
	shellVarRef   = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	profileHeader = regexp.MustCompile(`^\[profile\.\S+\]\s*$`)
)

type docCandidate struct {
	source string // human-readable locator, for a failing test's error text
	text   string
}

// extractFences returns the BODY of every fenced code block in text (fence
// lines themselves excluded), tagged with the 1-based line number of the
// first body line.
func extractFences(text string) []docCandidate {
	lines := strings.Split(text, "\n")
	var out []docCandidate
	inFence := false
	var cur []string
	start := 0
	for i, line := range lines {
		if !inFence {
			if strings.HasPrefix(line, "```") {
				inFence = true
				cur = nil
				start = i + 2 // 1-based line number of the first body line
			}
			continue
		}
		if strings.TrimRight(line, " \t") == "```" {
			inFence = false
			out = append(out, docCandidate{
				source: fmt.Sprintf("line %d", start),
				text:   strings.Join(cur, "\n"),
			})
			continue
		}
		cur = append(cur, line)
	}
	return out
}

// extractHeredocs pulls every heredoc BODY out of one fenced block's text. See
// the file comment, step 2, for why the surrounding shell is discarded rather
// than kept as a candidate of its own.
func extractHeredocs(fenceSource, text string) []docCandidate {
	lines := strings.Split(text, "\n")
	var out []docCandidate
	for i := 0; i < len(lines); i++ {
		m := heredocStart.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		delim := m[1]
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.TrimRight(lines[j], " \t") == delim {
				break
			}
			body = append(body, lines[j])
		}
		out = append(out, docCandidate{
			source: fmt.Sprintf("%s, heredoc <<%s", fenceSource, delim),
			text:   strings.Join(body, "\n"),
		})
		i = j
	}
	return out
}

// inScope is step 3 of the file comment's rule: the first substantive line
// must itself be a complete `[profile.NAME]` header, or the candidate is a
// fragment (or not TOML at all) and is silently excluded.
func inScope(text string) (string, bool) {
	lines := strings.Split(text, "\n")
	i := 0
	for i < len(lines) {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "#") {
			i++
			continue
		}
		break
	}
	if i >= len(lines) || !profileHeader.MatchString(strings.TrimSpace(lines[i])) {
		return "", false
	}
	return strings.Join(lines[i:], "\n"), true
}

// substituteShellVars replaces every bash-style `$NAME` reference ($SC, $X,
// $HOME, ...) with a deterministic, always-absolute stand-in path.
//
// This does not evaluate the shell — it does not need to. `parse` (the
// profile-file parser, called below) never checks that a path EXISTS; that is
// Resolve's job, and this sweep deliberately stops at parse()+
// ValidateEnvGrants (the file comment says why). A `$SC`-shaped value only has
// to stay syntactically absolute for parse() to accept it, which a fixed
// stand-in guarantees without knowing what the real shell would have put
// there.
func substituteShellVars(text string) string {
	return shellVarRef.ReplaceAllString(text, "/tmp/docexample-$1")
}

// extractProfileExamples applies the full rule to one markdown file.
func extractProfileExamples(t *testing.T, path string) []docCandidate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var cands []docCandidate
	for _, fence := range extractFences(string(data)) {
		fenceSource := fmt.Sprintf("%s %s", path, fence.source)
		heredocs := extractHeredocs(fenceSource, fence.text)
		if len(heredocs) > 0 {
			cands = append(cands, heredocs...)
			continue
		}
		cands = append(cands, docCandidate{source: fenceSource, text: fence.text})
	}

	var out []docCandidate
	for _, c := range cands {
		body, ok := inScope(c.text)
		if !ok {
			continue
		}
		out = append(out, docCandidate{source: c.source, text: substituteShellVars(body)})
	}
	return out
}

// TestDocumentedExampleProfilesParse is the sweep. It has to run against the
// SAME entry point a file on disk goes through, and it has to be unable to
// pass by matching nothing.
func TestDocumentedExampleProfilesParse(t *testing.T) {
	var all []docCandidate
	all = append(all, extractProfileExamples(t, "../../README.md")...)
	all = append(all, extractProfileExamples(t, "../../VERIFY.md")...)

	// NON-VACUITY CONTROL. README and VERIFY.md between them write at least
	// ten in-scope profile examples today (five apiece); if the extraction
	// rule ever stops matching — a doc reformatted to use tildes instead of
	// backticks, a language-tag change that this rule does not in fact
	// depend on but a future edit might make it start depending on, or
	// simply every example rewritten as printf — this is what turns that
	// into a failure instead of a sweep that silently checks nothing, the
	// exact shape CLAUDE.md's "pasta" vs "pasta.avx2" scar describes.
	const floor = 8
	if len(all) < floor {
		t.Fatalf("found only %d in-scope profile example(s) across README.md and "+
			"VERIFY.md, want at least %d; the extraction rule stopped matching "+
			"something (see the file comment for what it looks for), or the "+
			"documents genuinely lost their examples", len(all), floor)
	}

	for _, c := range all {
		if _, err := parse([]byte(c.text), c.source, false); err != nil {
			t.Errorf("%s does not parse as a runnable snug profile:\n%v\n--- example text ---\n%s",
				c.source, err, c.text)
		}
	}
}
