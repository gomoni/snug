package cli

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// refusalDoc is the SHARED shape: the keys every --dry-run --json document
// carries whether or not a policy was ever resolved. Mounts is a pointer so
// this test can tell ABSENT from EMPTY, which is the distinction issue #334
// turns on — `"mounts": []` says this sandbox mounts nothing, and a document
// that never got a policy has no business saying that.
type refusalDoc struct {
	Snug struct {
		Format         int    `json:"format"`
		Outcome        string `json:"outcome"`
		Lossy          bool   `json:"lossy"`
		ExitCode       int    `json:"exit_code"`
		PolicyResolved bool   `json:"policy_resolved"`
	} `json:"snug"`
	Refusal *struct {
		Message string `json:"message"`
	} `json:"refusal"`
}

// policyKeys are the top-level keys that only a described policy can justify.
// Presence is checked on the RAW object, not on a decoded struct, and that is
// not fussiness: `[]jsonMount(nil)` marshals to `null`, and unmarshalling
// `null` into a *[]T leaves the pointer nil — so a struct-based check reports
// "absent" for a key that is right there in the file. Measured: with the
// refusal document given a nil `mounts` field, the struct check passed and this
// one fails.
var policyKeys = []string{"mounts", "environment", "network", "bwrap", "target"}

// TestEveryRefusalClassProducesAParseableDocument is issue #334's measurement
// turned into a gate.
//
// WHAT WAS FOUND. renderJSON's doc comment and #316's merge message both stated,
// absolutely, that --dry-run --json produces a complete parseable document for
// EVERY exit code, and both named clang's SARIF zero-byte-on-redirect as the
// failure mode designed against. It was false for most refusal classes, because
// the real boundary was `pol != nil`: policy.Resolve returns a policy only for a
// Validate failure, so every refusal ahead of Validate never entered the JSON
// path at all. Measured on the binary, all exiting 77:
//
//	no OS runtime                          11204 bytes
//	@parent-ro binds an ancestor of $HOME       0
//	unknown profile                             0
//	target does not exist                       0
//	@net-host without --i-know                  0
//	@tmp-shared grant missing                   0
//	unparseable profile file                    0
//
// So `snug --dry-run --json x > policy.json` produced exactly the empty file the
// format documents itself as preventing, for the most ordinary user errors —
// which are also the ones a CI gate hits most.
//
// WHY IT ENUMERATES RATHER THAN SAMPLES. A test that checked a single
// unknown-profile case would pass forever while the set behind it drifted. The
// classes below are the measured ones, each driven through run() itself rather
// than through a renderer, so a refusal that stops reaching a renderer fails
// here even if every renderer still works.
//
// ITS PARTNER IS THE AST SWEEP BELOW, and the division is deliberate: this test
// covers the classes a DRY RUN can reach, and two funnels (refuseVerbatim's two
// sites, refuseWithoutDocument's one) sit on paths a dry run never takes —
// targetBusyError and openRuntimeDir are both inside `if !cfg.dryRun`. Those are
// covered by totality, not by enumeration. Neither test is redundant: this one
// would pass on a build where a new refusal bypassed the funnel and happened to
// be unreachable from these fixtures, and the sweep would pass on a build where
// every funnel was called and the document itself was broken.
func TestEveryRefusalClassProducesAParseableDocument(t *testing.T) {
	// A HOME of our own, so the @parent-ro case below is a fact about the
	// fixture rather than about whoever is running the suite.
	home := t.TempDir()
	proj := filepath.Join(home, "src", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sits DIRECTLY in $HOME, which @home provides as an empty tmpfs — the
	// refusal @parent-ro raises about an ancestor of $HOME.
	inHome := filepath.Join(home, "directly")
	if err := os.MkdirAll(inHome, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// A config directory with a profile file that does not parse. Set per
	// case, not here: every other case needs a config directory that LOADS.
	badCfg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(badCfg, "snug", "profiles.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badCfg, "snug", "profiles.d", "bad.toml"),
		[]byte("this is not toml {{{\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	goodCfg := t.TempDir()

	cases := []struct {
		name string
		cfg  config
		// xdg is the XDG_CONFIG_HOME this case runs under.
		xdg string
		// code is the exit status run() must return.
		code int
		// outcome is snug.outcome.
		outcome string
		// resolved is snug.policy_resolved: whether a policy existed to
		// describe. The pre-Validate classes are exactly the false ones, and
		// they are the classes that used to write nothing at all.
		resolved bool
		// says is a distinctive fragment of the refusal, so a case that starts
		// hitting a DIFFERENT refusal fails here instead of quietly grading
		// the wrong path. This is the positive control: without it every
		// assertion below passes on a fixture that refuses for its own
		// reasons.
		says string
	}{
		{
			name:    "unparseable profile file",
			cfg:     config{dryRun: true, json: true, target: proj},
			xdg:     badCfg,
			code:    77,
			outcome: "refused",
			says:    "did not load",
		},
		{
			name:    "unknown profile",
			cfg:     config{dryRun: true, json: true, target: proj, profiles: []policy.ProfileName{"@nosuchprofile"}},
			xdg:     goodCfg,
			code:    77,
			outcome: "refused",
			says:    "unknown profile",
		},
		{
			name:    "target does not exist",
			cfg:     config{dryRun: true, json: true, target: filepath.Join(proj, "nope")},
			xdg:     goodCfg,
			code:    77,
			outcome: "refused",
			says:    "no such file",
		},
		{
			name:    "tmp-shared grant missing",
			cfg:     config{dryRun: true, json: true, noDefaults: true, target: proj, profiles: []policy.ProfileName{"@tmp-shared"}},
			xdg:     goodCfg,
			code:    77,
			outcome: "refused",
			says:    "which does not exist",
		},
		{
			name:    "parent-ro binds an ancestor of HOME",
			cfg:     config{dryRun: true, json: true, target: inHome},
			xdg:     goodCfg,
			code:    77,
			outcome: "refused",
			says:    "ephemeral tmpfs",
		},
		// The two that already produced a document, kept in the table so the
		// enumeration states the WHOLE set rather than only the broken half —
		// and so a change that breaks these two is caught by the test that
		// exists for this subject.
		{
			name:     "no OS runtime",
			cfg:      config{dryRun: true, json: true, noDefaults: true, target: proj},
			xdg:      goodCfg,
			code:     77,
			outcome:  "refused",
			resolved: true,
			says:     "floor of the lattice",
		},
		{
			name:     "net-host without --i-know",
			cfg:      config{dryRun: true, json: true, target: proj, profiles: []policy.ProfileName{"@net-host"}},
			xdg:      goodCfg,
			code:     77,
			outcome:  "refused",
			resolved: true,
			says:     "--i-know",
		},
		// The success arm, which is what makes the assertions below mean
		// something: a build that emitted the refusal document unconditionally
		// would pass every refused case and fail this one.
		{
			name:     "ok",
			cfg:      config{dryRun: true, json: true, target: proj},
			xdg:      goodCfg,
			code:     0,
			outcome:  "ok",
			resolved: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", tc.xdg)
			stdout, stderr, code := captureRun(t, tc.cfg)

			if code != tc.code {
				t.Fatalf("run() returned %d, want %d\nstderr:\n%s", code, tc.code, stderr)
			}
			if len(stdout) == 0 {
				t.Fatalf("stdout is EMPTY — this is the zero-byte redirect the format documents "+
					"itself as preventing (issue #334)\nstderr:\n%s", stderr)
			}

			var doc refusalDoc
			if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
				t.Fatalf("stdout is not ONE parseable JSON document: %v\nstdout:\n%s", err, stdout)
			}
			if doc.Snug.Format != dryRunFormat {
				t.Errorf("snug.format is %d, want %d", doc.Snug.Format, dryRunFormat)
			}
			if doc.Snug.Outcome != tc.outcome {
				t.Errorf("snug.outcome is %q, want %q", doc.Snug.Outcome, tc.outcome)
			}
			// The exit code is compared against what run() ACTUALLY returned,
			// not against the table: Report.ExitCode is derived from refusedBy
			// rather than threaded through dryRun, and this is what stops that
			// derivation being a sentence nobody checks.
			if doc.Snug.ExitCode != code {
				t.Errorf("snug.exit_code is %d and run() returned %d — a consumer holding only "+
					"the redirected file would be told the wrong status", doc.Snug.ExitCode, code)
			}
			if doc.Snug.PolicyResolved != tc.resolved {
				t.Errorf("snug.policy_resolved is %v, want %v", doc.Snug.PolicyResolved, tc.resolved)
			}
			if doc.Snug.Lossy {
				t.Error("snug.lossy is true for an all-UTF-8 fixture, so a gate asserting it " +
					"would fail closed on an ordinary run")
			}

			// ABSENT, not empty, and not null either. A consumer reading
			// "mounts": [] as "this sandbox mounts nothing" is worse off than
			// one that finds no key and knows the question was never answered.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
				t.Fatalf("re-decoding the document as a raw object: %v", err)
			}
			for _, k := range policyKeys {
				_, present := raw[k]
				if tc.resolved && !present {
					t.Errorf("snug.policy_resolved is true and there is no %q key — the "+
						"boolean and the document disagree about whether a policy is "+
						"described", k)
				}
				if !tc.resolved && present {
					t.Errorf("no policy was resolved and the document still carries %q = %s. "+
						"Absent and empty must be distinguishable, and `null` is present",
						k, raw[k])
				}
			}

			if tc.outcome == "refused" {
				if doc.Refusal == nil {
					t.Fatalf("outcome is refused and there is no `refusal` object\nstdout:\n%s", stdout)
				}
				// The positive control. Without it this whole table passes on
				// a fixture that is refused for a reason nobody intended.
				if !strings.Contains(doc.Refusal.Message, tc.says) {
					t.Errorf("this case is meant to hit the %q refusal and the document says "+
						"%q — the fixture is grading a different path", tc.says, doc.Refusal.Message)
				}
				// The human text is still on stderr, where it always was. A
				// document that replaced it would be a regression in the
				// other direction.
				if !strings.Contains(stderr, "snug:") {
					t.Errorf("stderr carries no `snug:` diagnostic:\n%s", stderr)
				}
			} else if doc.Refusal != nil {
				t.Errorf("outcome is ok and a `refusal` object is present: %q", doc.Refusal.Message)
			}
		})
	}
}

// funnels is the CLOSED SET of ways a refusal may leave run(). Each member
// exists for a stated reason in main.go's own doc comments; this test's job is
// that the set stays closed, not that it stays small.
var funnels = map[string]string{
	"refuse":                "the no-policy arm: stderr, then the policy-less document",
	"refusePolicy":          "a policy exists and is described in full, both renderers",
	"refuseVerbatim":        "the diagnostic is not an error value (targetBusyError, openRuntimeDir)",
	"refuseWithoutDocument": "the ONE named exemption: the render failure itself",
}

// TestEveryRefusalInRunGoesThroughAFunnel is the totality half of issue #334,
// and it is why the fix is a funnel rather than five edited call sites.
//
// The defect was structural, not local: each refusal wrote its own stderr line
// and returned its own code, and whether a document came out depended on which
// side of policy.Resolve the refusal happened to be on. A SIXTH refusal added
// tomorrow would join the silent ones with nothing to notice — and the ticket
// asks, in its own words, for a test that "must fail if a new refusal path is
// added ahead of Validate without a decision".
//
// So this reads run's own AST and treats every non-zero exit as an obligation.
// It is an inventory of CALL SITES — a closed set the compiler already knows,
// whose entries are obligations — and not a catalogue of INPUTS, which is the
// open-set shape this repo deletes on sight. The distinction is CLAUDE.md's own
// standing ruling and it is what makes this test legitimate where a list of
// known-bad refusal spellings would not be.
//
// Two returns are NOT refusals and are allowed by their literal form rather
// than by name: `return 0` (the dry run succeeded) and `return code` (the
// PAYLOAD's own exit status, propagated verbatim, which is the one number in
// this function that is not snug's opinion about anything).
func TestEveryRefusalInRunGoesThroughAFunnel(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}

	var runFn *ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "run" {
			runFn = fn
		}
	}
	if runFn == nil {
		t.Fatal("no func run in main.go — this test has lost its subject and would " +
			"otherwise pass by finding nothing")
	}

	seen := map[string]int{}
	returns := 0
	ast.Inspect(runFn.Body, func(n ast.Node) bool {
		// A closure's return is not run's exit, so its body is skipped
		// wholesale rather than inspected and then explained away. The two
		// FuncLits in run today are the OnInfo callback and the runDir
		// cleanup defer; neither can end the process.
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		returns++
		switch v := ret.Results[0].(type) {
		case *ast.BasicLit:
			if v.Value != "0" {
				t.Errorf("%s: `return %s` — an exit status written as a literal. Every "+
					"non-zero exit out of run must go through a funnel (%s), or "+
					"--dry-run --json writes zero bytes for it",
					fset.Position(ret.Pos()), v.Value, funnelNames())
			}
		case *ast.Ident:
			if v.Name != "code" {
				t.Errorf("%s: `return %s` — the only bare identifier run may return is "+
					"`code`, the payload's own exit status. Everything else is snug's "+
					"verdict and belongs in a funnel (%s)",
					fset.Position(ret.Pos()), v.Name, funnelNames())
			}
		case *ast.CallExpr:
			id, ok := v.Fun.(*ast.Ident)
			if !ok {
				t.Errorf("%s: run returns a call this sweep cannot name, so it cannot say "+
					"whether it is a funnel", fset.Position(ret.Pos()))
				return true
			}
			if _, ok := funnels[id.Name]; !ok {
				t.Errorf("%s: `return %s(...)` is not one of the funnels (%s). Adding a new "+
					"one is a decision, not a refactor: it must say in its own doc comment "+
					"what document it writes and why, and be added to this test's set",
					fset.Position(ret.Pos()), id.Name, funnelNames())
				return true
			}
			seen[id.Name]++
		default:
			t.Errorf("%s: run returns an expression this sweep does not understand",
				fset.Position(ret.Pos()))
		}
		return true
	})

	// POSITIVE CONTROL, and it is the assertion most able to pass by accident:
	// a sweep that found no returns at all — a renamed function, a parser that
	// silently gave back an empty body — reports success. Measured against the
	// tree this landed on: 22 single-result returns in run.
	if returns < 15 {
		t.Fatalf("this sweep found only %d returns in run, which is too few for the "+
			"function that exists — it is measuring nothing", returns)
	}
	// And every funnel must actually BE used. A funnel with no call sites is a
	// name this test would keep accepting forever after the last caller left.
	for name := range funnels {
		if name == "refuseWithoutDocument" {
			// One site, and it is the exemption; asserted below by name so a
			// second one is a visible diff rather than an increment.
			continue
		}
		if seen[name] == 0 {
			t.Errorf("funnel %q has no call site in run — either it is dead and should go, "+
				"or a refusal that should use it does not", name)
		}
	}
	if seen["refuseWithoutDocument"] != 1 {
		t.Errorf("refuseWithoutDocument has %d call sites, want exactly 1. It is the single "+
			"named exemption from `every refusal writes a document`, and a second one is a "+
			"decision that has to be argued, not a line added", seen["refuseWithoutDocument"])
	}
}

func funnelNames() string {
	names := make([]string, 0, len(funnels))
	for n := range funnels {
		names = append(names, n)
	}
	// Sorted so the message is stable between runs; a test whose text depends
	// on map order is a diff nobody can review.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return strings.Join(names, ", ")
}

// captureRun drives run() with stdout and stderr SEPARATE, which is the whole
// property under test here and the one thing captureStdout (visible_test.go)
// deliberately does not give: that helper merges the two into one file because
// its subject is what a human sees in a terminal, where they interleave. This
// one's subject is the opposite — the document must be the WHOLE of stdout,
// with the prose on stderr — and a merged capture cannot tell the two apart.
func captureRun(t *testing.T, cfg config) (stdout, stderr string, code int) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	dir := t.TempDir()
	outF, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = outF, errF
	code = run(cfg)
	os.Stdout, os.Stderr = origOut, origErr
	outF.Close()
	errF.Close()

	ob, err := os.ReadFile(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	eb, err := os.ReadFile(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	return string(ob), string(eb), code
}
