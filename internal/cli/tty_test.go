package cli

// tty_test.go covers the two screens that speak about the terminal: --dry-run's
// TTY block and the ~/.claude/CLAUDE.md snug injects for the agent. Issue #528.
//
// BOTH ARMS, ALWAYS. The failure these tests exist against is not a missing
// sentence — it is the arm that says nothing while sounding like an all-clear.
// "shared session — job control works" was the whole of the old block, and it
// is true and reads as a posture; what it left out is that the payload can
// write escape sequences to the operator's emulator (OSC 52 sets a clipboard),
// which snug does not filter and will not.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// resolveForTTY is resolveFor with the terminal shape of the run made explicit
// — the field the whole TTY block derives from.
func resolveForTTY(t *testing.T, sel []policy.ProfileName, terminals policy.StdioSet, legacyTIOCSTI bool) *policy.Policy {
	t.Helper()
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{
		Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
		StdioTerminals: terminals, LegacyTIOCSTI: legacyTIOCSTI,
	}
	p, err := policy.Resolve(reg, sel, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	return p
}

func TestDescribeTTYNamesEveryReasonAndTheResidual(t *testing.T) {
	all := policy.StdinTerminal | policy.StdoutTerminal | policy.StderrTerminal
	for _, tc := range []struct {
		name      string
		why       policy.NewSessionReason
		terminals policy.StdioSet
		want      []string
		notWant   []string
		newSess   bool
		wantJSON  []string
	}{
		{
			name:      "no terminal on snug's stdio",
			why:       policy.NewSessionNoTerminal,
			terminals: 0,
			newSess:   true,
			want:      []string{"--new-session", "is a terminal", "no job control to lose"},
			notWant:   []string{"TIOCSTI is disabled kernel-wide", "Your terminal IS shared"},
			wantJSON:  []string{"no_terminal"},
		},
		{
			// REDTEAM, round two, and the row that was WRONG rather than
			// missing: it used to leave StdioTerminals at zero, which cannot
			// happen — the TIOCSTI-only reason means NewSessionNoTerminal is
			// unset, and that is exactly the case where a terminal IS shared.
			// The impossible pairing is what hid the defect: with the real
			// pairing the block claimed "the sandbox is kept out of your
			// terminal" for a run whose payload holds the operator's pty on
			// all three descriptors, measured with legacy_tiocsti forced to 1.
			// This is the common shape on any kernel without the sysctl, where
			// legacyTIOCSTI() fails safe to true.
			name:      "legacy TIOCSTI, terminal still shared",
			why:       policy.NewSessionTIOCSTI,
			terminals: all,
			newSess:   true,
			want: []string{"--new-session", "TIOCSTI", "Your terminal IS shared",
				"stdin, stdout and stderr", "does\n         NOT take back the descriptors"},
			notWant:  []string{"no job control to lose", "kept out of your terminal"},
			wantJSON: []string{"tiocsti"},
		},
		{
			// Both reasons, which requires the empty descriptor set: the
			// no-terminal reason IS "StdioTerminals is empty".
			name:      "both reasons, no terminal anywhere",
			why:       policy.NewSessionTIOCSTI | policy.NewSessionNoTerminal,
			terminals: 0,
			newSess:   true,
			want:      []string{"--new-session", "TIOCSTI", "no job control to lose"},
			notWant:   []string{"Your terminal IS shared"},
			wantJSON:  []string{"tiocsti", "no_terminal"},
		},
		{
			// THE ARM THAT MATTERS. No reason applies, so snug asks for
			// nothing — and the screen has to say what is shared rather than
			// stop at "job control works".
			name:      "shared terminal on all three",
			why:       0,
			terminals: all,
			newSess:   false,
			want: []string{"shared session", "OSC 52", "/dev/console",
				"stdin, stdout and stderr", "ALL THREE"},
			wantJSON: nil,
		},
		{
			// REDTEAM, this round: the shared arm used to assert /dev/console
			// and tell the reader to "redirect snug's output" whatever the
			// shape. Measured, one pty on one descriptor at a time: bwrap
			// creates /dev/console ONLY when snug's stdout is a terminal, and
			// `snug ... > log` leaves the channel open on stderr, where
			// redirecting output closes nothing. Both sentences were false in
			// this shape, on the screen whose whole job is being trusted.
			name:      "terminal on stderr alone",
			why:       0,
			terminals: policy.StderrTerminal,
			newSess:   false,
			want: []string{"shared session", "stderr", "no /dev/console here",
				"ALL THREE"},
			notWant:  []string{"binds that same pty as /dev/console"},
			wantJSON: nil,
		},
		{
			name:      "terminal on stdout alone",
			why:       0,
			terminals: policy.StdoutTerminal,
			newSess:   false,
			want:      []string{"stdout", "binds that same pty as /dev/console"},
			notWant:   []string{"no /dev/console here"},
			wantJSON:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			describeTTY(&buf, Report{
				NewSession:     tc.newSess,
				NewSessionWhy:  tc.why,
				StdioTerminals: tc.terminals,
			})
			got := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("the TTY block does not mention %q:\n%s", want, got)
				}
			}
			for _, no := range tc.notWant {
				if strings.Contains(got, no) {
					t.Errorf("the TTY block states %q, which does not apply to this run:\n%s", no, got)
				}
			}
			gotJSON := ttyReasons(tc.why)
			if len(gotJSON) != len(tc.wantJSON) {
				t.Fatalf("ttyReasons = %v, want %v", gotJSON, tc.wantJSON)
			}
			for i, want := range tc.wantJSON {
				if gotJSON[i] != want {
					t.Errorf("ttyReasons[%d] = %q, want %q", i, gotJSON[i], want)
				}
			}
		})
	}
}

// The injected guidance claims in its own header to describe "what is actually
// true", so the terminal it describes must be the terminal this run has. An
// agent told nothing about its stdout has no way to know that an escape
// sequence it emits is an action on the operator's machine rather than a
// character on a screen.
func TestClaudeGuidanceTerminalSectionTracksTheRun(t *testing.T) {
	sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}

	all := policy.StdinTerminal | policy.StdoutTerminal | policy.StderrTerminal
	shared := string(claudeGuidance(resolveForTTY(t, sel, all, false)))
	if !strings.Contains(shared, "operator's real terminal") || !strings.Contains(shared, "OSC 52") {
		t.Errorf("an interactive run shares the operator's terminal and the guidance does not "+
			"say so:\n%s", shared)
	}
	if strings.Contains(shared, "no controlling terminal") {
		t.Errorf("the guidance claims there is no controlling terminal in a run that has "+
			"one:\n%s", shared)
	}

	// The DESCRIPTOR is named from the policy, not assumed. An agent told its
	// stdout is a terminal when stdout is a file can check and find that false,
	// and this file's header claims it "describes what is actually true".
	stderrOnly := string(claudeGuidance(resolveForTTY(t, sel, policy.StderrTerminal, false)))
	if !strings.Contains(stderrOnly, "Your stderr is the **operator's real terminal**") {
		t.Errorf("with the terminal on stderr alone the guidance does not name stderr:\n%s", stderrOnly)
	}
	if strings.Contains(stderrOnly, "stdout") {
		t.Errorf("the guidance names stdout as a terminal in a run where it is not one:\n%s", stderrOnly)
	}

	// The same defect in the other screen: --new-session for the TIOCSTI reason
	// does not mean the agent has no terminal, and telling it so is a claim it
	// can check and find false.
	tiocsti := string(claudeGuidance(resolveForTTY(t, sel, all, true)))
	if strings.Contains(tiocsti, "no controlling terminal") {
		t.Errorf("--new-session fired for TIOCSTI while the terminal is still on stdio, and "+
			"the guidance tells the agent it has none:\n%s", tiocsti)
	}
	if !strings.Contains(tiocsti, "operator's real terminal") {
		t.Errorf("the guidance does not name the shared terminal in a TIOCSTI run:\n%s", tiocsti)
	}
	if !strings.Contains(tiocsti, "`/dev/tty` itself does not open here") {
		t.Errorf("the guidance does not tell the agent /dev/tty is shut, which it is:\n%s", tiocsti)
	}

	cut := string(claudeGuidance(resolveForTTY(t, sel, 0, false)))
	if !strings.Contains(cut, "no controlling terminal") {
		t.Errorf("a run snug put in its own session has no /dev/tty, and the guidance does not "+
			"tell the agent — which is a tool failure it will otherwise try to work "+
			"around:\n%s", cut)
	}
	if strings.Contains(cut, "OSC 52") {
		t.Errorf("the guidance warns about the operator's terminal in a run that cannot reach "+
			"one:\n%s", cut)
	}
}
