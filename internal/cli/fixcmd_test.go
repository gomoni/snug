package cli

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// WHOSE range this is decides whether the line works or merely looks right,
// and the wrong answer is the DEFAULT one: under sudo, os.Getuid() is 0 and
// the obvious implementation emits `root:1001:64535`, delegating a range to an
// account no rootless container ever runs as. In a distrobox init_hook it is
// worse — root runs the hook and the box user is the target.
//
// Every host fact is injected for the reason subuidHost exists one file over:
// a test that reads the machine asserts whatever machine ran it. The root arm
// cannot be exercised any other way at all.
func TestTheSubuidRangeIsNamedForTheRightUser(t *testing.T) {
	known := map[string]string{"michal": "1000", "runner": "1001"}
	lookup := func(name string) (*user.User, error) {
		uid, ok := known[name]
		if !ok {
			return nil, errors.New("unknown user " + name)
		}
		return &user.User{Username: name, Uid: uid}, nil
	}
	self := func() (string, int) { return "invoker", 4242 }

	for _, tc := range []struct {
		name     string
		explicit string
		sudoUser string
		euid     int
		wantName string
		wantUID  int
		wantErr  string
	}{
		{name: "an explicit user wins over everything", explicit: "michal", sudoUser: "runner", euid: 0,
			wantName: "michal", wantUID: 1000},
		{name: "under sudo the invoking user is taken from SUDO_USER", sudoUser: "michal", euid: 0,
			wantName: "michal", wantUID: 1000},
		{name: "an ordinary run names the invoker", euid: 1000, wantName: "invoker", wantUID: 4242},
		// THE ONE THAT MATTERS. Without this arm the command emits a line for
		// root, which is syntactically perfect and delegates nothing.
		{name: "root with nothing to go on REFUSES rather than naming root", euid: 0,
			wantErr: "a range delegated to root delegates nothing"},
		{name: "an unknown explicit user is named in the refusal", explicit: "nosuchuser", euid: 1000,
			wantErr: "no such user"},
		{name: "an unknown SUDO_USER is named in the refusal", sudoUser: "nosuchuser", euid: 0,
			wantErr: "$SUDO_USER names"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotUID, err := resolveSubuidUser(tc.explicit, tc.sudoUser, tc.euid, lookup, self)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("got %s:%d, want a refusal containing %q", gotName, gotUID, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("refusal %q does not contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if gotName != tc.wantName || gotUID != tc.wantUID {
				t.Errorf("got %s:%d, want %s:%d", gotName, gotUID, tc.wantName, tc.wantUID)
			}
		})
	}
}

// The colon is load-bearing: matching the bare name would report `michal` as
// already present because `michalx` is, and the command would then silently do
// nothing on a host that needs it.
func TestAnOwnerIsPresentOnlyWithItsColon(t *testing.T) {
	const content = "# a comment\nmichalx:100000:65536\n\nrunner:1001:64535\n"
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"runner", true},
		{"michalx", true},
		{"michal", false},
		{"unner", false},
		{"", false},
	} {
		if got := subuidOwnerPresent(content, tc.name); got != tc.want {
			t.Errorf("subuidOwnerPresent(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAppendLineAddsExactlyOneLineAndCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subuid")
	if err := os.WriteFile(path, []byte("existing:1:2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendLine(path, "tester:1001:64535"); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != "existing:1:2\ntester:1001:64535\n" {
		t.Errorf("appended content is %q", blob)
	}

	// It creates nothing. /etc/subuid exists on every host with shadow-utils,
	// and inventing one would be a bigger claim about the machine than this
	// command makes.
	missing := filepath.Join(dir, "not-there")
	if err := appendLine(missing, "x:1:2"); err == nil {
		t.Error("appendLine created a file that did not exist")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("a file was created anyway (err=%v)", err)
	}
}

// The namespace rule: the noun is mandatory and a bare `snug fix` acts on
// nothing. `snug engine gc` states the same rule for itself, and it gets
// stricter rather than looser as the namespace grows — the day a second noun
// exists, a "fix everything" default would run one nobody asked for.
func TestBareFixActsOnNothing(t *testing.T) {
	for _, argv := range [][]string{nil, {}, {"-w"}, {"--write"}} {
		if code := fixCmd(argv); code != exitUsage {
			t.Errorf("`snug fix %v` exited %d, want exitUsage (%d) — it must never act without a subject",
				argv, code, exitUsage)
		}
	}
	if code := fixCmd([]string{"nosuchsubject"}); code != exitUsage {
		t.Errorf("an unknown subject exited %d, want exitUsage (%d)", code, exitUsage)
	}
}

// -w is the only flag, and an unrecognised one REFUSES rather than being read
// as the nearest thing it resembles — the rule ParseNetMode and ParseSSHMode
// already follow for their own value sets.
func TestFixSubuidRefusesAnUnknownFlagAndASecondUser(t *testing.T) {
	if code := fixSubuidCmd([]string{"--apply"}); code != exitUsage {
		t.Errorf("an unknown flag exited %d, want exitUsage (%d)", code, exitUsage)
	}
	if code := fixSubuidCmd([]string{"alice", "bob"}); code != exitUsage {
		t.Errorf("two users exited %d, want exitUsage (%d)", code, exitUsage)
	}
}
