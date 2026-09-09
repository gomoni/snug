package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// snugCLIHelperEnv gates TestSnugCLIHelperProcess: unset, an ordinary `go
// test` run of this file never reaches it. Set — by runSnugMain, below — it
// makes THIS test binary BE `snug`, hidden-verb switch and reserved-word
// switch included, for exactly one subprocess invocation.
const snugCLIHelperEnv = "SNUG_CLI_HELPER_PROCESS"

// TestSnugCLIHelperProcess is internal/sandbox/teardown_test.go's own pattern
// (TestTeardownSignalHelperProcess): a second personality for this same test
// binary, selected at runtime by an environment variable instead of a second
// `go build`. It is what lets a test of Main()'s own argv dispatch — the
// reserved-word switch runs inside Main, before parseArgs ever sees argv —
// live in internal/cli, unprivileged, rather than test/integration building
// ./cmd/snug: nothing this file's tests exercise creates a namespace, so
// nothing here needs one.
//
// The real argv is read off os.Args directly, after a literal "--", never
// through the flag package: go test's generated main() has already consumed
// every "-test.*" flag by the time this body runs, and Main() below reads
// os.Args itself — using flag.Args() here would read a package-level
// FlagSet's idea of what survived "--", not necessarily the same slice.
func TestSnugCLIHelperProcess(t *testing.T) {
	if os.Getenv(snugCLIHelperEnv) == "" {
		return
	}
	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	os.Args = append([]string{os.Args[0]}, args...)
	Main() // calls os.Exit; never returns
}

// runSnugMain runs Main() in a fresh subprocess of this test binary, with dir
// as its working directory and args as argv[1:]. env is layered over this
// process's own environ — os/exec keeps the LAST duplicate of a key, so an
// entry here overrides whatever this test process inherited — which is how
// every case below points HOME and XDG_CONFIG_HOME at scratch directories
// rather than the machine running the suite.
//
// Bounded at 15s and reported as a hang, not a timeout, if it is ever hit:
// nothing this file drives Main() through does host I/O anywhere near that
// slow, so hitting the bound is itself the finding.
func runSnugMain(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmdArgs := append([]string{"-test.run=^TestSnugCLIHelperProcess$", "--"}, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, os.Environ()...), append([]string{snugCLIHelperEnv + "=1"}, env...)...)

	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	if ctx.Err() != nil {
		t.Fatalf("snug %s did not finish within 15s (a hang is a finding):\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), out.String(), errb.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running the snug CLI helper subprocess (args %v): %v", args, err)
		}
		return out.String(), errb.String(), ee.ExitCode()
	}
	return out.String(), errb.String(), 0
}

// TestADeletedVerbIsNotAReservedWord pins the decision that `attach` — the
// one verb snug has ever removed — went back to being an ordinary word the
// moment its code did. The tombstone alternative was written and dropped: a
// `case "attach":` that only refuses costs every user a directory name
// forever, on behalf of a habit that lasts one release, and issue #548 makes
// exactly that argument about the reserved-word list in general ("every flat
// verb permanently removes a word from the set of directory names a user can
// pass bare").
//
// So the assertion is that `snug attach`, run from a tree containing
// ./attach, sandboxes it — the same as any other directory name. --dry-run is
// enough: it reaches policy resolution and prints the TARGET it settled on
// while starting nothing, so this stays an unprivileged test.
//
// The stable spelling this leaves a script with is `snug ./attach`, and
// whether a flag form should make it stable WITHOUT a path prefix is issue
// #564.
func TestADeletedVerbIsNotAReservedWord(t *testing.T) {
	dir := t.TempDir()
	attachDir := filepath.Join(dir, "attach")
	if err := os.Mkdir(attachDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "--dry-run", "attach")

	if code != 0 {
		t.Fatalf("`snug --dry-run attach` exited %d, want 0 — a bare \"attach\" must be read "+
			"as a directory, not intercepted:\nstderr:\n%s", code, stderr)
	}
	// attachDir, not a resolved realpath: dry-run's TARGET line is
	// filepath.Abs(target) exactly as parseArgs sets it, with no symlink
	// resolution, and that is what filepath.Join(dir, "attach") already is
	// for a target given as a plain t.TempDir() path.
	if !strings.Contains(stdout, "TARGET   "+attachDir) {
		t.Errorf("the dry-run screen does not name %s as TARGET: something is still "+
			"intercepting the bare word \"attach\":\n%s", attachDir, stdout)
	}
}

// TestALiveSubcommandIsStillAReservedWord is the contrast that makes the two
// tests around it readable: a live verb, in a tree where NOTHING of that name
// exists, dispatches exactly as before. Issue #564 narrowed when the word loses
// to a directory; it did not change what the word does when there is no
// directory to lose to, and a refusal that fired on every `snug config` would
// pass TestAReservedWordThatAlsoNamesADirectoryIsRefused just as well.
//
// The witness is structural rather than the exit code. run()'s first
// host-visible act is lockTarget, so if `snug config` were ever read as a
// target instead of a subcommand, lockPathForTarget's file is where it would
// show up — before profile resolution, before bwrap, before any namespace.
//
// POSITIVE CONTROL: lockTarget is called on the identical path in-process
// first, so a typo in lockPathForTarget's arithmetic cannot make the negative
// pass by checking a path nothing was ever going to write to (the "pasta" vs
// "pasta.avx2" shape: a check that always reads zero).
func TestALiveSubcommandIsStillAReservedWord(t *testing.T) {
	dir := t.TempDir()
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	// The lock path a bare `snug config` WOULD take if the word were read as a
	// relative target: the cwd's own ./config, which this tree deliberately does
	// not contain. lockTarget resolves symlinks, so the control below has to
	// create it to compute the same path snug would.
	configDir := filepath.Join(dir, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := lockPathForTarget(t, configDir)
	t.Cleanup(func() { os.Remove(lockPath) })
	if _, err := os.Lstat(lockPath); err == nil {
		t.Fatalf("a lock file already exists at %s before this test touched anything; the "+
			"target hash collided with something else on this host", lockPath)
	}

	// ── positive control ────────────────────────────────────────────────
	unlock, err := lockTarget(configDir)
	if err != nil {
		t.Fatalf("lockTarget(%s): %v", configDir, err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("lockTarget did not create a lock file at %s, the path this test computed: %v — "+
			"the assertion below would then pass on a path nothing was ever going to "+
			"write to", lockPath, err)
	}
	unlock()
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("removing the control's own lock file: %v", err)
	}

	// ── the actual case ─────────────────────────────────────────────────
	// The directory goes away first: with it present the run is ambiguous and
	// #564 refuses, which is the test above, not this one.
	if err := os.Remove(configDir); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runSnugMain(t, dir, env, "config")

	if code != 0 {
		t.Errorf("`snug config` in a tree with no ./config exited %d, want 0 — the ambiguity "+
			"refusal has to fire on the collision, not on the word:\nstderr:\n%s", code, stderr)
	}
	if _, err := os.Lstat(lockPath); err == nil {
		t.Errorf("a lock file exists at %s after `snug config`: the word was read as a target "+
			"rather than dispatched, so the reserved-word switch is not doing what main.go's "+
			"comment says", lockPath)
	}
}

// lockPathForTarget returns the exact path lockTarget(target) itself places
// its flock file at: target-<hash(realpath)>.lock, in the per-uid runtime
// directory targetLockBase resolves from the uid ALONE (never from an
// environment variable, which is the one thing this test could not carry
// across the subprocess boundary anyway). It is the one host-visible effect
// of run() that needs no bwrap and no namespace — a plain flock on a regular
// file — which is what makes it usable as a witness from an unprivileged
// test.
func lockPathForTarget(t *testing.T, target string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("resolving %s: %v", target, err)
	}
	base, snugName, err := targetLockBase()
	if err != nil {
		t.Fatalf("targetLockBase: %v", err)
	}
	return filepath.Join(base, snugName, targetLockName(real))
}

// TestAReservedWordThatAlsoNamesADirectoryIsRefused is issue #564: snug shares
// one namespace between its reserved verbs and its primary positional, and
// until now the verb won silently — a `fix/` directory in the cwd got a
// subcommand instead of a sandbox, with nothing said. git is the surveyed
// prior art that solves this and it solves it by refusing (`fatal: ambiguous
// argument 'feature': both revision and filename`, then both spellings), so
// snug refuses too.
//
// The witness is threefold, because two of the three can pass for the wrong
// reason on their own: the exit code is exitUsage, the message names BOTH
// spellings, and — the structural half inherited from
// TestALiveSubcommandIsStillAReservedWord — no target lock file exists
// afterwards, so the refusal is not quietly sandboxing the directory instead.
func TestAReservedWordThatAlsoNamesADirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	lockPath := lockPathForTarget(t, configDir)
	t.Cleanup(func() { os.Remove(lockPath) })

	_, stderr, code := runSnugMain(t, dir, env, "config")

	if code != exitUsage {
		t.Errorf("`snug config` with ./config present exited %d, want %d (exitUsage):\nstderr:\n%s",
			code, exitUsage, stderr)
	}
	for _, want := range []string{`"config" is both a subcommand and a directory here`, "snug ./config", "snug config"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not contain %q — it has to name both spellings, "+
				"which is the only place the path-prefix rule reaches a user who has not "+
				"read main.go:\n%s", want, stderr)
		}
	}
	if _, err := os.Lstat(lockPath); err == nil {
		t.Errorf("a lock file exists at %s after the refusal: snug sandboxed the directory "+
			"rather than refusing to guess", lockPath)
	}
}

// TestEveryReservedWordRefusesWhenADirectoryOfThatNameExists is the reason
// subcommands() is a map and not a switch: the refusal is defined over exactly
// the set that dispatches, so the set is enumerable and this test walks all of
// it. A word added to snug's top level in the future is covered here the day
// it lands, with no list to update — which is what issue #548 needs, since it
// moves words in and out of that set.
func TestEveryReservedWordRefusesWhenADirectoryOfThatNameExists(t *testing.T) {
	for word := range subcommands() {
		t.Run(word, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, word), 0o755); err != nil {
				t.Fatal(err)
			}
			env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

			_, stderr, code := runSnugMain(t, dir, env, word)

			if code != exitUsage {
				t.Fatalf("`snug %s` with ./%s present exited %d, want %d:\nstderr:\n%s",
					word, word, code, exitUsage, stderr)
			}
			if !strings.Contains(stderr, "snug ./"+word) {
				t.Errorf("the refusal for %q does not name the path spelling `snug ./%s`:\n%s",
					word, word, stderr)
			}
		})
	}
}

// TestThePathSpellingSandboxesTheDirectory is the other half of the refusal:
// the message tells the user to write `snug ./config`, so `snug ./config` has
// to work. An error naming a fix that does not fix it is worse than no error.
func TestThePathSpellingSandboxesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "--dry-run", "./config")

	if code != 0 {
		t.Fatalf("`snug --dry-run ./config` exited %d, want 0:\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "TARGET   "+configDir) {
		t.Errorf("the dry-run screen does not name %s as TARGET, so the spelling the "+
			"refusal recommends does not do what it says:\n%s", configDir, stdout)
	}
}

// TestAFileNamedLikeAReservedWordIsNotAmbiguous pins the narrow trigger. snug's
// positional is a DIRECTORY to sandbox, so a regular file named `config` is not
// a second reading of the word and refusing there would break `snug config` for
// anyone with such a file — a refusal that fires when nothing is ambiguous is
// the failure mode that gets a check deleted.
func TestAFileNamedLikeAReservedWordIsNotAmbiguous(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("not a directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "config")

	if code != 0 {
		t.Fatalf("`snug config` with a regular file ./config exited %d, want 0 — the file is "+
			"not a target snug could have meant:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, "both a subcommand and a directory") {
		t.Errorf("the ambiguity refusal fired on a regular file:\n%s", stderr)
	}
}

// TestASymlinkToADirectoryIsAmbiguousToo: `snug config` would follow such a
// symlink and sandbox what it points at, so the two readings of the word are
// exactly as live as for a real directory. os.Lstat alone cannot tell the two
// apart from a symlink to a FILE, which is why the check stats through.
func TestASymlinkToADirectoryIsAmbiguousToo(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "somewhere")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(dir, "config")); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	_, stderr, code := runSnugMain(t, dir, env, "config")

	if code != exitUsage {
		t.Errorf("`snug config` with ./config a symlink to a directory exited %d, want %d:\nstderr:\n%s",
			code, exitUsage, stderr)
	}
}

// TestADanglingSymlinkIsNotAmbiguous is the same question one step further out,
// and it is here because os.Lstat SUCCEEDS on a dangling symlink — the exact
// disagreement between Lstat and what a mount actually resolves that put the
// #186 guard on the wrong side once (internal/cli/claude.go's
// projectableTargetFile). Nothing is ambiguous here: snug could not sandbox
// this name if it tried.
func TestADanglingSymlinkIsNotAmbiguous(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "config")); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	_, stderr, code := runSnugMain(t, dir, env, "config")

	if code != 0 {
		t.Fatalf("`snug config` with ./config a dangling symlink exited %d, want 0:\nstderr:\n%s",
			code, stderr)
	}
}

// TestALeadingFlagStillReadsAReservedWordAsADirectory pins a measured
// consequence of where the refusal sits rather than an intention: the dispatch
// switch is guarded by !strings.HasPrefix(argv[0], "-"), so `snug --dry-run
// fix` never reaches it and `fix` is an ordinary positional there. The refusal
// is placed at the dispatch it guards, so it inherits that guard exactly. The
// reading is unambiguous in this form — there is no verb to compete with once a
// flag has been seen — and the test exists so a future move of the check
// upwards is a deliberate, visible delta.
func TestALeadingFlagStillReadsAReservedWordAsADirectory(t *testing.T) {
	dir := t.TempDir()
	fixDir := filepath.Join(dir, "fix")
	if err := os.Mkdir(fixDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "--dry-run", "fix")

	if code != 0 {
		t.Fatalf("`snug --dry-run fix` exited %d, want 0:\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stdout, "TARGET   "+fixDir) {
		t.Errorf("the dry-run screen does not name %s as TARGET:\n%s", fixDir, stdout)
	}
}

// TestUsageListsEveryReservedWord closes issue #564's stated worst case: the
// refusal tells a user that `fix` is a subcommand, and before this change
// `fix`, `engine` and `help` were dispatched by main.go while appearing nowhere
// in usage(). A message pointing at a verb the help text does not admit to is
// the one outcome worse than the silent dispatch it replaces.
func TestUsageListsEveryReservedWord(t *testing.T) {
	dir := t.TempDir()
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	_, stderr, _ := runSnugMain(t, dir, env, "help")

	for word := range subcommands() {
		if !strings.Contains(stderr, "snug "+word) {
			t.Errorf("usage() never writes `snug %s`, but that word is dispatched and the "+
				"ambiguity refusal will name it:\n%s", word, stderr)
		}
	}
}

// TestTheReservedWordSetIsExactlyThis is the tripwire on issue #548's answer,
// and it is the only thing in the tree that makes that answer bind.
//
// #548 asked where tomorrow's command goes, researched grouping against git,
// podman, docker, gh, nix, kubectl, flatpak, systemctl, npm, go and aws, and
// answered: the tree stays FLAT, because grouping aims at the wrong words here.
// Measured over 13,806 directories on the maintainer's host, the words a `host`
// noun would release are `doctor` (0 directories) and `fix` (1), while the words
// it cannot take are `config` (20) and `proxy` (7). subcommands() carries the
// full rule and the argument.
//
// The answer has a shelf life and nothing else notices when it expires. Every
// tool in that survey grouped EVENTUALLY: docker regrouped at forty-plus
// commands, and its stated reason — help length and tab completion — is a
// threshold snug has not reached at seven and will reach at some number nobody
// can name in advance. So the decision that is actually being pinned is not
// "flat forever"; it is "flat at this size, re-argued at the next one".
//
// A comment cannot enforce that, and neither can a CI note asking for scrutiny:
// both are read by people who already agree. A failing test is read by the
// person adding the word, at the moment they add it, which is the only moment
// the rule is worth anything. Adding a top-level word must therefore cost an
// edit HERE, to a test that argues back — the same friction a golden argv diff
// applies to the security boundary, applied to the namespace.
//
// So this test does not fail because a new word is wrong. It fails because a new
// word is a DECISION, and the four tests in subcommands() are what it has to be
// decided against — in order, first answer wins:
//
//  1. it can be a flag on the default action  -> make it a flag;
//  2. an existing word already owns the subject -> make it a sub-verb;
//  3. it needs a new word -> only if that subject will answer two or more
//     commands, and then the word is a NOUN holding verbs, not a verb;
//  4. a word that moves is deleted, never aliased.
//
// If a word passes all four, edit the list below and say in the commit message
// which test admitted it. If several arrive at once, that is the signal #548
// deferred: re-run its measurement rather than growing this list one row at a
// time, because seven words that each passed test 3 in isolation is exactly how
// docker reached forty.
func TestTheReservedWordSetIsExactlyThis(t *testing.T) {
	// Sorted, so the diff a new word produces is one line in a stable place.
	want := []string{"config", "doctor", "engine", "fix", "help", "profile", "proxy"}

	var got []string
	for word := range subcommands() {
		got = append(got, word)
	}
	slices.Sort(got)

	if !slices.Equal(got, want) {
		t.Fatalf("the top-level reserved-word set changed.\n"+
			"  have: %v\n"+
			"  want: %v\n"+
			"Every word here permanently costs a caller one bare directory name, so this is a\n"+
			"decision and not a detail. Read subcommands() in main.go: a command becomes a flag\n"+
			"if it can (test 1), a sub-verb of a word that already owns its subject if it can\n"+
			"(test 2), and a new word ONLY if its subject will answer two or more commands\n"+
			"(test 3). If it passed, update `want` above and name the test that admitted it in\n"+
			"the commit message. If several words are arriving at once, re-argue issue #548\n"+
			"instead: the flat tree was measured at seven words and is not a permanent answer.",
			got, want)
	}
}
