package profile

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A GRANT OF A DIRECTORY IS A GRANT OF EVERY COMMAND TABLE ANYONE EVER WRITES
// INTO IT. That is issue #140, and it is the third time the same shape has got
// past a rule written about the layer above it.
//
// sensitiveHostPath (credentialsurface_test.go) matches on the path a profile
// NAMES. `@claude` names `{home}/.claude/plugins`, a directory, and `claude`
// itself then clones marketplaces into it — so `.git/config` and `.npmrc` files
// appeared inside a granted tree with nobody naming them, and the sweep
// CLAUDE.md calls "mechanical, with no allowlist" could not look there.
//
// Measured on this development host when the issue was filed: two `.git/config`
// files and four `.npmrc` files under `~/.claude/plugins`, and NONE of them
// carrying a key that names a program. That is why this is low severity and
// also why the bar below is the one it is.
//
// THE BAR, stated as a line rather than a feeling. Refusing every directory
// grant whose contents snug does not control would refuse `{home}/.claude/
// plugins` outright, which is issue #68's open question and not a test's to
// decide. Refusing nothing is what let this through. So: a nested command table
// may EXIST under a granted directory, and it may not NAME A PROGRAM or CARRY A
// CREDENTIAL. The first is what the plugin ecosystem legitimately produces; the
// second is what turns a read-only bind into a supply of commands, which is
// exactly what CLAUDE.md means by "a read-only bind does not stop that; it
// supplies it".
//
// Scope is deliberately the HOME-rooted grants. `/usr` and `/opt` are granted
// too, and they are root-owned package content — a different trust class, a
// different threat, and a full walk of /usr at test time would be slow enough
// that someone would delete this test rather than wait for it.

// commandTableKind is what a nested file IS, which decides which keys make it
// dangerous. A basename alone is not enough: `config` means nothing until you
// know it sits under `.git`.
type commandTableKind int

const (
	kindGitConfig commandTableKind = iota
	kindNpmrc
	kindShellRC
	kindNetrc
)

// nestedCommandTable is one hit: what was found and what it is.
type nestedCommandTable struct {
	Path string
	Kind commandTableKind
}

// executingKeys are the keys that make each kind a command table rather than a
// preferences file — the same list GIT-CONFIG.md extracts a whitelist against,
// plus the credential-bearing spellings for the others.
//
// Matching is a lowercased substring search over the file, NOT a parse. A
// parser would be more precise and would also be a second implementation of
// git's config grammar living in a test; a substring match errs towards firing,
// which is the correct direction for a check whose whole job is to notice.
var executingKeys = map[commandTableKind][]string{
	kindGitConfig: {
		"sshcommand", "credential.helper", "helper =", "helper=",
		"pager", "hookspath", "textconv", "clean =", "clean=", "smudge =", "smudge=",
		"fsmonitor", "askpass", "editor",
	},
	kindNpmrc: {
		// npm runs lifecycle scripts and reads auth from here. `_auth`,
		// `_authToken` and `_password` are credentials; the script keys name
		// programs npm will execute.
		"_auth", "_password", "onload-script", "ignore-scripts=false", "node-options",
	},
	kindShellRC: {
		// Every line of a shell rc is a command; there is no safe subset, so the
		// bar for these is "must not be here at all" and any non-comment line
		// trips it.
		"",
	},
	kindNetrc: {"password", "login"},
}

func (k commandTableKind) String() string {
	switch k {
	case kindGitConfig:
		return ".git/config"
	case kindNpmrc:
		return ".npmrc"
	case kindShellRC:
		return "a shell rc"
	case kindNetrc:
		return ".netrc"
	}
	return "unknown"
}

// classifyNested says whether path is a command table and which kind, given its
// position in the tree. Returns false for everything else.
func classifyNested(path string) (commandTableKind, bool) {
	base := filepath.Base(path)
	switch base {
	case "config":
		// Only under a .git directory. `config` is far too common a basename to
		// treat as a command table on its own, and a check that fires on every
		// `config` is a check somebody switches off.
		if filepath.Base(filepath.Dir(path)) == ".git" {
			return kindGitConfig, true
		}
	case ".npmrc":
		return kindNpmrc, true
	case ".netrc", "_netrc":
		return kindNetrc, true
	case ".bashrc", ".bash_profile", ".profile", ".zshrc":
		return kindShellRC, true
	case ".gitconfig", ".git-credentials":
		return kindGitConfig, true
	}
	return 0, false
}

// nestedCommandTables walks root and returns every command table under it.
//
// It does NOT follow symlinks (filepath.WalkDir does not), which is the right
// call for a sweep rather than a resolver: a symlink out of the tree is its own
// finding and would be reported at the granted path by the mount policy, not
// here. Unreadable subtrees are skipped rather than failing the walk — this
// runs against a real home directory and a permission error there is not what
// the test is about.
func nestedCommandTables(root string) []nestedCommandTable {
	var found []nestedCommandTable
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if kind, ok := classifyNested(path); ok {
			found = append(found, nestedCommandTable{Path: path, Kind: kind})
		}
		return nil
	})
	return found
}

// namesAProgram reports which executing or credential-bearing keys a hit
// carries, reading the file itself. Empty means the file is inert: it exists,
// and it tells no tool to run anything.
func namesAProgram(t *testing.T, hit nestedCommandTable) []string {
	t.Helper()
	raw, err := os.ReadFile(hit.Path)
	if err != nil {
		// Unreadable is not innocent, and it is not this test's business
		// either: report it as a hit so it is seen rather than silently passing.
		return []string{"unreadable: " + err.Error()}
	}
	body := strings.ToLower(string(raw))

	var hits []string
	for _, key := range executingKeys[hit.Kind] {
		if key == "" {
			// kindShellRC: any non-comment, non-blank line is a command.
			for _, line := range strings.Split(body, "\n") {
				if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") {
					hits = append(hits, "a shell command: "+l)
					break
				}
			}
			continue
		}
		if strings.Contains(body, key) {
			hits = append(hits, key)
		}
	}
	return hits
}

// homeRootedGrants returns every builtin grant whose host side is under the
// home directory, expanded to a real path on this host.
//
// The `{home}`/`~` spellings and the `host:guest` form are handled here for the
// same reason sensitiveHostPath normalises: a profile may legally write any of
// them, and a sweep that only understood one spelling would report an empty set
// and look like proof of absence.
func homeRootedGrants(t *testing.T) []string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/" {
		t.Skip("SKIP: no usable home directory to resolve {home} grants against")
	}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range reg {
		for _, g := range append(append([]string{}, p.RO...), p.RW...) {
			host := g
			if i := strings.Index(g, ":"); i > 0 {
				host = g[:i]
			}
			rest, ok := strings.CutPrefix(host, "{home}")
			if !ok {
				if rest, ok = strings.CutPrefix(host, "~"); !ok {
					continue
				}
			}
			out = append(out, filepath.Join(home, filepath.Clean("/"+rest)))
		}
	}
	return out
}

// TestNoNestedCommandTableUnderAGrantNamesAProgram is issue #140's regression,
// run against the REAL grants on the REAL host, because the whole point of the
// finding is that the dangerous file is one nobody named — so a fixture alone
// would test the walker and not the property.
//
// A hit is reported with its path and the key that fired, because the fix
// depends on which: a `.git/config` with `core.hooksPath` is a supply-chain
// question for that plugin, while a `.npmrc` with `_authToken` is a credential
// this project would rather not be handing over at all.
//
// It cannot fail on a host that has none of these directories, which is most CI
// runners — that is what TestTheNestedSweepActuallyFires below is for.
func TestNoNestedCommandTableUnderAGrantNamesAProgram(t *testing.T) {
	swept := 0
	for _, dir := range homeRootedGrants(t) {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue // absent on this host, or a single-file grant: nothing to walk
		}
		swept++
		for _, hit := range nestedCommandTables(dir) {
			keys := namesAProgram(t, hit)
			if len(keys) == 0 {
				continue // it exists and is inert, which is the tolerated case
			}
			t.Errorf("%s under the granted directory %s names a program or carries a "+
				"credential (%s).\n"+
				"snug binds that directory read-only, which does not stop a tool reading "+
				"this file — it SUPPLIES it. A grant of a directory is a grant of every "+
				"command table written into it later (issue #140).\n"+
				"Fix: stop granting the directory, or narrow the grant to the entries snug "+
				"actually needs.",
				hit.Path, dir, strings.Join(keys, ", "))
		}
	}
	t.Logf("swept %d home-rooted directory grant(s) that exist on this host", swept)
}

// TestTheNestedSweepActuallyFires is the positive control, and it carries more
// weight here than usual: the test above passes trivially on any host that has
// no `~/.claude` at all, so without this one a broken walker would look exactly
// like a clean machine.
//
// The fixture reproduces what was really found (a `.git/config` nested three
// levels down, and a `.npmrc` beside it) plus the dangerous version of each,
// so both the walker and the key predicate are exercised.
func TestTheNestedSweepActuallyFires(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) string {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	inert := write("marketplaces/x/.git/config",
		"[remote \"origin\"]\n\turl = https://github.com/example/x\n")
	hostile := write("cache/y/1.0.0/.git/config",
		"[core]\n\tsshCommand = /tmp/evil\n\thooksPath = /tmp/hooks\n")
	inertNpm := write("marketplaces/x/plugins/z/.npmrc", "registry=https://registry.npmjs.org/\n")
	hostileNpm := write("marketplaces/x/plugins/w/.npmrc",
		"//registry.npmjs.org/:_authToken=deadbeef\n")
	notAConfig := write("marketplaces/x/config", "this is not a git config\n")

	found := map[string]bool{}
	for _, hit := range nestedCommandTables(root) {
		found[hit.Path] = true
	}
	for _, want := range []string{inert, hostile, inertNpm, hostileNpm} {
		if !found[want] {
			t.Errorf("the sweep did not find %s, so the check above cannot see a command "+
				"table under a granted directory at all", want)
		}
	}
	if found[notAConfig] {
		t.Errorf("the sweep matched %s: a bare `config` is not a git config, and a check "+
			"that fires on every file called `config` is one somebody switches off",
			notAConfig)
	}

	// And the key predicate: inert must stay inert, hostile must fire. Both
	// halves, because a predicate that fired on everything would pass the
	// first half of this test and make the real sweep useless.
	for _, tc := range []struct {
		path string
		kind commandTableKind
		want bool
	}{
		{inert, kindGitConfig, false},
		{hostile, kindGitConfig, true},
		{inertNpm, kindNpmrc, false},
		{hostileNpm, kindNpmrc, true},
	} {
		got := namesAProgram(t, nestedCommandTable{Path: tc.path, Kind: tc.kind})
		if (len(got) > 0) != tc.want {
			t.Errorf("%s: names a program = %v (%v), want %v", tc.path, len(got) > 0, got, tc.want)
		}
	}
}

// TestTheNestedSweepHasSomethingToSweep guards the way this check would most
// plausibly stop meaning anything: not by breaking, but by covering nothing.
//
// homeRootedGrants understands `{home}` and `~`. A profile edit that spelled a
// grant some third way — or a refactor that changed how Builtins reports
// them — would leave the sweep walking an empty list, passing forever, with no
// symptom. This asserts the set is non-empty and that the one grant the issue
// is about is in it.
func TestTheNestedSweepHasSomethingToSweep(t *testing.T) {
	grants := homeRootedGrants(t)
	if len(grants) == 0 {
		t.Fatal("no builtin grant resolved to a home-rooted path, so the nested sweep walks " +
			"nothing and passes on every host. Either the builtins stopped granting anything " +
			"under {home}, or homeRootedGrants no longer understands how they are spelled")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("SKIP: no home directory")
	}
	want := filepath.Join(home, ".claude", "plugins")
	for _, g := range grants {
		if g == want {
			return
		}
	}
	t.Errorf("%s is not among the home-rooted grants (%v). If @claude stopped granting the "+
		"plugin tree, issue #68 was answered and this expectation should be updated in the "+
		"same commit; if it did not, the sweep is not looking where issue #140 found the "+
		"problem", want, grants)
}
