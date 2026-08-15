package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// extractGitConfig reads the host's global git config and returns the
// whitelisted keys, with `includeIf "gitdir:"` evaluated against the target.
//
// WHY SNUG PARSES THIS AT ALL, rather than binding ~/.gitconfig read-only as the
// previous @git-ro did: that file is a command table. `credential.helper`,
// `alias.x = !cmd`, `core.pager`, `core.sshCommand`, `diff.*.textconv` and
// `filter.*.clean/smudge` all name programs for git to run, and a read-only bind
// does not stop them — it supplies them.
//
// WHY SNUG EVALUATES THE CONDITION rather than asking git, which would obviously
// be more faithful. Measured, both directions:
//
//   - `git -C <target> config --get user.email` reads the TARGET's own config,
//     and the target is the untrusted material. A repo that sets user.email in
//     .git/config wins over everything the human wrote.
//   - `git config --global --get user.email` never fires a `gitdir:` condition
//     at all: with no repository there is nothing to match against.
//
// So there is no invocation that both honours the condition and keeps the
// sandboxed material out of the decision. snug reads the FILE (git does the
// tokenising, via `--file … --list`) and decides the condition itself.
//
// `includeIf "hasconfig:remote.*.url:…"` is deliberately not implemented and is
// reported instead. Measured on git 2.55: a repository whose only property was a
// crafted remote URL pulled in a host config file carrying
// `credential.helper = !command`. That condition hands the choice of which host
// file is read to the repository — invariant 3, exactly.
func extractGitConfig(home, target string) (policy.GitValues, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		// Invariant 5. The profile promises the sandbox gets the name and email
		// you commit under; on a host with no git there is nothing to read, and
		// saying nothing hands over a sandbox where `git commit` fails with
		// "tell me who you are" and no explanation anywhere.
		return nil, fmt.Errorf("git is not installed on the host, so there is no config " +
			"to read.\n\n      Install git, or deselect the profile that asks for it.")
	}

	// git matches a `gitdir:` condition against the REAL path of the git
	// directory (`strbuf_realpath`), so snug must too. Without this, a project
	// tree reached through a symlink — `~/work -> /data/work`, an ordinary
	// layout — matched `gitdir:~/work/` here and did NOT match in git, and the
	// sandbox committed under an identity the host would never use.
	if real, err := filepath.EvalSymlinks(target); err == nil {
		target = real
	}
	gitDir := filepath.Join(target, ".git")
	if fi, err := os.Stat(gitDir); err != nil || !fi.IsDir() {
		// A worktree's .git is a FILE, and a bare repo has none. Matching the
		// target itself is the closest honest approximation, and it is what a
		// `gitdir:~/projects/x/` pattern means to a human either way.
		gitDir = target
	} else if real, err := filepath.EvalSymlinks(gitDir); err == nil {
		gitDir = real
	}

	out := policy.GitValues{}
	seen := map[string]bool{}
	for _, f := range globalGitFiles(home) {
		if err := readGitFile(git, f, home, gitDir, out, seen, 0); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// hostGitValues is the one call main.go makes: extract only when a selected
// profile asked for it, and be loud when it cannot.
//
// dryRun follows the identity band exactly (stageGhConfig): a real run refuses,
// a dry run warns and prints the policy anyway, because --dry-run is how a
// profile gets inspected on a host that cannot satisfy it.
func hostGitValues(reg profileRegistry, selected []policy.ProfileName, home, target string, verbose, dryRun bool) (policy.GitValues, error) {
	if !gitExtractSelected(reg, selected) {
		return nil, nil
	}
	v, err := extractGitConfig(home, target)
	if err != nil {
		if !dryRun {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "snug: %v\n      (dry run: continuing with no git config)\n", err)
		return nil, nil
	}
	if len(v) == 0 {
		// Not an error — a host may genuinely set none of these — but it is the
		// difference between "the profile did nothing" and "the profile did its
		// job", and inside the sandbox both look identical until `git commit`.
		fmt.Fprintln(os.Stderr, "snug: the host's git config has none of the keys this profile "+
			"carries (user.name, user.email, init.defaultBranch), so the sandbox has no git identity")
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "snug: git config extracted: %s\n", gitValuesLine(v))
	}
	return v, nil
}

// gitExtractSelected peeks at the selection so the caller only does the host IO
// when something actually asked for it. Same shape as identityHost: resolution
// stays pure, and a sandbox that never mentions git never reads your git config.
func gitExtractSelected(reg profileRegistry, selected []policy.ProfileName) bool {
	set, err := policy.Expand(map[policy.ProfileName]*policy.Profile(reg), selected)
	if err != nil {
		return false
	}
	for _, p := range set {
		if mode, err := policy.ParseGitMode(p.Git); err == nil && mode == policy.GitExtract {
			return true
		}
	}
	return false
}

// globalGitFiles is every file git treats as GLOBAL config, in the order git
// reads them. Both, not one: git merges ~/.gitconfig AND
// $XDG_CONFIG_HOME/git/config, which is the same two-file fact that made
// GIT_CONFIG_GLOBAL necessary for the identity work.
func globalGitFiles(home string) []string {
	if f := os.Getenv("GIT_CONFIG_GLOBAL"); f != "" {
		return []string{f}
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}
	return []string{filepath.Join(xdg, "git", "config"), filepath.Join(home, ".gitconfig")}
}

// readGitFile folds one config file's whitelisted keys into out, then follows
// the includes that apply.
//
// `seen` makes a diamond of includes read each file once. `depth` is the cycle
// backstop; with only a depth bound, a diamond re-read and re-exec'd git up to
// 2^8 times. A missing file is not an error — git treats an include of a file
// that is not there as a no-op, and so does an absent ~/.gitconfig. A file that
// git REFUSES TO PARSE is a different thing entirely, and it is reported.
func readGitFile(git, file, home, gitDir string, out policy.GitValues, seen map[string]bool, depth int) error {
	if depth > 8 {
		return nil
	}
	if real, err := filepath.EvalSymlinks(file); err == nil {
		file = real
	}
	if seen[file] {
		return nil
	}
	seen[file] = true
	if _, err := os.Stat(file); err != nil {
		return nil
	}
	// `git config --file … --list` does the tokenising, so snug never writes an
	// INI parser. Includes are NOT followed for --file (git's own default), which
	// is exactly what this code needs: the includeIf lines come back as data.
	cmd := exec.Command(git, "config", "--file", file, "--list", "-z")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		// Silence here meant a single syntax error anywhere in the host's config
		// produced a sandbox with no identity and nothing on screen — invariant
		// 5, and the message git already wrote was being thrown away.
		return fmt.Errorf("git refused to parse %s: %s\n\n"+
			"      snug reads that file to build the sandbox's git config. Fix it on the "+
			"host (git config --file %s --list shows the same error), or deselect the "+
			"profile that asks for it.", file, strings.TrimSpace(stderr.String()), file)
	}

	for _, entry := range strings.Split(string(data), "\x00") {
		key, value, ok := strings.Cut(entry, "\n")
		if !ok {
			continue
		}
		// The KEY keeps its case and the lowercase copy is only for comparing.
		// git lowercases section and variable names but PRESERVES the
		// subsection, which for an includeIf is the path pattern — so folding
		// the whole key made every `gitdir:` pattern lowercase and every
		// condition silently false on a case-sensitive filesystem. Caught by the
		// control in this file's test, which is the whole reason it has one.
		lower := strings.ToLower(key)

		for _, w := range policy.GitKeyWhitelist {
			if lower != w {
				continue
			}
			// A git config VALUE may legally span lines, and the whitelist is a
			// list of KEYS — which is half a rule. Found by the red team: with
			//
			//	[user]
			//	  name = "evil\n[alias]\n\tanything = !touch /tmp/PWNED"
			//
			// `git config --list -z` returns the embedded newline faithfully, the
			// renderer wrote it verbatim as `name = <value>`, and the value closed
			// that line and opened a real `[alias]` section in the file the
			// sandbox trusts. `git anything` then ran the command. Every one of
			// the three whitelisted keys worked as the carrier, so the exact class
			// this profile exists to strip — credential.helper, core.pager,
			// core.sshCommand, alias = !cmd — came back through the value channel.
			//
			// This is the same shape as checkEnvValue, which has refused control
			// characters in a profile-supplied env value since that hole was
			// found: a rule written once and applied to one of its two halves.
			// Dropped rather than escaped, and named on stderr — git's quoting
			// rules are one more thing to get subtly wrong, and no name, email or
			// branch needs a control character.
			if i := strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }); i >= 0 {
				fmt.Fprintf(os.Stderr, "snug: dropping git %s from %s: the value contains a "+
					"control character, which would author directives in the config snug "+
					"generates rather than being carried as a value\n", lower, file)
				continue
			}
			out[lower] = value
		}

		switch {
		case lower == "include.path":
			// The UNCONDITIONAL include, which is how most people split a
			// gitconfig and which this code did not follow at all — so the
			// commonest layout of the very file snug reads was half-read, with
			// nothing said. git applies it wherever the line sits; so does this,
			// because the recursion happens inside the same loop.
			if err := readGitFile(git, resolveIncludePath(value, home, file),
				home, gitDir, out, seen, depth+1); err != nil {
				return err
			}

		case strings.HasPrefix(lower, "includeif.gitdir:") && strings.HasSuffix(lower, ".path"),
			strings.HasPrefix(lower, "includeif.gitdir/i:") && strings.HasSuffix(lower, ".path"):
			pattern := strings.TrimSuffix(strings.SplitN(key, ":", 2)[1], ".path")
			pat, dir, h := pattern, gitDir, home
			if strings.HasPrefix(lower, "includeif.gitdir/i:") {
				// All three, not two: `~/` is expanded against home inside the
				// matcher, so leaving home in its original case spliced a
				// mixed-case path into an otherwise lowercased pattern and the
				// condition never fired on a host whose home path has a capital
				// in it.
				pat, dir, h = strings.ToLower(pat), strings.ToLower(dir), strings.ToLower(home)
			}
			if !policy.GitdirMatches(pat, h, dir) {
				continue
			}
			if err := readGitFile(git, resolveIncludePath(value, home, file),
				home, gitDir, out, seen, depth+1); err != nil {
				return err
			}

		case strings.HasPrefix(lower, "includeif.hasconfig:"),
			strings.HasPrefix(lower, "includeif.onbranch:"):
			// Named, not skipped. Both conditions are decided by the SANDBOXED
			// MATERIAL — `hasconfig` by the repository's remotes, `onbranch` by
			// which branch it happens to be on — so honouring either would let
			// the repo choose which of the host's files snug reads. A human who
			// wrote one is entitled to know it was ignored, rather than
			// discovering later that the sandbox commits under a different
			// identity from the host.
			cond := "hasconfig:…"
			if strings.HasPrefix(lower, "includeif.onbranch:") {
				cond = "onbranch:…"
			}
			fmt.Fprintf(os.Stderr, "snug: ignoring an `includeIf %q` in %s: that condition is "+
				"decided by the repository being sandboxed, so honouring it would let the "+
				"sandboxed material choose which of your files snug reads\n", cond, file)
		}
	}
	return nil
}

// resolveIncludePath expands the three spellings an include path may use:
// home-relative, relative to the including file, and absolute.
func resolveIncludePath(p, home, including string) string {
	switch {
	case strings.HasPrefix(p, "~/"):
		return filepath.Join(home, p[2:])
	case strings.HasPrefix(p, "./"), !filepath.IsAbs(p):
		return filepath.Join(filepath.Dir(including), p)
	default:
		return filepath.Clean(p)
	}
}

// gitValuesLine renders the extraction for --dry-run and for the verbose log.
func gitValuesLine(v policy.GitValues) string {
	if len(v) == 0 {
		return "(nothing extracted)"
	}
	var b bytes.Buffer
	for _, k := range policy.SortedGitKeys() {
		if val, ok := v[k]; ok {
			if b.Len() > 0 {
				b.WriteString(" ")
			}
			fmt.Fprintf(&b, "%s=%s", k, val)
		}
	}
	return b.String()
}
