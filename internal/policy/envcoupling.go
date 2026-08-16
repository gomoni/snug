package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The grant-coupling rule (§2.5).
//
// IT IS A COUPLING RULE, NOT AN EXISTENCE CHECK, and the distinction is the
// whole of it. The profile that NAMES a path in the environment must be the
// profile that put a node on the chain to it, so a reviewer reading one profile
// sees both acts on one screen. It cannot prove the path exists: internal/policy
// may not touch the filesystem, a `tmpfs` grant creates an EMPTY directory, and
// a bind's contents are host state that changes under us.
//
// So do not cite this check as a boundary. IT IS NOT ONE. The value is inert —
// nothing in the environment grants access to anything — and the payload can set
// any variable it likes the moment it is running. It stops a profile LYING; it
// does not stop anything REACHING. A false positive here yields a variable
// naming an empty directory, which is a usability bug rather than a hole.
//
// Scope: values a profile WRITES (set/merge/prepend) at names the type table
// marks path-valued. `inherit` and `sanitise` are exempt because the value is
// the host's, not the profile's — sanitise has its own filter for exactly that
// (envresolve.go). EDITOR=vim is out of scope because EDITOR is not a path.
//
// The verdict is computed over profile TEXT, never over resolved mounts, and
// that is deliberate. @claude marks every one of its `ro` entries optional, so
// an absent grant produces no mount at all — checking mounts would make a
// profile's LEGALITY depend on the host reading it, which is precisely the
// defect §4.4 records for the old forbidden-name check, adopted there by
// accident and refused here on purpose.

// checkEnvCoupling refuses a profile whose environment names a path it does not
// grant.
//
// THE INCLUDE CLOSURE COUNTS; THE SELECTED SET DOES NOT. `include` is the
// profile's own text: static, host-independent, and rendered by `snug profile
// tree`. If the selected set counted, Resolve([a]) could refuse what
// Resolve([a,b]) admits — one profile would change another profile's verdict,
// which is not a visibility break but is one edit away from being one. See
// TestCouplingVerdictDoesNotDependOnTheSelectedSet, which exists because that
// edit is easy to make and impossible to notice.
func checkEnvCoupling(reg map[ProfileName]*Profile, name ProfileName, g EnvGrants, vars map[string]string) error {
	if !writesAnyPath(g) {
		return nil
	}
	guests, links, err := profileGuestGrants(reg, name, vars)
	if err != nil {
		return err
	}

	for _, k := range sortedMapKeys(g.Set) {
		if err := checkCoupled(name, VerbSet, k, g.Set[k], vars, guests, links); err != nil {
			return err
		}
	}
	for _, verb := range []EnvVerb{VerbMerge, VerbPrepend} {
		m := g.Merge
		if verb == VerbPrepend {
			m = g.Prepend
		}
		for _, k := range sortedListKeys(m) {
			for _, raw := range m[k] {
				if err := checkCoupled(name, verb, k, raw, vars, guests, links); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// writesAnyPath is the cheap gate, so a profile with no path-valued write never
// pays for the closure walk.
//
// It asks the WIDER question (valueIsAPath), because a profile whose only
// path-valued write is `set BASH_ENV` still has to reach checkCoupled — for the
// absolute-path verdict, not for a coverage check it is exempt from. Asking the
// narrow one here would have made the fix below unreachable for exactly the
// names it is about.
func writesAnyPath(g EnvGrants) bool {
	for _, m := range []map[string][]string{g.Merge, g.Prepend} {
		for k := range m {
			if valueIsAPath(k) {
				return true
			}
		}
	}
	for k := range g.Set {
		if valueIsAPath(k) {
			return true
		}
	}
	return false
}

// isPathValued is the coupling rule's scope, and an UNROSTERED name is outside
// it.
//
// READ THE NEXT PARAGRAPH AS SCOPED TO THIS FUNCTION, WHICH IS WHERE IT WAS NOT
// READ. It defends the COUPLING rule's scope and it was quoted, once, to defend
// the ABSOLUTE-PATH rule's — for which it is false, because valueIsAPath now has
// a third source and the annotation table does hold facts about unrostered
// names. Coupling is a different question ("did the profile that names this path
// grant it") and its answer for an unrostered name is unchanged.
//
// That is not an oversight and it is the honest answer rather than the
// convenient one: `path` is a fact snug holds about a name, and for a name with
// no roster row snug holds no TYPE at all. The alternative is to decide a value
// is a path because it starts with a '/', which is precisely the shape-sniffing
// this file's header refuses ("the shape is the same for a search path, a URL, a
// template language bash performs command substitution on, and a set of
// delimiter characters"). So an unrostered value naming a path the profile does
// not grant is NOT refused, where the same value under a rostered path-valued
// name would be. What that costs is one profile-lying case going unreported —
// and --dry-run still marks that row `← unchecked`, and grantMark still says
// `← not granted` where the value is spelled like an absolute path nothing
// covers. What it would cost to close by guessing is a rule that refuses a
// correct value for every name whose value merely looks like a path —
// LESSOPEN's does, and it is a command line.
func isPathValued(name string) bool {
	t, known := typeOf(name)
	return known && t.path
}

// valueIsAPath answers a WIDER question than isPathValued: not "does the
// grant-coupling rule apply to this name" but "is this value a filesystem path
// at all". The two were one flag, and that is the defect: turning coupling off
// for the startup files turned the absolute-path rule off with them.
//
// WHY REFUSING A RELATIVE VALUE IS A TYPE REFUSAL AND NOT A PERMISSION ONE,
// written here because this is where the next reader meets it, and because
// §1.4 says snug refuses in three shapes and "this grant is dangerous" is not
// one of them.
//
// A profile is static text with a host-independent meaning. The sandbox's
// working directory is `--chdir <target>`, which the profile did not choose,
// cannot know, and which is the one directory a hostile payload can write. So
// `BASH_ENV = ".snug-init.sh"` does not name a file: it names whatever file of
// that name happens to be in the directory the payload was last in. There is no
// string snug can put in `--setenv` that means what the author meant, because
// the author cannot have meant anything definite. Refusing is snug declining to
// carry a value it cannot represent honestly — the same shape as declining
// `sanitise` on MANPATH.
//
// THE TEST THAT TELLS THE TWO APART, AND IT IS THE ONE TO APPLY TO ANY FUTURE
// REFUSAL IN THIS FILE: a refusal with an accepted spelling of the same intent
// is not a denial. `BASH_ENV = "{target}/.snug-init.sh"` is accepted and says
// precisely what the author meant. The identical refusal already applied,
// unremarked, to thirteen other names and to every element of every path-valued
// list; what changed here is the INCONSISTENCY, not the policy.
//
// And what it does NOT close: nothing. The payload sets BASH_ENV for itself
// whenever it likes. What it stops is snug HANDING OVER a value whose meaning is
// decided by the payload's cwd — the `sanitise` rule, one table over: the
// environment snug itself hands over must not ship the ambiguity pre-installed.
//
// IT READS TWO TABLES, AND THE SECOND ONE IS THE FIX FOR A NAME THE FIRST ONE
// COULD NEVER CARRY. A POINTER is, by inlineConfigPointers' own definition, "a
// name whose value is a PATH to a file snug or a profile generated" — the whole
// of "generate, don't bind" at the environment. Four of the five writable
// pointers happen to have a roster row with `path: true`, so both rules fired for
// them; GIT_CONFIG_SYSTEM has no roster row, so NEITHER did, and the argument in
// the paragraph above applied to it word for word. Measured INSIDE a running
// sandbox (redteam host round 2, F1), on this branch:
//
//	[profile.gitsys.environ.set]
//	GIT_CONFIG_SYSTEM = "sys.gitconfig"        -> ACCEPTED, and --dry-run said
//	                                              nothing about the value either
//	  (grantMark returns "" for a value that does not start with '/')
//	$ snug … -p @cwd-rw -p gitsys /tmp/rt2/tgt -- sh -c 'git st; git ls-remote …'
//	  CWD=/tmp/rt2/tgt
//	  RELATIVE-GIT-CONFIG-SYSTEM-ALIAS-RAN uid=1000        <- [alias] st = "!cmd"
//	  RELATIVE-GIT-CONFIG-SYSTEM-SSHCOMMAND-RAN args=…     <- core.sshCommand
//
// The file it resolved against is `--chdir <target>`: the one writable thing a
// hostile payload controls. The same four spellings that ARE rostered were
// refused in the same run.
//
// WHY A PREDICATE AND NOT A ROSTER ROW. Adding `"GIT_CONFIG_SYSTEM": {path:
// true}` to envTypes would fix the same two lines and would ALSO open the builtin
// gate: internal/profile's checkBuiltinEnvRoster is written on IsUncheckedEnv,
// which answers from the roster alone, so a row here makes the name one a profile
// snug SHIPS may write. That gate is deliberate and this fix must not touch it —
// so the fact "snug's own tables call this a pointer at a FILE" is read from the
// table that already holds it. The pointer set is a security boundary
// (IsInlineConfigEnv's doc comment); this is one more consequence of being in it.
//
// It stays OUT of isPathValued, so the coupling rule's scope is unchanged: an
// absolute GIT_CONFIG_SYSTEM the profile does not grant is still accepted, still
// marked `← not granted`, and still carries its own annotation. Only the
// unrepresentable spelling is refused.
//
// IT READS THREE TABLES NOW, AND THE THIRD IS THE SAME LESSON A THIRD TIME
// (redteam host round 3). Closing the pointer set closed the pointer set. It did
// not reach the git names that carry the identical power and are in neither
// table — measured, INSIDE a running sandbox, at 8d17f85:
//
//	GIT_CONFIG_SYSTEM = "sys.gitconfig"  -> REFUSED   (the fix above)
//	GIT_TEMPLATE_DIR  = "tpl"            -> ACCEPTED, and the hook in <target>/r/tpl/
//	                                        was copied into .git/hooks and FIRED
//	                                        on the next commit, uid 1000
//	GIT_EXEC_PATH     = "gx"             -> ACCEPTED, and `git probecmd` ran
//	                                        <target>/gx/git-probecmd, uid 1000
//	GIT_DIR, GIT_COMMON_DIR              -> ACCEPTED (hooks, one indirection out)
//
// isPathValued's comment below defends leaving unrostered names alone with "for
// a name with no roster row snug holds no facts at all". That is true of a name
// snug has never heard of and FALSE of these four: each carries an envNotes
// sentence naming the code the directory runs, printed on --dry-run. snug held
// the fact, showed it to the human, and then asked two other tables.
//
// So the third source is the annotation's own shape column (valueShape), read
// through noteExact — the EXACT table only, never a prefix, because a family's
// members do not share a shape. What that buys over a list of the four names is
// the property the round asked for: the question "is this value a path" is now
// asked of every annotation that is ever ADDED, since the column has no valid
// zero value (TestEveryAnnotationSaysWhatItsValueIS).
//
// The pointer clause stays even though every writable pointer is also
// shapePath — GIT_CONFIG_GLOBAL and GH_CONFIG_DIR are snug's own and carry no
// annotation at all, and "a pointer is a path" should not become a fact that
// only holds while somebody keeps writing the sentence.
func valueIsAPath(name string) bool {
	if namesAPointerFile(name) {
		return true
	}
	if n, ok := noteExact(name); ok && n.shape == shapePath {
		return true
	}
	t, known := typeOf(name)
	return known && (t.path || t.pathNoGrant)
}

// checkCoupled is the verdict on one written value.
func checkCoupled(profile ProfileName, verb EnvVerb, name, raw string, vars map[string]string, guests []string, links map[string]string) error {
	// TWO QUESTIONS, ASKED SEPARATELY. Coupling applies to the names the roster
	// marks `path`; the absolute-path rule applies to every name whose value IS a
	// path, which is a wider set (valueIsAPath). A name in the wider set only
	// gets the second verdict and returns before the coverage walk below.
	coupled := isPathValued(name)
	if !coupled && !valueIsAPath(name) {
		return nil
	}
	value, err := expandVars(raw, vars)
	if err != nil {
		return fmt.Errorf("profile %q: %w", profile, err)
	}
	// A relative value can never be covered — there is nothing to compare it
	// against — but it has its own defect and its own message, so hand it to the
	// one function that owns that refusal rather than writing a second wording of
	// it here. This is also the only path by which a relative `set` is refused:
	// checkAbsoluteElement is called from the list verbs alone.
	if !filepath.IsAbs(value) {
		return checkAbsoluteElement(profile, name, verb, raw, value)
	}
	if !coupled {
		// Absolute is the whole of what snug checks for BASH_ENV, ENV and
		// PYTHONSTARTUP. The grant is not checked, and the annotation says so
		// rather than instructing — see their envNotes entries, which used to
		// read "grant the path in the same profile" while nothing did.
		return nil
	}
	// Symlinks are RESOLVED FIRST and are never a grant themselves. On a
	// usr-merged host /bin is a symlink snug creates, so a profile granting /usr
	// and naming /bin/foo named the path the sandbox will actually see.
	resolved := resolveLinkForEnv(links, filepath.Clean(value))
	if coversGuest(guests, resolved) {
		return nil
	}
	via := ""
	if resolved != filepath.Clean(value) {
		via = fmt.Sprintf(" (which resolves to %s through a symlink the profile creates)", resolved)
	}
	return fmt.Errorf("profile %q %ss %s=%s%s, which it does not grant.\n"+
		"       Add the path to that profile's ro/rw/tmpfs — or to a profile it includes — or\n"+
		"       drop the variable: a variable naming a path that is not inside the sandbox is\n"+
		"       worse than an absent one, because every tool that reads it will believe it.\n"+
		"       snug is not checking that the path EXISTS (it cannot: a tmpfs grant creates an\n"+
		"       empty directory), only that the profile naming it is the profile that granted it.",
		profile, verb, name, value, via)
}

// coversGuest is lexical containment on `/` boundaries, DOWNWARD with no depth
// limit: a grant covers itself and everything under it.
//
// Coverage rather than an exact match, because SHELL=/usr/bin/bash against
// ro=["/usr"] must pass and there is no principled depth at which to stop. The
// accepted cost is that @home is a rubber stamp for all of $HOME, and that a
// profile including @sys+@home is checked vacuously under /usr and {home} — see
// @podman-socket. That is correct: the profile DID bring them, on an `include`
// line that --dry-run and $SNUG_PROFILES both render.
func coversGuest(guests []string, path string) bool {
	for _, g := range guests {
		if path == g || strings.HasPrefix(path, g+"/") {
			return true
		}
	}
	return false
}

// profileGuestGrants collects the GUEST side of every path grant a profile
// makes, over its own text plus its `include` closure, and the symlink map from
// the same closure.
//
// The guest side, because that is the path the environment value will name from
// inside; a `host:guest` spec's host side is irrelevant to what the payload sees.
//
// A spec that fails to expand or split is SKIPPED rather than reported here.
// That is not swallowing an error: every profile in the closure is also in the
// selected set (Resolve expands includes before folding), so the same spec is
// parsed again by the fold and refused there, with the right profile named.
// Skipping makes this set SMALLER, so the coupling check gets stricter, never
// laxer.
func profileGuestGrants(reg map[ProfileName]*Profile, name ProfileName, vars map[string]string) ([]string, map[string]string, error) {
	closure := map[ProfileName]*Profile{}
	if err := expand(reg, name, closure, nil); err != nil {
		return nil, nil, err
	}

	var guests []string
	links := map[string]string{}
	for _, n := range sortedProfileNames(closure) {
		prof := closure[n]
		for _, specs := range [][]string{prof.RO, prof.RW} {
			for _, s := range specs {
				_, guest, err := splitSpec(s, vars)
				if err != nil {
					continue
				}
				guests = append(guests, guest)
			}
		}
		for _, s := range prof.Tmpfs {
			g, err := expandVars(s, vars)
			if err != nil {
				continue
			}
			guests = append(guests, filepath.Clean(g))
		}
		for _, s := range prof.Symlink {
			at, err := expandVars(s.At, vars)
			if err != nil {
				continue
			}
			at = filepath.Clean(at)
			target := s.Target
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(at), target)
			}
			links[at] = filepath.Clean(target)
		}
	}
	return guests, links, nil
}

// sortedProfileNames is slices.Sort rather than sort.Strings for the same
// reason Resolve's fold is: ProfileName is a defined type over string, which
// cmp.Ordered admits and []string does not. The ordering is byte-wise either
// way, so nothing observable moves.
func sortedProfileNames(m map[ProfileName]*Profile) []ProfileName {
	out := make([]ProfileName, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
