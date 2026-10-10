package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// conditionalEnv is a name snug writes only when a profile key turns a feature
// on — DOCKER_HOST when `podman` is on, SSH_AUTH_SOCK when an identity asks for
// the agent proxy. It is the other half of SnugOwnedEnv: a name there is snug's
// in every run and is refused at parse time; a name here is snug's in the runs
// whose SELECTION turns its feature on, and is refused at resolve time, as a
// conflict between snug's claim on the slot and a profile's.
//
// Parse-time ownership of these nine protected nobody hostile. `environ.*`
// comes only from the trusted profile set (invariant 3), and the payload can
// export DOCKER_HOST for itself. What it DID protect is real and is kept: a
// profile's line on a slot snug fills is discarded with no trace on any screen —
// the silent downgrade invariant 5 forbids. The six written in internal/cli
// after Resolve go through AuthorEnv, which replaces the whole variable; the
// three written inside Resolve (LISTEN_*, GIT_CONFIG_GLOBAL) keep the profile's
// entry BESIDE snug's, and a scalar's value is its first entry, so the
// profile's is carried and never used. So a profile that claims the slot in a
// selection where snug also fills it is refused, naming both claimants, exactly
// as two profiles `set`ting one scalar to two values are.
//
// THE PREDICATE READS THE SELECTION, NEVER THE WRITE. Two writers are
// conditional on more than their key: GIT_CONFIG_GLOBAL is not written when
// `git = "extract"` finds an empty host git config, and GH_CONFIG_DIR/GH_HOST
// are not written on a dry run that minted no token. A rule reading "refuse if
// snug authored it" would pass a profile on one host and refuse it on another
// (§4.4), and let --dry-run admit a selection the run refuses. So `on` is a
// predicate over resolved Policy fields that no host fact decides, and
// TestConditionalEnvWritersAreCoveredByTheirPredicate asserts the other
// direction: every name snug authored has its predicate true.
//
// THE CLAIM IS THE PROFILE TEXT, NEVER THE CLAIM SET. collectEnv records an
// `inherit` only when the host has the variable, so keying on envClaims would
// refuse `inherit DOCKER_HOST` on a host that exports it and admit it on one
// that does not — §4.4 again, arriving through the other claimant.
type conditionalEnv struct {
	// names are the variables snug writes for the feature — by AuthorEnv, or by
	// an `export` in a script it stages (LISTEN_PID).
	names []string
	// outranks are variables snug does NOT write but whose value the tool reads
	// IN PLACE OF what snug wrote: GH_TOKEN beats the token in the hosts.yml
	// snug generates, CONTAINER_CONNECTION beats CONTAINER_HOST. A profile's
	// line on one redirects the feature exactly as a line on a name above would,
	// so it is the same conflict. Each is measured beside its envNotes row.
	outranks []string
	// key names, for one profile, the key in its text that turns the feature on,
	// as the message prints it.
	key func(prof *Profile) string
	// on is the selection predicate over the resolved policy.
	on func(p *Policy) bool
	// by reports whether one profile's TEXT turns the feature on, so the
	// message can name every profile on snug's side of the conflict, not the
	// one a fold happened to be holding.
	by func(prof *Profile) bool
	// writes is what snug does with the slot, for the message.
	writes string
}

var conditionalEnvs = []conditionalEnv{
	{
		names:    []string{"CONTAINER_HOST", "DOCKER_BUILDKIT", "DOCKER_HOST"},
		outranks: []string{"CONTAINER_CONNECTION"},
		key:      func(prof *Profile) string { return fmt.Sprintf("podman = %q", prof.Podman) },
		on:       func(p *Policy) bool { return p.Podman != PodmanOff },
		by: func(prof *Profile) bool {
			m, err := ParsePodmanMode(prof.Podman)
			return err == nil && m != PodmanOff
		},
		writes: "points the container clients at its filtering proxy",
	},
	{
		// Every selected identity is the same identity once normalised — Resolve
		// refuses two that differ — so the per-profile half is "has an identity"
		// and the agent mode is read once, off the resolved one.
		names:  []string{"SSH_AUTH_SOCK"},
		key:    func(*Profile) string { return `identity.ssh.agent = "proxy"` },
		on:     func(p *Policy) bool { return p.Identity != nil && p.Identity.SSH.Agent != SSHNone },
		by:     func(prof *Profile) bool { return prof.Identity != nil },
		writes: "points ssh at its one-key agent proxy",
	},
	{
		names:    []string{"GH_CONFIG_DIR", "GH_HOST"},
		outranks: []string{"GH_ENTERPRISE_TOKEN", "GH_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GITHUB_TOKEN"},
		key:      func(*Profile) string { return "identity.gh.user" },
		on:       func(p *Policy) bool { return p.Identity != nil && p.Identity.Gh.User != "" },
		by:       func(prof *Profile) bool { return prof.Identity != nil },
		writes:   "points gh at the config it generates for that one account",
	},
	{
		names: []string{"GIT_CONFIG_GLOBAL"},
		key: func(prof *Profile) string {
			if prof.Identity != nil {
				return "identity"
			}
			return `git = "extract"`
		},
		on: func(p *Policy) bool { return p.Git == GitExtract || p.Identity != nil },
		by: func(prof *Profile) bool {
			m, err := ParseGitMode(prof.Git)
			return prof.Identity != nil || (err == nil && m == GitExtract)
		},
		writes: "points git at the ~/.gitconfig it generates",
	},
	{
		names:  []string{"LISTEN_FDNAMES", "LISTEN_FDS", "LISTEN_PID"},
		key:    func(*Profile) string { return "listen_names" },
		on:     func(p *Policy) bool { return len(p.ListenNames) > 0 },
		by:     func(prof *Profile) bool { return len(prof.ListenNames) > 0 },
		writes: "hands the payload its listening descriptors",
	},
	{
		names: []string{"BROWSER"},
		key:   func(prof *Profile) string { return fmt.Sprintf("login = %q", prof.Login) },
		on:    func(p *Policy) bool { return p.Login.Has(LoginClaude) },
		by: func(prof *Profile) bool {
			s, err := ParseLoginSet(prof.Login)
			return err == nil && s.Has(LoginClaude)
		},
		writes: "points Claude Code's browser opener at snug's login bridge",
	},
}

// ConditionalEnvNames is every name snug writes for a feature, sorted.
// Exported for internal/cli's ownership test, which asserts the names snug
// writes — AuthorEnv calls and `export`s in staged scripts — equal SnugOwnedEnv
// plus these, so a new conditional writer is a row here or a failing build.
func ConditionalEnvNames() []string {
	var out []string
	for _, c := range conditionalEnvs {
		out = append(out, c.names...)
	}
	sort.Strings(out)
	return out
}

// ConditionalEnvClaimed is ConditionalEnvNames plus the names that outrank
// them: every name a profile may not write in a selection that turns the
// feature on, and a profile snug ships may never write.
func ConditionalEnvClaimed() []string {
	out := ConditionalEnvNames()
	for _, c := range conditionalEnvs {
		out = append(out, c.outranks...)
	}
	sort.Strings(out)
	return out
}

// ConditionalEnvOn reports whether the selection behind p makes snug the
// author of name. False for a name that is not conditional.
func ConditionalEnvOn(p *Policy, name string) bool {
	for _, c := range conditionalEnvs {
		if slices.Contains(c.names, name) {
			return c.on(p)
		}
	}
	return false
}

// checkConditionalEnv refuses a profile that claims a slot the selection makes
// snug fill. It runs after the fold, when every predicate's field is final, and
// BEFORE the first conditional writer, LISTEN_FDS, so no refused selection
// gets as far as authoring anything.
//
// No agreement arm: a profile that "agrees" with snug's value has written
// nothing snug did not, and for the post-Resolve writers snug's value is not
// known here at all.
func checkConditionalEnv(p *Policy, set map[ProfileName]*Profile, names, selected []ProfileName) error {
	for _, c := range conditionalEnvs {
		if !c.on(p) {
			continue
		}
		for _, env := range append(append([]string(nil), c.names...), c.outranks...) {
			var claims []string
			for _, n := range names {
				g := set[n].Environ
				if v, ok := g.Set[env]; ok {
					claims = append(claims, fmt.Sprintf("%s (environ.set) says %q", n, VisibleText(v)))
				}
				if slices.Contains(g.Inherit, env) {
					claims = append(claims, fmt.Sprintf("%s (environ.inherit) takes the host's value", n))
				}
			}
			if len(claims) == 0 {
				continue
			}
			var keys []string
			owners := map[ProfileName]bool{}
			for _, n := range names {
				if c.by(set[n]) {
					owners[n] = true
					keys = append(keys, fmt.Sprintf("%s sets %s", n, c.key(set[n])))
				}
			}
			var b strings.Builder
			if slices.Contains(c.names, env) {
				fmt.Fprintf(&b, "%s has two authors in this selection, and snug will not choose:\n", env)
			} else {
				fmt.Fprintf(&b, "%s outranks what snug writes in this selection, and snug will not choose:\n", env)
			}
			for _, cl := range claims {
				fmt.Fprintf(&b, "         %s\n", cl)
			}
			fmt.Fprintf(&b, "         %s, so snug %s\n", strings.Join(keys, "; "), c.writes)
			b.WriteString("       Keeping the profile's value would leave snug's feature pointing nowhere;\n")
			b.WriteString("       keeping snug's would discard a line the profile wrote. Remove the line, or\n")
			fmt.Fprintf(&b, "       drop %s from the selection.", JoinNames(reaching(set, selected, owners), ", "))
			return fmt.Errorf("%s", b.String())
		}
	}
	return nil
}

// reaching returns the SELECTED profiles whose include closure contains any of
// owners — the names a user can actually drop. An owner that arrived through an
// include is not in the selection, and naming it would be a fix nobody can
// apply.
func reaching(set map[ProfileName]*Profile, selected []ProfileName, owners map[ProfileName]bool) []ProfileName {
	var out []ProfileName
	for _, root := range selected {
		closure := map[ProfileName]*Profile{}
		// set is already the expanded, cycle-checked closure of every root, so
		// expanding one root over it cannot fail.
		_ = expand(set, root, closure, nil)
		for n := range closure {
			if owners[n] {
				out = append(out, root)
				break
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
