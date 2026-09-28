package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// EnvKind is a TYPE a profile declares, in [profile.NAME.environ.types], for a
// name snug's roster has no row for. Two kinds, and the kind fixes every fact a
// verb reads (envType below) — there is no separator key, no sanitise key, no
// empty-element key, because those are measurements snug cannot take on the
// author's behalf.
//
// Abuse: a hostile process inside the sandbox can use a declaration to do
// nothing it cannot already do with `export` — it is trusted-layer profile
// text, grants no path, device or socket, and changes only which verbs that
// one profile's author may write. A MISTAKEN author gets a value the tool
// misreads (a ';'- or space-reading consumer sees one nonexistent path), or,
// for a consumer whose elements do not compose, every declared element loaded
// into every process as that author — rendered on --dry-run as
// `← unknown` and `← declared path-list by <profile>`. A declared code
// search list pointing at a writable directory is the human-profile residual
// the shadow-slot rule already accepts; a shipped profile cannot declare.
type EnvKind uint8

const (
	envKindUnset    EnvKind = iota // no valid zero: a code-built Profile with 0 is refused
	EnvKindPath                    // one absolute path; grant-coupling + absolute rule
	EnvKindPathList                // ':'-joined absolute paths; merge/prepend only
)

// EnvKinds returns every valid EnvKind, in declaration order. It is the whole
// accepted set: ParseEnvKind accepts exactly the String of one of these.
func EnvKinds() []EnvKind { return []EnvKind{EnvKindPath, EnvKindPathList} }

// String returns the TOML spelling of k: "path", "path-list", or "unset" for
// the zero value, which no profile can write.
func (k EnvKind) String() string {
	switch k {
	case EnvKindPath:
		return "path"
	case EnvKindPathList:
		return "path-list"
	}
	return "unset"
}

// ParseEnvKind returns the EnvKind whose String is exactly s. Any other value,
// including a different case or the empty string, is an error quoting s and
// naming the accepted set — it is never read as the nearest kind it resembles.
func ParseEnvKind(s string) (EnvKind, error) {
	for _, k := range EnvKinds() {
		if s == k.String() {
			return k, nil
		}
	}
	return envKindUnset, fmt.Errorf("unknown environ type %q (want path or path-list)", s)
}

func (k EnvKind) envType() envType {
	switch k {
	case EnvKindPath:
		return envType{path: true}
	case EnvKindPathList:
		// emptyOperator is the WORST CASE, not a measurement: snug does not know
		// the consumer, and "empty = cwd" is the middle case. sanitisable is false
		// for the same reason. mergeable ⇒ path holds by construction
		// (TestEveryMergeableListIsPathValued sweeps EnvKinds too).
		return envType{list: true, sep: ":", path: true, empty: emptyOperator, mergeable: true}
	}
	return envType{}
}

// compatibleWith: a declaration of a ROSTERED name is admitted only when every
// verb it licenses is legal under the row with the same join and at least the
// same checks. The row then governs; the declaration is inert.
func (k EnvKind) compatibleWith(t envType) bool {
	switch k {
	case EnvKindPath:
		return !t.list && t.path
	case EnvKindPathList:
		return t.list && t.sep == ":" && t.path && t.mergeable
	}
	return false
}

// describe renders a roster row for the refusal that quotes it against a
// declaration.
func (t envType) describe() string {
	if !t.list {
		switch {
		case t.path:
			return "a scalar path"
		case t.pathNoGrant:
			return "a scalar path the grant-coupling rule deliberately does not check"
		}
		return "a scalar that is not a path"
	}
	s := fmt.Sprintf("a list separated by %q", t.sep)
	if t.altSep != "" {
		s += fmt.Sprintf(" or %q", t.altSep)
	}
	if !t.path {
		s += ", not of paths"
	}
	if !t.mergeable {
		s += ", whose elements snug does not compose"
	}
	return s
}

// envDeclaration is the selection's verdict on one declared, unrostered name:
// the kind, and every profile that declared it, sorted.
type envDeclaration struct {
	kind EnvKind
	by   []string
}

// checkEnvTypes is the parse-time verdict on a profile's environ.types block.
// It runs before any verb is judged, because every verb check reads the
// declarations it admits.
func checkEnvTypes(g EnvGrants) error {
	names := make([]string, 0, len(g.Types))
	for n := range g.Types {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		kind := g.Types[name]
		if err := checkEnvNameAt(name, "types"); err != nil {
			return err
		}
		if kind != EnvKindPath && kind != EnvKindPathList {
			return fmt.Errorf("environ.types gives %s no type. Write %s = \"path\" or %s = \"path-list\"",
				name, name, name)
		}
		if slices.Contains(SnugOwnedEnv, name) {
			return fmt.Errorf("environ.types names %s, which snug writes itself. snug types its own "+
				"names: a declaration there is either redundant (PATH is already a ':' list a "+
				"profile may merge onto without one) or a way to reach a scalar snug owns with a "+
				"list verb. Remove the line", name)
		}
		if slices.Contains(bwrapOwnedEnv, name) {
			return fmt.Errorf("environ.types names %s, which bwrap sets to the sandbox's "+
				"working directory after every --setenv. No profile line on it reaches the "+
				"payload. Remove the line", name)
		}
		if slices.Contains(ConditionalEnvClaimed(), name) {
			return fmt.Errorf("environ.types names %s, which snug writes, or which outranks what "+
				"snug writes, when a feature is on (podman, identity, git = \"extract\", "+
				"listen_names). A declared list would reach it through environ.merge, and snug "+
				"judges a profile's claim on these names only as the single value its own "+
				"replaces. Remove the line; to point the tool elsewhere, environ.set it in a "+
				"selection that leaves the feature off", name)
		}
		if t, known := typeOf(name); known && !kind.compatibleWith(t) {
			return fmt.Errorf("environ.types declares %s %s, and snug's roster already types it: %s. "+
				"A declaration supplies a fact for a name snug has NOT measured; it never "+
				"overrides one snug has. Remove the line — the row decides which verbs %s takes",
				name, kind, t.describe(), name)
		}
		switch kind {
		case EnvKindPathList:
			_, merged := g.Merge[name]
			_, prepended := g.Prepend[name]
			if !merged && !prepended {
				return fmt.Errorf("environ.types declares %s path-list, and this profile neither "+
					"merges nor prepends it. A declaration applies to this profile's own lines "+
					"only — not to a profile that includes this one, nor to one selected beside "+
					"it — so here it does nothing. Remove it, or add the environ.merge line it "+
					"was written for", name)
			}
		case EnvKindPath:
			if _, set := g.Set[name]; !set {
				return fmt.Errorf("environ.types declares %s path, and this profile does not "+
					"environ.set it. A path declaration governs a value this profile WRITES — "+
					"environ.inherit copies the host's value, which snug does not check — so "+
					"here it does nothing. Remove it, or add the environ.set line it was written "+
					"for", name)
			}
		}
	}
	return nil
}

// checkDeclaredVerbType is checkEnvVerbType for a name with no roster row that
// this profile declared, and it reads the kind's facts rather than a row's.
func checkDeclaredVerbType(name string, verb EnvVerb, kind EnvKind) error {
	switch kind {
	case EnvKindPathList:
		switch verb {
		case VerbSet:
			return fmt.Errorf("environ.set on %s, which this profile declares path-list — a list. "+
				"Use environ.merge, or environ.prepend if the order matters: environ.set on a "+
				"list would replace every other profile's entries", name)
		case VerbInherit:
			return fmt.Errorf("environ.inherit on %s, which this profile declares path-list — a "+
				"list. Inheriting a host list wholesale imports directories the sandbox does not "+
				"have, and a declared list cannot be sanitised either. Use environ.merge with the "+
				"directories you mean", name)
		case VerbSanitise:
			return fmt.Errorf("environ.sanitise on %s, which this profile declares path-list. snug "+
				"does not know what an EMPTY element means to %s's consumer — ignored, the "+
				"current directory, or an instruction that ADDS directories "+
				"(.claude/design/ENVIRONMENT-VARIABLES.md §3.3) — so it assumes the last, and "+
				"under that a filter can add directories instead of removing them. Use "+
				"environ.merge with the directories you mean, or add a row to "+
				"internal/policy/envtypes.go carrying the measured empty-element kind", name, name)
		}
	case EnvKindPath:
		switch verb {
		case VerbMerge, VerbPrepend:
			return fmt.Errorf("environ.%s on %s, which this profile declares path — a scalar, not "+
				"a list. Use environ.set, or declare it path-list if its consumer reads "+
				"':'-joined paths", verb, name)
		case VerbSanitise:
			return fmt.Errorf("environ.sanitise on %s, which this profile declares path — a "+
				"scalar. sanitise filters the ELEMENTS of a host list; use environ.inherit to "+
				"take the host's value, or environ.set to write one", name)
		}
	}
	return nil
}

// checkEnvShapeAgreement refuses a selection in which a name with no roster
// row is a declared list in one profile and a single value in another, and
// returns the selection's declaration for every declared unrostered name.
//
// It reads profile TEXT only — an `inherit` counts whether or not the host has
// the variable — so the verdict is the same on every host, and every conflict
// names every claimant whatever order the profiles were selected in.
func checkEnvShapeAgreement(set map[ProfileName]*Profile, names, selected []ProfileName) (map[string]envDeclaration, error) {
	vars := map[string]bool{}
	for _, n := range names {
		g := set[n].Environ
		for k := range g.Types {
			vars[k] = true
		}
		for k := range g.Set {
			vars[k] = true
		}
		for k := range g.Merge {
			vars[k] = true
		}
		for k := range g.Prepend {
			vars[k] = true
		}
		for _, k := range g.Inherit {
			vars[k] = true
		}
	}
	sortedVars := make([]string, 0, len(vars))
	for k := range vars {
		if _, known := typeOf(k); !known {
			sortedVars = append(sortedVars, k)
		}
	}
	sort.Strings(sortedVars)

	sortedNames := append([]ProfileName(nil), names...)
	slices.Sort(sortedNames)

	decls := map[string]envDeclaration{}
	for _, x := range sortedVars {
		var listSide, scalarSide, claims []string
		claimants := map[ProfileName]bool{}
		var decl envDeclaration
		for _, n := range sortedNames {
			g := set[n].Environ
			kind, declared := g.Types[x]
			if declared {
				decl.by = append(decl.by, string(n))
				if kind == EnvKindPathList || decl.kind == envKindUnset {
					decl.kind = kind
				}
			}
			if v, ok := g.Set[x]; ok {
				line := fmt.Sprintf("%s (environ.set) writes it as one value: %q", n, v)
				if declared && kind == EnvKindPath {
					line += ", declared path"
				}
				scalarSide = append(scalarSide, line)
				claims = append(claims, line)
				claimants[n] = true
			}
			if vs, ok := g.Merge[x]; ok && declared && kind == EnvKindPathList {
				line := fmt.Sprintf("%s (environ.types) declares it path-list and merges %s", n, seqKey(vs))
				listSide = append(listSide, line)
				claims = append(claims, line)
				claimants[n] = true
			}
			if vs, ok := g.Prepend[x]; ok && declared && kind == EnvKindPathList {
				line := fmt.Sprintf("%s (environ.types) declares it path-list and prepends %s", n, seqKey(vs))
				listSide = append(listSide, line)
				claims = append(claims, line)
				claimants[n] = true
			}
			if slices.Contains(g.Inherit, x) {
				line := fmt.Sprintf("%s (environ.inherit) takes the host's value as one value", n)
				scalarSide = append(scalarSide, line)
				claims = append(claims, line)
				claimants[n] = true
			}
		}
		if len(listSide) > 0 && len(scalarSide) > 0 {
			var b strings.Builder
			fmt.Fprintf(&b, "%s is typed two ways in this selection, and snug will not choose:\n", x)
			for _, cl := range claims {
				fmt.Fprintf(&b, "         %s\n", cl)
			}
			b.WriteString("       A list and a single value cannot share a name: joining would make the single\n")
			b.WriteString("       value one element of a list it was never written as, and keeping it would\n")
			fmt.Fprintf(&b, "       discard every element. Declare %s = \"path-list\" in every profile that writes\n", x)
			fmt.Fprintf(&b, "       it and use environ.merge, or drop one of %s from the selection.",
				JoinNames(reaching(set, selected, claimants), ", "))
			return nil, fmt.Errorf("%s", b.String())
		}
		if len(decl.by) > 0 {
			decls[x] = decl
		}
	}
	return decls, nil
}

// DeclaredEnvNote renders an environ.types declaration for the row of one
// entry: "  ← declared <kind> by <profiles>". It returns "" for VerbSnug, for
// the zero EnvKind, and for an empty by — the three cases in which no profile
// declared the name.
func DeclaredEnvNote(kind EnvKind, by []string, verb EnvVerb) string {
	if verb == VerbSnug || kind == envKindUnset || len(by) == 0 {
		return ""
	}
	return "  ← declared " + kind.String() + " by " + strings.Join(by, ", ")
}

// DeclaredEnvNoteIn is DeclaredEnvNote for `snug profile show`, which renders
// one profile and so names only prof. It returns "" when snug's roster types
// name — the row governs and the declaration is inert — or when g declares no
// type for name.
func DeclaredEnvNoteIn(name string, verb EnvVerb, g EnvGrants, prof ProfileName) string {
	if _, known := typeOf(name); known {
		return ""
	}
	kind, ok := g.Types[name]
	if !ok {
		return ""
	}
	return DeclaredEnvNote(kind, []string{string(prof)}, verb)
}

// RedundantEnvDeclarationNote marks a declaration of a name snug's roster
// already types: "  ← redundant: snug's roster types this name, and the row
// governs". It returns "" for a name the roster does not know.
func RedundantEnvDeclarationNote(name string) string {
	if _, known := typeOf(name); !known {
		return ""
	}
	return "  ← redundant: snug's roster types this name, and the row governs"
}
