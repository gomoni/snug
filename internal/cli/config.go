package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// userConfig is ~/.config/snug/config.toml. It holds preferences, never grants:
// what a bare `snug <dir>` selects, and nothing that could widen a sandbox on
// its own. Grants live in profiles, which is the one vocabulary for them.
type userConfig struct {
	// Defaults is what a bare `snug <dir>` selects. It NAMES profiles; it cannot
	// define one, because a config file able to redefine a builtin would let
	// `sys` silently come to mean something else.
	//
	// Naming it here REPLACES profile.BuiltinDefaults wholesale rather than
	// merging with it: merging would make it impossible to have fewer defaults
	// than snug ships with, which is a legitimate thing to want. `-p` still
	// adds on top, and `--no-defaults` is the only way to decline the list.
	//
	// The names are written exactly as they are selected: snug's own carry the
	// @ mark (`@sys`), a profile from profiles.d does not.
	//
	// A POINTER, deliberately: `defaults = []` must mean "replace the built-in
	// list with nothing" (equivalent to always running --no-defaults), not
	// "the key was absent". A plain []string cannot tell an explicit empty list
	// from an unset one, since both decode to len 0 — that told a user's
	// written `defaults = []` a lie by silently widening it back to the
	// built-in four.
	//
	// []string and NOT []policy.ProfileName, deliberately, even though every
	// element is a profile name: go-toml writes this field by REFLECTION, which
	// would put a value into a ProfileName without ever calling
	// NewProfileName — the one door the type cannot close on its own. It
	// decodes as text and defaultProfiles converts, which is where a bad name
	// gets an error naming the file. TestNoDecodedStructFieldIsAProfileName
	// asserts no struct in this module takes the other route.
	Defaults *[]string `toml:"defaults"`
}

func configPath() string {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "snug", "config.toml")
}

func loadUserConfig() userConfig {
	cfg := userConfig{}
	path := configPath()
	if path == "" {
		return cfg
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// Only "there is no config file" is a non-event. Every OTHER read error
		// — unreadable mode, EIO, a dangling symlink — used to return the empty
		// config, which silently WIDENS the sandbox back to the built-in four
		// while `snug config` reports the source as "built-in". `chmod 000` on a
		// file saying `defaults = []` produced a full default sandbox. A parse
		// error was already fatal; a read error must be too, for the same reason
		// (invariant 5: no silent downgrade).
		// errors.Is, not os.IsNotExist — see internal/cli/runstate.go and
		// issue #124: the old predicate does not unwrap, so it silently
		// answers false for a wrapped ENOENT. Here that would turn "there is
		// no config file" into a fatal read error.
		if !errors.Is(err, fs.ErrNotExist) {
			// The PATH is $XDG_CONFIG_HOME's, and the error text is the
			// operating system's report about it — neither is snug's, and this
			// is a screen. Same rule as badfiles.go, one file over.
			fmt.Fprintf(os.Stderr, "snug: %s: %v\n", policy.VisibleText(path),
				policy.VisibleText(err.Error()))
			os.Exit(exitPolicy)
		}
		return cfg
	}
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		// go-toml quotes the offending LINE of the file back at you, so this
		// message carries config-file text verbatim. Whole-string rather than
		// per-line here (unlike badfiles.go): a decode error from this path is
		// one line, and there is no diagram to preserve.
		fmt.Fprintf(os.Stderr, "snug: %s: %v\n", policy.VisibleText(path),
			policy.VisibleText(err.Error()))
		os.Exit(exitPolicy)
	}
	return cfg
}

// defaultProfiles is the effective `defaults` setting, with the source it came
// from so `snug config` can say which one is in effect. There is no profile
// called `default` any more: the built-in list is a preference (see
// profile.BuiltinDefaults), and a config file replaces it wholesale.
// It is also the door through which the `defaults` setting becomes
// policy.ProfileName. A name the grammar refuses is fatal here rather than
// carried: `defaults` is read on the path that starts a sandbox, so continuing
// with the built-in four instead would be a silent widening — invariant 5, and
// the same reasoning that already makes an unreadable config.toml fatal above.
func defaultProfiles() (names []policy.ProfileName, source string) {
	c := loadUserConfig()
	if c.Defaults == nil {
		return profile.BuiltinDefaults(), "built-in"
	}
	out, err := policy.NewProfileNames(*c.Defaults)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %s: defaults: %v\n", policy.VisibleText(configPath()),
			policy.VisibleText(err.Error()))
		os.Exit(exitPolicy)
	}
	return out, configPath()
}

// configCmd prints the resolved configuration and where each part came from.
// Read-only for now: writing it is trivial to add, but knowing which file is in
// effect is the part that actually gets people unstuck.
func configCmd(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: snug config    (prints the resolved configuration)")
		fmt.Fprintln(os.Stderr, "to change it, edit the file shown in the output")
		return exitUsage
	}

	// Load the profiles even though this command does not otherwise need them.
	//
	// A redefinition is a HARD failure everywhere, and that has to include the
	// commands people reach for when something is wrong. `snug config` reporting
	// a tidy configuration while the profile set is unloadable is the worst
	// possible answer to "why will snug not start".
	_, bad, err := profile.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	broken := reportBadFiles(bad)

	path := configPath()
	fmt.Printf("config file      %s", path)
	if _, err := os.Stat(path); err != nil {
		fmt.Print("   (absent)")
	}
	fmt.Println()

	names, source := defaultProfiles()
	origin := "built-in (internal/profile/defaults.go)"
	if source != "built-in" {
		origin = "from " + source
	}
	// Test the LIST, not the rendered string: `defaults = [""]` joined to "" and
	// displayed as the empty selection, so `snug config` — the "what is in
	// effect" command — showed neither the file nor reality. The run then failed
	// with `unknown profile ""`. Quote each name so an empty or space-bearing
	// one is visible rather than invisible.
	//
	// That exact spelling can no longer reach here — defaultProfiles refuses it,
	// because "" fails the grammar and a ProfileName is the only thing it can
	// return — but the reasoning survives it: this branch is about not deciding
	// what to print from a string that has already lost the list's structure,
	// and the next value that renders to nothing will meet it again.
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = strconv.Quote(string(n))
	}
	shown := strings.Join(quoted, " ")
	if len(names) == 0 {
		// `defaults = []` is a legitimate, explicit choice: the empty selection,
		// same floor `--no-defaults` reaches. Say so rather than printing a
		// blank line that reads like the value failed to load.
		shown = "(none — every run starts from the empty floor, same as --no-defaults)"
	}
	fmt.Printf("defaults         %s\n", shown)
	fmt.Printf("                 %s\n", origin)
	fmt.Println()
	fmt.Println("`defaults` is what a bare `snug <dir>` selects. Setting it in the config file")
	fmt.Println("REPLACES the built-in list rather than adding to it. -p NAME then adds to")
	fmt.Println("whatever it resolved to, and --no-defaults declines it entirely:")
	fmt.Println()
	fmt.Println("  defaults = [\"@sys\", \"@home\", \"@cwd-rw\", \"@parent-ro\"]")
	fmt.Println()
	fmt.Println("Nothing grants less: profiles only ever grant, and no flag reduces a resolved")
	fmt.Println("policy. A read-only project is --no-defaults plus the profiles you do want.")
	fmt.Println()

	fmt.Println("profile search path, in order (later layers may add names, never redefine one):")
	fmt.Println("  builtin (@name)                            compiled in, cannot be shadowed")
	for _, d := range profile.ConfigDirs() {
		state := "absent"
		if entries, err := os.ReadDir(d); err == nil {
			n := 0
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".toml") {
					n++
				}
			}
			state = fmt.Sprintf("%d file(s)", n)
		}
		fmt.Printf("  %-42s %s\n", d, state)
	}
	fmt.Println()
	fmt.Println("repo-local config is never auto-loaded: a repository that could ship its own")
	fmt.Println("profile would be granting itself permissions. See .claude/design/INDEX.md §2.7.")
	// The output above is still worth printing — it is what someone runs this
	// command for — but the exit code must not say everything is fine while a
	// file in the search path above did not load.
	if broken {
		return exitPolicy
	}
	return 0
}

// uncheckedMark is `snug profile show`'s half of the mark --dry-run's
// ENVIRONMENT block draws on the same (name, verb) pair, and both the decision
// and the WORDING come from internal/policy — because two screens deciding
// separately what "snug knows this name" means is how one of them comes to lie,
// and two screens spelling the same decision differently is how a reader learns
// to distrust both. The string was held here once; see policy.UncheckedEnvNote.
//
// It is a fact about ONE name, so it goes on that name's own line rather than
// once per block: a heading is read as decoration by the time the eye reaches
// the third row, and a block can mix rostered and unrostered names freely.
func uncheckedMark(name string, verb policy.EnvVerb) string {
	return policy.UncheckedEnvNote(name, verb)
}

// envMarks is this screen's half of the JOIN --dry-run's ENVIRONMENT block makes
// on the same (name, verb) pair: the unchecked mark, then whatever
// policy.EnvNote has to say about what the tool DOES with the value.
//
// Two marks here rather than three — grantMark has no counterpart on this
// screen, because `snug profile show` renders a profile with no target and so
// has no mounts to judge a value against. The two that do apply keep --dry-run's
// order, so a reader moving between the screens reads the same row the same way.
//
// It is a function rather than two concatenations at each of the three call
// sites below for the reason this file already records: a mark added at one site
// and forgotten at the other two is how a screen comes to say less than its
// neighbour, and `snug profile show` is precisely where that happened last time
// (the mark used to hang off a block that was removed).
func envMarks(name string, verb policy.EnvVerb) string {
	return uncheckedMark(name, verb) + policy.EnvNote(name, verb)
}

// showEnviron renders the five environment verbs.
//
// It renders ALL of them for the same reason `snug profile show` exists at all:
// this line used to read `show("env", p.Env)` and never rendered `path` either,
// so a profile putting a directory on the sandbox's PATH looked, on this
// screen, like a profile that granted nothing to the environment. A display
// that omits a grant is worse than no display, because it is read as complete.
//
// The parse-time checks in policy.ValidateEnvGrants are part of the argument
// for `snug profile show` reporting a verdict with no target; showing what it
// checked is the other half.
func showEnviron(g policy.EnvGrants, show func(label string, vals []string)) {
	pairs := func(label string, verb policy.EnvVerb, m map[string]string) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		vals := make([]string, 0, len(names))
		for _, n := range names {
			vals = append(vals, n+" = "+m[n]+envMarks(n, verb))
		}
		show(label, vals)
	}
	lists := func(label string, verb policy.EnvVerb, m map[string][]string) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		vals := make([]string, 0, len(names))
		for _, n := range names {
			vals = append(vals, n+" = "+strings.Join(m[n], " ")+envMarks(n, verb))
		}
		show(label, vals)
	}
	// The two NAME SETS. Same mark, same predicate; the value is the host's, so
	// there is nothing else on the line for it to qualify.
	names := func(label string, verb policy.EnvVerb, in []string) {
		vals := make([]string, 0, len(in))
		for _, n := range in {
			vals = append(vals, n+envMarks(n, verb))
		}
		show(label, vals)
	}
	// The labels carry the `environ.` prefix the TOML uses. Bare "set" and
	// "merge" sit directly under "ro" and "tmpfs" on this screen, where they read
	// as two more kinds of filesystem grant; the prefix is what says these are
	// the environment, and it is also the string somebody will grep for.
	//
	// The mark's wording is deliberately the same "unchecked" the --dry-run mark
	// uses: two words for one property is how a reader concludes there are two
	// properties.
	pairs("environ.set", policy.VerbSet, g.Set)
	lists("environ.merge", policy.VerbMerge, g.Merge)
	lists("environ.prepend", policy.VerbPrepend, g.Prepend)
	names("environ.inherit", policy.VerbInherit, g.Inherit)
	names("environ.sanitise", policy.VerbSanitise, g.Sanitise)
}

func profileCmd(args []string) int {
	// DIAGNOSTIC, so a file that will not parse is reported and skipped rather
	// than taking the registry down with it. `snug profile list` is precisely the
	// command someone runs to find out what still works, and it used to be the
	// first casualty. The exit code still says something is wrong.
	reg, bad, err := profile.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}
	broken := reportBadFiles(bad)
	code := 0
	if broken {
		code = exitPolicy
	}

	// Every SUBCOMMAND here used to drop the arguments it did not read:
	// `snug profile list --json` exited 0 with the human listing and the flag
	// silently ignored, and so did `snug profile show NAME --json` (issue
	// #52). Prose on a stream something is about to json.Unmarshal is worse
	// for a consumer than a rejection it can read, so a flag is refused before
	// any subcommand runs.
	//
	// "anything starting with -", not a list of known flags: a profile name
	// cannot begin with one (checkName is an allowlist), so this refuses
	// exactly the argument class that has no meaning here, and it does not go
	// stale when a flag is added to the main parser.
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "snug: `snug profile` takes no flags (got %s)\n", visibleValue(a))
			fmt.Fprintln(os.Stderr, "      there is no machine-readable profile listing; --json belongs to --dry-run")
			return exitUsage
		}
	}

	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}

	switch sub {
	case "list":
		names := sortedNames(reg)
		sel, _ := defaultProfiles()
		def := policy.JoinNames(sel, " ")
		for _, n := range names {
			p := reg[n]
			marker := " "
			if strings.Contains(" "+def+" ", " "+string(n)+" ") {
				marker = "*"
			}
			// One line per profile here, unlike `show`, so the whole description
			// is escaped: a newline in it would produce a second row on the one
			// screen whose job is to say what profiles exist.
			fmt.Printf("%s %-16s %s\n", marker, visibleValue(string(n)), visibleValue(p.Description))
		}
		fmt.Println()
		fmt.Printf("* = selected by a bare `snug <dir>`.  @ = shipped by snug, cannot be redefined.\n")
		fmt.Printf("Details: snug profile show NAME\n")
		return code

	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: snug profile show NAME")
			return exitUsage
		}
		name, err := policy.NewProfileName(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitUsage
		}
		p, ok := reg[name]
		if !ok {
			// Same error the resolver gives, so `snug profile show sys` and
			// `snug -p sys` both point at `@sys` rather than one of them
			// leaving the reader to guess.
			fmt.Fprintf(os.Stderr, "snug: %v\n", unknownProfile(reg, name, bad))
			return exitPolicy
		}
		fmt.Printf("profile     %s\n", name)
		if p.Description != "" {
			// A multi-line description is deliberate and stays multi-line, so
			// this escapes each line rather than the whole string: newline is
			// the one control character with a meaning here, and every other
			// one — ESC above all — is a way to rewrite lines the reader has
			// already been shown.
			lines := strings.Split(p.Description, "\n")
			for i, l := range lines {
				lines[i] = visibleValue(l)
			}
			fmt.Printf("            %s\n", strings.Join(lines, "\n            "))
		}
		// The file this profile came from — a path snug listed out of
		// profiles.d rather than one it chose, so it is host text on a screen
		// and gets the same treatment as the description four lines up, which
		// was already escaped when this was not (issue #65).
		fmt.Printf("defined in  %s\n", visibleValue(p.Source))
		fmt.Println()
		// visibleValue on every value, in the closure rather than at each call
		// site, so `includes`, `ro`, `rw`, `tmpfs`, `optional` and all five
		// environ verbs are covered by one line and a new key cannot be added
		// without it.
		//
		// This is the screen someone reads to decide WHETHER to select a profile,
		// which puts it upstream of every --dry-run — and it rendered profile text
		// verbatim. Measured in a real terminal: an environ.set value ending in
		// ESC[1A CR overwrote the row above it, and `rw  /home/u` — the whole
		// of $HOME, writable — was simply not on the screen. `cat -v` showed it
		// there all along.
		show := func(label string, vals []string) {
			for i, v := range vals {
				head := ""
				if i == 0 {
					head = label
				}
				fmt.Printf("  %-16s %s\n", head, visibleValue(v))
			}
		}
		show("includes", policy.NameStrings(p.Include))
		show("ro", p.RO)
		show("rw", p.RW)
		// tmpfs is never marked — it supplies and discloses nothing, the same
		// Kind gating issues #169/#170 give KindTmpfs on --dry-run's
		// FILESYSTEM block.
		show("tmpfs", p.Tmpfs)
		showEnviron(p.Environ, show)
		for i, s := range p.Symlink {
			head := ""
			if i == 0 {
				head = "symlink"
			}
			fmt.Printf("  %-16s %s -> %s\n", head, visibleValue(s.At), visibleValue(s.Target))
		}
		showCapabilities(p, show)
		if len(p.Optional) > 0 {
			fmt.Printf("  %-16s %s\n", "optional", visibleValue(strings.Join(p.Optional, " ")))
		}
		fmt.Println()
		fmt.Println("To see what this actually produces for a directory:")
		fmt.Printf("  snug --dry-run -p %s <dir>\n", name)
		return code

	case "tree":
		roots, err := policy.NewProfileNames(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitUsage
		}
		if len(roots) == 0 {
			roots, _ = defaultProfiles()
		}
		for _, r := range roots {
			if _, ok := reg[r]; !ok {
				fmt.Fprintf(os.Stderr, "snug: %v\n", unknownProfile(reg, r, bad))
				return exitPolicy
			}
			printTree(reg, r, "", "", map[policy.ProfileName]bool{})
		}
		return code

	case "dot":
		roots, err := policy.NewProfileNames(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitUsage
		}
		if rc := profileDot(reg, roots); rc != 0 {
			return rc
		}
		return code

	default:
		fmt.Fprintf(os.Stderr, "snug: unknown subcommand %q\nusage: snug profile [list|show NAME|tree [NAME...]|dot]\n", sub)
		return exitUsage
	}
}

// printTree renders the include DAG. A profile reached more than once is shown
// once and then marked, because `include` composes as a SET — a diamond is
// harmless and pretending otherwise would misrepresent the model.
// line is the prefix for this profile's own line; kids is the prefix its
// children's lines build on. Keeping them separate is what makes the box-drawing
// line up more than one level deep.
func printTree(reg profile.Registry, name policy.ProfileName, line, kids string, seen map[policy.ProfileName]bool) {
	p := reg[name]
	if p == nil {
		fmt.Printf("%s%s  (unknown)\n", line, visibleValue(string(name)))
		return
	}

	suffix := ""
	if n := len(p.RO) + len(p.RW) + len(p.Tmpfs) + len(p.Symlink); n > 0 {
		suffix = fmt.Sprintf("  [%s]", plural(n, "grant"))
	}
	if seen[name] {
		// Not an error: include composes as a SET, so a diamond is harmless.
		// Saying so beats printing the same subtree twice.
		//
		// visibleValue here for the same reason as the two branches around it,
		// and it is the THIRD branch of this one function: the first pass of
		// issue #20 guarded the (unknown) branch above and the normal branch
		// below and left this one raw, which is CLAUDE.md's "the commit that
		// added it fixed the ENVIRONMENT block and left the argv block four
		// lines below it" happening inside a single `if`. A registry key
		// cannot carry a control character now that checkName is an allowlist,
		// so this is defence in depth rather than a live hole — which is
		// exactly why it was easy to miss.
		fmt.Printf("%s%s%s  (already included above)\n", line, visibleValue(string(name)), suffix)
		return
	}
	seen[name] = true
	fmt.Printf("%s%s%s\n", line, visibleValue(string(name)), suffix)

	for i, inc := range p.Include {
		branch, cont := "├── ", "│   "
		if i == len(p.Include)-1 {
			branch, cont = "└── ", "    "
		}
		printTree(reg, inc, kids+branch, kids+cont, seen)
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// profileDot emits the include graph for `snug profile dot | dot -Tpng -o x.png`.
func profileDot(reg profile.Registry, roots []policy.ProfileName) int {
	fmt.Println("digraph snug_profiles {")
	fmt.Println(`  rankdir=LR;`)
	fmt.Println(`  node [shape=box, fontname="monospace"];`)

	show := map[policy.ProfileName]bool{}
	if len(roots) == 0 {
		for n := range reg {
			show[n] = true
		}
	} else {
		set, err := policy.Expand(map[policy.ProfileName]*policy.Profile(reg), roots)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snug: %v\n", err)
			return exitPolicy
		}
		for n := range set {
			show[n] = true
		}
	}

	for _, n := range sortedNames(reg) {
		if !show[n] {
			continue
		}
		p := reg[n]
		grants := len(p.RO) + len(p.RW) + len(p.Tmpfs) + len(p.Symlink)
		// A profile that grants nothing is a pure composition point; drawing it
		// differently makes the shape of the set readable at a glance.
		style := ""
		if grants == 0 {
			style = `, style=dashed`
		}
		fmt.Printf("  %q [label=\"%s\\n%s\"%s];\n", n, n, plural(grants, "grant"), style)
	}
	for _, n := range sortedNames(reg) {
		if !show[n] {
			continue
		}
		for _, inc := range reg[n].Include {
			fmt.Printf("  %q -> %q;\n", n, inc)
		}
	}
	fmt.Println("}")
	return 0
}

func sortedNames(reg profile.Registry) []policy.ProfileName {
	names := make([]policy.ProfileName, 0, len(reg))
	for n := range reg {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// showCapabilities renders the NON-PATH grants: the network, the container
// engine, the git reconstruction and the pinned identity.
//
// WHY THIS EXISTS (issue #195). `profile show` rendered `description`, `source`,
// `includes`, `ro`, `rw`, `tmpfs`, the environ verbs, `symlink` and `optional` —
// every key that names a PATH — and dropped every key that does not. A profile
// granting full internet egress plus a host->sandbox port forward therefore read
// as a profile with ZERO grants, on the screen a human uses to decide whether to
// select it. Under the guiding principle a hole is a named grant, so a screen
// that cannot name the network hole is naming the wrong set.
//
// Each entry carries the CONSEQUENCE on continuation rows, not just the value,
// for the same reason --dry-run's NETWORK block does: "egress" is a word, "the
// sandbox reaches the whole internet" is the thing being agreed to. The
// profile's RAW text is rendered rather than a resolved NetMode, because this
// screen has no target and no resolution — it shows what the FILE says, and an
// unrecognised value must render as itself rather than be normalised away.
//
// TestProfileShowRendersEveryProfileField is what stops this recurring: it walks
// policy.Profile by reflection, so a field added for a future feature fails the
// suite until it is either rendered here or exempted with a reason.
func showCapabilities(p *policy.Profile, show func(string, []string)) {
	if p.Network != "" {
		show("network", capRows(p.Network, networkConsequence(p.Network)))
	}
	if p.DNS {
		show("dns", capRows("yes",
			"a generated /etc/resolv.conf names a resolver inside the sandbox"))
	}
	if len(p.Publish) > 0 {
		ports := make([]string, len(p.Publish))
		for i, n := range p.Publish {
			ports[i] = strconv.Itoa(n)
		}
		show("publish", capRows(strings.Join(ports, " "),
			"the HOST's 127.0.0.1 forwards these INTO the sandbox, so anything "+
				"a hostile process listens on there is reachable from your browser"))
	}
	if len(p.Plugins) > 0 {
		show("plugins", capRows(strings.Join(p.Plugins, " "),
			"regenerates ~/.claude/plugins/installed_plugins.json naming only these, so "+
				"Claude Code auto-loads each named plugin's command tables — measured on the "+
				"development host as hooks.json running bash/sh/python3 (issue #68)"))
	}
	// Address and gateway render as ONE entry per family. They are a pair by
	// construction (checkAddressPair requires all four or none, issue #165), and
	// two rows would invite reading them as two independent grants.
	if p.Address != "" || p.Gateway != "" {
		show("address", addressRows(p.Address, p.Gateway))
	}
	if p.Address6 != "" || p.Gateway6 != "" {
		show("address6", addressRows(p.Address6, p.Gateway6))
	}
	if p.MTU != 0 {
		show("mtu", []string{strconv.Itoa(p.MTU)})
	}
	if p.Podman != "" {
		show("podman", capRows(p.Podman,
			"starts a container engine and delegates your whole subuid range, "+
				"even with no network profile selected"))
	}
	if p.Git != "" {
		show("git", capRows(p.Git,
			"~/.gitconfig is REGENERATED from a whitelist, never bound - it names "+
				"programs git would run"))
	}
	showIdentity(p.Identity, show)
}

// capRows puts the value on the labelled row and the consequence on wrapped
// continuation rows, which `show` renders with a blank label. One long line
// would run past 120 columns and wrap wherever the terminal decided, in the
// middle of a sentence a human is meant to weigh.
func capRows(value, consequence string) []string {
	rows := []string{value}
	return append(rows, wrapWords(consequence, showConsequenceWidth)...)
}

// showConsequenceWidth is 80 minus the "  %-16s " prefix `show` prints, so a
// full row lands inside an 80-column terminal. Asserted by
// TestProfileShowFitsAnEightyColumnScreen rather than trusted.
const showConsequenceWidth = 80 - 19

func wrapWords(text string, width int) []string {
	if text == "" {
		return nil
	}
	var out []string
	line := ""
	for _, w := range strings.Fields(text) {
		switch {
		case line == "":
			line = w
		case len(line)+1+len(w) <= width:
			line += " " + w
		default:
			out = append(out, line)
			line = w
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// networkConsequence says what the mode COSTS, in the same vocabulary
// --dry-run's NETWORK block uses. An unrecognised value gets no sentence rather
// than a guessed one: profile text is not validated at this point, and inventing
// a consequence for a mode snug does not implement would be worse than silence.
func networkConsequence(mode string) string {
	switch mode {
	case "egress":
		return "the sandbox reaches the whole internet, from a private netns. " +
			"Host loopback and abstract unix sockets stay unreachable " +
			"(pathname sockets — X11, D-Bus — are a mount question, not this one)."
	case "host":
		return "the HOST's own netns. Loopback services and abstract unix sockets " +
			"(X11, D-Bus among them) ARE reachable. This is the --i-know path."
	default:
		return ""
	}
}

func addressRows(addr, gw string) []string {
	value := addr
	if gw != "" {
		if value == "" {
			value = "(no address)"
		}
		value += " via " + gw
	}
	return capRows(value, "synthetic; the host's own address is not copied inside, "+
		"so the sandbox does not learn your LAN or ISP-attributable address")
}

// showIdentity renders the pin. WHICH account is the whole point of an identity
// profile and is exactly what a human is deciding about, so each half gets its
// own row rather than being packed onto one line.
//
// No key MATERIAL is rendered and none is available to render: Identity.SSHKey
// selects one key from the already-unlocked host agent, and ssh_mode =
// "agent-proxy" means no private key ever enters the sandbox.
func showIdentity(id *policy.Identity, show func(string, []string)) {
	if id == nil {
		return
	}
	var rows []string
	if id.SSHKey != "" {
		row := "ssh key " + id.SSHKey
		if id.SSHMode != "" {
			row += " (" + string(id.SSHMode) + ")"
		}
		rows = append(rows, row)
	}
	if id.GitName != "" || id.GitEmail != "" {
		rows = append(rows, strings.TrimSpace("git "+id.GitName+" <"+id.GitEmail+">"))
	}
	if id.GhUser != "" {
		host := id.GhHost
		if host == "" {
			host = "github.com"
		}
		rows = append(rows, "gh "+id.GhUser+" @ "+host)
	}
	show("identity", rows)
}
