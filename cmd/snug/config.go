package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"snug/internal/policy"
	"snug/internal/profile"
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
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "snug: %s: %v\n", path, err)
			os.Exit(exitPolicy)
		}
		return cfg
	}
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %s: %v\n", path, err)
		os.Exit(exitPolicy)
	}
	return cfg
}

// defaultProfiles is the effective `defaults` setting, with the source it came
// from so `snug config` can say which one is in effect. There is no profile
// called `default` any more: the built-in list is a preference (see
// profile.BuiltinDefaults), and a config file replaces it wholesale.
func defaultProfiles() (names []string, source string) {
	if c := loadUserConfig(); c.Defaults != nil {
		return *c.Defaults, configPath()
	}
	return profile.BuiltinDefaults(), "built-in"
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
	if _, err := profile.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}

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
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = strconv.Quote(n)
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
	fmt.Println("profile would be granting itself permissions. See .claude/design/DESIGN.md §2.7.")
	return 0
}

func profileCmd(args []string) int {
	reg, err := profile.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitPolicy
	}

	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}

	switch sub {
	case "list":
		names := sortedNames(reg)
		sel, _ := defaultProfiles()
		def := strings.Join(sel, " ")
		for _, n := range names {
			p := reg[n]
			marker := " "
			if strings.Contains(" "+def+" ", " "+n+" ") {
				marker = "*"
			}
			fmt.Printf("%s %-16s %s\n", marker, n, p.Description)
		}
		fmt.Println()
		fmt.Printf("* = selected by a bare `snug <dir>`.  @ = shipped by snug, cannot be redefined.\n")
		fmt.Printf("Details: snug profile show NAME\n")
		return 0

	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: snug profile show NAME")
			return exitUsage
		}
		name := args[1]
		p, ok := reg[name]
		if !ok {
			// Same error the resolver gives, so `snug profile show sys` and
			// `snug -p sys` both point at `@sys` rather than one of them
			// leaving the reader to guess.
			fmt.Fprintf(os.Stderr, "snug: %v\n", policy.UnknownProfile(reg, name))
			return exitPolicy
		}
		fmt.Printf("profile     %s\n", name)
		if p.Description != "" {
			fmt.Printf("            %s\n", strings.ReplaceAll(p.Description, "\n", "\n            "))
		}
		fmt.Printf("defined in  %s\n", p.Source)
		fmt.Println()
		show := func(label string, vals []string) {
			for i, v := range vals {
				head := ""
				if i == 0 {
					head = label
				}
				fmt.Printf("  %-10s %s\n", head, v)
			}
		}
		show("includes", p.Include)
		show("ro", p.RO)
		show("rw", p.RW)
		show("tmpfs", p.Tmpfs)
		show("env", p.Env)
		for i, s := range p.Symlink {
			head := ""
			if i == 0 {
				head = "symlink"
			}
			fmt.Printf("  %-10s %s -> %s\n", head, s.At, s.Target)
		}
		if len(p.Optional) > 0 {
			fmt.Printf("  %-10s %s\n", "optional", strings.Join(p.Optional, " "))
		}
		fmt.Println()
		fmt.Println("To see what this actually produces for a directory:")
		fmt.Printf("  snug --dry-run -p %s <dir>\n", name)
		return 0

	case "tree":
		roots := args[1:]
		if len(roots) == 0 {
			roots, _ = defaultProfiles()
		}
		for _, r := range roots {
			if _, ok := reg[r]; !ok {
				fmt.Fprintf(os.Stderr, "snug: %v\n", policy.UnknownProfile(reg, r))
				return exitPolicy
			}
			printTree(reg, r, "", "", map[string]bool{})
		}
		return 0

	case "dot":
		return profileDot(reg, args[1:])

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
func printTree(reg profile.Registry, name, line, kids string, seen map[string]bool) {
	p := reg[name]
	if p == nil {
		fmt.Printf("%s%s  (unknown)\n", line, name)
		return
	}

	suffix := ""
	if n := len(p.RO) + len(p.RW) + len(p.Tmpfs) + len(p.Symlink); n > 0 {
		suffix = fmt.Sprintf("  [%s]", plural(n, "grant"))
	}
	if seen[name] {
		// Not an error: include composes as a SET, so a diamond is harmless.
		// Saying so beats printing the same subtree twice.
		fmt.Printf("%s%s%s  (already included above)\n", line, name, suffix)
		return
	}
	seen[name] = true
	fmt.Printf("%s%s%s\n", line, name, suffix)

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
func profileDot(reg profile.Registry, roots []string) int {
	fmt.Println("digraph snug_profiles {")
	fmt.Println(`  rankdir=LR;`)
	fmt.Println(`  node [shape=box, fontname="monospace"];`)

	show := map[string]bool{}
	if len(roots) == 0 {
		for n := range reg {
			show[n] = true
		}
	} else {
		set, err := policy.Expand(map[string]*policy.Profile(reg), roots)
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

func sortedNames(reg profile.Registry) []string {
	names := make([]string, 0, len(reg))
	for n := range reg {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
