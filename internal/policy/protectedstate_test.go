package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

// Spelling and boundary tables for the refusals over snug's own trusted state:
// refuseWritableConfigRoot, refuseEngineDataRootGrant and the per-run tmp name
// prefix in refuseRuntimeDirGrant. Each row says whether ONE spelling of a
// grant reaches the protected path, so a refusal that only matches the
// canonical spelling fails here instead of in a red-team round.
//
// Every refused row asserts the refusal's own sentence, not merely an error:
// an unrelated rule speaking first would make "refused" pass for the wrong
// reason. Rows whose grant is also caught by an earlier rule name it in
// `other`. Every refused row has an allowed twin in the sibling tables below,
// which is the positive control that the resolver is not simply failing.
//
// What these do not reach: the producers of the root lists
// (profile.TrustedConfigRoots, engine.DataRoots, engine.TmpDirPrefixes) are
// injected here, so a producer that drops a root is not caught in this file.

const (
	cfgSentence    = "trusted configuration (profiles.d, config.toml)"
	engineSentence = "engine store "
	tmpSentence    = "a per-run directory"
)

type protCase struct {
	name  string
	acc   string // "ro" or "rw"
	grant string // as the profile writes it, possibly via ~/ or {target}
	// target overrides the default target; "" keeps /home/u/proj/sub.
	target string
	// useTarget grants through @target-rw instead of a profile grant.
	useTarget bool
	links     map[string]string
	parents   bool // fakeEnv.resolveParents
	// extra directories that exist on the fixture host.
	exist []string

	configRoots []string
	dataRoots   []EngineDataRoot
	prefixes    []string
	runtimeDirs []string

	refused bool
	want    string // sentence the refusal must contain
	other   string // set when an earlier rule is expected to speak instead
}

func (tc protCase) run(t *testing.T) {
	t.Helper()
	clean := filepath.Clean(tc.grant)
	target := tc.target
	if target == "" {
		target = "/home/u/proj/sub"
	}
	env := envWith(append([]string{clean, target}, tc.exist...)...)
	for k, v := range tc.links {
		env.links[k] = v
	}
	env.resolveParents = tc.parents

	ctx := testCtx()
	ctx.Target = target
	ctx.ConfigRoots = tc.configRoots
	ctx.EngineDataRoots = tc.dataRoots
	ctx.EngineTmpPrefixes = tc.prefixes
	ctx.RuntimeDirs = tc.runtimeDirs

	reg := testRegistry()
	sel := append([]ProfileName{}, testDefaults...)
	if !tc.useTarget {
		p := &Profile{Name: "peek"}
		if tc.acc == "ro" {
			p.RO = []string{tc.grant}
		} else {
			p.RW = []string{tc.grant}
		}
		reg["peek"] = p
		sel = append(sel, "peek")
	}
	_, err := Resolve(reg, sel, ctx, env)
	switch {
	case tc.refused && err == nil:
		t.Fatalf("ACCEPTED %s %s", tc.acc, tc.grant)
	case !tc.refused && err != nil:
		t.Fatalf("%s %s was REFUSED:\n%v", tc.acc, tc.grant, err)
	case tc.refused:
		want := tc.want
		if tc.other != "" {
			want = tc.other
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%s %s refused, but not by the expected rule (want %q):\n%v", tc.acc, tc.grant, want, err)
		}
	}
}

func runProt(t *testing.T, cases []protCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

var (
	protCfg  = []string{"/etc/snug", "/home/u/.config/snug"}
	protCfgX = []string{"/etc/snug", "/s/x/snug", "/home/u/.config/snug"}
)

// TestConfigRootWriteSpellingsRefused would catch a refusal keyed on the
// canonical text of a trusted configuration root: a trailing slash, a "..", a
// doubled slash, a "~/" spelling, a link to the root or an ancestor, an
// ancestor grant of any depth, or the whole filesystem each reaching the root
// and being accepted. It does not reach a root the injected list omits.
func TestConfigRootWriteSpellingsRefused(t *testing.T) {
	var cases []protCase
	add := func(name, grant string, roots []string, mod func(*protCase)) {
		tc := protCase{name: name, acc: "rw", grant: grant, configRoots: roots, refused: true, want: cfgSentence}
		if mod != nil {
			mod(&tc)
		}
		cases = append(cases, tc)
	}
	for _, g := range []struct{ name, grant string }{
		{"root", "/home/u/.config/snug"},
		{"profiles.d", "/home/u/.config/snug/profiles.d"},
		{"config.toml", "/home/u/.config/snug/config.toml"},
		{"trailing slash", "/home/u/.config/snug/"},
		{"dotdot out and back", "/home/u/.config/other/../snug"},
		{"dotdot inside", "/home/u/.config/snug/profiles.d/../config.toml"},
		{"doubled slashes", "/home//u///.config//snug"},
		{"tilde spelling", "~/.config/snug"},
		{"system root", "/etc/snug"},
		{"system profiles.d", "/etc/snug/profiles.d"},
		{"ancestor ~/.config", "/home/u/.config"},
		{"ancestor $HOME", "/home/u"},
		{"ancestor /home", "/home"},
		{"ancestor /etc", "/etc"},
		{"whole filesystem", "/"},
	} {
		g := g
		add(g.name, g.grant, protCfg, func(tc *protCase) {
			tc.exist = []string{"/etc/snug", "/home/u/.config/snug/config.toml", "/home/u/.config/snug/profiles.d"}
		})
	}
	add("custom XDG_CONFIG_HOME root", "/s/x/snug/profiles.d", protCfgX, func(tc *protCase) {
		tc.exist = []string{"/s/x/snug/profiles.d"}
	})
	add("custom XDG_CONFIG_HOME, trailing slash and dotdot", "/s/x/./snug/../snug/", protCfgX, func(tc *protCase) {
		tc.exist = []string{"/s/x/snug"}
	})
	add("custom XDG_CONFIG_HOME ancestor", "/s/x", protCfgX, func(tc *protCase) {
		tc.exist = []string{"/s/x/snug"}
	})
	add("symlink to the root", "/home/u/lnk", protCfg, func(tc *protCase) {
		tc.links = map[string]string{"/home/u/lnk": "/home/u/.config/snug"}
		tc.exist = []string{"/home/u/.config/snug"}
	})
	add("symlink to an ancestor", "/home/u/lnk", protCfg, func(tc *protCase) {
		tc.links = map[string]string{"/home/u/lnk": "/home/u/.config"}
		tc.exist = []string{"/home/u/.config/snug"}
	})
	add("symlink below the root's own link", "/srv/dot/snug", protCfg, func(tc *protCase) {
		// ~/.config/snug is itself a link; the grant names where it lands.
		tc.links = map[string]string{"/home/u/.config/snug": "/srv/dot/snug"}
		tc.exist = []string{"/srv/dot/snug"}
	})
	add("HOME reached through a symlink, grant spelled by its target", "/var/home/u/.config/snug", protCfg, func(tc *protCase) {
		tc.links = map[string]string{"/home/u": "/var/home/u"}
		tc.parents = true
		tc.exist = []string{"/var/home/u/.config/snug", "/var/home/u/proj/sub"}
	})
	add("HOME reached through a symlink, grant spelled by the link", "/home/u/.config/snug", protCfg, func(tc *protCase) {
		tc.links = map[string]string{"/home/u": "/var/home/u"}
		tc.parents = true
		tc.exist = []string{"/var/home/u/.config/snug", "/var/home/u/proj/sub"}
	})
	add("chain of two links", "/home/u/a", protCfg, func(tc *protCase) {
		tc.links = map[string]string{"/home/u/a": "/home/u/b", "/home/u/b": "/home/u/.config/snug"}
		tc.parents = true
		tc.exist = []string{"/home/u/.config/snug"}
	})
	add("@target-rw on the root", "/home/u/.config/snug", protCfg, func(tc *protCase) {
		// Sits directly in @home's ~/.config tmpfs, so the ephemeral-target
		// rule speaks first; only the fact of refusal is pinned.
		tc.useTarget, tc.target, tc.other = true, "/home/u/.config/snug", "refusing to sandbox"
	})
	add("@target-rw on a path inside the root", "/home/u/.config/snug/notes", protCfg, func(tc *protCase) {
		tc.useTarget, tc.target = true, "/home/u/.config/snug/notes"
	})
	// The ephemeral-target rule speaks first for these two, so only the fact
	// of refusal is pinned, and by that rule's own wording.
	add("@target-rw on $HOME", "/home/u", protCfg, func(tc *protCase) {
		tc.useTarget, tc.target, tc.other = true, "/home/u", "refusing to sandbox"
	})
	add("@target-rw on ~/.config", "/home/u/.config", protCfg, func(tc *protCase) {
		tc.useTarget, tc.target, tc.other = true, "/home/u/.config", "refusing to sandbox"
	})
	runProt(t, cases)
}

// TestConfigRootSiblingsAndReadAllowed is the positive control for the table
// above: it fails if the config-root refusal grows over a sibling whose name
// merely starts with "snug", over an unrelated directory, or over read access.
func TestConfigRootSiblingsAndReadAllowed(t *testing.T) {
	runProt(t, []protCase{
		{name: "~/.config/snugx", acc: "rw", grant: "/home/u/.config/snugx", configRoots: protCfg},
		{name: "~/.config/snug-notes", acc: "rw", grant: "/home/u/.config/snug-notes", configRoots: protCfg},
		{name: "/etc/snugx", acc: "rw", grant: "/etc/snugx", configRoots: protCfg},
		{name: "~/.config/nvim", acc: "rw", grant: "/home/u/.config/nvim", configRoots: protCfg},
		{name: "dotdot that stays beside", acc: "rw", grant: "/home/u/.config/snug/../snugx", configRoots: protCfg, exist: []string{"/home/u/.config/snugx"}},
		{name: "ro root", acc: "ro", grant: "/home/u/.config/snug", configRoots: protCfg, exist: []string{"/home/u/.config/snug"}},
		{name: "symlink to a sibling", acc: "rw", grant: "/home/u/lnk", configRoots: protCfg,
			links: map[string]string{"/home/u/lnk": "/home/u/.config/snugx"}, exist: []string{"/home/u/.config/snugx"}},
	})
}

var protData = []EngineDataRoot{{Path: "/data/x/snug"}, {Path: "/home/u/.local/share/snug"}}

// TestEngineDataRootSpellingsRefused would catch an engine-store refusal keyed
// on one spelling: ro and rw alike must be refused for a trailing slash, "..",
// doubled slashes, "~/", a link in either direction, an ancestor at any depth
// (including ~/.local/share read-only, where the store is a child), and
// $HOME's default store under a custom XDG_DATA_HOME. It does not reach a root
// the injected list omits.
func TestEngineDataRootSpellingsRefused(t *testing.T) {
	var cases []protCase
	for _, acc := range []string{"ro", "rw"} {
		acc := acc
		add := func(name, grant string, mod func(*protCase)) {
			tc := protCase{name: acc + " " + name, acc: acc, grant: grant, dataRoots: protData, refused: true, want: engineSentence,
				exist: []string{"/data/x/snug", "/home/u/.local/share/snug"}}
			if mod != nil {
				mod(&tc)
			}
			cases = append(cases, tc)
		}
		add("XDG root", "/data/x/snug", nil)
		add("default root under custom XDG", "/home/u/.local/share/snug", nil)
		add("engines inside", "/home/u/.local/share/snug/engines", func(tc *protCase) {
			tc.exist = append(tc.exist, "/home/u/.local/share/snug/engines")
		})
		add("trailing slash", "/home/u/.local/share/snug/", nil)
		add("dotdot", "/home/u/.local/share/x/../snug", nil)
		add("doubled slashes", "//home//u/.local//share/snug", nil)
		add("tilde", "~/.local/share/snug", nil)
		add("ancestor ~/.local/share", "/home/u/.local/share", nil)
		add("ancestor ~/.local", "/home/u/.local", nil)
		add("ancestor $HOME", "/home/u", nil)
		add("ancestor XDG_DATA_HOME", "/data/x", nil)
		add("whole filesystem", "/", nil)
		add("symlink to root", "/home/u/lnk", func(tc *protCase) {
			tc.links = map[string]string{"/home/u/lnk": "/home/u/.local/share/snug"}
		})
		add("symlink to ancestor", "/home/u/lnk", func(tc *protCase) {
			tc.links = map[string]string{"/home/u/lnk": "/home/u/.local/share"}
		})
		add("HOME through a symlink, spelled by target", "/var/home/u/.local/share/snug", func(tc *protCase) {
			tc.links = map[string]string{"/home/u": "/var/home/u"}
			tc.parents = true
			tc.exist = append(tc.exist, "/var/home/u/.local/share/snug", "/var/home/u/proj/sub")
		})
		add("XDG_DATA_HOME through a symlink, spelled by target", "/real/x/snug", func(tc *protCase) {
			tc.links = map[string]string{"/data/x": "/real/x"}
			tc.parents = true
			tc.exist = append(tc.exist, "/real/x/snug")
		})
	}
	cases = append(cases,
		// Directly in @home's ~/.local/share tmpfs, the ephemeral-target rule
		// speaks first for the store itself; one level down it is ours.
		protCase{name: "@target-rw on the store", acc: "rw", useTarget: true, grant: "/home/u/.local/share/snug",
			target: "/home/u/.local/share/snug", dataRoots: protData, refused: true, want: "refusing to sandbox"},
		protCase{name: "@target-rw inside the store", acc: "rw", useTarget: true, grant: "/home/u/.local/share/snug/engines",
			target: "/home/u/.local/share/snug/engines", dataRoots: protData, refused: true, want: engineSentence},
		protCase{name: "@target-rw on ~/.local/share", acc: "rw", useTarget: true, grant: "/home/u/.local/share",
			target: "/home/u/.local/share", dataRoots: protData, refused: true, want: "refusing to sandbox"},
	)
	runProt(t, cases)
}

// TestEngineDataRootSiblingsAllowed is the positive control: it fails if the
// store refusal covers a sibling whose name starts with "snug", or an
// unrelated directory under the same parent, in either access mode.
func TestEngineDataRootSiblingsAllowed(t *testing.T) {
	var cases []protCase
	for _, acc := range []string{"ro", "rw"} {
		for _, g := range []string{
			"/home/u/.local/share/snug-other",
			"/home/u/.local/share/snugx",
			"/home/u/.local/share/applications",
			"/data/x/snug-notes",
			"/home/u/.local/share/snug/../snug-other",
		} {
			cases = append(cases, protCase{name: acc + " " + g, acc: acc, grant: g, dataRoots: protData, exist: []string{filepath.Clean(g)}})
		}
	}
	runProt(t, cases)
}

var protPrefixes = []string{"/tmp/snug-1000-", "/tmp/snug-engines-1000-"}

// TestEngineTmpDirSpellingsRefused would catch a per-run tmp refusal that
// misses a spelling: trailing slash, "..", doubled slashes, a link to the
// directory, a different $TMPDIR carrying the same names, both name families.
// Both access modes, since a read-only bind does not stop connect(2). It does
// not reach an ancestor grant: a grant of /tmp itself is left to the runtime
// directory rule and is asserted separately below.
func TestEngineTmpDirSpellingsRefused(t *testing.T) {
	var cases []protCase
	for _, acc := range []string{"ro", "rw"} {
		acc := acc
		add := func(name, grant string, prefixes []string, mod func(*protCase)) {
			tc := protCase{name: acc + " " + name, acc: acc, grant: grant, prefixes: prefixes, refused: true, want: tmpSentence}
			if mod != nil {
				mod(&tc)
			}
			cases = append(cases, tc)
		}
		add("run dir", "/tmp/snug-1000-4242", protPrefixes, nil)
		add("run dir conf", "/tmp/snug-1000-4242/conf", protPrefixes, nil)
		add("run dir trailing slash", "/tmp/snug-1000-4242/", protPrefixes, nil)
		add("dotdot", "/tmp/x/../snug-1000-4242/sock", protPrefixes, nil)
		add("doubled slashes", "//tmp//snug-1000-4242", protPrefixes, nil)
		add("runroot", "/tmp/snug-engines-1000-abc/rr", protPrefixes, nil)
		add("runroot top", "/tmp/snug-engines-1000-abc", protPrefixes, nil)
		add("empty pid suffix", "/tmp/snug-1000-", protPrefixes, nil)
		add("symlink to the run dir", "/home/u/lnk", protPrefixes, func(tc *protCase) {
			tc.links = map[string]string{"/home/u/lnk": "/tmp/snug-1000-4242"}
			tc.exist = []string{"/tmp/snug-1000-4242"}
		})
		add("TMPDIR elsewhere, prefix under it", "/var/tmp/t/snug-1000-4242/conf",
			[]string{"/var/tmp/t/snug-1000-", "/var/tmp/t/snug-engines-1000-", "/tmp/snug-1000-", "/tmp/snug-engines-1000-"}, nil)
		add("TMPDIR elsewhere, /tmp spelling still covered", "/tmp/snug-1000-4242",
			[]string{"/var/tmp/t/snug-1000-", "/var/tmp/t/snug-engines-1000-", "/tmp/snug-1000-", "/tmp/snug-engines-1000-"}, nil)
		add("TMPDIR is a symlink to /tmp, grant spelled by the link", "/tmp/snug-1000-4242/conf",
			[]string{"/var/tmp/snug-1000-"}, func(tc *protCase) {
				tc.links = map[string]string{"/var/tmp": "/tmp"}
				tc.parents = true
				tc.exist = []string{"/var/tmp", "/tmp/snug-1000-4242/conf"}
			})
	}
	runProt(t, cases)
}

// TestEngineTmpAncestorGrantsRefused pins that rw /tmp is refused when the
// runtime-directory candidates cli.runtimeDirCandidates yields are injected, by
// the runtime directory rule: the name-prefix match deliberately leaves a
// containing grant to it. rw / is covered by the other tables. It fails if /tmp stops being
// reachable by either rule; it does not claim the name-prefix match refuses
// /tmp on its own.
func TestEngineTmpAncestorGrantsRefused(t *testing.T) {
	var cases []protCase
	for _, g := range []string{"/tmp"} {
		cases = append(cases, protCase{name: "rw " + g, acc: "rw", grant: g, prefixes: protPrefixes,
			runtimeDirs: []string{"/run/user/1000/snug", "/tmp/snug-1000"},
			exist:       []string{"/tmp", "/tmp/snug-1000-4242"}, refused: true, want: "runtime directory"})
	}
	runProt(t, cases)
}

// TestEngineTmpSiblingsAllowed is the positive control for the prefix match:
// the boundary is the trailing dash, so a longer uid, an unrelated name, the
// runtime-directory fallback "snug-<uid>" and a name under a different uid
// must still be granted.
func TestEngineTmpSiblingsAllowed(t *testing.T) {
	var cases []protCase
	for _, acc := range []string{"ro", "rw"} {
		for _, g := range []string{
			"/tmp/snug-1000x",
			"/tmp/snug-1000x/sub",
			"/tmp/snug-10001-1",
			"/tmp/snug-engines-1000x",
			"/tmp/snug-2000-1",
			"/tmp/snugx-1000-1",
			"/tmp/work/snug-1000-1",
			"/tmp/x/../snug-1000x",
		} {
			cases = append(cases, protCase{name: acc + " " + g, acc: acc, grant: g, prefixes: protPrefixes, exist: []string{filepath.Clean(g)}})
		}
	}
	runProt(t, cases)
}

// TestToolchainRootSpellings: $SNUG_PODMAN_ROOT is refused rw in every
// spelling and allowed ro, including an ancestor and a link. It would catch a
// toolchain refusal that treats ReadAllowed as covering write, or one keyed on
// text.
func TestToolchainRootSpellings(t *testing.T) {
	roots := append([]EngineDataRoot{{Path: "/opt/podman", ReadAllowed: true}}, protData...)
	toolchain := "toolchain root /opt/podman ($SNUG_PODMAN_ROOT)"
	var cases []protCase
	for _, g := range []struct {
		name, grant string
		mod         func(*protCase)
	}{
		{"root", "/opt/podman", nil},
		{"trailing slash", "/opt/podman/", nil},
		{"dotdot", "/opt/x/../podman/usr/bin", nil},
		{"doubled slashes", "//opt//podman", nil},
		{"inside", "/opt/podman/usr/bin", nil},
		{"ancestor /opt", "/opt", nil},
		{"symlink to root", "/home/u/lnk", func(tc *protCase) {
			tc.links = map[string]string{"/home/u/lnk": "/opt/podman"}
		}},
	} {
		tc := protCase{name: "rw " + g.name, acc: "rw", grant: g.grant, dataRoots: roots, refused: true, want: toolchain,
			exist: []string{"/opt/podman/usr/bin"}}
		if g.mod != nil {
			g.mod(&tc)
		}
		cases = append(cases, tc)
		ro := tc
		ro.name, ro.acc, ro.refused = "ro "+g.name, "ro", false
		cases = append(cases, ro)
	}
	cases = append(cases, protCase{name: "rw sibling /opt/podmanx", acc: "rw", grant: "/opt/podmanx", dataRoots: roots,
		exist: []string{"/opt/podmanx"}})
	runProt(t, cases)
}

// TestRelativeRootsMatchNothingAbsolute documents what a relative root list
// entry does in the resolver: nothing, because a grant is always absolute and
// the resolver has no working directory. The guard against a relative
// $XDG_CONFIG_HOME or $XDG_DATA_HOME therefore has to live in the producer;
// this pins only the resolver half, so it does not claim the producer is safe.
func TestRelativeRootsMatchNothingAbsolute(t *testing.T) {
	runProt(t, []protCase{
		{name: "relative config root", acc: "rw", grant: "/home/u/proj/sub/rel/snug",
			configRoots: []string{"/etc/snug", "rel/snug"}, exist: []string{"/home/u/proj/sub/rel/snug"}},
		{name: "relative data root", acc: "rw", grant: "/home/u/proj/sub/rel/snug",
			dataRoots: []EngineDataRoot{{Path: "rel/snug"}}, exist: []string{"/home/u/proj/sub/rel/snug"}},
	})
}
