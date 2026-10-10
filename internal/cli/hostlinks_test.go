package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// builtinReg is the real builtin profile set as the resolver takes it.
func builtinReg(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	return map[policy.ProfileName]*policy.Profile(reg)
}

// TestClaudeBinaryLinkIsCoveredByItsOwnTree fails if @claude stops resolving for
// the native installer layout: ~/.local/bin/claude is the user's own link into
// the ~/.local/share/claude tree that @claude also grants, so the redirect is
// covered. The control is a launcher that leaves the tree (an npm or nvm
// shim), which must refuse and say what to grant.
func TestClaudeBinaryLinkIsCoveredByItsOwnTree(t *testing.T) {
	const version = "/home/u/.local/share/claude/versions/1"
	build := func(dest string) *envFakeEnv {
		env := newEnvFakeEnv()
		delete(env.dirs, "/home/u/.local/bin/claude")
		env.dirs["/home/u/.local/bin"] = true
		env.dirs["/home/u/.local/share/claude"] = true
		env.hostLink(1000, "/home/u/.local/bin/claude", dest)
		env.files[dest] = true
		return env
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude")

	p, err := policy.Resolve(builtinReg(t), sel, envGoldenCtx(), build(version))
	if err != nil {
		t.Fatalf("@claude with a user-owned launcher link into its own tree was refused: %v", err)
	}
	m, ok := p.Mounts["/snug/bin/claude"]
	if !ok || m.Host != version || m.Access != policy.AccessRO {
		t.Fatalf("/snug/bin/claude = %+v (present %v), want a read-only bind of %s", m, ok, version)
	}

	const elsewhere = "/home/u/.nvm/bin/claude"
	_, err = policy.Resolve(builtinReg(t), sel, envGoldenCtx(), build(elsewhere))
	if err == nil {
		t.Fatal("a user-owned launcher that leaves the granted tree was followed")
	}
	for _, want := range []string{"/home/u/.local/bin/claude", elsewhere, "uid 1000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
}

// rootLinkedHost is a host whose /opt and /home are root-owned links, as on
// distributions that keep both under /var.
func rootLinkedHost() *envFakeEnv {
	env := newEnvFakeEnv()
	env.resolveParents = true
	for _, d := range []string{"/var/opt", "/var/home", "/var/home/u", "/var/home/u/proj", "/var/home/u/proj/sub"} {
		env.dirs[d] = true
	}
	env.hostLink(0, "/opt", "/var/opt")
	env.hostLink(0, "/home", "/var/home")
	return env
}

// TestDefaultSelectionAndClaudeResolveOnARootLinkedHost fails if the ownership
// rule refuses what a distribution ships. The sweep resolves every builtin on
// a plain host and on the root-linked one: whatever resolves on the first must
// resolve on the second. Defaults and @claude are named outright so the sweep
// cannot pass on an empty set.
func TestDefaultSelectionAndClaudeResolveOnARootLinkedHost(t *testing.T) {
	reg := builtinReg(t)
	base := profile.BuiltinDefaults()
	resolved := map[policy.ProfileName]bool{}
	for name := range reg {
		sel := append(append([]policy.ProfileName{}, base...), name)
		if _, err := policy.Resolve(reg, sel, envGoldenCtx(), newEnvFakeEnv()); err != nil {
			continue // needs a fixture this host does not have; not this test's subject
		}
		resolved[name] = true
		p, err := policy.Resolve(reg, sel, envGoldenCtx(), rootLinkedHost())
		if err != nil {
			t.Errorf("%v resolves on a plain host but is refused where /opt and /home are root-owned links: %v", sel, err)
			continue
		}
		if p.TargetAsked != "/home/u/proj/sub" || p.Target != "/var/home/u/proj/sub" {
			t.Errorf("%v: Target = %q, TargetAsked = %q", sel, p.Target, p.TargetAsked)
		}
	}
	for _, must := range []policy.ProfileName{"@sys", "@claude"} {
		if !resolved[must] {
			t.Errorf("control: %s did not resolve on the plain host, so the sweep proved nothing about it", must)
		}
	}
	if _, err := policy.Resolve(reg, base, envGoldenCtx(), rootLinkedHost()); err != nil {
		t.Errorf("the default selection is refused on a root-linked host: %v", err)
	}
}

func targetLinkedHost() *envFakeEnv {
	env := newEnvFakeEnv()
	env.hostLink(0, "/home/u/asked\u202e", "/home/u/proj/sub")
	return env
}

func targetLinkReport(t *testing.T, asked string, env *envFakeEnv) (Report, *policy.Policy) {
	t.Helper()
	ctx := envGoldenCtx()
	ctx.Target = asked
	p, err := policy.Resolve(builtinReg(t), profile.BuiltinDefaults(), ctx, env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return buildReport(env, p, p.BwrapArgs(0, 0), config{}, nil, nil), p
}

// TestDryRunNamesWhatTheTargetWasAskedAs fails if --dry-run shows only the
// resolved target: a link left by an earlier run redirected it, and the human
// reading TARGET must be able to see the path they typed was not the path used.
// Both formats, the redirected and the plain case, and the asked path's forging
// rune: a link's NAME is as sandbox-chosen as its destination.
func TestDryRunNamesWhatTheTargetWasAskedAs(t *testing.T) {
	const asked = "/home/u/asked\u202e"

	rep, p := targetLinkReport(t, asked, targetLinkedHost())
	if p.Target != "/home/u/proj/sub" || p.TargetAsked != asked {
		t.Fatalf("control: Target = %q, TargetAsked = %q; the fixture did not redirect", p.Target, p.TargetAsked)
	}

	screen := dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)
	var line string
	for _, l := range strings.Split(screen, "\n") {
		if strings.HasPrefix(l, "TARGET") {
			line = l
		}
	}
	if !strings.Contains(line, "(resolved from ") {
		t.Fatalf("TARGET line %q does not say it was resolved from something", line)
	}
	if !strings.Contains(line, "/home/u/proj/sub") || !strings.Contains(line, "/home/u/asked") {
		t.Errorf("TARGET line %q names neither the resolved nor the asked path", line)
	}
	if strings.ContainsRune(line, '\u202e') {
		t.Errorf("TARGET line renders the asked path's U+202E raw: %q", line)
	}

	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the document is not JSON: %v", err)
	}
	if doc["target_asked"] != asked {
		t.Errorf("target_asked = %v, want %q", doc["target_asked"], asked)
	}
	if doc["target"] != "/home/u/proj/sub" {
		t.Errorf("target = %v", doc["target"])
	}
	if strings.ContainsRune(buf.String(), '\u202e') {
		t.Errorf("the document carries U+202E raw")
	}

	// Not redirected: neither format mentions an asked path.
	plain, pp := targetLinkReport(t, "/home/u/proj/sub", newEnvFakeEnv())
	if pp.TargetAsked != "" {
		t.Fatalf("control: TargetAsked = %q on a target that is not a link", pp.TargetAsked)
	}
	if s := dryRunText(pp, pp.BwrapArgs(0, 0), config{}, nil); strings.Contains(s, "resolved from") {
		t.Errorf("a target that was not redirected is annotated:\n%s", s)
	}
	var pbuf bytes.Buffer
	if err := renderJSON(&pbuf, plain); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pbuf.String(), "target_asked") {
		t.Errorf("a document for a target that was not redirected carries target_asked")
	}
}

// TestDryRunTargetAskedEscapesAnEscapeSequence is the terminal half: ESC in the
// asked path must not reach the screen raw.
func TestDryRunTargetAskedEscapesAnEscapeSequence(t *testing.T) {
	const asked = "/home/u/a\x1b[2K\x1b[1Asnug: verified safe"
	env := newEnvFakeEnv()
	env.hostLink(0, asked, "/home/u/proj/sub")
	_, p := targetLinkReport(t, asked, env)
	screen := dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)
	if !strings.Contains(screen, "verified safe") {
		t.Fatalf("control: the asked path is not on the screen at all:\n%s", screen)
	}
	if strings.ContainsRune(screen, '\x1b') {
		t.Errorf("--dry-run rendered the asked path's ESC raw")
	}
}
