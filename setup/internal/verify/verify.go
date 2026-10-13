// Package verify has the real snug resolve a draft and compares the result
// with the draft's intent ledger. A draft whose resolved policy differs from
// what the human asked for is not saved.
//
// The dry-run document is decoded here field by field rather than by
// importing snug's packages: setup/ is a separate module so that snug never
// links anything snug-setup needs.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/intent"
)

// Format is the dry-run document format this package reads.
const Format = 2

// Defaults is what a bare `snug DIR` selects, from snug's
// profile.BuiltinDefaults. The check runs snug with an empty
// XDG_CONFIG_HOME, so a `defaults =` in the user's config.toml does not apply
// to it.
var Defaults = []string{"@sys", "@home", "@target-rw"}

// Doc is the part of `snug --dry-run --json` this package reads.
type Doc struct {
	Snug struct {
		Format         int    `json:"format"`
		Outcome        string `json:"outcome"`
		Lossy          bool   `json:"lossy"`
		PolicyResolved bool   `json:"policy_resolved"`
	} `json:"snug"`
	Refusal *struct {
		Message string `json:"message"`
	} `json:"refusal"`
	Profiles struct {
		Selected []string `json:"selected"`
		Implied  []string `json:"implied"`
	} `json:"profiles"`
	Mounts []struct {
		Guest  string   `json:"guest"`
		Host   string   `json:"host"`
		Kind   string   `json:"kind"`
		Access string   `json:"access"`
		From   []string `json:"from"`
	} `json:"mounts"`
	Network struct {
		Mode   string `json:"mode"`
		Egress bool   `json:"egress"`
	} `json:"network"`
}

// Diff is one way the resolved policy differs from the ledger.
type Diff struct {
	What string // what snug resolved, against what was asked
	Fix  string // what the human can say or change
}

func (d Diff) String() string { return d.What + "\n    fix: " + d.Fix }

// Parse decodes a dry-run document. It returns an error for a document that
// is not JSON, whose format is not Format, or that is lossy (a path that is
// not valid UTF-8 cannot be compared exactly).
func Parse(raw []byte) (Doc, error) {
	var doc Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Doc{}, fmt.Errorf("snug's dry-run output is not a JSON document (%v); is the snug on PATH older than --json?", err)
	}
	if doc.Snug.Format != Format {
		return Doc{}, fmt.Errorf("snug's dry-run document is format %d and snug-setup reads format %d; use a snug and a snug-setup from the same checkout", doc.Snug.Format, Format)
	}
	if doc.Snug.Lossy {
		return Doc{}, errors.New("snug's dry-run document is lossy (a path is not valid UTF-8), so it cannot be compared exactly; grant a path whose name is valid UTF-8")
	}
	return doc, nil
}

// Compare returns every difference between doc and d's effective ledger, in
// a fixed order: refusal, selection, network, paths. It is pure.
func Compare(d *draft.Draft, doc Doc) []Diff {
	if doc.Snug.Outcome != "ok" || !doc.Snug.PolicyResolved {
		msg := "(no message)"
		if doc.Refusal != nil {
			msg = doc.Refusal.Message
		}
		return []Diff{{What: "snug refused the draft: " + msg, Fix: "change what snug names above; the draft as it stands cannot run"}}
	}
	name := d.Name
	var diffs []Diff
	add := func(what, fix string, a ...any) { diffs = append(diffs, Diff{What: fmt.Sprintf(what, a...), Fix: fix}) }

	if !slices.Contains(doc.Profiles.Selected, name) {
		add("snug did not select the profile %s at all (selected: %s)", "this is a snug-setup bug: the dry run was given the wrong name", name, strings.Join(doc.Profiles.Selected, " "))
	}
	resolved := map[string]bool{}
	for _, n := range append(slices.Clone(doc.Profiles.Selected), doc.Profiles.Implied...) {
		if n != name {
			resolved[n] = true
		}
	}

	base := []string{"@sys", "@home"}
	if !d.ReadOnlyTarget {
		base = Defaults
	}
	allowed := map[string]bool{}
	for _, b := range base {
		for _, n := range draft.Closure(b) {
			allowed[n] = true
		}
	}
	eff := d.Effective()
	type grant struct {
		access string
		by     []string
	}
	grants := map[string]*grant{}
	var order []string
	drops := map[string]string{}
	stages := map[string]string{}
	// userIncludes: a profile of the human's own brings in whatever it
	// includes, in a file this check does not read, so what it implies is
	// theirs by having included it.
	userIncludes := false
	for _, e := range eff {
		a := e.Action
		why := origin(e)
		switch a.Op {
		case intent.OpUseProfile:
			for _, n := range draft.Closure(a.Name) {
				allowed[n] = true
			}
			if !resolved[a.Name] {
				add("%s asked for %s; snug's resolved selection does not have it", "ask for it again; if it persists, the draft lost it (a snug-setup bug)", why, a.Name)
			}
		case intent.OpIncludeProfile:
			userIncludes = true
			allowed[a.Name] = true
			if !resolved[a.Name] {
				add("%s asked for your profile %s; snug's resolved selection does not have it", "check that the profile still exists in your profiles.d, then ask for it again", why, a.Name)
			}
		case intent.OpDropProfile:
			if resolved[a.Name] {
				fix := "find what includes " + a.Name + " in the profile and drop that too"
				if slices.Contains(base, a.Name) {
					fix = a.Name + " comes with a bare `snug DIR`, so dropping it from the profile removes nothing"
					if a.Name == "@target-rw" {
						fix += "; say \"read-only here\" to run with --no-defaults and a read-only target"
					}
				}
				add("%s asked to drop %s; snug still selects it", fix, why, a.Name)
			}
		case intent.OpGrantPath:
			p := d.HostPath(a.Path)
			g := grants[p]
			if g == nil {
				g = &grant{}
				grants[p] = g
				order = append(order, p)
			}
			switch {
			case a.Access == "tmpfs" || g.access == "":
				g.access = a.Access
			case a.Access == "rw" && g.access == "ro":
				g.access = "rw"
			}
			g.by = append(g.by, why)
		case intent.OpDropPath:
			drops[d.HostPath(a.Path)] = why
		case intent.OpStageBinary:
			stages["/snug/bin/"+a.Name] = why
		}
	}
	if d.ReadOnlyTarget {
		t := d.HostPath("{target}")
		if grants[t] == nil {
			grants[t] = &grant{access: "ro", by: []string{"the read-only target"}}
			order = append(order, t)
		}
	}

	var extra []string
	for n := range resolved {
		if !allowed[n] && !(userIncludes && slices.Contains(doc.Profiles.Implied, n)) {
			extra = append(extra, n)
		}
	}
	slices.Sort(extra)
	for _, n := range extra {
		add("snug selects %s, which nothing in the intent ledger asked for", "say \"drop "+n+"\", or ask for it in your own words if you want it", n)
	}

	if doc.Network.Egress != resolved["@net"] {
		add("snug's network is %s (egress %v) while @net is %s", "this is a snug-setup or snug bug: report it with the profile file", doc.Network.Mode, doc.Network.Egress, map[bool]string{true: "selected", false: "not selected"}[resolved["@net"]])
	}

	mine := func(from []string) bool { return slices.Contains(from, name) }
	matched := map[int]bool{}
	for _, p := range order {
		g := grants[p]
		found := false
		for i, m := range doc.Mounts {
			if !mine(m.From) || m.Guest != p {
				continue
			}
			matched[i] = true
			found = true
			got := m.Access
			if m.Kind == "tmpfs" {
				got = "tmpfs"
			}
			if got != g.access {
				add("%s asked for %s on %s; snug mounts it %s", "a grant the profile shares with another grant joins by the widest; drop the path and grant it once, as you want it", strings.Join(g.by, ", "), g.access, p, got)
			}
		}
		if !found {
			add("%s asked for %s on %s; snug mounts nothing there from %s", "check the path exists on this host, then grant it again", strings.Join(g.by, ", "), g.access, p, name)
		}
	}
	guests := slices.Sorted(maps.Keys(stages))
	for _, guest := range guests {
		why := stages[guest]
		found := false
		for i, m := range doc.Mounts {
			if mine(m.From) && m.Guest == guest {
				matched[i], found = true, true
			}
		}
		if !found {
			add("%s staged %s; snug mounts nothing there", "stage the binary again", why, guest)
		}
	}
	for i, m := range doc.Mounts {
		if !mine(m.From) || matched[i] {
			continue
		}
		if why, ok := drops[m.Guest]; ok {
			add("%s dropped %s; snug still mounts it from %s", "drop the path again; if it persists, the draft kept it (a snug-setup bug)", why, m.Guest, name)
			continue
		}
		add("snug mounts %s (%s) from %s, which nothing in the intent ledger asked for", "say \"drop path "+m.Guest+"\"", m.Guest, m.Access, name)
	}
	return diffs
}

func origin(e draft.Entry) string {
	switch {
	case e.Source == draft.SourceUser:
		return "\"" + draft.Comment(e.Origin) + "\""
	case e.Source == draft.SourceDefault:
		return "a default"
	}
	return draft.Comment(e.Origin)
}

// File is a profile file of the human's, copied into the check's scratch
// configuration so a draft that includes one of their profiles can resolve.
type File struct {
	Name string
	Body []byte
}

// Run writes d as a profile of a fresh XDG_CONFIG_HOME, with the files in
// others beside it, runs `snug --dry-run --json` on it the way the run line
// will, and returns the parsed document. A refusal (exit 77) still yields a
// document; an error is returned only when there is none to read. others is
// empty unless the draft includes one of the human's own profiles: the check
// is otherwise hermetic, and a stray profile of theirs cannot change its
// verdict.
func Run(ctx context.Context, run hostfacts.Runner, snug string, d *draft.Draft, others []File) (Doc, error) {
	xdg, err := os.MkdirTemp("", "snug-setup-check-")
	if err != nil {
		return Doc{}, fmt.Errorf("making a scratch config directory for the check: %w (set TMPDIR to a writable directory)", err)
	}
	defer os.RemoveAll(xdg)
	dir := filepath.Join(xdg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Doc{}, fmt.Errorf("making %s for the check: %w", dir, err)
	}
	for _, f := range others {
		if err := os.WriteFile(filepath.Join(dir, f.Name), f.Body, 0o600); err != nil {
			return Doc{}, fmt.Errorf("copying %s for the check: %w", f.Name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, d.Name+".toml"), []byte(d.Render()), 0o600); err != nil {
		return Doc{}, fmt.Errorf("writing the draft for the check: %w", err)
	}
	args := append([]string{"--dry-run", "--json"}, d.RunArgs(d.Host.Target)...)
	res, err := run(ctx, []string{"XDG_CONFIG_HOME=" + xdg}, snug, args...)
	if len(res.Stdout) == 0 {
		if errors.Is(err, exec.ErrNotFound) {
			return Doc{}, fmt.Errorf("%s cannot be run: %w", snug, err)
		}
		status := "it exited 0"
		if err != nil {
			status = err.Error()
		}
		return Doc{}, fmt.Errorf("snug %s printed no document (%s)\n%s", strings.Join(args, " "), status, strings.TrimSpace(string(res.Stderr)))
	}
	return Parse(res.Stdout)
}
