// Package verify has the real snug resolve a draft and compares the result
// with the draft's ledger. A draft whose resolved policy differs from what the
// screen shows is not saved.
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

// Diff is one way the resolved policy differs from the draft.
type Diff struct {
	What string // what snug resolved, against what the draft holds
}

func (d Diff) String() string { return d.What }

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
		return []Diff{{What: "snug refused the draft: " + msg}}
	}
	name := d.Name
	var diffs []Diff
	add := func(what string, a ...any) { diffs = append(diffs, Diff{What: fmt.Sprintf(what, a...)}) }

	if !slices.Contains(doc.Profiles.Selected, name) {
		add("snug did not select the profile %s at all (selected: %s); this is a snug-setup bug: the dry run was given the wrong name", name, strings.Join(doc.Profiles.Selected, " "))
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
		case draft.OpUseProfile:
			for _, n := range draft.Closure(a.Name) {
				allowed[n] = true
			}
			if !resolved[a.Name] {
				add("%s is in the draft (%s); snug's resolved selection does not have it", a.Name, why)
			}
		case draft.OpIncludeProfile:
			userIncludes = true
			allowed[a.Name] = true
			if !resolved[a.Name] {
				add("your profile %s is in the draft (%s); snug's resolved selection does not have it; check that it still exists in your profiles.d", a.Name, why)
			}
		case draft.OpDropProfile:
			if resolved[a.Name] {
				fix := "something else in the profile includes " + a.Name
				if slices.Contains(base, a.Name) {
					fix = a.Name + " comes with a bare `snug DIR`, so dropping it from the profile removes nothing"
				}
				add("%s is dropped in the draft (%s); snug still selects it: %s", a.Name, why, fix)
			}
		case draft.OpGrantPath:
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
		case draft.OpDropPath:
			drops[d.HostPath(a.Path)] = why
		case draft.OpStageBinary:
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
		add("snug selects %s, which the draft does not hold", n)
	}

	if doc.Network.Egress != resolved["@net"] {
		add("snug's network is %s (egress %v) while @net is %s; this is a snug-setup or snug bug", doc.Network.Mode, doc.Network.Egress, map[bool]string{true: "selected", false: "not selected"}[resolved["@net"]])
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
				add("%s on %s is in the draft (%s); snug mounts it %s, because grants of one path join by the widest", g.access, p, strings.Join(g.by, ", "), got)
			}
		}
		if !found {
			add("%s on %s is in the draft (%s); snug mounts nothing there from %s; check the path exists on this host", g.access, p, strings.Join(g.by, ", "), name)
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
			add("%s is staged in the draft (%s); snug mounts nothing there", guest, why)
		}
	}
	for i, m := range doc.Mounts {
		if !mine(m.From) || matched[i] {
			continue
		}
		if why, ok := drops[m.Guest]; ok {
			add("%s is dropped in the draft (%s); snug still mounts it from %s", m.Guest, why, name)
			continue
		}
		add("snug mounts %s (%s) from %s, which the draft does not hold", m.Guest, m.Access, name)
	}
	return diffs
}

func origin(e draft.Entry) string { return draft.Comment(e.Origin) }

// File is a profile file of the human's, copied into the check's scratch
// configuration so a draft that includes one of their profiles can resolve.
type File struct {
	Name string
	Body []byte
}

// GHConfigDir is the directory gh reads its logins from for this person:
// their $GH_CONFIG_DIR (envGH) when set, else $XDG_CONFIG_HOME/gh when
// XDG_CONFIG_HOME is set, else ~/.config/gh.
func GHConfigDir(envGH string, h draft.Host) string {
	switch {
	case envGH != "":
		return envGH
	case h.ConfigHome != "":
		return filepath.Join(h.ConfigHome, "gh")
	}
	return filepath.Join(h.Home, ".config", "gh")
}

// SnugEnv is the environment added to a snug run that reads its profiles from
// the scratch config directory xdg. gh finds its logins under
// $XDG_CONFIG_HOME, which is now the scratch one, so GH_CONFIG_DIR points it
// back at the person's own: without it snug reports "no gh token" for a login
// that exists. The value is a path to gh's own directory, never a token.
func SnugEnv(xdg string, h draft.Host) []string {
	return []string{"XDG_CONFIG_HOME=" + xdg, "GH_CONFIG_DIR=" + GHConfigDir(os.Getenv("GH_CONFIG_DIR"), h)}
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
	res, err := run(ctx, SnugEnv(xdg, d.Host), snug, args...)
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
