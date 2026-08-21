package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// installedPluginsManifest is Claude Code's ~/.claude/plugins/installed_plugins.json,
// modelled only as deeply as the filter needs: a version and a map from
// "<name>@<marketplace>" to opaque per-install entries. The entries are kept as
// json.RawMessage rather than a struct because their fields (installPath,
// version, gitCommitSha, …) are Claude Code's to change and snug only forwards
// the ones for NAMED plugins verbatim — it never authors an entry.
type installedPluginsManifest struct {
	Version json.RawMessage            `json:"version"`
	Plugins map[string]json.RawMessage `json:"plugins"`
}

// FilterInstalledPlugins regenerates installed_plugins.json from the host's,
// keeping ONLY the plugins the allowlist names and dropping every other one.
//
// This is issue #68's fix: @claude binds ~/.claude/plugins read-only, and a
// plugin's hooks.json is loaded automatically by Claude Code — so the bind
// hands the sandbox every plugin's command tables. installed_plugins.json is
// what tells Claude Code which plugins are installed and where; snug replaces
// the host's with one naming only the allowlisted set, so auto-loading becomes
// "the plugins you named" rather than "everything anyone ever installed".
// Everything else under the bind stays visible and inert — nothing in the
// filtered manifest points Claude Code at it.
//
// The allowlist is NAMES, never paths (issue #68, and the #42 shape it avoids):
// an entry matches a manifest key by the whole key ("caveman@caveman") or by
// the bare plugin name before the "@" ("caveman"). snug decides the guest path
// this content lands at; the profile only chooses which of the host's installed
// plugins survive.
//
// Invariant 5 — no silent downgrade — applies to a named plugin that is not
// installed: it is an ERROR, not a silent omission, because a run that asked for
// a plugin and did not get it should fail loudly rather than start without it.
//
// hostRaw may be empty (the host never ran Claude Code, or the file is absent).
// An empty allowlist then yields an empty-but-valid manifest — the strict
// default, which is the whole point: even naming nothing REPLACES the host's
// file, so no plugin auto-loads. A NON-empty allowlist against a missing host
// manifest is an error: the named plugins cannot be validated as installed.
func FilterInstalledPlugins(hostRaw []byte, allowlist []string) ([]byte, error) {
	host := installedPluginsManifest{
		Version: json.RawMessage("2"),
		Plugins: map[string]json.RawMessage{},
	}
	if len(hostRaw) > 0 {
		host.Plugins = nil
		if err := json.Unmarshal(hostRaw, &host); err != nil {
			return nil, fmt.Errorf("the host's installed_plugins.json does not parse (%w); refusing "+
				"to regenerate a plugin manifest from a file snug cannot read, because the strict "+
				"default it would fall back to could hide a plugin the run named", err)
		}
		if host.Plugins == nil {
			host.Plugins = map[string]json.RawMessage{}
		}
		if len(host.Version) == 0 {
			host.Version = json.RawMessage("2")
		}
	} else if len(allowlist) > 0 {
		return nil, fmt.Errorf("the profile names %d plugin(s) (%s) but the host has no "+
			"installed_plugins.json to validate them against — a named plugin that is not "+
			"installed is an error, not a silent omission (issue #68, invariant 5)",
			len(allowlist), strings.Join(allowlist, ", "))
	}

	out := installedPluginsManifest{Version: host.Version, Plugins: map[string]json.RawMessage{}}
	for _, name := range allowlist {
		matched := false
		for key, entry := range host.Plugins {
			if key == name || strings.HasPrefix(key, name+"@") {
				out.Plugins[key] = entry
				matched = true
			}
		}
		if !matched {
			installed := make([]string, 0, len(host.Plugins))
			for key := range host.Plugins {
				installed = append(installed, key)
			}
			sort.Strings(installed)
			return nil, fmt.Errorf("the profile names plugin %q, which is not installed on the "+
				"host — a named plugin that is not installed is an error, not a silent omission "+
				"(issue #68, invariant 5). Installed: %s", name, strings.Join(installed, ", "))
		}
	}

	// Marshal with sorted keys (encoding/json sorts map keys), so the same
	// allowlist against the same host manifest produces byte-identical content —
	// a KindData mount whose bytes wobble run to run is a --dry-run diff nobody
	// authored.
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("rendering the filtered installed_plugins.json: %w", err)
	}
	return body, nil
}
