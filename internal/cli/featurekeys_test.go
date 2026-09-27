package cli

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// The rule #627 settled: a feature key (`network`, `dns`, `nss`, `podman`,
// `git`) makes snug AUTHOR something — a generated file, a helper, a proxy —
// and never binds a host path; a builtin that sets one is that key plus the
// ordinary grants and includes the feature needs. Both spellings stay: the key
// is the primitive a user builds unusual sandboxes from, the builtin the
// ready-made bundle. These two tests hold the rule, so a future key or builtin
// that breaks it fails here rather than in a doc nobody re-reads.

// featureKeyProfiles is each feature key alone, as a user profile writes it.
var featureKeyProfiles = map[policy.ProfileName]*policy.Profile{
	"k-podman-socket": {Name: "k-podman-socket", Podman: "socket"},
	"k-podman-build":  {Name: "k-podman-build", Podman: "build"},
	"k-git":           {Name: "k-git", Git: "extract"},
	"k-net":           {Name: "k-net", Network: "egress", DNS: true},
	"k-nss":           {Name: "k-nss", NSS: true},
}

// featureRegistry is the builtins plus featureKeyProfiles plus "rt", a runtime
// with no feature key of its own — @sys sets nss, so a base built on it would
// hide what nss adds.
func featureRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	for n, p := range featureKeyProfiles {
		m[n] = p
	}
	m["rt"] = &policy.Profile{Name: "rt", RO: []string{"/usr"}, RW: []string{"{target}"}}
	return m
}

// featureCtx gives every key something to author: host git values for `git`,
// a nameserver for `dns`.
func featureCtx() policy.Context {
	c := envGoldenCtx()
	c.HostGit = policy.GitValues{"user.name": "Some One"}
	c.HostNameservers = []string{"192.0.2.53"}
	return c
}

func resolveFeature(t *testing.T, reg map[policy.ProfileName]*policy.Profile, sel ...policy.ProfileName) *policy.Policy {
	t.Helper()
	p, err := policy.Resolve(reg, sel, featureCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	return p
}

// A feature key alone adds only mounts snug authored, and never a bind of a
// host path. A key that bound one would be a grant with no `ro`/`rw` line
// naming it — a host path on --dry-run under a profile that never wrote it.
func TestAFeatureKeyAuthorsAndNeverBindsAHostPath(t *testing.T) {
	reg := featureRegistry(t)
	base := []policy.ProfileName{"rt", "@home"}
	without := resolveFeature(t, reg, base...)
	authored := 0
	for key := range featureKeyProfiles {
		with := resolveFeature(t, reg, append(append([]policy.ProfileName{}, base...), key)...)
		for guest, m := range with.Mounts {
			if old, ok := without.Mounts[guest]; ok && old.Kind == m.Kind && old.Host == m.Host && old.Access == m.Access {
				continue
			}
			authored++
			if m.Kind == policy.KindBind || !m.Authored {
				t.Errorf("%s alone added %s (kind %s, host %q, authored %v): a feature key "+
					"authors; a host path is granted by a profile's ro/rw line", key, guest, m.Kind, m.Host, m.Authored)
			}
		}
		if len(with.Grafts) != len(without.Grafts) {
			t.Errorf("%s alone changed the engine grafts at Resolve (%d -> %d)", key, len(without.Grafts), len(with.Grafts))
		}
	}
	// POSITIVE CONTROL: git's ~/.gitconfig and nss's three account files are
	// authored mounts the loop must have seen, or it compared nothing.
	if authored < 4 {
		t.Errorf("only %d authored mounts seen across the keys; the fixture no longer "+
			"exercises what the keys add", authored)
	}
}

// A builtin that sets a feature key resolves to the SAME value of it as the
// key alone, and to a superset of the key-only mounts at no lower access —
// the bundle adds grants, never a different feature.
func TestAFeatureBuiltinIsItsKeyPlusGrants(t *testing.T) {
	reg := featureRegistry(t)
	base := []policy.ProfileName{"rt", "@home"}
	for _, pair := range []struct{ builtin, key policy.ProfileName }{
		{"@podman-socket", "k-podman-socket"},
		{"@podman-build", "k-podman-build"},
		{"@git", "k-git"},
		{"@net", "k-net"},
		{"@sys", "k-nss"},
	} {
		b := resolveFeature(t, reg, append(append([]policy.ProfileName{}, base...), pair.builtin)...)
		k := resolveFeature(t, reg, append(append([]policy.ProfileName{}, base...), pair.key)...)
		// The key the builtin itself writes carries the same value as the
		// key-only profile: the twin is that key, not a different setting.
		bp, kp := reg[pair.builtin], reg[pair.key]
		if bp.Podman != kp.Podman || bp.Git != kp.Git || bp.NSS != kp.NSS ||
			bp.Network != kp.Network || bp.DNS != kp.DNS {
			t.Errorf("%s writes a different feature value than %s: %+v vs %+v", pair.builtin,
				pair.key, featureValues(bp), featureValues(kp))
		}
		// Resolved, the bundle may carry MORE — @podman-socket includes @sys,
		// which sets nss — but never less of any feature.
		if b.Podman < k.Podman || b.Git < k.Git || (k.NSS && !b.NSS) ||
			b.Net.Mode < k.Net.Mode || (k.Net.DNS && !b.Net.DNS) {
			t.Errorf("%s resolves to less of a feature than %s alone: podman %v/%v git %v/%v "+
				"nss %v/%v network %v/%v dns %v/%v", pair.builtin, pair.key, b.Podman, k.Podman,
				b.Git, k.Git, b.NSS, k.NSS, b.Net.Mode, k.Net.Mode, b.Net.DNS, k.Net.DNS)
		}
		for guest, km := range k.Mounts {
			bm, ok := b.Mounts[guest]
			if !ok {
				t.Errorf("%s grants %s and %s does not", pair.key, guest, pair.builtin)
				continue
			}
			if bm.Access < km.Access {
				t.Errorf("%s: %s is %v under the builtin, %v under the key", guest, pair.builtin, bm.Access, km.Access)
			}
		}
	}
}

func featureValues(p *policy.Profile) [5]any {
	return [5]any{p.Podman, p.Git, p.NSS, p.Network, p.DNS}
}
