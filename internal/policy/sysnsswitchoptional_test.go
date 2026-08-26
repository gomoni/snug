package policy

import (
	"strings"
	"testing"
)

// sysMirrorFixture duplicates @sys's RO/Optional/Symlink lists from
// profiles/base.toml, deliberately, for the reason testRegistry's @home
// fixture already states: internal/policy cannot import internal/profile (the
// dependency runs the other way), so a resolver-layer regression for this
// grant has no choice but to carry its own copy of the shape. It is NOT
// testRegistry()'s "@sys" entry — that one binds /usr, /etc and /opt
// wholesale and exists for tests that do not care which /etc file is which.
// A future edit to base.toml's @sys and not here is a real risk; the
// golden-argv layer (internal/cli/envgolden_test.go) is what catches that
// drift, because it resolves the real profile from base.toml rather than a
// copy of it.
func sysMirrorFixture() *Profile {
	return &Profile{
		Name: "@sys",
		RO: []string{
			"/usr", "/opt",
			"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
			"/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/ca-certificates.conf",
			"/etc/crypto-policies", "/var/lib/ca-certificates", "/usr/share/ca-certificates",
			"/etc/nsswitch.conf", "/etc/passwd", "/etc/group",
			"/etc/localtime", "/etc/os-release", "/etc/alternatives",
		},
		Optional: []string{
			"/opt", "/etc/ld.so.conf.d",
			"/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/ca-certificates.conf",
			"/etc/crypto-policies", "/var/lib/ca-certificates", "/usr/share/ca-certificates",
			"/etc/nsswitch.conf",
			"/etc/localtime", "/etc/os-release", "/etc/alternatives",
		},
		Symlink: []Symlink{
			{At: "/bin", Target: "usr/bin"},
			{At: "/sbin", Target: "usr/sbin"},
			{At: "/lib", Target: "usr/lib"},
			{At: "/lib64", Target: "usr/lib64"},
		},
	}
}

// sysRegistryWithout builds a registry carrying sysMirrorFixture in place of
// testRegistry's simplified @sys, and a fakeEnv holding every path @sys's
// still-required entries need (ld.so.cache, ld.so.conf, passwd, group)
// EXCEPT the ones named in without — so a caller can drop exactly the file
// the grant in question is about and nothing else.
func sysRegistryWithout(without ...string) (map[ProfileName]*Profile, *fakeEnv) {
	drop := map[string]bool{}
	for _, p := range without {
		drop[p] = true
	}
	env := newFakeEnv()
	for _, p := range []string{"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/passwd", "/etc/group"} {
		if !drop[p] {
			env.files[p] = true
		}
	}
	reg := testRegistry()
	reg["@sys"] = sysMirrorFixture()
	return reg, env
}

// registry.opensuse.org/opensuse/tumbleweed:latest has no /etc/nsswitch.conf,
// only /usr/etc/nsswitch.conf (measured: GitHub Actions run 32941695379,
// issue #395) — glibc's own fallback, and that file is already inside @sys's
// /usr bind. Fails if the grant is ever required again: Resolve would then
// return "profile \"@sys\" grants \"/etc/nsswitch.conf\" which does not
// exist" instead of succeeding.
func TestSysResolvesWhenOnlyTheVendorNsswitchExists(t *testing.T) {
	reg, env := sysRegistryWithout() // every required file present, nsswitch.conf absent throughout
	p, err := Resolve(reg, []ProfileName{"@sys", "@parent-ro"}, testCtx(), env)
	if err != nil {
		t.Fatalf("Resolve with only the vendor nsswitch.conf present: %v", err)
	}
	if m, ok := p.Mounts["/etc/nsswitch.conf"]; ok {
		t.Fatalf("optional grant produced a mount even though the host file is absent: %+v", m)
	}
	m, ok := p.Mounts["/usr"]
	if !ok || m.Kind != KindBind || m.Access != AccessRO {
		t.Fatalf("expected a read-only bind at /usr (the path glibc's own fallback needs), got %+v (present=%v)", m, ok)
	}
}

// The negative that proves exactly ONE path was loosened. Fails if a later
// edit widens `optional` to cover /etc/passwd (or any other still-required
// entry) as well as nsswitch.conf, which would make this Resolve call
// succeed instead of naming the missing file.
func TestSysStillRefusesAMissingRequiredEtcGrant(t *testing.T) {
	reg, env := sysRegistryWithout("/etc/passwd")
	_, err := Resolve(reg, []ProfileName{"@sys", "@parent-ro"}, testCtx(), env)
	if err == nil {
		t.Fatal("a missing /etc/passwd was silently accepted; only nsswitch.conf is optional")
	}
	if want := `grants "/etc/passwd" which does not exist`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
	}
}

// Pins the rejected alternative from base.toml's comment: adding a grant for
// /usr/etc/nsswitch.conf directly is legal (sameUnderlyingTree, since it sits
// under the /usr bind) but redundant and false on every non-openSUSE host.
// Fails if @sys ever grows such a line, which would put a second mount in
// p.Mounts naming that path on either side.
func TestVendorNsswitchIsNotSeparatelyGranted(t *testing.T) {
	reg := testRegistry()
	reg["@sys"] = sysMirrorFixture()
	env := newFakeEnv()
	for _, p := range []string{"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/passwd", "/etc/group",
		"/etc/nsswitch.conf"} {
		env.files[p] = true
	}
	// The openSUSE vendor copy, present ALONGSIDE the /etc one (the "both
	// copies exist" case named in the task) rather than instead of it, so this
	// test does not depend on the loosening under test to even resolve.
	env.files["/usr/etc/nsswitch.conf"] = true

	p, err := Resolve(reg, testDefaults, testCtx(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// Positive control: the /usr bind that would make the vendor copy
	// reachable is actually present, and so is the direct /etc grant — so an
	// absent mount at /usr/etc/nsswitch.conf below is a real negative and not
	// an artifact of nothing having resolved at all.
	if _, ok := p.Mounts["/usr"]; !ok {
		t.Fatal("positive control failed: no mount at /usr, so the vendor copy is not reachable by ANY path and the negative below is vacuous")
	}
	if _, ok := p.Mounts["/etc/nsswitch.conf"]; !ok {
		t.Fatal("positive control failed: the direct /etc/nsswitch.conf grant produced no mount despite the host file existing")
	}

	for guest, m := range p.Mounts {
		if guest == "/usr/etc/nsswitch.conf" || m.Host == "/usr/etc/nsswitch.conf" {
			t.Fatalf("a profile grants the vendor nsswitch.conf directly: %+v; it must stay reachable only through the /usr bind above it", m)
		}
	}
}
