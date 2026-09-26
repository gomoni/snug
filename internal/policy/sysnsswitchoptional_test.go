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
			"/etc/localtime", "/etc/os-release", "/etc/alternatives",
		},
		Optional: []string{
			"/opt", "/etc/ld.so.conf.d",
			"/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/ca-certificates.conf",
			"/etc/crypto-policies", "/var/lib/ca-certificates", "/usr/share/ca-certificates",
			"/etc/localtime", "/etc/os-release", "/etc/alternatives",
		},
		Symlink: []Symlink{
			{At: "/bin", Target: "usr/bin"},
			{At: "/sbin", Target: "usr/sbin"},
			{At: "/lib", Target: "usr/lib"},
			{At: "/lib64", Target: "usr/lib64"},
		},
		// Matches the real @sys's own `nss = true` (base.toml): generates
		// /etc/passwd, /etc/group and /etc/nsswitch.conf rather than binding
		// any of them — nsswitch.conf left this profile's ro/optional lists
		// entirely (issue #612), so the vendor-copy fallback the two tests
		// below used to pin no longer has a grant to loosen.
		NSS: true,
	}
}

// sysRegistryWithout builds a registry carrying sysMirrorFixture in place of
// testRegistry's simplified @sys, and a fakeEnv holding every path @sys's
// still-required entries need (ld.so.cache, ld.so.conf) EXCEPT the ones named
// in without — so a caller can drop exactly the file the grant in question is
// about and nothing else. passwd and group are not in this list: since issue
// #612 they are GENERATED, not bound from @sys, so no host file need exist
// for either to resolve.
func sysRegistryWithout(without ...string) (map[ProfileName]*Profile, *fakeEnv) {
	drop := map[string]bool{}
	for _, p := range without {
		drop[p] = true
	}
	env := newFakeEnv()
	for _, p := range []string{"/etc/ld.so.cache", "/etc/ld.so.conf"} {
		if !drop[p] {
			env.files[p] = true
		}
	}
	reg := testRegistry()
	reg["@sys"] = sysMirrorFixture()
	return reg, env
}

// TestSysStillRefusesAMissingRequiredEtcGrant is the negative that proves the
// remaining required /etc entries are still required: nsswitch.conf left
// this profile's ro/optional lists entirely once it became a GENERATED file
// (issue #612), so there is no longer an "only nsswitch.conf is optional"
// loosening to pin against — this just confirms a real required grant still
// fails closed when its host file is absent.
func TestSysStillRefusesAMissingRequiredEtcGrant(t *testing.T) {
	reg, env := sysRegistryWithout("/etc/ld.so.cache")
	_, err := Resolve(reg, []ProfileName{"@sys", "@parent-ro"}, testCtx(), env)
	if err == nil {
		t.Fatal("a missing /etc/ld.so.cache was silently accepted")
	}
	if want := `grants "/etc/ld.so.cache" which does not exist`; !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
	}
}
