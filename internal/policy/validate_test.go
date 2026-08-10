package policy

import "testing"

// The two symlink entry points ask two different questions of one map, and both
// used to be one function that answered neither reliably. These tests pin the
// difference so nobody re-folds them.

// usrMerged is the shipped shape: /bin, /sbin and /lib all point into /usr, and
// /lib is a PREFIX of /lib64. That last pair is what made map iteration order
// observable.
func usrMerged() map[string]string {
	return map[string]string{
		"/bin":   "/usr/bin",
		"/sbin":  "/usr/sbin",
		"/lib":   "/usr/lib",
		"/lib64": "/usr/lib64",
	}
}

// The deepest link decides, every time. Repeated because the defect this
// replaces was a map range returning whichever key it felt like: a single call
// would have passed roughly half the time, which is the worst kind of green.
func TestResolveViaDeepestIsDeterministicWhenOneLinkPrefixesAnother(t *testing.T) {
	for i := 0; i < 200; i++ {
		via, resolved := resolveViaDeepest(usrMerged(), "/lib64/tls/libc.so")
		if via != "/lib64" || resolved != "/usr/lib64/tls/libc.so" {
			t.Fatalf("iteration %d: got via=%q resolved=%q, want /lib64 and /usr/lib64/tls/libc.so "+
				"— /lib prefixes /lib64, so a first-match walk answers this differently on "+
				"different runs", i, via, resolved)
		}
	}
}

// A grant AT the link path is the link itself; there is no mountpoint being
// created at a symlink destination, so there is nothing to refuse.
func TestResolveViaDeepestSkipsTheLinkItself(t *testing.T) {
	if via, _ := resolveViaDeepest(usrMerged(), "/bin"); via != "" {
		t.Fatalf("a grant at the link path itself was reported as passing through %q", via)
	}
}

func TestResolveViaDeepestIgnoresAnUnrelatedPath(t *testing.T) {
	if via, _ := resolveViaDeepest(usrMerged(), "/opt/tools/bin"); via != "" {
		t.Fatalf("an unrelated path was reported as passing through %q", via)
	}
}

// The environment question is the other one: a PATH element can be literally
// /bin, and on a usr-merged host that IS a symlink. Refusing to rewrite it would
// judge a profile against a path the sandbox never sees.
func TestResolveLinkForEnvMatchesTheLinkItself(t *testing.T) {
	if got := resolveLinkForEnv(usrMerged(), "/bin"); got != "/usr/bin" {
		t.Fatalf("resolveLinkForEnv(/bin) = %q, want /usr/bin", got)
	}
}

func TestResolveLinkForEnvIsDeterministicWhenOneLinkPrefixesAnother(t *testing.T) {
	for i := 0; i < 200; i++ {
		if got := resolveLinkForEnv(usrMerged(), "/lib64/pkgconfig"); got != "/usr/lib64/pkgconfig" {
			t.Fatalf("iteration %d: got %q, want /usr/lib64/pkgconfig", i, got)
		}
	}
}

// No link applies, so the caller gets the path back unchanged and has exactly
// one value to compare.
func TestResolveLinkForEnvLeavesAnUnlinkedPathAlone(t *testing.T) {
	if got := resolveLinkForEnv(usrMerged(), "/usr/local/bin"); got != "/usr/local/bin" {
		t.Fatalf("resolveLinkForEnv rewrote a path no link covers: %q", got)
	}
}
