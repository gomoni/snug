package policy

import "testing"

// A variable's VALUE may contain ':', and it must never be read as the
// author's host:guest separator. On the target /w/x:/etc/proj, @parent-ro's
// `{target_parent}` split after expansion into host /w/x, guest /etc: a
// sibling directory the selection never granted, mounted over /etc.
func TestGrantSplitsOnTheAuthorsColonNotTheExpansions(t *testing.T) {
	vars := map[string]string{"target": "/w/x:/etc/proj", "target_parent": "/w/x:/etc"}
	for _, tc := range []struct{ spec, host, guest string }{
		{"{target_parent}", "/w/x:/etc", "/w/x:/etc"},
		{"{target}", "/w/x:/etc/proj", "/w/x:/etc/proj"},
		{"{target}:/work", "/w/x:/etc/proj", "/work"},
		{"/opt/a:{target_parent}/b", "/opt/a", "/w/x:/etc/b"},
	} {
		host, guest, err := splitSpec(tc.spec, vars)
		if err != nil {
			t.Fatalf("splitSpec(%q): %v", tc.spec, err)
		}
		if host != tc.host || guest != tc.guest {
			t.Errorf("splitSpec(%q) = %q:%q, want %q:%q", tc.spec, host, guest, tc.host, tc.guest)
		}
	}
	// The author's own separator still splits, and a relative side is still refused.
	if _, _, err := splitSpec("/opt/a:rel", vars); err == nil {
		t.Error(`splitSpec("/opt/a:rel") admitted a relative guest`)
	}
}
