package policy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestBookPathSpecExamplesAreWhatSplitSpecDoes runs every row of the path
// spec examples table in docs/src/filesystem.md through splitSpec, with the
// variable values the page states above the table. A row with `—` in both
// columns is one the page says is refused.
func TestBookPathSpecExamplesAreWhatSplitSpecDoes(t *testing.T) {
	const page = "../../docs/src/filesystem.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"home":          "/home/me",
		"target":        "/home/me/src/app",
		"target_parent": "/home/me/src",
	}
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\| (?:`([^`]*)`|(—)) \\| (?:`([^`]*)`|(—)) \\|")
	rows := row.FindAllStringSubmatch(string(data), -1)
	var accepted, refused int
	for _, r := range rows {
		spec, wantHost, wantGuest := r[1], r[2], r[4]
		host, guest, err := splitSpec(spec, vars)
		if r[3] != "" || r[5] != "" {
			refused++
			if err == nil {
				t.Errorf("%s says %q is refused; splitSpec accepts it as host %q guest %q", page, spec, host, guest)
			}
			continue
		}
		accepted++
		if err != nil {
			t.Errorf("%s says %q binds %q at %q; splitSpec refuses it: %v", page, spec, wantHost, wantGuest, err)
			continue
		}
		if host != wantHost || guest != wantGuest {
			t.Errorf("%s says %q binds %q at %q; splitSpec gives %q at %q", page, spec, wantHost, wantGuest, host, guest)
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("%s: found %d accepted and %d refused example rows; the table moved or changed shape", page, accepted, refused)
	}

	// The `:` and `{` table: each refused row's quoted error is what
	// splitSpec says.
	refusal := regexp.MustCompile("(?m)^\\| `[^`]+` \\| `([^`]+)` \\| refused: `([^`]+)`")
	matched := 0
	for _, r := range refusal.FindAllStringSubmatch(string(data), -1) {
		matched++
		_, _, err := splitSpec(r[1], vars)
		if err == nil || !strings.Contains(err.Error(), r[2]) {
			t.Errorf("%s says %q is refused with %q; splitSpec gives %v", page, r[1], r[2], err)
		}
	}
	if matched == 0 {
		t.Errorf("%s: no refused rows in the `:` and `{` table; the table moved or changed shape", page)
	}

	// The same table's {target} rows: a ':' or '{' in a variable's value is
	// part of the path, never a separator or another variable.
	for _, tgt := range []string{"/w/x:y", "/tmp/{foo}"} {
		vars["target"] = tgt
		host, guest, err := splitSpec("{target}", vars)
		if err != nil || host != tgt || guest != tgt {
			t.Errorf("%s says {target} at %s grants %s on both sides; splitSpec gives %q at %q, %v", page, tgt, tgt, host, guest, err)
		}
	}
}
