package policy

import (
	"slices"
	"strings"
	"testing"
)

func fileReg(extra map[ProfileName]*Profile) map[ProfileName]*Profile {
	reg := testRegistry()
	reg["rt"] = &Profile{Name: "rt", RO: []string{"/usr"}, Symlink: []Symlink{{At: "/bin", Target: "usr/bin"}}}
	for n, p := range extra {
		reg[n] = p
	}
	return reg
}

func resolveFile(t *testing.T, reg map[ProfileName]*Profile, sel ...ProfileName) (*Policy, error) {
	t.Helper()
	return Resolve(reg, append([]ProfileName{"rt"}, sel...), testCtx(), newFakeEnv())
}

func gitconfig(content string) []FileGrant {
	return []FileGrant{{Path: "/etc/gitconfig", Content: content}}
}

func TestProfileFileResolvesToReadOnlyUnauthoredData(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"w": {Name: "w", File: gitconfig("[init]\n\tdefaultBranch = main\n")},
	})
	p, err := resolveFile(t, reg, "@target-rw", "w")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts["/etc/gitconfig"]
	if !ok {
		t.Fatal("no mount at /etc/gitconfig")
	}
	if m.Kind != KindData || m.Authored || m.Access != AccessRO {
		t.Errorf("got kind=%s authored=%v access=%s, want data, not authored, ro", m.Kind, m.Authored, m.Access)
	}
	if m.Perms == nil || *m.Perms != 0o444 {
		t.Errorf("perms = %v, want 0444", m.Perms)
	}
	if string(m.Content) != "[init]\n\tdefaultBranch = main\n" {
		t.Errorf("content = %q", []byte(m.Content))
	}
	if got := p.Files["/etc/gitconfig"].From; len(got) != 1 || got[0] != "w" {
		t.Errorf("ledger From = %v", got)
	}
}

func TestProfileFileIdenticalContentJoins(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"a": {Name: "a", File: gitconfig("x\n")},
		"b": {Name: "b", File: gitconfig("x\n")},
	})
	p, err := resolveFile(t, reg, "@target-rw", "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Files["/etc/gitconfig"].From; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("ledger From = %v, want [a b]", got)
	}
}

func TestProfileFileConflictingContentRefusesNamingBoth(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"a": {Name: "a", File: gitconfig("one\n")},
		"b": {Name: "b", File: gitconfig("two\n")},
	})
	for _, sel := range [][]ProfileName{{"@target-rw", "a", "b"}, {"@target-rw", "b", "a"}} {
		_, err := resolveFile(t, reg, sel...)
		if err == nil {
			t.Fatalf("%v: two different file contents joined", sel)
		}
		for _, want := range []string{"different file contents", " a ", " b", "/etc/gitconfig"} {
			if !strings.Contains(err.Error()+" ", want) {
				t.Errorf("%v: %q lacks %q", sel, err, want)
			}
		}
	}
}

func TestProfileFileVsGrantAtSamePathRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"f": {Name: "f", File: gitconfig("x\n")},
		"t": {Name: "t", Tmpfs: []string{"/etc/gitconfig"}},
	})
	if _, err := resolveFile(t, reg, "@target-rw", "f", "t"); err == nil ||
		!strings.Contains(err.Error(), "conflict at /etc/gitconfig") {
		t.Fatalf("a file and a tmpfs at one path: err = %v", err)
	}
}

func TestProfileFileUnderBindIsMasking(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"f": {Name: "f", File: gitconfig("x\n")},
	})
	_, err := resolveFile(t, reg, "@sys", "@target-rw", "f")
	if err == nil {
		t.Fatal("a profile file under the /etc bind was allowed")
	}
	if !strings.Contains(err.Error(), "a file the profile writes") || strings.Contains(err.Error(), "snug generates") {
		t.Errorf("message = %q", err)
	}
}

func TestProfileFileUnderTmpfsIsAllowed(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"f": {Name: "f", File: []FileGrant{{Path: "~/.config/x/conf", Content: "x"}}},
	})
	p, err := resolveFile(t, reg, "@target-rw", "f")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Mounts["/home/u/.config/x/conf"]; !ok {
		t.Errorf("~/ was not expanded in path: %v", p.SortedMounts())
	}
}

func TestProfileFileRelativePathRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{"f": {Name: "f", File: []FileGrant{{Path: "etc/x", Content: ""}}}})
	if _, err := resolveFile(t, reg, "@target-rw", "f"); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("err = %v", err)
	}
}

func TestGrantBeneathProfileFileRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"f": {Name: "f", File: []FileGrant{{Path: "{home}/d", Content: "x"}}},
		"t": {Name: "t", Tmpfs: []string{"{home}/d/inner"}},
	})
	if _, err := resolveFile(t, reg, "@target-rw", "f", "t"); err == nil {
		t.Fatal("a grant beneath a profile file was allowed")
	}
}

func TestProfileFileInSnugsOwnRefuses(t *testing.T) {
	for _, path := range []string{"/proc/x", "/dev/x", "/snug/bin/git", "/sys/x"} {
		reg := fileReg(map[ProfileName]*Profile{"f": {Name: "f", File: []FileGrant{{Path: path, Content: "x"}}}})
		if _, err := resolveFile(t, reg, "@target-rw", "f"); err == nil {
			t.Errorf("a profile file at %s was allowed", path)
		}
	}
}

func TestGeneratedMountBeneathProfileFileRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{"f": {Name: "f", File: []FileGrant{{Path: "{home}/.ssh", Content: "x"}}}})
	p, err := resolveFile(t, reg, "@target-rw", "f")
	if err != nil {
		t.Fatal(err)
	}
	p.Replace(Mount{Guest: "/home/u/.ssh/config", Kind: KindData, Access: AccessRO, From: []string{"(snug)"}})
	err = p.Validate(newFakeEnv())
	if err == nil || !strings.Contains(err.Error(), "is mounted beneath it") {
		t.Fatalf("err = %v", err)
	}
}

func TestProfileFileDisplacedBySnugsOwnFileRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{"f": {Name: "f", File: []FileGrant{{Path: "{home}/.gitconfig", Content: "x"}}}})
	p, err := resolveFile(t, reg, "@target-rw", "f")
	if err != nil {
		t.Fatal(err)
	}
	p.Replace(Mount{Guest: "/home/u/.gitconfig", Kind: KindData, Access: AccessRO, From: []string{"identity:id"}})
	err = p.Validate(newFakeEnv())
	if err == nil {
		t.Fatal("a generated file displaced a profile file silently")
	}
	for _, want := range []string{"profile f writes a file at /home/u/.gitconfig", "never replaces", `/etc/gitconfig`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %q", err, want)
		}
	}
}

func TestValidateRefusesAnUnrecordedProfileFile(t *testing.T) {
	p := mustResolve(t, "@sys", "@target-rw")
	p.Mounts["/home/u/x"] = Mount{Guest: "/home/u/x", Kind: KindData, Access: AccessRO, From: []string{"w"}}
	err := p.Validate(newFakeEnv())
	if err == nil || !strings.Contains(err.Error(), "snug bug") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateRefusesALedgerEntryWithoutAMount(t *testing.T) {
	p := mustResolve(t, "@sys", "@target-rw")
	p.Files = map[string]ProfileFile{"/home/u/gone": {From: []ProfileName{"w"}}}
	err := p.Validate(newFakeEnv())
	if err == nil || !strings.Contains(err.Error(), "snug bug") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckFileGrantsRefusals(t *testing.T) {
	cases := map[string]struct {
		in   []FileGrant
		want string
	}{
		"empty path":  {[]FileGrant{{Content: "x"}}, "empty path"},
		"duplicate":   {[]FileGrant{{Path: "/a", Content: "x"}, {Path: "/a", Content: "y"}}, "written twice"},
		"NUL":         {[]FileGrant{{Path: "/a", Content: "a\x00b"}}, "NUL"},
		"ESC":         {[]FileGrant{{Path: "/a", Content: "a\x1b[2Kb"}}, `\x1b`},
		"CR":          {[]FileGrant{{Path: "/a", Content: "a\rb"}}, `\r`},
		"DEL":         {[]FileGrant{{Path: "/a", Content: "a\x7fb"}}, `\x7f`},
		"NEL":         {[]FileGrant{{Path: "/a", Content: "a\u0085b"}}, "\\u0085"},
		"RLO":         {[]FileGrant{{Path: "/a", Content: "a\u202eb"}}, "\\u202e"},
		"LS":          {[]FileGrant{{Path: "/a", Content: "a\u2028b"}}, "\\u2028"},
		"bad utf8":    {[]FileGrant{{Path: "/a", Content: "a\xffb"}}, "UTF-8"},
		"over limit":  {[]FileGrant{{Path: "/a", Content: strings.Repeat("x", MaxFileBytes+1)}}, "limit"},
		"unknown":     {[]FileGrant{{Path: "/a", Content: "a\n{nope}\n"}}, "line 2: unknown placeholder {nope}"},
		"unterminted": {[]FileGrant{{Path: "/a", Content: "x\ny {home\n"}}, "line 2"},
		"malformed":   {[]FileGrant{{Path: "/a", Content: "{profile.x}"}}, "malformed"},
		"path leaf":   {[]FileGrant{{Path: "/a", Content: "{profile.x.identity.ssh.key}"}}, "host path"},
		"not a key":   {[]FileGrant{{Path: "/a", Content: "{profile.x.environ.set}"}}, "not a key"},
		"bad name":    {[]FileGrant{{Path: "/a", Content: "{profile.a b.identity.ssh.host}"}}, "profile name"},
	}
	for name, c := range cases {
		err := CheckFileGrants(c.in)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q lacks %q", name, err, c.want)
		}
	}
	ok := []FileGrant{
		{Path: "/a", Content: "tab\there\nline\n{home} {lbrace}{rbrace} } {profile.x.identity.ssh.host}"},
		{Path: "/b", Content: strings.Repeat("x", MaxFileBytes)},
		{Path: "/c", Content: ""},
	}
	if err := CheckFileGrants(ok); err != nil {
		t.Errorf("legal grants refused: %v", err)
	}
}

func TestCheckFileGrantsErrorDoesNotQuoteTheWholeBody(t *testing.T) {
	body := strings.Repeat("secret-line\n", 50) + "{nope}\n"
	err := CheckFileGrants([]FileGrant{{Path: "/a", Content: body}})
	if err == nil || strings.Contains(err.Error(), "secret-line") {
		t.Fatalf("err = %v", err)
	}
}

func idProfile(name ProfileName, ssh IdentitySSH) *Profile {
	return &Profile{Name: name, Identity: &Identity{SSH: ssh}}
}

func TestProfileFilePlaceholderExpandsTransitively(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id":  idProfile("id", IdentitySSH{Host: "git.example"}),
		"mid": {Name: "mid", Include: []ProfileName{"id"}},
		"w": {Name: "w", Include: []ProfileName{"mid"}, File: gitconfig(
			"[url \"git@{profile.id.identity.ssh.host}:\"]\n\tx = {home}{lbrace}{rbrace}\n")},
	})
	p, err := resolveFile(t, reg, "@target-rw", "w")
	if err != nil {
		t.Fatal(err)
	}
	want := "[url \"git@git.example:\"]\n\tx = /home/u{}\n"
	if got := string(p.Mounts["/etc/gitconfig"].Content); got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
	ph := p.Files["/etc/gitconfig"].Placeholders
	if len(ph) != 1 || ph[0].Text != "{profile.id.identity.ssh.host}" || ph[0].Value != "git.example" {
		t.Errorf("placeholders = %v", ph)
	}
}

func TestProfileFilePlaceholderOutsideClosureRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id": idProfile("id", IdentitySSH{Host: "git.example"}),
		"w":  {Name: "w", File: gitconfig("{profile.id.identity.ssh.host}\n")},
	})
	for _, sel := range [][]ProfileName{{"@target-rw", "w"}, {"@target-rw", "w", "id"}} {
		_, err := resolveFile(t, reg, sel...)
		if err == nil {
			t.Fatalf("%v: a placeholder outside the include closure resolved", sel)
		}
		for _, want := range []string{"line 1", "neither", `include = ["id"]`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v: %q lacks %q", sel, err, want)
			}
		}
	}
}

func TestProfileFilePlaceholderUnsetKeyRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id": idProfile("id", IdentitySSH{Key: "/home/u/k.pub"}),
		"w":  {Name: "w", Include: []ProfileName{"id"}, File: gitconfig("{profile.id.identity.ssh.host}\n")},
	})
	_, err := resolveFile(t, reg, "@target-rw", "w")
	if err == nil || !strings.Contains(err.Error(), "never expands a placeholder to nothing") {
		t.Fatalf("err = %v", err)
	}
}

func TestProfileFilePlaceholderValueIsCheckedText(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id": idProfile("id", IdentitySSH{Host: "a\nb"}),
		"w":  {Name: "w", Include: []ProfileName{"id"}, File: gitconfig("{profile.id.identity.ssh.host}\n")},
	})
	if _, err := resolveFile(t, reg, "@target-rw", "w"); err == nil {
		t.Fatal("a newline in an identity value reached a file body")
	}
}

func TestProfileFilePlaceholderIsSinglePass(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id": {Name: "id", Identity: &Identity{Git: IdentityGit{Name: "{home}", Email: "a@example.com"}}},
		"w":  {Name: "w", Include: []ProfileName{"id"}, File: gitconfig("{profile.id.identity.git.name}")},
	})
	p, err := resolveFile(t, reg, "@target-rw", "w")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(p.Mounts["/etc/gitconfig"].Content); got != "{home}" {
		t.Errorf("an expanded value was scanned again: %q", got)
	}
}

func TestProfileFileTargetWithNewlineRefuses(t *testing.T) {
	reg := fileReg(nil)
	reg["w"] = &Profile{Name: "w"}
	// The newline-bearing value goes in through the variable table, which is
	// what a target with a newline in its name would fill.
	vars := pathVars("/t\nx", "/home/u")
	if _, _, err := expandFileContent(reg, "w", "/etc/gitconfig", "{target}", vars); err == nil ||
		!strings.Contains(err.Error(), `\n`) {
		t.Fatalf("err = %v", err)
	}
}

func TestProfileFileTildeIsNotExpandedInContent(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{"w": {Name: "w", File: gitconfig("~/x\n")}})
	p, err := resolveFile(t, reg, "@target-rw", "w")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(p.Mounts["/etc/gitconfig"].Content); got != "~/x\n" {
		t.Errorf("content = %q", got)
	}
}

func TestLiteralBraceEscapes(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"w": {Name: "w",
			File:    gitconfig("a{lbrace}b{rbrace}c}d"),
			Tmpfs:   []string{"{home}/{lbrace}x{rbrace}"},
			Environ: EnvGrants{Set: map[string]string{"MARK": "{lbrace}v{rbrace}"}},
		},
	})
	p, err := resolveFile(t, reg, "@target-rw", "w")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(p.Mounts["/etc/gitconfig"].Content); got != "a{b}c}d" {
		t.Errorf("content = %q", got)
	}
	if _, ok := p.Mounts["/home/u/{x}"]; !ok {
		t.Errorf("tmpfs path did not expand {lbrace}/{rbrace}: %v", p.SortedMounts())
	}
	if v := p.Env["MARK"]; len(v.Entries) == 0 || v.Entries[0].Value != "{v}" {
		t.Errorf("environ value = %+v", v)
	}
}

func TestProfileFileUnknownPlaceholderNamesTheLine(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{"w": {Name: "w", File: gitconfig("ok\n{homee}\n")}})
	_, err := resolveFile(t, reg, "@target-rw", "w")
	if err == nil || !strings.Contains(err.Error(), "line 2: unknown placeholder {homee}") {
		t.Fatalf("err = %v", err)
	}
}

func TestDroppingAPlaceholderKeyRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id": idProfile("id", IdentitySSH{Host: "h.example"}),
		"w":  {Name: "w", Include: []ProfileName{"id"}, File: gitconfig("{profile.id.identity.ssh.host}")},
	})
	if _, err := resolveFile(t, reg, "@target-rw", "w"); err != nil {
		t.Fatal(err)
	}
	reg["id"].Identity.SSH.Host = ""
	if _, err := resolveFile(t, reg, "@target-rw", "w"); err == nil {
		t.Fatal("dropping the key a placeholder names resolved to an empty expansion")
	}
}

func TestProfileFileVerdictDoesNotDependOnTheSelectedSet(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"id": idProfile("id", IdentitySSH{Host: "h.example"}),
		"w":  {Name: "w", File: gitconfig("{profile.id.identity.ssh.host}")},
	})
	if err := CheckProfileFiles(reg, "w"); err == nil {
		t.Fatal("CheckProfileFiles accepted a placeholder outside the include closure")
	}
	reg["w"].Include = []ProfileName{"id"}
	if err := CheckProfileFiles(reg, "w"); err != nil {
		t.Fatalf("closure member refused: %v", err)
	}
}

// PIP_CONFIG_FILE because coupling applies only to names the roster types as
// paths; an unrostered name is never coupled and would pass either way.
func pipConf(path string) EnvGrants {
	return EnvGrants{Set: map[string]string{"PIP_CONFIG_FILE": path}}
}

func TestEnvCouplingCountsAFileAsAGrant(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"w":    {Name: "w", File: gitconfig("x\n"), Environ: pipConf("/etc/gitconfig")},
		"bare": {Name: "bare", Environ: pipConf("/etc/gitconfig")},
	})
	if _, err := resolveFile(t, reg, "@target-rw", "w"); err != nil {
		t.Fatalf("a variable naming the profile's own file was refused as ungranted: %v", err)
	}
	if _, err := resolveFile(t, reg, "@target-rw", "bare"); err == nil {
		t.Fatal("control: without the file the same variable was accepted, so the case above proves nothing")
	}
}

// TestEnvCouplingDoesNotBorrowAnotherProfilesFile would catch: profile b
// naming a file profile a writes, with neither including the other, because
// both are selected.
func TestEnvCouplingDoesNotBorrowAnotherProfilesFile(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"a": {Name: "a", File: gitconfig("x\n")},
		"b": {Name: "b", Environ: pipConf("/etc/gitconfig")},
	})
	_, err := resolveFile(t, reg, "@target-rw", "a", "b")
	if err == nil || !strings.Contains(err.Error(), `profile "b" sets PIP_CONFIG_FILE`) {
		t.Fatalf("b borrowed a's file: err = %v", err)
	}
}

// TestEnvCouplingFileClosureIsDownwardOnly would catch: an included profile
// naming a file written by the profile that includes it. The closure runs from
// the variable's profile down its includes, never up.
func TestEnvCouplingFileClosureIsDownwardOnly(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"child":  {Name: "child", Environ: pipConf("/etc/gitconfig")},
		"parent": {Name: "parent", Include: []ProfileName{"child"}, File: gitconfig("x\n")},
	})
	_, err := resolveFile(t, reg, "@target-rw", "parent")
	if err == nil || !strings.Contains(err.Error(), `profile "child" sets PIP_CONFIG_FILE`) {
		t.Fatalf("child borrowed its includer's file: err = %v", err)
	}
}

// TestProfileFileAtAnyGeneratedPathRefuses would catch: a profile file landing
// on a path snug generates for the same selection and winning or losing it
// quietly. The set of paths is DERIVED, not listed: it is every Authored,
// non-Anchor mount of a selection that turns on every identity leaf and every
// feature that writes a file, so a generator added tomorrow is covered the day
// it lands. It covers only what that one maximal selection generates; a path
// written only under a different selection (a Kube credential kind, say) is
// outside it. The CLI's post-Resolve writers are covered by the internal/cli
// staged-path test.
func TestProfileFileAtAnyGeneratedPathRefuses(t *testing.T) {
	max := maximalProfile()
	max.File = nil
	reg := fileReg(map[ProfileName]*Profile{"maximal": max})
	base, err := resolveFile(t, reg, "@sys", "maximal")
	if err != nil {
		t.Fatalf("the maximal selection does not resolve, so the control is empty: %v", err)
	}

	var guests []string
	for _, m := range base.SortedMounts() {
		if m.Authored && !m.Anchor {
			guests = append(guests, m.Guest)
		}
	}
	// Positive control: the derivation found the generated files this test
	// exists to protect. If a generator is renamed away, this is the failure
	// that says the loop below no longer tests it.
	for _, must := range []string{base.Home + "/.gitconfig", base.Home + "/.ssh/config",
		base.Home + "/.ssh/known_hosts", base.Home + "/.kube/config", "/etc/resolv.conf",
		"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		if !slices.Contains(guests, must) {
			t.Errorf("control: %s is not an Authored mount of the maximal selection (have %v)", must, guests)
		}
	}

	wording := map[string]string{
		base.Home + "/.gitconfig":       "/etc/gitconfig",
		base.Home + "/.ssh/config":      "no layer",
		base.Home + "/.ssh/known_hosts": "no layer",
		base.Home + "/.kube/config":     "credential",
		"/etc/resolv.conf":              "network policy",
		"/etc/passwd":                   "nss = true",
		"/etc/group":                    "nss = true",
		"/etc/nsswitch.conf":            "nss = true",
	}
	for _, g := range guests {
		g := g
		t.Run(strings.TrimPrefix(g, "/"), func(t *testing.T) {
			intruder := &Profile{Name: "intruder", File: []FileGrant{{Path: g, Content: "x\n"}}}
			reg2 := fileReg(map[ProfileName]*Profile{"maximal": maximalProfile(), "intruder": intruder})
			reg2["maximal"].File = nil
			_, err := resolveFile(t, reg2, "@sys", "maximal", "intruder")
			if err == nil {
				t.Fatalf("a profile file at %s, a path snug generates, was ACCEPTED", g)
			}
			if want, ok := wording[g]; ok && !strings.Contains(err.Error(), want) {
				t.Errorf("refusal for %s lacks %q: %v", g, want, err)
			}
			if !strings.Contains(err.Error(), g) {
				t.Errorf("refusal does not name %s: %v", g, err)
			}
		})
	}
}

// TestProfileFileThroughSymlinkRefuses would catch: a profile file whose path
// is reached through a symlink snug creates, which would put the bytes at a
// different guest path than the one the author wrote and the dry-run shows.
func TestProfileFileThroughSymlinkRefuses(t *testing.T) {
	reg := fileReg(map[ProfileName]*Profile{
		"f": {Name: "f", File: []FileGrant{{Path: "/bin/evil.conf", Content: "x\n"}}},
	})
	if _, err := resolveFile(t, reg, "@target-rw", "f"); err == nil {
		t.Fatal("a profile file under the /bin -> usr/bin symlink was accepted")
	}
}
