package policy

import (
	"reflect"
	"strings"
	"testing"
)

// passwdFields splits the generated /etc/passwd's single line into its seven
// colon-separated fields, failing the test rather than panicking on a short
// slice so a regression in the generator reads as a normal test failure.
func passwdFields(t *testing.T, p *Policy) []string {
	t.Helper()
	m, ok := p.Mounts["/etc/passwd"]
	if !ok {
		t.Fatal("no generated mount at /etc/passwd")
	}
	line := strings.TrimSuffix(string(m.Content), "\n")
	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		t.Fatalf("/etc/passwd has %d fields, want 7: %q", len(fields), line)
	}
	return fields
}

// TestGeneratedPasswdDirIsAuthoredHOME is issue #612's central invariant:
// getpwuid(getuid())->pw_dir == $HOME, by construction, across the three ways
// a host's passwd entry and $HOME can diverge that #603 used to detect and
// refuse instead of fixing.
func TestGeneratedPasswdDirIsAuthoredHOME(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() Context
		env  func() *fakeEnv
	}{
		{
			name: "HOME does not match HostPasswdHome",
			ctx: func() Context {
				ctx := testCtx()
				ctx.HostPasswdHome = "/some/other/home"
				return ctx
			},
			env: newFakeEnv,
		},
		{
			name: "HOME is a symlink (Silverblue/MicroOS /home -> /var/home)",
			ctx:  testCtx,
			env: func() *fakeEnv {
				env := newFakeEnv()
				env.links["/home/u"] = "/var/home/u"
				env.dirs["/var/home/u"] = true
				return env
			},
		},
		{
			name: "no HostPasswdHome at all (sssd/LDAP account, unmapped uid)",
			ctx: func() Context {
				ctx := testCtx()
				ctx.HostPasswdHome = ""
				return ctx
			},
			env: newFakeEnv,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Resolve(testRegistry(), testDefaults, tc.ctx(), tc.env())
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			fields := passwdFields(t, p)
			wantHome, ok := p.EnvValue("HOME")
			if !ok {
				t.Fatal("policy carries no HOME")
			}
			if fields[5] != wantHome {
				t.Errorf("pw_dir = %q, want $HOME %q", fields[5], wantHome)
			}
			wantUser, ok := p.EnvValue("USER")
			if !ok {
				t.Fatal("policy carries no USER")
			}
			wantLogname, _ := p.EnvValue("LOGNAME")
			if fields[0] != wantUser || fields[4] != wantUser || wantLogname != wantUser {
				t.Errorf("pw_name=%q gecos=%q USER=%q LOGNAME=%q, want all four equal",
					fields[0], fields[4], wantUser, wantLogname)
			}
			wantShell, _ := p.EnvValue("SHELL")
			if fields[6] != wantShell {
				t.Errorf("pw_shell = %q, want $SHELL %q", fields[6], wantShell)
			}
		})
	}
}

// TestFloorHasNoGeneratedAccounts is TestPasswdAndGroupGeneratedWithoutSys
// inverted: the floor selection (no profiles at all) has no profile whose
// `nss` could ever fold true, so Policy.NSS is false and none of the three
// generated files exists — unlike /etc/resolv.conf, which stays unconditional.
func TestFloorHasNoGeneratedAccounts(t *testing.T) {
	p, err := Resolve(testRegistry(), nil, testCtx(), newFakeEnv())
	if p == nil {
		t.Fatal("Resolve(nil selection) returned a nil policy")
	}
	if err == nil {
		t.Fatal("the floor selection must still be refused by Validate")
	}
	if p.NSS {
		t.Error("the floor selection resolved with Policy.NSS true; no profile selected can set it")
	}
	for _, guest := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		if m, ok := p.Mounts[guest]; ok {
			t.Errorf("floor carries a mount at %s despite selecting no `nss` profile: %+v", guest, m)
		}
	}
	if _, err := Resolve(testRegistry(), nil, testCtx(), newFakeEnv()); err == nil {
		t.Fatal("control: the floor selection must still be refused by Validate")
	}
}

// TestNSSFilesOnlyWhenSelected is the other half: with @sys (which sets
// `nss = true`) all three exist; with no `nss` profile at all, a profile's own
// `ro = ["/etc/passwd"]` grant stays an ordinary bind rather than being
// silently upgraded into a generated file.
func TestNSSFilesOnlyWhenSelected(t *testing.T) {
	t.Run("no nss: a profile's own bind of /etc/passwd stays a bind", func(t *testing.T) {
		reg := testRegistry()
		reg["etcbind"] = &Profile{Name: "etcbind", RO: []string{"/etc/passwd", "/usr"}}
		p, err := Resolve(reg, []ProfileName{"etcbind", "@target-rw"}, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if p.NSS {
			t.Fatal("fixture: Policy.NSS is true, so this case does not test the `nss`-off arm at all")
		}
		m, ok := p.Mounts["/etc/passwd"]
		if !ok {
			t.Fatal("no mount at /etc/passwd at all")
		}
		if m.Kind != KindBind {
			t.Errorf("/etc/passwd: Kind = %v, want KindBind — a profile's own grant, untouched", m.Kind)
		}
		for _, guest := range []string{"/etc/group", "/etc/nsswitch.conf"} {
			if _, ok := p.Mounts[guest]; ok {
				t.Errorf("%s exists despite no selected profile setting `nss`", guest)
			}
		}
	})

	t.Run("with @sys: all three are generated", func(t *testing.T) {
		p, err := Resolve(testRegistry(), testDefaults, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !p.NSS {
			t.Fatal("fixture: @sys did not fold NSS true")
		}
		for _, guest := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
			m, ok := p.Mounts[guest]
			if !ok {
				t.Fatalf("no mount at %s", guest)
			}
			if m.Kind != KindData {
				t.Errorf("%s: Kind = %v, want KindData", guest, m.Kind)
			}
		}
	})
}

// TestUserProfileMayEnableNSS: a profile with only `nss = true`, no @sys at
// all, still gets all three generated files — Policy.NSS is a plain OR-fold,
// not a fact special-cased to @sys's own name.
func TestUserProfileMayEnableNSS(t *testing.T) {
	reg := testRegistry()
	reg["wantsnss"] = &Profile{Name: "wantsnss", NSS: true, RO: []string{"/usr"}}
	p, err := Resolve(reg, []ProfileName{"wantsnss", "@target-rw"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !p.NSS {
		t.Fatal("Policy.NSS is false despite a selected profile setting nss = true")
	}
	for _, guest := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		if m, ok := p.Mounts[guest]; !ok || m.Kind != KindData {
			t.Errorf("%s: got %+v (ok=%v), want a KindData mount", guest, m, ok)
		}
	}
}

// TestNSSJoinCommutes is the same property TestBwrapArgsAreOrderIndependent
// pins for the whole policy, narrowed to this one fold: Resolve([sys,x]) and
// Resolve([x,sys]) must carry an IDENTICAL mount set when x also sets nss,
// because p.NSS is an OR and OR commutes.
func TestNSSJoinCommutes(t *testing.T) {
	reg := testRegistry()
	reg["alsonss"] = &Profile{Name: "alsonss", NSS: true}
	a, err := Resolve(reg, []ProfileName{"@sys", "alsonss", "@target-rw"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve([@sys, alsonss]): %v", err)
	}
	b, err := Resolve(reg, []ProfileName{"alsonss", "@sys", "@target-rw"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve([alsonss, @sys]): %v", err)
	}
	for _, guest := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		ma, oka := a.Mounts[guest]
		mb, okb := b.Mounts[guest]
		if oka != okb || !reflect.DeepEqual(ma, mb) {
			t.Errorf("%s: order dependent — [@sys,alsonss]=%+v (ok=%v), [alsonss,@sys]=%+v (ok=%v)",
				guest, ma, oka, mb, okb)
		}
	}
}

// TestGeneratedNSSwitchContent pins the exact bytes: every db terminal on
// `files` succeeding (no [ACTION] token anywhere), `hosts` also carrying
// `myhostname` (the one module that answers `localhost` with no generated
// /etc/hosts), and `services`/`protocols`/`rpc`/`ethers` carrying `usrfiles`
// — the four databases glibc ships a second, /usr-rooted nss_files backend
// for, and the one gap a shorter version measurably left open (see
// generatedNsswitchConf's own doc comment).
func TestGeneratedNSSwitchContent(t *testing.T) {
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	m, ok := p.Mounts["/etc/nsswitch.conf"]
	if !ok {
		t.Fatal("no generated mount at /etc/nsswitch.conf")
	}
	want := "passwd:    files\n" +
		"group:     files\n" +
		"shadow:    files\n" +
		"gshadow:   files\n" +
		"hosts:     files myhostname dns\n" +
		"networks:  files dns\n" +
		"services:  files usrfiles\n" +
		"protocols: files usrfiles\n" +
		"rpc:       files usrfiles\n" +
		"ethers:    files usrfiles\n" +
		"netgroup:  files\n"
	if got := string(m.Content); got != want {
		t.Errorf("generated /etc/nsswitch.conf:\n--- got\n%s--- want\n%s", got, want)
	}
}

// TestHostAccountErrRefusesRegardlessOfNSS pins the refusal move: the cli's
// own getent lookup never refuses (main.go), so a failure reaches Resolve as
// ctx.HostAccountErr — and Resolve refuses on it unconditionally, because
// USER and LOGNAME need HostUserName on every run and there is no fallback
// name for either, `nss` or not.
func TestHostAccountErrRefusesRegardlessOfNSS(t *testing.T) {
	const lookupFailed = "getent passwd 1000: no entry (exit 2). Give 1000 an NSS entry"

	t.Run("no nss: the getent failure still refuses", func(t *testing.T) {
		reg := testRegistry()
		reg["usr"] = &Profile{Name: "usr", RO: []string{"/usr"}}
		ctx := testCtx()
		ctx.HostAccountErr = lookupFailed
		ctx.HostUserName, ctx.HostGroupName = "", ""
		p, err := Resolve(reg, []ProfileName{"usr", "@target-rw"}, ctx, newFakeEnv())
		if err == nil {
			t.Fatal("Resolve accepted a selection with no `nss` profile despite a recorded getent failure")
		}
		if err.Error() != lookupFailed {
			t.Errorf("error = %q, want the recorded HostAccountErr verbatim: %q", err.Error(), lookupFailed)
		}
		if p != nil {
			t.Fatal("fixture: expected a nil policy alongside the refusal")
		}
	})

	t.Run("with @sys: the getent failure is the refusal", func(t *testing.T) {
		ctx := testCtx()
		ctx.HostAccountErr = lookupFailed
		ctx.HostUserName, ctx.HostGroupName = "", ""
		_, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv())
		if err == nil {
			t.Fatal("Resolve accepted a selection with @sys despite a recorded getent failure")
		}
		if err.Error() != lookupFailed {
			t.Errorf("error = %q, want the recorded HostAccountErr verbatim: %q", err.Error(), lookupFailed)
		}
	})
}

// TestPasswdReplacesAProfileBindOfEtc: @sys sets `nss = true`, and a SECOND
// profile granting `ro = ["/etc"]` covers /etc/passwd, /etc/group and
// /etc/nsswitch.conf by ANCESTRY, at the map key "/etc" rather than at any of
// the three generated files' own keys, so Policy.Replace's own same-key
// displacement note never fires. passwdReplacesNote exists so the covering
// grant is still disclosed on --dry-run instead of silently losing the
// profile's claim to files it never named.
func TestPasswdReplacesAProfileBindOfEtc(t *testing.T) {
	reg := testRegistry()
	reg["etcbind"] = &Profile{Name: "etcbind", RO: []string{"/etc"}}
	p, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "etcbind"), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, guest := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf"} {
		m, ok := p.Mounts[guest]
		if !ok {
			t.Fatalf("no mount at %s", guest)
		}
		if m.Kind != KindData {
			t.Errorf("%s: Kind = %v, want KindData", guest, m.Kind)
		}
		from := strings.Join(m.From, "+")
		if !strings.Contains(from, "replaces:") || !strings.Contains(from, "etcbind") {
			t.Errorf("%s: From = %q, want a replaces: note naming etcbind", guest, from)
		}
	}
}

// TestPasswdFieldRefusals pins the format guard resolve.go runs before either
// generated file is authored: every field it writes must read back as the
// entry snug means, or a reader downstream (getent, ssh, git) parses it
// differently than snug intended.
func TestPasswdFieldRefusals(t *testing.T) {
	invalidUTF8 := string([]byte{0xff, 0xfe})
	cases := []struct {
		name    string
		mutate  func(*Context, *fakeEnv)
		wantErr bool
		want    string
	}{
		{"name contains ':'", func(c *Context, e *fakeEnv) { c.HostUserName = "a:b" }, true, "cannot appear in a passwd entry"},
		{"name contains a newline", func(c *Context, e *fakeEnv) { c.HostUserName = "a\nb" }, true, "cannot appear in a passwd entry"},
		{"name contains ESC", func(c *Context, e *fakeEnv) { c.HostUserName = "a\x1bb" }, true, "cannot appear in a passwd entry"},
		{"name begins with '+' (NIS)", func(c *Context, e *fakeEnv) { c.HostUserName = "+nis" }, true, "NIS directive"},
		{"name begins with '-' (NIS)", func(c *Context, e *fakeEnv) { c.HostUserName = "-x" }, true, "NIS directive"},
		{"name begins with '#' (NIS)", func(c *Context, e *fakeEnv) { c.HostUserName = "#x" }, true, "NIS directive"},
		{"name contains a space", func(c *Context, e *fakeEnv) { c.HostUserName = "a b" }, true, "whitespace"},
		{"name is invalid UTF-8", func(c *Context, e *fakeEnv) { c.HostUserName = invalidUTF8 }, true, "UTF-8"},
		{"name is empty", func(c *Context, e *fakeEnv) { c.HostUserName = "" }, true, "is empty"},
		{"gname contains ':'", func(c *Context, e *fakeEnv) { c.HostGroupName = "a:b" }, true, "cannot appear in a passwd entry"},
		{"gname is empty", func(c *Context, e *fakeEnv) { c.HostGroupName = "" }, true, "is empty"},
		{"home contains ':'", func(c *Context, e *fakeEnv) {
			c.Home = "/home/u:evil"
			e.dirs["/home/u:evil"] = true
		}, true, "cannot appear in a passwd entry"},
		{"shell contains ':'", func(c *Context, e *fakeEnv) { c.Shell = "/bin/sh:evil" }, true, "cannot appear in a passwd entry"},
		{"name with a domain resolves (no POSIX charset whitelist)", func(c *Context, e *fakeEnv) { c.HostUserName = "user@domain" }, false, ""},
		{"name with a dot resolves (no POSIX charset whitelist)", func(c *Context, e *fakeEnv) { c.HostUserName = "first.last" }, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testCtx()
			env := newFakeEnv()
			tc.mutate(&ctx, env)
			_, err := Resolve(testRegistry(), testDefaults, ctx, env)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Resolve accepted a field that cannot appear in a passwd entry")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error = %q, want it to contain %q", err.Error(), tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve refused a legitimate account name: %v", err)
			}
		})
	}
}
