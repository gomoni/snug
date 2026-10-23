package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// fakeGPGConfHost puts a gpgconf and a gpg on an otherwise empty PATH that
// answer for a host whose homedir and sysconfdir are temporary directories,
// and returns those two. Both start empty, so what the probe finds does not
// depend on the machine running the suite. gpgconf prints sysconfdir before homedir, as the real
// one does whatever order it is asked in.
func fakeGPGConfHost(t *testing.T, version string) (home, sys string) {
	t.Helper()
	bin, home, sys := t.TempDir(), t.TempDir(), t.TempDir()
	scripts := map[string]string{
		"gpgconf": "#!/bin/sh\nprintf 'sysconfdir:%s\\nbindir:/usr/bin\\nhomedir:%s\\n' '" + sys + "' '" + home + "'\n",
		// Only --version answers; an export or a key listing fails, as on a
		// host whose gpg does not know the key.
		"gpg": "#!/bin/sh\nfor a; do [ \"$a\" = --version ] && printf 'gpg (GnuPG) " + version +
			"\\nlibgcrypt 1.12.4\\n' && exit 0; done\nexit 2\n",
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	return home, sys
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestGPGUserConfNamesIsGPGsOrder: the full version first, then one component
// shorter at a time, then the bare name — the order measured on gpg 2.5.24.
func TestGPGUserConfNamesIsGPGsOrder(t *testing.T) {
	got := gpgUserConfNames("2.5.24")
	want := []string{"gpg.conf-2.5.24", "gpg.conf-2.5", "gpg.conf-2", "gpg.conf"}
	if !slices.Equal(got, want) {
		t.Errorf("gpgUserConfNames(2.5.24) = %q, want %q", got, want)
	}
}

func TestParseGPGVersion(t *testing.T) {
	if v, err := parseGPGVersion("gpg (GnuPG) 2.5.24\nlibgcrypt 1.12.4\n"); err != nil || v != "2.5.24" {
		t.Errorf("parseGPGVersion = %q, %v", v, err)
	}
	if v, err := parseGPGVersion("gpg (GnuPG/MacGPG2) 2.2.41\n"); err != nil || v != "2.2.41" {
		t.Errorf("parseGPGVersion of a vendor build = %q, %v", v, err)
	}
	for _, bad := range []string{"", "gpg (GnuPG) 2.5.24-beta3\n", "gpg (GnuPG) ../x\n", "sq 1.0\n"} {
		if v, err := parseGPGVersion(bad); err == nil {
			t.Errorf("parseGPGVersion(%q) = %q, want a refusal", bad, v)
		}
	}
}

// TestProbeGPGConfReadsTheFileGPGReads: with both gpg.conf-2.5 and gpg.conf in
// the homedir, the probe takes gpg.conf-2.5 as gpg does, and reads the system
// file from the sysconfdir gpgconf names.
func TestProbeGPGConfReadsTheFileGPGReads(t *testing.T) {
	home, sys := fakeGPGConfHost(t, "2.5.24")
	write(t, filepath.Join(home, "gpg.conf"), "digest-algo SHA224\n")
	write(t, filepath.Join(home, "gpg.conf-2.5"), "digest-algo SHA256\n")
	write(t, filepath.Join(home, "gpg.conf-2.4"), "digest-algo MD5\n")
	write(t, filepath.Join(sys, "gpg.conf"), "[force]\ncompliance gnupg\n")
	f, err := probeGPGConf()
	if err != nil {
		t.Fatal(err)
	}
	if f.userPath != filepath.Join(home, "gpg.conf-2.5") || string(f.user) != "digest-algo SHA256\n" {
		t.Errorf("user file = %s %q, want gpg.conf-2.5", f.userPath, f.user)
	}
	if f.systemPath != filepath.Join(sys, "gpg.conf") || !strings.Contains(string(f.system), "[force]") {
		t.Errorf("system file = %s %q", f.systemPath, f.system)
	}
}

// TestProbeGPGConfAbsentFilesAreNotAnError: a host with no gpg.conf anywhere
// probes cleanly, and staging still writes the user file (empty of options)
// and no system file.
func TestProbeGPGConfAbsentFilesAreNotAnError(t *testing.T) {
	_, sys := fakeGPGConfHost(t, "2.5.24")
	f, err := probeGPGConf()
	if err != nil {
		t.Fatal(err)
	}
	if f.user != nil || f.system != nil || f.userPath != "" || f.systemPath != "" {
		t.Errorf("absent files probed as %+v", f)
	}
	pol := &policy.Policy{Mounts: map[string]policy.Mount{}, Home: "/home/u"}
	if err := stageGPGConf(pol, f); err != nil {
		t.Fatal(err)
	}
	if _, ok := pol.Mounts["/home/u/"+policy.GPGConfGuest]; !ok {
		t.Error("no user gpg.conf staged on a host with none")
	}
	if _, ok := pol.Mounts[filepath.Join(sys, "gpg.conf")]; ok {
		t.Error("a system gpg.conf was staged on a host with none")
	}
}

// TestProbeGPGConfRefusesAnUnreadableFile: gpg itself skips a gpg.conf it
// cannot read; snug refuses, naming the file, rather than run the sandbox on
// defaults the file may have tightened.
func TestProbeGPGConfRefusesAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	home, _ := fakeGPGConfHost(t, "2.5.24")
	p := filepath.Join(home, "gpg.conf")
	write(t, p, "digest-algo SHA256\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := probeGPGConf(); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("an unreadable %s probed as %v", p, err)
	}
}

// TestProbeGPGConfRefusesAFailedProbe: a gpgconf that fails, or prints no
// usable homedir, refuses rather than probing nothing.
func TestProbeGPGConfRefusesAFailedProbe(t *testing.T) {
	for name, body := range map[string]string{
		"exits non-zero":   "#!/bin/sh\nexit 2\n",
		"no homedir":       "#!/bin/sh\nprintf 'sysconfdir:/etc/gnupg\\n'\n",
		"relative homedir": "#!/bin/sh\nprintf 'sysconfdir:/etc/gnupg\\nhomedir:gnupg\\n'\n",
		"escaped homedir":  "#!/bin/sh\nprintf 'sysconfdir:/etc/gnupg\\nhomedir:/h/a%%3ab\\n'\n",
	} {
		t.Run(name, func(t *testing.T) {
			fakeGPGConfHost(t, "2.5.24")
			if err := os.WriteFile(filepath.Join(os.Getenv("PATH"), "gpgconf"), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := probeGPGConf(); err == nil || !strings.Contains(err.Error(), "gpgconf --list-dirs") {
				t.Errorf("probe = %v, want a refusal naming gpgconf --list-dirs", err)
			}
		})
	}
	t.Run("no gpgconf", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := probeGPGConf(); err == nil || !strings.Contains(err.Error(), "no gpgconf is on PATH") {
			t.Errorf("probe without gpgconf = %v", err)
		}
	})
}

// TestStageGPGConfMountsBothFilesGenerated: the system file lands at the
// host's sysconfdir path and the user file in the sandbox's GNUPGHOME, both
// read-only, both generated, and neither carrying a non-allowlisted line.
func TestStageGPGConfMountsBothFilesGenerated(t *testing.T) {
	f := gpgConfFiles{
		system: []byte("[force]\nweak-digest SHA224\nkeyserver hkps://x\n"), systemPath: "/etc/gnupg/gpg.conf",
		user: []byte("exec-path /tmp\npersonal-digest-preferences SHA256\n"), userPath: "/h/.gnupg/gpg.conf",
	}
	pol := &policy.Policy{Mounts: map[string]policy.Mount{}, Home: "/home/u"}
	if err := stageGPGConf(pol, f); err != nil {
		t.Fatal(err)
	}
	for guest, want := range map[string]string{
		"/etc/gnupg/gpg.conf":            "[force]\nweak-digest SHA224\n",
		"/home/u/" + policy.GPGConfGuest: "\npersonal-digest-preferences SHA256\n",
	} {
		m, ok := pol.Mounts[guest]
		if !ok {
			t.Errorf("%s not staged", guest)
			continue
		}
		if m.Kind != policy.KindData || m.Access != policy.AccessRO || !m.Authored {
			t.Errorf("%s staged as kind %v access %v authored %v", guest, m.Kind, m.Access, m.Authored)
		}
		c := string(m.Content)
		if !strings.HasSuffix(c, want) || strings.Contains(c, "\nkeyserver") || strings.Contains(c, "\nexec-path") {
			t.Errorf("%s content:\n%s", guest, c)
		}
	}
}

// TestStageGPGConfRefusesAnUncarriableLine: one allowlisted line snug cannot
// render refuses the run, and stages nothing.
func TestStageGPGConfRefusesAnUncarriableLine(t *testing.T) {
	f := gpgConfFiles{user: []byte("digest-algo \"SHA256\n"), userPath: "/h/.gnupg/gpg.conf"}
	pol := &policy.Policy{Mounts: map[string]policy.Mount{}, Home: "/home/u"}
	err := stageGPGConf(pol, f)
	if err == nil || !strings.Contains(err.Error(), "/h/.gnupg/gpg.conf:1") {
		t.Fatalf("stageGPGConf = %v, want a refusal naming /h/.gnupg/gpg.conf:1", err)
	}
	if len(pol.Mounts) != 0 {
		t.Errorf("a refused stage left mounts: %v", pol.Mounts)
	}
}

// TestProbeGPGConfRefusesAFIFO: a FIFO where gpg.conf goes is refused, not
// opened — an open(2) of a FIFO with no writer never returns.
func TestProbeGPGConfRefusesAFIFO(t *testing.T) {
	home, _ := fakeGPGConfHost(t, "2.5.24")
	p := filepath.Join(home, "gpg.conf")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := probeGPGConf(); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("a FIFO at %s probed as %v", p, err)
	}
}

// TestStageGPGConfRefusesBesideAProfileStub: a profile's own grant at
// ~/.gnupg/gpg.conf and a generated file are two authors for one path, so
// staging refuses, naming both, when the host's user file carries anything —
// never displacing the stub. With nothing carried the stub stays as the only
// author and no user file is generated (control). A grant at a versioned
// name is refused whatever the host sets: gpg would read it instead.
func TestStageGPGConfRefusesBesideAProfileStub(t *testing.T) {
	stubbed := func(guest string) *policy.Policy {
		return &policy.Policy{Home: "/home/u", Mounts: map[string]policy.Mount{
			guest: {Guest: guest, Host: "/x/stub", Kind: policy.KindBind, Access: policy.AccessRO,
				From: []string{"gpg-stub"}},
		}}
	}
	userGuest := "/home/u/" + policy.GPGConfGuest
	carrying := gpgConfFiles{user: []byte("digest-algo SHA256\n"), userPath: "/h/.gnupg/gpg.conf"}

	pol := stubbed(userGuest)
	err := stageGPGConf(pol, carrying)
	if err == nil || !strings.Contains(err.Error(), "gpg-stub") || !strings.Contains(err.Error(), "/h/.gnupg/gpg.conf") {
		t.Fatalf("stageGPGConf beside a stub = %v, want a refusal naming the stub and the host file", err)
	}
	if pol.Mounts[userGuest].Kind != policy.KindBind {
		t.Error("the refused stage displaced the stub")
	}

	pol = stubbed(userGuest)
	if err := stageGPGConf(pol, gpgConfFiles{user: []byte("keyserver hkps://x\n"), userPath: "/h/.gnupg/gpg.conf"}); err != nil {
		t.Fatalf("nothing carried, yet: %v", err)
	}
	if m := pol.Mounts[userGuest]; m.Kind != policy.KindBind || m.Authored {
		t.Errorf("with nothing carried the stub must stay, got %+v", m)
	}

	versioned := userGuest + "-2.5"
	pol = stubbed(versioned)
	if err := stageGPGConf(pol, gpgConfFiles{}); err == nil || !strings.Contains(err.Error(), versioned) {
		t.Errorf("a grant at %s = %v, want a refusal naming it", versioned, err)
	}
}
