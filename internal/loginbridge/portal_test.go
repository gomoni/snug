package loginbridge

import (
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/dbus/dbustest"
)

func fakePortal(t *testing.T, p *dbustest.Portal) *dbustest.Portal {
	t.Helper()
	if err := p.Listen(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestPortalVersionAnswersAndNamesWhyNot(t *testing.T) {
	p := fakePortal(t, &dbustest.Portal{Version: 5})
	v, err := PortalVersion(p.Addr)
	if err != nil || v != 5 {
		t.Fatalf("portal present: %d %v", v, err)
	}
	absent := fakePortal(t, &dbustest.Portal{Absent: true})
	if _, err := PortalVersion(absent.Addr); err == nil || !strings.Contains(err.Error(), "ServiceUnknown") {
		t.Fatalf("no portal on the bus: %v", err)
	}
	for addr, want := range map[string]string{
		"":                           "not set",
		"tcp:host=localhost,port=1":  "no unix:path=",
		"unix:path=/nonexistent/bus": "could not connect",
	} {
		if _, err := PortalVersion(addr); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", addr, err, want)
		}
	}
}

func TestPortalOpenerSendsTheURLAndReadsTheResponse(t *testing.T) {
	const u = "https://claude.com/cai/oauth/authorize?code=true&state=x"
	p := fakePortal(t, &dbustest.Portal{Version: 5})
	if err := (PortalOpener{Addr: p.Addr, Patience: 5 * time.Second}).Open(u); err != nil {
		t.Fatal(err)
	}
	if got := p.URLs(); len(got) != 1 || got[0] != u {
		t.Fatalf("portal received %q, want exactly %q", got, u)
	}

	dismissed := fakePortal(t, &dbustest.Portal{Version: 5, Response: 1})
	err := PortalOpener{Addr: dismissed.Addr, Patience: 5 * time.Second}.Open(u)
	if err == nil || !strings.Contains(err.Error(), "dismissed") {
		t.Fatalf("response 1: %v", err)
	}
	other := fakePortal(t, &dbustest.Portal{Version: 5, Response: 2})
	err = PortalOpener{Addr: other.Addr, Patience: 5 * time.Second}.Open(u)
	if err == nil || !strings.Contains(err.Error(), "response 2") {
		t.Fatalf("response 2: %v", err)
	}
	absent := fakePortal(t, &dbustest.Portal{Absent: true})
	err = PortalOpener{Addr: absent.Addr, Patience: 5 * time.Second}.Open(u)
	if err == nil || !strings.Contains(err.Error(), "refused OpenURI") {
		t.Fatalf("portal gone after preflight: %v", err)
	}
}

// A portal dialog nobody answers is not a failure: Open returns after
// Patience, as for an xdg-open still running.
func TestPortalOpenerReturnsAfterPatienceWhenNoResponse(t *testing.T) {
	p := fakePortal(t, &dbustest.Portal{Version: 5, Hold: true})
	start := time.Now()
	if err := (PortalOpener{Addr: p.Addr, Patience: 200 * time.Millisecond}).Open("https://claude.com/x"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Open took %s with a 200ms patience", d)
	}
}

// The URL is a D-Bus string: one with NUL is refused before anything is
// sent, never truncated at the NUL.
func TestPortalOpenerRefusesAURLWithNUL(t *testing.T) {
	p := fakePortal(t, &dbustest.Portal{Version: 5})
	err := PortalOpener{Addr: p.Addr, Patience: time.Second}.Open("https://claude.com/\x00https://evil.example/")
	if err == nil || len(p.URLs()) != 0 {
		t.Fatalf("err=%v urls=%q", err, p.URLs())
	}
}
