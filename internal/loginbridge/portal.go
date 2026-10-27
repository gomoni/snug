package loginbridge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/dbus"
)

const (
	portalDest      = "org.freedesktop.portal.Desktop"
	portalPath      = "/org/freedesktop/portal/desktop"
	portalOpenURI   = "org.freedesktop.portal.OpenURI"
	portalRequest   = "org.freedesktop.portal.Request"
	portalReqPrefix = portalPath + "/request/"
)

// PortalProbeTimeout bounds the preflight's question to the portal. It is
// xdg-open's own: xdg-utils 1.2.0 calls OpenURI with `gdbus call --timeout 5`
// in the flatpak and toolbx branches. The portal is D-Bus activatable, so the
// first question may start it.
const PortalProbeTimeout = 5 * time.Second

// PortalVersion asks the desktop portal on the session bus at addr (a
// DBUS_SESSION_BUS_ADDRESS value) for its OpenURI interface version. A non-nil
// error is the reason the portal cannot open a URL for this run: no address,
// no unix socket in it, a bus that refused the connection or uid, no portal
// on the bus, a portal without OpenURI, or no answer within
// PortalProbeTimeout.
func PortalVersion(addr string) (uint32, error) {
	c, err := dbus.Dial(addr, os.Getuid(), time.Now().Add(PortalProbeTimeout))
	if err != nil {
		return 0, err
	}
	defer c.Close()
	var e dbus.Encoder
	e.String(portalOpenURI)
	e.String("version")
	body, err := e.Bytes()
	if err != nil {
		return 0, err
	}
	r, err := c.Call(dbus.Message{
		Type:        dbus.TypeMethodCall,
		Path:        portalPath,
		Interface:   "org.freedesktop.DBus.Properties",
		Member:      "Get",
		Destination: portalDest,
		Signature:   "ss",
		Body:        body,
	})
	if err != nil {
		return 0, err
	}
	d := dbus.NewDecoder(r)
	v := d.Variant()
	if d.Err() != nil {
		return 0, d.Err()
	}
	n, ok := v.(uint32)
	if !ok {
		return 0, fmt.Errorf("the portal's %s version is %T, not a uint32", portalOpenURI, v)
	}
	return n, nil
}

// PortalOpener opens a URL with the desktop portal's OpenURI. No host program
// runs in snug's process tree: the portal starts the user's default browser
// in the desktop session, with the session's environment rather than snug's.
type PortalOpener struct {
	// Addr is the session bus address the preflight probed.
	Addr string
	// Patience is how long Open waits for the portal's Response; zero means
	// OpenerPatience.
	Patience time.Duration
}

// Open asks the portal to open url and waits up to Patience for the
// request's Response. It returns an error when the bus or the call fails,
// or when the Response is not success: 1 is the user dismissing the portal's
// own dialog, 2 anything else. A Response still pending after Patience — a
// portal dialog nobody has answered — is left to a goroutine that waits for
// it while snug lives, and Open returns nil, as for an xdg-open still running.
func (o PortalOpener) Open(url string) error {
	patience := o.Patience
	if patience == 0 {
		patience = OpenerPatience
	}
	c, err := dbus.Dial(o.Addr, os.Getuid(), time.Now().Add(patience))
	if err != nil {
		return fmt.Errorf("the desktop portal could not be reached: %v", err)
	}
	var tok [8]byte
	rand.Read(tok[:])
	token := "snug" + hex.EncodeToString(tok[:])
	// The handle the portal will use, subscribed to before the call so the
	// Response cannot arrive unmatched (the portal's documented handle_token
	// scheme). A portal that returns a different handle is matched by it too.
	sender := strings.ReplaceAll(strings.TrimPrefix(c.Name, ":"), ".", "_")
	want := portalReqPrefix + sender + "/" + token
	if err := addResponseMatch(c, want); err != nil {
		c.Close()
		return err
	}
	var e dbus.Encoder
	e.String("")
	e.String(url)
	e.StringVariantDict([][2]string{{"handle_token", token}})
	body, err := e.Bytes()
	if err != nil {
		c.Close()
		return err
	}
	r, err := c.Call(dbus.Message{
		Type:        dbus.TypeMethodCall,
		Path:        portalPath,
		Interface:   portalOpenURI,
		Member:      "OpenURI",
		Destination: portalDest,
		Signature:   "ssa{sv}",
		Body:        body,
	})
	if err != nil {
		c.Close()
		return fmt.Errorf("the desktop portal refused OpenURI: %v", err)
	}
	d := dbus.NewDecoder(r)
	handle := d.String()
	if d.Err() != nil {
		c.Close()
		return d.Err()
	}
	if handle != want {
		if err := addResponseMatch(c, handle); err != nil {
			c.Close()
			return err
		}
	}
	type result struct {
		code uint32
		err  error
	}
	// Patience alone decides when Open stops waiting: a connection deadline
	// at the same instant would race it and turn a pending dialog into an
	// error. Past Patience the goroutine keeps the request's connection until
	// the portal answers, since a caller vanishing from the bus may cancel a
	// dialog the user is still looking at.
	c.SetDeadline(time.Time{})
	done := make(chan result, 1)
	go func() {
		defer c.Close()
		s, err := c.WaitSignal(func(m *dbus.Message) bool {
			return m.Path == handle && m.Interface == portalRequest && m.Member == "Response"
		})
		if err != nil {
			done <- result{err: err}
			return
		}
		d := dbus.NewDecoder(s)
		code := d.Uint32()
		done <- result{code: code, err: d.Err()}
	}()
	select {
	case res := <-done:
		switch {
		case res.err != nil:
			return fmt.Errorf("the desktop portal never answered the OpenURI request: %v", res.err)
		case res.code == 0:
			return nil
		case res.code == 1:
			return fmt.Errorf("the desktop portal's dialog was dismissed; nothing was opened")
		default:
			return fmt.Errorf("the desktop portal could not open the URL (response %d)", res.code)
		}
	case <-time.After(patience):
		return nil
	}
}

func addResponseMatch(c *dbus.Conn, path string) error {
	var e dbus.Encoder
	e.String("type='signal',sender='" + portalDest + "',interface='" + portalRequest +
		"',member='Response',path='" + path + "'")
	body, err := e.Bytes()
	if err != nil {
		return err
	}
	_, err = c.Call(dbus.Message{
		Type:        dbus.TypeMethodCall,
		Path:        "/org/freedesktop/DBus",
		Interface:   "org.freedesktop.DBus",
		Member:      "AddMatch",
		Destination: "org.freedesktop.DBus",
		Signature:   "s",
		Body:        body,
	})
	if err != nil {
		return fmt.Errorf("the session bus refused a signal match for the portal's answer: %v", err)
	}
	return nil
}
