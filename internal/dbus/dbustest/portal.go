// Package dbustest is a fake session bus with a fake desktop portal on it,
// for tests of the login bridge's portal opener. It speaks the wire protocol
// through package dbus, so it cannot catch a marshalling bug the client
// shares with it; that is what scripts/0037 against a real bus is for.
package dbustest

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomoni/snug/internal/dbus"
)

// Portal is a fake bus that answers Hello and AddMatch, and, when Absent is
// false, the desktop portal's OpenURI version property and OpenURI itself.
type Portal struct {
	// Addr is the DBUS_SESSION_BUS_ADDRESS value naming the socket.
	Addr string
	// Absent answers every portal call with ServiceUnknown, as a bus with
	// no portal on it does.
	Absent bool
	// Version is OpenURI's version property.
	Version uint32
	// Response is the code the Request's Response signal carries: 0
	// success, 1 dismissed, 2 other.
	Response uint32
	// Hold answers OpenURI but never sends the Response, as a portal whose
	// dialog nobody answers.
	Hold bool
	// OnOpen is called with each URL OpenURI receives, before the reply.
	OnOpen func(url string)

	ln *net.UnixListener
	mu sync.Mutex
	// URLs is every URL OpenURI received, in order.
	urls []string
}

// Listen starts p on a socket in dir and serves until Close.
func (p *Portal) Listen(dir string) error {
	path := filepath.Join(dir, "bus")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		return err
	}
	p.ln = ln
	p.Addr = "unix:path=" + path + ",guid=0123456789abcdef0123456789abcdef"
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return nil
}

// Close stops listening.
func (p *Portal) Close() error { return p.ln.Close() }

// URLs returns every URL OpenURI received.
func (p *Portal) URLs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.urls...)
}

func (p *Portal) serve(c *net.UnixConn) {
	defer c.Close()
	r := bufio.NewReader(c)
	if b, err := r.ReadByte(); err != nil || b != 0 {
		return
	}
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "AUTH EXTERNAL ") {
		c.Write([]byte("REJECTED EXTERNAL\r\n"))
		return
	}
	c.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n"))
	if line, err = r.ReadString('\n'); err != nil || line != "BEGIN\r\n" {
		return
	}
	const name = ":1.42"
	var serial uint32
	send := func(m dbus.Message) {
		serial++
		m.Serial = serial
		b, err := m.Marshal()
		if err == nil {
			c.Write(b)
		}
	}
	reply := func(call *dbus.Message, sig string, body func(*dbus.Encoder)) {
		var e dbus.Encoder
		if body != nil {
			body(&e)
		}
		b, _ := e.Bytes()
		send(dbus.Message{Type: dbus.TypeMethodReturn, ReplySerial: call.Serial,
			Destination: name, Sender: "org.freedesktop.DBus", Signature: sig, Body: b})
	}
	fail := func(call *dbus.Message, errName, msg string) {
		var e dbus.Encoder
		e.String(msg)
		b, _ := e.Bytes()
		send(dbus.Message{Type: dbus.TypeError, ReplySerial: call.Serial, ErrorName: errName,
			Destination: name, Signature: "s", Body: b})
	}
	for {
		m, err := dbus.ReadMessage(r)
		if err != nil {
			return
		}
		if m.Type != dbus.TypeMethodCall {
			continue
		}
		switch {
		case m.Member == "Hello":
			reply(m, "s", func(e *dbus.Encoder) { e.String(name) })
		case m.Member == "AddMatch":
			reply(m, "", nil)
		case p.Absent:
			fail(m, "org.freedesktop.DBus.Error.ServiceUnknown",
				"The name "+m.Destination+" was not provided by any .service files")
		case m.Interface == "org.freedesktop.DBus.Properties" && m.Member == "Get":
			reply(m, "v", func(e *dbus.Encoder) {
				e.Signature("u")
				e.Uint32(p.Version)
			})
		case m.Interface == "org.freedesktop.portal.OpenURI" && m.Member == "OpenURI":
			d := dbus.NewDecoder(m)
			_ = d.String() // parent_window
			u := d.String()
			opts := d.VariantDict()
			if d.Err() != nil {
				fail(m, "org.freedesktop.DBus.Error.InvalidArgs", d.Err().Error())
				continue
			}
			tok, _ := opts["handle_token"].(string)
			handle := "/org/freedesktop/portal/desktop/request/1_42/" + tok
			p.mu.Lock()
			p.urls = append(p.urls, u)
			p.mu.Unlock()
			if p.OnOpen != nil {
				p.OnOpen(u)
			}
			reply(m, "o", func(e *dbus.Encoder) { e.ObjectPath(handle) })
			if !p.Hold {
				var e dbus.Encoder
				e.Uint32(p.Response)
				e.StringVariantDict(nil)
				b, _ := e.Bytes()
				send(dbus.Message{Type: dbus.TypeSignal, Path: handle,
					Interface: "org.freedesktop.portal.Request", Member: "Response",
					Destination: name, Sender: ":1.7", Signature: "ua{sv}", Body: b})
			}
		default:
			fail(m, "org.freedesktop.DBus.Error.UnknownMethod", m.Interface+"."+m.Member)
		}
	}
}
