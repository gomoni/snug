// Package dbus is the smallest D-Bus client snug needs: connect to a session
// bus over a unix socket, authenticate with SASL EXTERNAL, call a method and
// read a signal. It exists so the login bridge can ask the desktop portal to
// open a URL without executing a host program, and without a third
// dependency in go.mod.
//
// Only the wire types the portal calls use are encoded and decoded: y, u, s,
// o, g, v and a{sv}. Anything else in a body the caller reads is an error,
// never a guess.
package dbus

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Message types.
const (
	TypeMethodCall   = 1
	TypeMethodReturn = 2
	TypeError        = 3
	TypeSignal       = 4
)

// Header field codes.
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSender      = 7
	fieldSignature   = 8
	fieldUnixFDs     = 9
)

// maxQueued bounds the signals Call keeps while it waits for a reply. A
// client that subscribed to one Response receives that and the bus's own
// NameAcquired; a peer sending more is flooding, and without the bound each
// one is up to maxMessage held until the deadline.
const maxQueued = 16

// maxMessage bounds what ReadMessage accepts. The protocol allows 128 MiB;
// nothing the portal or the bus daemon sends to snug comes near 1 MiB, and
// a peer announcing more is not one snug is talking to on purpose.
const maxMessage = 1 << 20

// Message is one D-Bus message. Body is the marshalled body, aligned from its
// own start: a message's body begins on an 8-byte boundary, so alignment
// relative to the body is alignment relative to the message.
type Message struct {
	Type        byte
	Flags       byte
	Serial      uint32
	ReplySerial uint32
	Path        string
	Interface   string
	Member      string
	ErrorName   string
	Destination string
	Sender      string
	Signature   string
	UnixFDs     uint32
	Body        []byte
	// order is the byte order the message arrived in; Decoder reads Body
	// with it.
	order binary.ByteOrder
}

// Encoder marshals values in little-endian D-Bus wire format.
type Encoder struct {
	b   []byte
	err error
}

// Bytes returns what was encoded, or the first error: a string that is not
// valid UTF-8 or contains NUL, which the protocol forbids.
func (e *Encoder) Bytes() ([]byte, error) { return e.b, e.err }

func (e *Encoder) align(n int) {
	for len(e.b)%n != 0 {
		e.b = append(e.b, 0)
	}
}

// Byte encodes y.
func (e *Encoder) Byte(v byte) { e.b = append(e.b, v) }

// Uint32 encodes u.
func (e *Encoder) Uint32(v uint32) {
	e.align(4)
	e.b = binary.LittleEndian.AppendUint32(e.b, v)
}

func (e *Encoder) checkString(s string) {
	if e.err == nil && (!utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0) {
		e.err = fmt.Errorf("D-Bus string %q is not valid UTF-8 or contains NUL", s)
	}
}

// String encodes s; ObjectPath encodes o, which has the same wire form.
func (e *Encoder) String(s string) {
	e.checkString(s)
	e.Uint32(uint32(len(s)))
	e.b = append(e.b, s...)
	e.b = append(e.b, 0)
}

// ObjectPath encodes o.
func (e *Encoder) ObjectPath(s string) { e.String(s) }

// Signature encodes g.
func (e *Encoder) Signature(s string) {
	e.checkString(s)
	if len(s) > 255 {
		e.err = fmt.Errorf("D-Bus signature %q is longer than 255 bytes", s)
		return
	}
	e.b = append(e.b, byte(len(s)))
	e.b = append(e.b, s...)
	e.b = append(e.b, 0)
}

// StringVariantDict encodes a{sv} whose every value is a string.
func (e *Encoder) StringVariantDict(m [][2]string) {
	e.Uint32(0)
	at := len(e.b) - 4
	e.align(8)
	start := len(e.b)
	for _, kv := range m {
		e.align(8)
		e.String(kv[0])
		e.Signature("s")
		e.String(kv[1])
	}
	// The array length counts the elements, not the padding before the
	// first one.
	binary.LittleEndian.PutUint32(e.b[at:], uint32(len(e.b)-start))
}

// Marshal returns m's wire form. Body must already be little-endian, as
// Encoder writes it.
func (m *Message) Marshal() ([]byte, error) {
	var e Encoder
	e.Byte('l')
	e.Byte(m.Type)
	e.Byte(m.Flags)
	e.Byte(1)
	e.Uint32(uint32(len(m.Body)))
	e.Uint32(m.Serial)
	e.Uint32(0)
	at := len(e.b) - 4
	fields := func(code byte, sig string, put func()) {
		e.align(8)
		e.Byte(code)
		e.Signature(sig)
		put()
	}
	str := func(code byte, sig, v string) {
		if v != "" {
			fields(code, sig, func() {
				if sig == "g" {
					e.Signature(v)
				} else {
					e.String(v)
				}
			})
		}
	}
	str(fieldPath, "o", m.Path)
	str(fieldInterface, "s", m.Interface)
	str(fieldMember, "s", m.Member)
	str(fieldErrorName, "s", m.ErrorName)
	if m.ReplySerial != 0 {
		fields(fieldReplySerial, "u", func() { e.Uint32(m.ReplySerial) })
	}
	str(fieldDestination, "s", m.Destination)
	str(fieldSender, "s", m.Sender)
	str(fieldSignature, "g", m.Signature)
	binary.LittleEndian.PutUint32(e.b[at:], uint32(len(e.b)-at-4))
	e.align(8)
	e.b = append(e.b, m.Body...)
	return e.Bytes()
}

// Decoder reads values from a message body.
type Decoder struct {
	b     []byte
	off   int
	order binary.ByteOrder
	err   error
}

// NewDecoder reads m's body in the byte order m arrived in.
func NewDecoder(m *Message) *Decoder {
	o := m.order
	if o == nil {
		o = binary.LittleEndian
	}
	return &Decoder{b: m.Body, order: o}
}

// Err is the first decoding error: a value running past the end of the body,
// a string that is not NUL-terminated, or a variant of a type this package
// does not decode.
func (d *Decoder) Err() error { return d.err }

func (d *Decoder) fail(format string, a ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("malformed D-Bus message: "+format, a...)
	}
}

func (d *Decoder) align(n int) {
	for d.off%n != 0 {
		d.off++
	}
}

func (d *Decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || d.off+n > len(d.b) {
		d.fail("%d bytes wanted at offset %d of %d", n, d.off, len(d.b))
		return nil
	}
	s := d.b[d.off : d.off+n]
	d.off += n
	return s
}

// Byte decodes y.
func (d *Decoder) Byte() byte {
	s := d.take(1)
	if s == nil {
		return 0
	}
	return s[0]
}

// Uint32 decodes u.
func (d *Decoder) Uint32() uint32 {
	d.align(4)
	s := d.take(4)
	if s == nil {
		return 0
	}
	return d.order.Uint32(s)
}

func (d *Decoder) terminated(n int) string {
	s := d.take(n + 1)
	if s == nil {
		return ""
	}
	if s[n] != 0 {
		d.fail("string at offset %d is not NUL-terminated", d.off-n-1)
		return ""
	}
	return string(s[:n])
}

// String decodes s or o.
func (d *Decoder) String() string {
	n := d.Uint32()
	if n > maxMessage {
		d.fail("string length %d", n)
		return ""
	}
	return d.terminated(int(n))
}

// Signature decodes g.
func (d *Decoder) Signature() string { return d.terminated(int(d.Byte())) }

// Variant decodes v holding y, u, s, o or g; the value is a byte, uint32 or
// string.
func (d *Decoder) Variant() any {
	switch sig := d.Signature(); sig {
	case "y":
		return d.Byte()
	case "u":
		return d.Uint32()
	case "s", "o":
		return d.String()
	case "g":
		return d.Signature()
	default:
		d.fail("variant of type %q", sig)
		return nil
	}
}

// VariantDict decodes a{sv} whose values Variant decodes.
func (d *Decoder) VariantDict() map[string]any {
	n := d.Uint32()
	d.align(8)
	end := d.off + int(n)
	if n > maxMessage || end > len(d.b) {
		d.fail("array of %d bytes at offset %d of %d", n, d.off, len(d.b))
		return nil
	}
	m := map[string]any{}
	for d.err == nil && d.off < end {
		d.align(8)
		k := d.String()
		m[k] = d.Variant()
	}
	return m
}

// ReadMessage reads one message from r.
func ReadMessage(r *bufio.Reader) (*Message, error) {
	fixed := make([]byte, 16)
	if _, err := readFull(r, fixed); err != nil {
		return nil, err
	}
	m := &Message{Type: fixed[1], Flags: fixed[2]}
	switch fixed[0] {
	case 'l':
		m.order = binary.LittleEndian
	case 'B':
		m.order = binary.BigEndian
	default:
		return nil, fmt.Errorf("malformed D-Bus message: endianness byte %q", fixed[0])
	}
	if fixed[3] != 1 {
		return nil, fmt.Errorf("malformed D-Bus message: protocol version %d", fixed[3])
	}
	bodyLen := m.order.Uint32(fixed[4:])
	m.Serial = m.order.Uint32(fixed[8:])
	fieldsLen := m.order.Uint32(fixed[12:])
	if bodyLen > maxMessage || fieldsLen > maxMessage {
		return nil, fmt.Errorf("D-Bus message of %d+%d bytes is over snug's %d-byte bound", fieldsLen, bodyLen, maxMessage)
	}
	pad := (8 - (16+int(fieldsLen))%8) % 8
	rest := make([]byte, int(fieldsLen)+pad+int(bodyLen))
	if _, err := readFull(r, rest); err != nil {
		return nil, err
	}
	// The field array starts at offset 16, a multiple of 8, so alignment
	// within it matches the message's own.
	d := &Decoder{b: rest[:fieldsLen], order: m.order}
	for d.err == nil && d.off < len(d.b) {
		d.align(8)
		code := d.Byte()
		v := d.Variant()
		switch code {
		case fieldPath:
			m.Path, _ = v.(string)
		case fieldInterface:
			m.Interface, _ = v.(string)
		case fieldMember:
			m.Member, _ = v.(string)
		case fieldErrorName:
			m.ErrorName, _ = v.(string)
		case fieldReplySerial:
			m.ReplySerial, _ = v.(uint32)
		case fieldDestination:
			m.Destination, _ = v.(string)
		case fieldSender:
			m.Sender, _ = v.(string)
		case fieldSignature:
			m.Signature, _ = v.(string)
		case fieldUnixFDs:
			m.UnixFDs, _ = v.(uint32)
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	m.Body = rest[int(fieldsLen)+pad:]
	return m, nil
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := r.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Conn is an authenticated connection to a message bus.
type Conn struct {
	c      net.Conn
	r      *bufio.Reader
	serial uint32
	// Name is the unique name the bus assigned in reply to Hello.
	Name string
	// queued holds signals that arrived while Call waited for a reply.
	queued []*Message
}

// UnixAddr returns the socket a bus address names: the first unix:path= or
// unix:abstract= entry, unescaped. It refuses an empty address and one with
// neither, naming what it found, because snug dials no other transport.
func UnixAddr(addr string) (*net.UnixAddr, error) {
	if addr == "" {
		return nil, errors.New("DBUS_SESSION_BUS_ADDRESS is not set")
	}
	for one := range strings.SplitSeq(addr, ";") {
		transport, kv, ok := strings.Cut(one, ":")
		if !ok || transport != "unix" {
			continue
		}
		for pair := range strings.SplitSeq(kv, ",") {
			k, v, _ := strings.Cut(pair, "=")
			v, err := url.PathUnescape(v)
			if err != nil {
				continue
			}
			switch k {
			case "path":
				return &net.UnixAddr{Net: "unix", Name: v}, nil
			case "abstract":
				return &net.UnixAddr{Net: "unix", Name: "@" + v}, nil
			}
		}
	}
	return nil, fmt.Errorf("DBUS_SESSION_BUS_ADDRESS names no unix:path= or unix:abstract= socket: %q", addr)
}

// Dial connects to the bus at addr (a DBUS_SESSION_BUS_ADDRESS value),
// authenticates as uid with SASL EXTERNAL and sends Hello. Every read and
// write before deadline; Conn keeps that deadline until SetDeadline changes it.
func Dial(addr string, uid int, deadline time.Time) (*Conn, error) {
	ua, err := UnixAddr(addr)
	if err != nil {
		return nil, err
	}
	nc, err := net.DialUnix("unix", nil, ua)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the session bus at %s: %w", ua.Name, err)
	}
	c := &Conn{c: nc, r: bufio.NewReaderSize(nc, 4096)}
	nc.SetDeadline(deadline)
	if err := c.auth(uid); err != nil {
		nc.Close()
		return nil, err
	}
	reply, err := c.Call(Message{
		Type:        TypeMethodCall,
		Path:        "/org/freedesktop/DBus",
		Interface:   "org.freedesktop.DBus",
		Member:      "Hello",
		Destination: "org.freedesktop.DBus",
	})
	if err != nil {
		nc.Close()
		return nil, err
	}
	d := NewDecoder(reply)
	c.Name = d.String()
	if d.Err() != nil || reply.Signature != "s" {
		nc.Close()
		return nil, fmt.Errorf("the session bus answered Hello with signature %q, not a name", reply.Signature)
	}
	return c, nil
}

func (c *Conn) auth(uid int) error {
	// The leading NUL is the credentials byte the protocol requires before
	// any SASL line.
	hello := "\x00AUTH EXTERNAL " + hex.EncodeToString([]byte(strconv.Itoa(uid))) + "\r\n"
	if _, err := c.c.Write([]byte(hello)); err != nil {
		return fmt.Errorf("could not authenticate to the session bus: %w", err)
	}
	// ReadSlice, not ReadString: the reply line is bounded by the reader's
	// buffer, where ReadString grows until a newline or the deadline.
	b, err := c.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return fmt.Errorf("the session bus sent a SASL line longer than %d bytes", c.r.Size())
	}
	if err != nil {
		return fmt.Errorf("could not authenticate to the session bus: %w", err)
	}
	line := string(b)
	if !strings.HasPrefix(line, "OK ") {
		return fmt.Errorf("the session bus refused SASL EXTERNAL for uid %d: %q", uid, strings.TrimSpace(line))
	}
	if _, err := c.c.Write([]byte("BEGIN\r\n")); err != nil {
		return fmt.Errorf("could not authenticate to the session bus: %w", err)
	}
	return nil
}

// SetDeadline sets the deadline for every later read and write; the zero
// time means none.
func (c *Conn) SetDeadline(t time.Time) { c.c.SetDeadline(t) }

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

// Call sends m as a method call and returns its METHOD_RETURN. An ERROR
// reply is returned as an error naming the error and its message. Signals
// read while waiting are kept for WaitSignal, up to maxQueued, past which
// Call fails; other messages are dropped.
func (c *Conn) Call(m Message) (*Message, error) {
	c.serial++
	m.Serial = c.serial
	b, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	if _, err := c.c.Write(b); err != nil {
		return nil, fmt.Errorf("D-Bus call %s.%s: %w", m.Interface, m.Member, err)
	}
	for {
		r, err := ReadMessage(c.r)
		if err != nil {
			return nil, fmt.Errorf("D-Bus call %s.%s: %w", m.Interface, m.Member, err)
		}
		switch {
		case r.Type == TypeSignal:
			if len(c.queued) == maxQueued {
				return nil, fmt.Errorf("D-Bus call %s.%s: more than %d signals arrived before its reply",
					m.Interface, m.Member, maxQueued)
			}
			c.queued = append(c.queued, r)
		case r.ReplySerial != m.Serial:
		case r.Type == TypeError:
			e := &Error{Name: r.ErrorName}
			if strings.HasPrefix(r.Signature, "s") {
				e.Message = NewDecoder(r).String()
			}
			return nil, e
		case r.Type == TypeMethodReturn:
			return r, nil
		}
	}
}

// WaitSignal returns the first signal match accepts, queued or read, until
// the connection's deadline.
func (c *Conn) WaitSignal(match func(*Message) bool) (*Message, error) {
	for i, s := range c.queued {
		if match(s) {
			c.queued = append(c.queued[:i], c.queued[i+1:]...)
			return s, nil
		}
	}
	for {
		r, err := ReadMessage(c.r)
		if err != nil {
			return nil, err
		}
		if r.Type == TypeSignal && match(r) {
			return r, nil
		}
	}
}

// Error is an ERROR reply.
type Error struct {
	Name    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Name
	}
	return e.Name + ": " + e.Message
}
