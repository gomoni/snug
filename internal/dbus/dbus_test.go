package dbus

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	var e Encoder
	e.String("")
	e.String("https://claude.com/x")
	e.StringVariantDict([][2]string{{"handle_token", "snug01"}, {"k", "v"}})
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	in := Message{Type: TypeMethodCall, Serial: 7, Path: "/org/freedesktop/portal/desktop",
		Interface: "org.freedesktop.portal.OpenURI", Member: "OpenURI",
		Destination: "org.freedesktop.portal.Desktop", Signature: "ssa{sv}", Body: body}
	b, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ReadMessage(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		t.Fatal(err)
	}
	if out.Path != in.Path || out.Interface != in.Interface || out.Member != in.Member ||
		out.Destination != in.Destination || out.Signature != in.Signature || out.Serial != 7 {
		t.Fatalf("header: %+v", out)
	}
	d := NewDecoder(out)
	if d.String() != "" || d.String() != "https://claude.com/x" {
		t.Fatal("strings")
	}
	m := d.VariantDict()
	if d.Err() != nil || m["handle_token"] != "snug01" || m["k"] != "v" || len(m) != 2 {
		t.Fatalf("dict %v %v", m, d.Err())
	}
}

// The a{sv} array length counts the elements and not the padding to the
// first one: with the length at offset 0, 4 bytes of padding follow it.
func TestStringVariantDictLengthExcludesLeadingPadding(t *testing.T) {
	var e Encoder
	e.StringVariantDict([][2]string{{"a", "b"}})
	b, _ := e.Bytes()
	// u32 len, 4 pad, "a": u32 1 + 'a' NUL, sig 1 's' NUL, pad to 4, "b": u32 1 + 'b' NUL
	if n := binary.LittleEndian.Uint32(b); int(n) != len(b)-8 {
		t.Fatalf("length %d, body %d bytes: % x", n, len(b), b)
	}
}

func TestEncoderRefusesNULAndInvalidUTF8(t *testing.T) {
	for _, s := range []string{"a\x00b", "\xff"} {
		var e Encoder
		e.String(s)
		if _, err := e.Bytes(); err == nil {
			t.Errorf("%q encoded", s)
		}
	}
}

// Truncations of a valid message, and a header announcing more than the
// bound, are errors, never a panic or a partial message.
func TestReadMessageRefusesTruncatedAndOversized(t *testing.T) {
	m := Message{Type: TypeSignal, Serial: 1, Path: "/a", Interface: "b.c", Member: "D"}
	b, _ := m.Marshal()
	for i := range len(b) {
		if _, err := ReadMessage(bufio.NewReader(bytes.NewReader(b[:i]))); err == nil {
			t.Fatalf("truncated at %d accepted", i)
		}
	}
	big := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(big[4:], maxMessage+1)
	if _, err := ReadMessage(bufio.NewReader(bytes.NewReader(big))); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("oversized: %v", err)
	}
}

func TestDecoderVariantRefusesUnknownType(t *testing.T) {
	var e Encoder
	e.Signature("ai")
	b, _ := e.Bytes()
	d := NewDecoder(&Message{Body: b})
	d.Variant()
	if d.Err() == nil {
		t.Fatal("variant of type ai decoded")
	}
}

func TestUnixAddr(t *testing.T) {
	for in, want := range map[string]string{
		"unix:path=/run/user/1000/bus":         "/run/user/1000/bus",
		"unix:abstract=/tmp/dbus-x,guid=00":    "@/tmp/dbus-x",
		"tcp:host=h,port=1;unix:path=/a%20b":   "/a b",
		"unix:guid=00,path=/run/user/1000/bus": "/run/user/1000/bus",
	} {
		a, err := UnixAddr(in)
		if err != nil || a.Name != want {
			t.Errorf("%q: %v %v, want %q", in, a, err, want)
		}
	}
}
