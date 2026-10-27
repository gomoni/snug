package dbus

import (
	"errors"
	"os"
	"testing"
	"time"
)

// TestOpenURIShapedCallOnARealBus sends an OpenURI-shaped call (ssa{sv}) to a
// name nobody owns on the real session bus named by SNUG_REAL_BUS. Nothing
// opens: the bus answers ServiceUnknown. scripts/0037 runs it under
// `busctl --user monitor`, whose decoder is sd-bus's, not this package's, and
// checks the body it prints. Skipped without SNUG_REAL_BUS, which CI never
// sets.
func TestOpenURIShapedCallOnARealBus(t *testing.T) {
	addr := os.Getenv("SNUG_REAL_BUS")
	if addr == "" {
		t.Skip("SNUG_REAL_BUS is not set; scripts/0037 sets it")
	}
	c, err := Dial(addr, os.Getuid(), time.Now().Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var e Encoder
	e.String("")
	e.String("https://claude.com/snug-0037")
	e.StringVariantDict([][2]string{{"handle_token", "snug0037"}, {"activation_token", "x"}})
	body, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Call(Message{Type: TypeMethodCall, Path: "/org/freedesktop/portal/desktop",
		Interface: "org.freedesktop.portal.OpenURI", Member: "OpenURI",
		Destination: "org.snug.NoSuchName0037", Signature: "ssa{sv}", Body: body})
	var de *Error
	if !errors.As(err, &de) || de.Name != "org.freedesktop.DBus.Error.ServiceUnknown" {
		t.Fatalf("want ServiceUnknown from the bus, got %v", err)
	}
	t.Logf("bus answered %v", err)
}
