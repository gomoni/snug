// Command fakeportal stands in for the host's session bus and the desktop
// portal on it, and hands each URL OpenURI receives to a browser stand-in.
//
// Usage: fakeportal SOCKETDIR BROWSER BROWSERDIR
//
// It listens on SOCKETDIR/bus, prints "READY <DBUS_SESSION_BUS_ADDRESS>" on
// stdout once it does, and for each OpenURI starts BROWSER URL with
// FAKEOPENER_DIR=BROWSERDIR and FAKEOPENER_MODE=callback, without waiting,
// as a portal starts the user's browser in the session and returns. It
// serves until killed.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gomoni/snug/internal/dbus/dbustest"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: fakeportal SOCKETDIR BROWSER BROWSERDIR")
		os.Exit(2)
	}
	browser, dir := os.Args[2], os.Args[3]
	p := &dbustest.Portal{Version: 5, OnOpen: func(url string) {
		cmd := exec.Command(browser, url)
		cmd.Env = append(os.Environ(), "FAKEOPENER_DIR="+dir, "FAKEOPENER_MODE=callback")
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "fakeportal:", err)
			return
		}
		go cmd.Wait()
	}}
	if err := p.Listen(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "fakeportal:", err)
		os.Exit(1)
	}
	fmt.Println("READY " + p.Addr)
	select {}
}
