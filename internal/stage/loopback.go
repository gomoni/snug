package stage

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// bringLoopbackUp sets IFF_UP on lo, on a plain AF_INET datagram socket. The
// kernel assigns 127.0.0.1/8 and ::1/128 itself once the interface is up, so no
// address code is needed.
//
// This is §3.5's fix for a real regression: today's offline sandbox has lo UP
// with 127.0.0.1/8 because bwrap configures the netns it CREATED
// (loopback_setup). Under the stage, bwrap does not create N — P1 does — so
// nothing brings lo up unless P1 does it itself, and TestSandboxHasItsOwnWorkingLoopback
// is the positive control that catches the regression if this is skipped.
//
// Never by executing ip(8): that would add a host binary dependency snug does
// not otherwise have, on a path (P1) that must not depend on what is or is not
// on $PATH.
func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("bringing lo up: socket: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("bringing lo up: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing lo up: SIOCGIFFLAGS: %w", err)
	}
	flags := ifr.Uint16()
	if flags&unix.IFF_UP != 0 {
		return nil // already up
	}
	ifr.SetUint16(flags | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing lo up: SIOCSIFFLAGS: %w", err)
	}
	return nil
}
