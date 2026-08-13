package stage

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// openNetSocketInN creates an AF_INET datagram socket and brings lo up through
// it. It MUST be called while the caller is still inside N, because both of the
// things it produces are namespace-scoped at that moment:
//
//   - lo is configured in N. Today's offline sandbox has lo UP with 127.0.0.1/8
//     because bwrap configures the netns IT created (loopback_setup). Under the
//     stage bwrap does not create N, so nothing brings lo up unless the stage
//     does it here — TestSandboxHasItsOwnWorkingLoopback is the positive control
//     that catches the regression if this is skipped.
//   - the returned socket stays bound to N for its whole life, which is what
//     lets the stage answer readiness questions about N after it has left.
//
// Never by executing ip(8): that would add a host binary dependency snug does
// not otherwise have, on a path that must not depend on what is on $PATH.
//
// The caller owns the descriptor.
func openNetSocketInN() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, fmt.Errorf("opening a socket in N: %w", err)
	}
	if err := bringUp(fd, "lo"); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// bringUp sets IFF_UP on name. The kernel assigns 127.0.0.1/8 and ::1/128
// itself once lo is up, so no address code is needed.
func bringUp(fd int, name string) error {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("bringing %s up: %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing %s up: SIOCGIFFLAGS: %w", name, err)
	}
	flags := ifr.Uint16()
	if flags&unix.IFF_UP != 0 {
		return nil // already up
	}
	ifr.SetUint16(flags | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing %s up: SIOCSIFFLAGS: %w", name, err)
	}
	return nil
}

// ifaceIsUp reports whether name exists in the socket's network namespace and
// is both UP and RUNNING.
//
// Both flags, not just IFF_UP. pasta creates the tap interface and then
// configures it; IFF_UP alone can be true on an interface that is not yet
// carrying anything, and the whole point of this check is that the payload must
// not start before the network it was promised actually works. IFF_RUNNING is
// the kernel's own answer to "is the link operational".
//
// A missing interface is (false, nil), not an error: it is the ordinary state
// while pasta is still starting, and the caller polls.
func ifaceIsUp(fd int, name string) (bool, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return false, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		if err == unix.ENODEV {
			return false, nil // not there yet
		}
		return false, fmt.Errorf("SIOCGIFFLAGS on %s: %w", name, err)
	}
	flags := ifr.Uint16()
	return flags&unix.IFF_UP != 0 && flags&unix.IFF_RUNNING != 0, nil
}

// waitForIface polls until name is up in the socket's namespace, or the
// deadline passes. It is the stage's replacement for polling a sandbox
// process's /proc/<pid>/net/dev, and it needs no process in N at all.
//
// The timeout is the caller's business; this returns a plain error naming what
// it was waiting for, because that error reaches a human as "snug could not
// bring the network up" and a bare "timeout" would send them to the wrong
// place.
func waitForIface(fd int, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		up, err := ifaceIsUp(fd, name)
		if err != nil {
			return err
		}
		if up {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("interface %s did not come up in the sandbox's network namespace "+
				"within %s — pasta started but never configured it", name, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
