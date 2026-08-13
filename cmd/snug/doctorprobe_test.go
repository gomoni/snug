package main

import "testing"

// TestParseNetDevIgnoresAnythingThatIsNotAnInterfaceList is the regression for a
// doctor failure that shipped to CI: the interface probe piped /proc/net/dev
// through awk, awk is a symlink into /etc/alternatives on Debian-family hosts,
// probeBase does not bind /etc, and so the runner got
//
//	/bin/sh: 1: awk: not found
//
// which the old field-splitting turned into three "interface names". doctor
// then reported "network namespace has more than loopback" and — because that
// case had just been made fatal — refused a host that runs snug perfectly well.
//
// Two properties, and the second is the one that failed:
//
//   - a real /proc/net/dev parses to exactly the interfaces present;
//   - anything that is NOT a /proc/net/dev parses to NOTHING, so the caller
//     reports the probe as inconclusive rather than reporting the sandbox as
//     broken. Distinguishing "the sandbox is wrong" from "the probe could not
//     look" is the whole job of the command.
func TestParseNetDevIgnoresAnythingThatIsNotAnInterfaceList(t *testing.T) {
	const realOffline = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo:       0       0    0    0    0     0          0         0        0       0
`
	const realWithSnug0 = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets
    lo:       0       0    0    0    0     0          0         0        0       0
 snug0:    1234      12    0    0    0     0          0         0     4321      21
`
	for _, tc := range []struct {
		name string
		in   string
		want []string
	}{
		{"offline sandbox", realOffline, []string{"lo"}},
		{"sandbox with pasta attached", realWithSnug0, []string{"lo", "snug0"}},

		// The case that shipped. Every one of these must yield NOTHING.
		{"awk missing (the CI failure)", "/bin/sh: 1: awk: not found\n", nil},
		{"bwrap refused", "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces.\n", nil},
		{"empty", "", nil},
		{"headers only", "Inter-|   Receive\n face |bytes\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseNetDev(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("parseNetDev(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseNetDev(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
