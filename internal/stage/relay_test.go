package stage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// startRelayStage starts a real stage — clone, uid map, the setup->serve
// re-exec — and stops short of "netready", which each test asks itself. No
// bwrap and no pasta: the "lo" arm of "netready" needs neither, and the relay
// sockets are created on that arm exactly as on the snug0 one.
func startRelayStage(t *testing.T) *Stage {
	t.Helper()
	infoR, infoW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { infoR.Close() })
	st, err := Start(Config{
		Topology:  policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidNone},
		Sandbox:   []*os.File{infoW},
		BwrapInfo: infoR,
		Stdin:     devNullFile(t), Stdout: devNullFile(t), Stderr: devNullFile(t),
	})
	infoW.Close()
	if err != nil {
		if isUnprivilegedUsernsRefusal(err) {
			t.Skipf("this host refuses unprivileged user namespaces: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func closeFiles(fs []*os.File) {
	for _, f := range fs {
		f.Close()
	}
}

// TestNetreadyHandsBackSocketsInN asserts the hole and its edge. Every socket
// is in N by SIOCGSKNS, compared with the id the "ready" event pinned and with
// the test's own netns. Then behaviour: one relay socket listens on N's
// 127.0.0.1 and another reaches it, while a socket made in the test's own
// netns gets ECONNREFUSED on the same address and port, so the sockets reach
// N's loopback and the host's own namespace does not.
func TestNetreadyHandsBackSocketsInN(t *testing.T) {
	st := startRelayStage(t)
	relay, err := st.WaitNetReady(5*time.Second, "lo", nil, maxRelaySockets)
	if err != nil {
		t.Fatalf("WaitNetReady asking for %d relay sockets: %v", maxRelaySockets, err)
	}
	defer closeFiles(relay)
	if len(relay) != maxRelaySockets {
		t.Fatalf("got %d relay sockets, want %d", len(relay), maxRelaySockets)
	}

	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if own == st.PinnedNetns() {
		t.Fatalf("PRECONDITION: the stage's pinned netns %s is the test's own", own)
	}
	for i, f := range relay {
		got, err := socketNetns(int(f.Fd()))
		if err != nil {
			t.Fatalf("relay socket %d: %v", i, err)
		}
		if got != st.PinnedNetns() {
			t.Errorf("relay socket %d is in %s, want the pinned %s (the test's own is %s)",
				i, got, st.PinnedNetns(), own)
		}
	}

	lfd, cfd := int(relay[0].Fd()), int(relay[1].Fd())
	if err := unix.Bind(lfd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("binding a relay socket to 127.0.0.1:0 inside N: %v", err)
	}
	if err := unix.Listen(lfd, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(lfd)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*unix.SockaddrInet4).Port
	target := &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: port}
	if err := unix.Connect(cfd, target); err != nil {
		t.Fatalf("a relay socket could not reach a listener on N's 127.0.0.1:%d: %v", port, err)
	}

	hfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(hfd)
	err = unix.Connect(hfd, target)
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Errorf("a socket in the test's own netns connecting to 127.0.0.1:%d got %v, want "+
			"ECONNREFUSED — either the port is taken on the host by chance (rerun) or N and "+
			"the host share a loopback", port, err)
	}
}

// TestNetreadyRefusesMoreThanThreeRelaySockets holds the bound on both sides.
// P1 refuses a raw request over it with an Err and no descriptor — that side
// is the trust boundary, so it is driven directly rather than through
// WaitNetReady — and WaitNetReady refuses before writing anything at all.
func TestNetreadyRefusesMoreThanThreeRelaySockets(t *testing.T) {
	t.Run("P1", func(t *testing.T) {
		st := startRelayStage(t)
		if err := sendRequest(st.control, request{Op: "netready", NetIface: "lo",
			RelaySockets: maxRelaySockets + 1}); err != nil {
			t.Fatal(err)
		}
		ev, fds, err := recvEventFDsTimeout(st.control, 5*time.Second)
		defer closeFDs(fds)
		if err != nil {
			t.Fatalf("reading the stage's answer: %v", err)
		}
		if len(fds) != 0 {
			t.Errorf("the refusal carried %d descriptor(s)", len(fds))
		}
		want := fmt.Sprintf("asking for %d login relay sockets", maxRelaySockets+1)
		if ev.Op != "netready" || !strings.Contains(ev.Err, want) {
			t.Errorf("got event %+v, want a \"netready\" whose Err contains %q", ev, want)
		}
	})

	for _, n := range []int{maxRelaySockets + 1, -1} {
		t.Run(fmt.Sprintf("P0 %d", n), func(t *testing.T) {
			p0, p1 := fakeControlPair(t)
			st := &Stage{control: p0}
			relay, err := st.WaitNetReady(time.Second, "lo", nil, n)
			if err == nil {
				closeFiles(relay)
				t.Fatalf("WaitNetReady accepted %d relay sockets", n)
			}
			if err := unix.SetNonblock(int(p1.Fd()), true); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, maxMessage)
			if _, err := unix.Read(int(p1.Fd()), buf); !errors.Is(err, unix.EAGAIN) {
				t.Errorf("WaitNetReady wrote a request before refusing (read: %v)", err)
			}
		})
	}
}

// TestP1HoldsNoRelaySocketAfterNetready walks /proc/<P1>/fd for the inode of
// every socket P0 received. P1 closes its copies after sendmsg, which can be
// after P0 has the message, so the walk polls for a bounded time.
func TestP1HoldsNoRelaySocketAfterNetready(t *testing.T) {
	st := startRelayStage(t)
	relay, err := st.WaitNetReady(5*time.Second, "lo", nil, maxRelaySockets)
	if err != nil {
		t.Fatalf("WaitNetReady: %v", err)
	}
	defer closeFiles(relay)

	want := map[string]bool{}
	for _, f := range relay {
		var stt unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &stt); err != nil {
			t.Fatal(err)
		}
		want[fmt.Sprintf("socket:[%d]", stt.Ino)] = true
	}

	dir := fmt.Sprintf("/proc/%d/fd", st.Pid())
	var held []string
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		held = nil
		sockets := 0
		for _, e := range entries {
			l, err := os.Readlink(dir + "/" + e.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(l, "socket:") {
				sockets++
			}
			if want[l] {
				held = append(held, e.Name()+" -> "+l)
			}
		}
		if sockets == 0 {
			t.Fatalf("PRECONDITION: %s lists no socket at all, not even the control socket, "+
				"so this walk is not reading P1's table", dir)
		}
		if len(held) == 0 {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("P1 still holds relay socket(s) after \"netready\": %v", held)
}

// TestNoP1ThreadIsLeftInN re-runs the task sweep MainServe runs at startup,
// from outside, after a "netready" that joined N on a thread. Which thread the
// worker goroutine lands on is up to the scheduler, so it asks several times.
func TestNoP1ThreadIsLeftInN(t *testing.T) {
	for i := range 5 {
		st := startRelayStage(t)
		relay, err := st.WaitNetReady(5*time.Second, "lo", nil, maxRelaySockets)
		if err != nil {
			t.Fatalf("run %d: WaitNetReady: %v", i, err)
		}
		closeFiles(relay)

		dir := fmt.Sprintf("/proc/%d/task", st.Pid())
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		seen := 0
		for _, e := range entries {
			ns, err := os.Readlink(dir + "/" + e.Name() + "/ns/net")
			if err != nil {
				continue
			}
			seen++
			if ns == st.PinnedNetns() {
				t.Errorf("run %d: P1 thread %s is in the sandbox's netns %s after \"netready\"",
					i, e.Name(), ns)
			}
		}
		if seen == 0 {
			t.Fatalf("PRECONDITION: no thread of P1 had a readable ns/net in %s", dir)
		}
		st.Close()
	}
}

// TestRelaySocketsAreCloexecInP0: every descriptor P0 holds reaches a child
// only by being named, and MSG_CMSG_CLOEXEC is what makes that true of these.
func TestRelaySocketsAreCloexecInP0(t *testing.T) {
	st := startRelayStage(t)
	relay, err := st.WaitNetReady(5*time.Second, "lo", nil, maxRelaySockets)
	if err != nil {
		t.Fatalf("WaitNetReady: %v", err)
	}
	defer closeFiles(relay)
	for i, f := range relay {
		fl, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if fl&unix.FD_CLOEXEC == 0 {
			t.Errorf("relay socket %d (fd %d) is not close-on-exec in P0", i, f.Fd())
		}
	}
}

// TestNetreadyWithoutRelaySocketsIsUnchangedOnTheWire is every run without
// the login bridge: the request carries no relay_sockets key, and the real
// stage's answer is the plain event with no ancillary data at all.
func TestNetreadyWithoutRelaySocketsIsUnchangedOnTheWire(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		p0, p1 := fakeControlPair(t)
		st := &Stage{control: p0}
		got := make(chan []byte, 1)
		go func() {
			b, _ := recvOn(p1)
			got <- b
			_ = sendEvent(p1, event{Op: "netready"})
		}()
		relay, err := st.WaitNetReady(5*time.Second, "lo", nil, 0)
		if err != nil {
			t.Fatalf("WaitNetReady: %v", err)
		}
		if relay != nil {
			t.Errorf("WaitNetReady returned %d relay sockets for a request of 0", len(relay))
		}
		b := <-got
		if want := `{"op":"netready","net_iface":"lo"}`; string(b) != want {
			t.Errorf("request bytes = %s, want %s", b, want)
		}
	})

	t.Run("event", func(t *testing.T) {
		st := startRelayStage(t)
		if err := sendRequest(st.control, request{Op: "netready", NetIface: "lo"}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, maxMessage+1)
		oob := make([]byte, unix.CmsgSpace(4*(maxRelaySockets+1)))
		n, oobn, _, _, err := unix.Recvmsg(int(st.control.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		if oobn != 0 {
			t.Errorf("the stage's \"netready\" answer carried %d bytes of ancillary data", oobn)
		}
		want, err := encode(event{Op: "netready"})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Errorf("event bytes = %s, want %s", buf[:n], want)
		}
	})
}

// TestWaitNetReadyRefusesSocketsItDidNotAskFor drives WaitNetReady with a fake
// P1 that sends the wrong thing, one way per check, and asserts the run is
// refused and every received descriptor closed.
func TestWaitNetReadyRefusesSocketsItDidNotAskFor(t *testing.T) {
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	inet := func(t *testing.T) int {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		return fd
	}
	cases := []struct {
		name    string
		netns   string
		claimed int
		ask     int
		fds     func(t *testing.T) []int
		want    string
	}{
		{"count claimed differs from delivered", own, 2, 2,
			func(t *testing.T) []int { return []int{inet(t)} }, "carried 1"},
		{"sockets nobody asked for", own, 1, 0,
			func(t *testing.T) []int { return []int{inet(t)} }, "asked for 0"},
		{"not AF_INET", own, 1, 1, func(t *testing.T) []int {
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			return []int{fd}
		}, "want AF_INET"},
		{"not SOCK_STREAM", own, 1, 1, func(t *testing.T) []int {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			return []int{fd}
		}, "want SOCK_STREAM"},
		// A socket from ANOTHER stage's N: SIOCGSKNS answers, and names a
		// namespace that is not the one this Stage pinned.
		{"another stage's netns", "net:[0]", 1, 1, func(t *testing.T) []int {
			other := startRelayStage(t)
			relay, err := other.WaitNetReady(5*time.Second, "lo", nil, 1)
			if err != nil {
				t.Fatalf("PRECONDITION: a second stage's relay socket: %v", err)
			}
			fd, err := unix.Dup(int(relay[0].Fd()))
			if err != nil {
				t.Fatal(err)
			}
			closeFiles(relay)
			return []int{fd}
		}, "not the sandbox's"},
		// A socket in the test's own netns: SIOCGSKNS returns EPERM to an
		// unprivileged process there, so the check fails closed with the
		// ioctl's own error rather than passing.
		{"a netns SIOCGSKNS will not name", own, 1, 1,
			func(t *testing.T) []int { return []int{inet(t)} }, "SIOCGSKNS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p0, p1 := fakeControlPair(t)
			st := &Stage{control: p0, netns: c.netns}
			sent := c.fds(t)
			inodes := socketInodes(t, sent)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer closeFDs(sent)
				if _, err := recvRequest(p1); err != nil {
					return
				}
				_ = sendEventFDs(p1, event{Op: "netready", RelaySockets: c.claimed}, sent)
			}()
			relay, err := st.WaitNetReady(5*time.Second, "lo", nil, c.ask)
			<-done
			if err == nil {
				closeFiles(relay)
				t.Fatal("WaitNetReady accepted it")
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "refusing the run") {
				t.Errorf("refusal %q does not contain %q and \"refusing the run\"", err, c.want)
			}
			if leaked := openSockets(t, inodes); len(leaked) != 0 {
				t.Errorf("received descriptors still open in P0 after the refusal: %v", leaked)
			}
		})
	}
}

func socketInodes(t *testing.T, fds []int) map[string]bool {
	t.Helper()
	m := map[string]bool{}
	for _, fd := range fds {
		var stt unix.Stat_t
		if err := unix.Fstat(fd, &stt); err != nil {
			t.Fatal(err)
		}
		m[fmt.Sprintf("socket:[%d]", stt.Ino)] = true
	}
	return m
}

// openSockets lists this process's descriptors that refer to one of inodes.
func openSockets(t *testing.T, inodes map[string]bool) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		l, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err == nil && inodes[l] {
			out = append(out, e.Name()+" -> "+l)
		}
	}
	return out
}
