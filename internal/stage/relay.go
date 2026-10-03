package stage

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// A hostile process inside the sandbox can use these sockets to receive, on a
// 127.0.0.1 port it listens on inside N, whatever P0 chooses to connect and
// write through them — and nothing else: they are created unconnected, P1
// keeps no copy, and they reach N's loopback only because a socket's network
// namespace is fixed when it is created, not by where its holder lives.

// relaySocketsInN creates n unconnected AF_INET stream sockets whose network
// namespace is N, the namespace netnsFD names, and returns their descriptors
// in this process. No thread of this process is in N when it returns: the
// setns happens on a locked thread the Go runtime destroys, and the caller
// re-runs threadsInNamespace before reporting success.
//
// P1 can make the setns(CLONE_NEWNET) call and P0 cannot: joining a netns
// needs CAP_SYS_ADMIN in the namespace's owning user namespace, which is U,
// where P1 holds a full set and P0 holds nothing.
func relaySocketsInN(netnsFD, n int) ([]int, error) {
	ch := make(chan relayResult, 1)
	go relayWorker(netnsFD, n, ch)
	r := <-ch
	return r.fds, r.err
}

type relayResult struct {
	fds []int
	err error
}

// relayWorker returns WITHOUT UnlockOSThread on every path past the
// thread-group-leader check, and that is the teardown: a goroutine that exits
// while locked takes its OS thread with it, so the thread that joined N stops
// existing instead of returning to the scheduler still in N.
//
// Except on the thread group leader. The Go runtime does not exit m0 — its
// mexit says "This is the main thread. Just wedge it." — so a locked
// goroutine that ends on the leader parks it forever, and here that would park
// it in N for the rest of P1's life. When this goroutine lands on the leader
// it keeps the leader locked (so the scheduler cannot put the retry there
// too), runs the work on a fresh goroutine, and only then unlocks.
//
// No thread the runtime creates while this one is locked inherits N: newm on
// a locked M hands the clone to the template thread, which never left P1's
// own netns.
func relayWorker(netnsFD, n int, ch chan<- relayResult) {
	runtime.LockOSThread()
	if unix.Gettid() == unix.Getpid() {
		inner := make(chan relayResult, 1)
		go relayWorker(netnsFD, n, inner)
		ch <- <-inner
		runtime.UnlockOSThread()
		return
	}
	if err := unix.Setns(netnsFD, unix.CLONE_NEWNET); err != nil {
		ch <- relayResult{err: fmt.Errorf("joining the sandbox's network namespace to create "+
			"the login relay sockets: setns: %w", err)}
		return
	}
	fds := make([]int, 0, n)
	for range n {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			closeFDs(fds)
			ch <- relayResult{err: fmt.Errorf("creating a login relay socket in the sandbox's "+
				"network namespace: %w", err)}
			return
		}
		fds = append(fds, fd)
	}
	ch <- relayResult{fds: fds}
}

// relayThreadGoneTimeout bounds how long P1 waits for the locked thread
// relayWorker leaves behind to finish exiting. The goroutine hands its result
// over before the runtime tears the thread down, so for a short while after
// relaySocketsInN returns the thread can still be listed, still in N.
const relayThreadGoneTimeout = 2 * time.Second

// waitNoThreadInNamespace polls threadsInNamespace until no thread of this
// process is in pinned, and refuses once timeout passes with one still there.
func waitNoThreadInNamespace(pinned string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		stuck, err := threadsInNamespace(pinned)
		if err != nil {
			return err
		}
		if len(stuck) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d thread(s) of the stage are still in the sandbox's network "+
				"namespace %s (tids %v) after creating the login relay sockets", len(stuck), pinned, stuck)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// verifyRelaySockets checks, from P0's side and without trusting the stage's
// own account, that fds is exactly what a "netready" asking for want sockets
// should have delivered: the count the event claims, the count requested and
// the count the kernel delivered all agree, and every descriptor is an
// AF_INET stream socket whose network namespace is netns (the "net:[…]" id
// the "ready" event pinned). SIOCGSKNS returns a new descriptor on the
// socket's namespace, closed here. It is not open to every caller: on a
// socket in the host's own netns an unprivileged process gets EPERM, so a
// socket from anywhere P0 has no standing over fails this check rather than
// passing it. On a socket in N it answers, TestNetreadyHandsBackSocketsInN
// being the measurement.
func verifyRelaySockets(fds []int, claimed, want int, netns string) error {
	if claimed != want || len(fds) != want {
		return fmt.Errorf("asked for %d login relay socket(s); the \"netready\" event claimed %d "+
			"and carried %d", want, claimed, len(fds))
	}
	for i, fd := range fds {
		dom, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil {
			return fmt.Errorf("login relay socket %d: SO_DOMAIN: %w", i, err)
		}
		if dom != unix.AF_INET {
			return fmt.Errorf("login relay socket %d has domain %d, want AF_INET (%d)", i, dom, unix.AF_INET)
		}
		typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil {
			return fmt.Errorf("login relay socket %d: SO_TYPE: %w", i, err)
		}
		if typ != unix.SOCK_STREAM {
			return fmt.Errorf("login relay socket %d has type %d, want SOCK_STREAM (%d)", i, typ, unix.SOCK_STREAM)
		}
		got, err := socketNetns(fd)
		if err != nil {
			return fmt.Errorf("login relay socket %d: %w", i, err)
		}
		if got != netns {
			return fmt.Errorf("login relay socket %d is in network namespace %s, not the sandbox's %s",
				i, got, netns)
		}
	}
	return nil
}

// socketNetns names the network namespace a socket was created in, as the
// "net:[…]" string readlink gives for a namespace descriptor.
func socketNetns(fd int) (string, error) {
	nsfd, err := unix.IoctlRetInt(fd, unix.SIOCGSKNS)
	if err != nil {
		return "", fmt.Errorf("SIOCGSKNS: %w", err)
	}
	defer unix.Close(nsfd)
	s, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", nsfd))
	if err != nil {
		return "", fmt.Errorf("naming the namespace SIOCGSKNS returned: %w", err)
	}
	return s, nil
}
