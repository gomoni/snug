package stage

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// recvOn reads exactly one SEQPACKET datagram off f. A short read is not
// possible for SOCK_SEQPACKET (the kernel delivers whole messages or MSG_TRUNC,
// never a partial one), so one Read call is the whole protocol's framing.
func recvOn(f *os.File) ([]byte, error) {
	buf := make([]byte, maxMessage+1)
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}
	if n > maxMessage {
		return nil, fmt.Errorf("control message exceeded the %d byte ceiling", maxMessage)
	}
	return buf[:n], nil
}

func sendOn(f *os.File, b []byte) error {
	_, err := f.Write(b)
	return err
}

func sendRequest(f *os.File, req request) error {
	b, err := encode(req)
	if err != nil {
		return err
	}
	return sendOn(f, b)
}

func recvRequest(f *os.File) (request, error) {
	var req request
	b, err := recvOn(f)
	if err != nil {
		return req, err
	}
	if err := decodeStrict(b, &req); err != nil {
		return req, err
	}
	return req, nil
}

func sendEvent(f *os.File, ev event) error {
	b, err := encode(ev)
	if err != nil {
		return err
	}
	return sendOn(f, b)
}

func recvEvent(f *os.File) (event, error) {
	var ev event
	b, err := recvOn(f)
	if err != nil {
		return ev, err
	}
	if err := decodeStrict(b, &ev); err != nil {
		return ev, err
	}
	return ev, nil
}

// sendEventFDs is sendEvent plus SCM_RIGHTS. With no descriptors it IS
// sendEvent — the same plain write, no ancillary data at all — so every
// "netready" answer on a run without relay sockets is unchanged on the wire.
// The kernel duplicates fds into the message at sendmsg time; the caller's
// copies stay open and are the caller's to close.
func sendEventFDs(f *os.File, ev event, fds []int) error {
	if len(fds) == 0 {
		return sendEvent(f, ev)
	}
	b, err := encode(ev)
	if err != nil {
		return err
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Write(func(fd uintptr) bool {
		serr = unix.Sendmsg(int(fd), b, unix.UnixRights(fds...), nil, 0)
		return serr != unix.EAGAIN
	}); err != nil {
		return err
	}
	return serr
}

// recvEventFDs is recvEvent for the one event that may carry descriptors.
// MSG_CMSG_CLOEXEC sets close-on-exec atomically with the descriptors'
// installation in this process, so there is no window in which a concurrent
// fork+exec elsewhere in P0 could inherit one.
//
// The control buffer has room for one descriptor MORE than maxRelaySockets,
// so a stage that sends too many is seen sending too many rather than being
// silently truncated to the bound; MSG_CTRUNC is refused outright. Every
// descriptor received is returned even when err is non-nil, except on a
// failed recvmsg, so the caller can close them.
func recvEventFDs(f *os.File) (event, []int, error) {
	var ev event
	buf := make([]byte, maxMessage+1)
	oob := make([]byte, unix.CmsgSpace(4*(maxRelaySockets+1)))
	rc, err := f.SyscallConn()
	if err != nil {
		return ev, nil, err
	}
	var n, oobn, flags int
	var rerr error
	if err := rc.Read(func(fd uintptr) bool {
		n, oobn, flags, _, rerr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC)
		return rerr != unix.EAGAIN
	}); err != nil {
		return ev, nil, err
	}
	if rerr != nil {
		return ev, nil, rerr
	}
	var fds []int
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return ev, nil, fmt.Errorf("parsing the control message's ancillary data: %w", err)
		}
		for i := range msgs {
			rights, err := unix.ParseUnixRights(&msgs[i])
			if err != nil {
				return ev, fds, fmt.Errorf("control message carries ancillary data that is not "+
					"SCM_RIGHTS: %w", err)
			}
			fds = append(fds, rights...)
		}
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return ev, fds, fmt.Errorf("control message carried more descriptors than the %d "+
			"this protocol allows (MSG_CTRUNC)", maxRelaySockets)
	}
	if n == 0 {
		return ev, fds, io.EOF
	}
	if n > maxMessage || flags&unix.MSG_TRUNC != 0 {
		return ev, fds, fmt.Errorf("control message exceeded the %d byte ceiling", maxMessage)
	}
	if err := decodeStrict(buf[:n], &ev); err != nil {
		return ev, fds, err
	}
	return ev, fds, nil
}
