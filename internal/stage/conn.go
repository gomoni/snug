package stage

import (
	"fmt"
	"os"
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
