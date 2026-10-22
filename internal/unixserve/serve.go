// Package unixserve is the accept loop the agent proxies share: one goroutine
// per connection, and a Close that ends them.
//
// Close ends live connections rather than waiting for them. A handler blocks
// reading its client with no deadline — the client is a process in the sandbox
// and may sit idle for as long as the run lasts — so a Close that only waited
// would hang snug's teardown on any client that connected and stayed silent.
package unixserve

import (
	"net"
	"sync"
)

type Server struct {
	ln net.Listener

	// mu orders Serve's wg.Add against Close's wg.Wait: an Add that can run
	// concurrently with a Wait on a zero counter is a misuse of WaitGroup, and
	// the race detector reports it. Once closed is set, Serve adds nothing.
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	once   sync.Once
	conns  map[net.Conn]struct{}
}

func New(ln net.Listener) *Server {
	return &Server{ln: ln, conns: map[net.Conn]struct{}{}}
}

// Serve accepts until the listener is closed, running handle for each
// connection on its own goroutine and closing the connection when it returns.
func (s *Server) Serve(handle func(net.Conn)) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.wg.Add(1)
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, c)
				s.mu.Unlock()
				c.Close()
			}()
			handle(c)
		}()
	}
}

// Close stops accepting, closes every live connection, and waits for their
// handlers to return.
func (s *Server) Close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.ln.Close()
		s.wg.Wait()
	})
}
