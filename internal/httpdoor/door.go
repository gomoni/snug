// Package httpdoor is the host side of `@http-proxy`: a loopback HTTP
// reverse proxy a human opens by hand to reach a dev server running inside
// the sandbox.
//
// Three facts shape every choice below:
//
//   - The backend is hostile and the client is trusted — the reverse of every
//     reverse-proxy guide. Admission (Sec-Fetch-Site, Origin, Host, the
//     per-run token) authenticates who may ask; nothing here authenticates
//     what the sandbox answers, so the response parser treats every byte
//     from the backend as adversarial input.
//   - This is a sandbox escape by design, not a bug to be minimised. The
//     bound is entirely in the admission checks; there is no sense in which
//     this package makes the hole "safer" beyond enforcing those checks
//     precisely and refusing anything it cannot parse confidently.
//   - The socket the backend answers on is created and handed to the sandbox
//     by the caller, listening before the sandbox starts (socket
//     activation); this package only dials it, via the injected
//     Config.Dial, and never opens or unlinks it.
package httpdoor

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
)

// Config is everything the door needs; the caller resolves all of it.
type Config struct {
	// Addr is the loopback address and port the door binds. Which slice of
	// 127.0.0.0/8 it comes from, and whether it collides with the human's
	// own services, is the caller's decision — this package binds exactly
	// what it is given and refuses if that fails.
	Addr netip.AddrPort
	// Token is the per-run URL path token. A request must name it as the
	// first path segment or it is refused (requirement 4).
	Token string
	// DoorName identifies the door in messages to the human and the log.
	DoorName string
	// Ready, if set, is called ONCE after the listener is bound and before the
	// first connection is served. It exists so a caller can print the URL only
	// when the URL works: printing it before the bind means printing one that is
	// refused for a moment, and printing one that never works at all when the
	// bind fails.
	Ready func()
	// Dial connects to the backend, one fresh connection per client request
	// (requirement 8). It must respect ctx: the door derives ctx's deadline
	// from the single round-trip bound (see roundTripTimeout) and relies on
	// Dial to give up when it expires rather than hanging past it.
	Dial func(ctx context.Context) (net.Conn, error)
	// Log receives one line per refusal and per backend protocol violation.
	// Never nil; the caller passes os.Stderr.
	Log io.Writer
}

// Door is a bound, per-run HTTP door. Create one with New and run it with
// Serve.
type Door struct {
	cfg    Config
	origin string // "http://<addr>", compared against the client's Origin header
	host   string // "<addr>", compared against the client's Host header
}

// New validates cfg and prepares a Door. It returns an error if Addr is not
// a valid address with a nonzero port, if Token or DoorName is empty, or if
// Dial or Log is nil — the conditions each Config field's doc comment states.
// It does not bind — that happens in Serve, so that constructing a Door and
// reporting its URL (for --dry-run) costs nothing and risks nothing.
func New(cfg Config) (*Door, error) {
	if !cfg.Addr.IsValid() || cfg.Addr.Port() == 0 {
		return nil, errors.New("httpdoor: Config.Addr must be a valid address with a nonzero port")
	}
	if cfg.Token == "" {
		return nil, errors.New("httpdoor: Config.Token must be non-empty")
	}
	if cfg.DoorName == "" {
		return nil, errors.New("httpdoor: Config.DoorName must be non-empty")
	}
	if cfg.Dial == nil {
		return nil, errors.New("httpdoor: Config.Dial must be set")
	}
	if cfg.Log == nil {
		// No silent fallback to os.Stderr: a caller that forgot Log would
		// otherwise lose every refusal and violation this package reports.
		return nil, errors.New("httpdoor: Config.Log must not be nil (pass os.Stderr)")
	}
	return &Door{
		cfg:    cfg,
		origin: "http://" + cfg.Addr.String(),
		host:   cfg.Addr.String(),
	}, nil
}

// URL is the exact URL a human should open.
func (d *Door) URL() string {
	return d.origin + "/" + d.cfg.Token + "/"
}

// Serve binds the door's address and serves until ctx is done, then closes
// the listener and returns nil. It never relocates on a bind failure
// (invariant 5) — a collision is reported with the address and the fix, not
// silently retried on another port.
func (d *Door) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", d.cfg.Addr.String())
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("httpdoor: %s: %s is already bound; stop whatever is listening there or choose a different door address", d.cfg.DoorName, d.cfg.Addr)
		}
		return fmt.Errorf("httpdoor: %s: bind %s: %w", d.cfg.DoorName, d.cfg.Addr, err)
	}
	defer ln.Close()
	if d.cfg.Ready != nil {
		d.cfg.Ready()
	}

	srv := &http.Server{Handler: d}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		srv.Close() // hard close: drop connections rather than drain them past ctx
		<-done
		return nil
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// ServeHTTP admits a request and, if admitted, forwards it. Every refusal is
// a 403 with a one-line body; a CONNECT or absolute-form target is refused
// before any other check runs, because either one turns the door into an
// open forward proxy regardless of what Origin or Host say.
func (d *Door) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		d.refuse(w, r, "the door forwards to one sandboxed backend; it is not a forward proxy")
		return
	}
	if !secFetchSiteAllowed(r.Header.Get("Sec-Fetch-Site")) {
		d.refuse(w, r, "cross-site request refused")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != d.origin {
		d.refuse(w, r, "wrong origin")
		return
	}
	if r.Host != d.host {
		// The DNS-rebinding defence: a name that resolves to this address
		// still has to present it verbatim in the Host line.
		d.refuse(w, r, "wrong host")
		return
	}
	// The token is a BOOTSTRAP, and it lives in the QUERY STRING rather than the
	// path.
	//
	// Measured with it in the path: a page served at /<token>/index.html loads,
	// and the browser then asks the ORIGIN ROOT for every absolute reference in
	// it — /style.css, not /<token>/style.css — which arrives with no token and
	// is refused 403 before the backend sees it. That breaks every framework
	// emitting absolute URLs.
	//
	// A query parameter cannot be mistaken for a path the app has to live under,
	// and it is the shape people already know from Jupyter. The first request
	// carrying it sets a cookie and redirects to the same path WITHOUT the
	// parameter, so the browser's address bar ends up on the app's own URL and
	// the token is never seen again.
	//
	// SameSite=Strict is doing security work rather than tidiness: a browser
	// will not attach the cookie to a request a cross-site page initiated, so
	// the credential is absent exactly when the initiator is one this door
	// refuses. HttpOnly keeps the page's own scripts from reading it back out.
	q := r.URL.Query()
	switch {
	case q.Get(tokenParam) != "":
		if subtle.ConstantTimeCompare([]byte(q.Get(tokenParam)), []byte(d.cfg.Token)) != 1 {
			d.refuse(w, r, "missing or wrong token")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     doorCookie,
			Value:    d.cfg.Token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		q.Del(tokenParam)
		clean := *r.URL
		clean.RawQuery = q.Encode()
		// 303, not 302: the redirect must become a GET even if the bootstrap
		// request was a POST, because this URL is one a human typed.
		http.Redirect(w, r, clean.RequestURI(), http.StatusSeeOther)
		return
	case d.cookieAdmits(r):
		// Already bootstrapped; the app owns the whole path space.
	default:
		d.refuse(w, r, "missing or wrong token")
		return
	}
	if r.Header.Get("Upgrade") != "" {
		// Loud, not silent (invariant 5): a 501 naming the limitation, not a
		// request quietly forwarded as if upgrades worked.
		w.Header().Set("Connection", "close")
		http.Error(w, "WebSocket and SSE are not proxied yet", http.StatusNotImplemented)
		return
	}
	// The path reaches the backend untouched: the token never was one.
	d.forward(w, r)
}

// tokenParam is where the token rides in the URL a human opens. A QUERY
// parameter, never a path segment: a path prefix would be one the app has to
// live under, and every absolute URL it emits would miss it.
const tokenParam = "snug-token"

// doorCookie carries the token after the bootstrap redirect. The name is
// deliberately snug's own rather than something an app might already use.
const doorCookie = "snug_door_token"

// cookieAdmits reports whether the request carries this door's token in its
// cookie. Constant-time, because this value is the credential that stands
// between a page the human never opened and the sandbox's server, and a
// byte-by-byte comparison leaks its prefix to anything that can time requests.
func (d *Door) cookieAdmits(r *http.Request) bool {
	c, err := r.Cookie(doorCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(d.cfg.Token)) == 1
}

// secFetchSiteAllowed reports whether the browser's own initiator signal
// permits the request. Absence is allowed — curl and older browsers send
// none, and a header no one sent cannot be treated as a lie — but any value
// other than the two safe ones is refused, including one this door does not
// recognise: the accepted set is the whole set, never the nearest guess.
func secFetchSiteAllowed(v string) bool {
	switch v {
	case "", "none", "same-origin":
		return true
	}
	return false
}

func (d *Door) refuse(w http.ResponseWriter, r *http.Request, reason string) {
	d.log("%s: refused %s %s: %s", d.cfg.DoorName, r.Method, r.URL.Path, reason)
	http.Error(w, reason, http.StatusForbidden)
}

func (d *Door) log(format string, args ...any) {
	fmt.Fprintf(d.cfg.Log, format+"\n", args...)
}
