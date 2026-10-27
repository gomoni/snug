//go:build integration

package integration

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// hostVendor plays Claude's two OAuth endpoints for the host-mode tests,
// without a knob in snug: snug's http client honours HTTPS_PROXY and
// SSL_CERT_FILE like any Go program, so the test points those two variables
// at a CONNECT proxy that terminates TLS under a CA of its own. The endpoints
// and the client id stay constants in the binary under test; nothing here
// re-aims them. What the vendor records is what snug really sent, which is
// also how a test proves the exchange was attempted against the pinned host
// and no other.
//
// It never speaks to the network, never sees a real credential, and answers
// every account with the fixture ones.
type hostVendor struct {
	addr   string
	caFile string

	mu       sync.Mutex
	connects []string // CONNECT targets, in order
	tokens   []string // request bodies of POST /v1/oauth/token
	profiles []string // Authorization headers of GET /api/oauth/profile
	gate     chan struct{}
	arrived  chan struct{}
	done     chan struct{}
	tokenOut string
	profOut  string
}

// newHostVendor starts the proxy. Its token answer is for the account
// acct (uuids acc-<acct>, org-<acct>), tokens NEW-AT-<acct> / NEW-RT-<acct>.
func newHostVendor(t *testing.T, acct string) *hostVendor {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "snug host-login test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	v := &hostVendor{addr: ln.Addr().String(), caFile: caFile, arrived: make(chan struct{}, 8), done: make(chan struct{}),
		tokenOut: fmt.Sprintf(`{"token_type":"Bearer","access_token":"NEW-AT-%[1]s","refresh_token":"NEW-RT-%[1]s",`+
			`"expires_in":3600,"refresh_token_expires_in":2592000,"scope":"user:inference user:profile",`+
			`"account":{"uuid":"acc-%[1]s","email_address":"fixture-%[1]s@example.com"},"organization":{"uuid":"org-%[1]s"}}`, acct),
		profOut: fmt.Sprintf(`{"account":{"uuid":"acc-%[1]s","email":"fixture-%[1]s@example.com"},`+
			`"organization":{"uuid":"org-%[1]s","organization_type":"claude_max","rate_limit_tier":"t"}}`, acct)}
	leaf := func(host string) tls.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: host},
			DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: k}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go v.serve(c, leaf)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		close(v.done)
	})
	return v
}

// holdToken makes the token endpoint read the request and then wait, so a
// test can act while an exchange is in flight. The returned function lets it
// answer.
func (v *hostVendor) holdToken() (release func()) {
	g := make(chan struct{})
	v.mu.Lock()
	v.gate = g
	v.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(g) }) }
}

func (v *hostVendor) serve(c net.Conn, leaf func(string) tls.Certificate) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(90 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil || req.Method != http.MethodConnect {
		fmt.Fprint(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	v.mu.Lock()
	v.connects = append(v.connects, req.Host)
	v.mu.Unlock()
	host, _, _ := net.SplitHostPort(req.Host)
	fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{leaf(host)}})
	if tc.Handshake() != nil {
		return
	}
	r, err := http.ReadRequest(bufio.NewReader(tc))
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	out := ""
	var gate chan struct{}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/oauth/token":
		v.mu.Lock()
		v.tokens = append(v.tokens, string(body))
		gate, out = v.gate, v.tokenOut
		v.mu.Unlock()
		v.arrived <- struct{}{}
		if gate != nil {
			select {
			case <-gate:
			case <-v.done:
				return
			case <-time.After(60 * time.Second):
				return
			}
		}
	case r.Method == http.MethodGet && r.URL.Path == "/api/oauth/profile":
		v.mu.Lock()
		v.profiles = append(v.profiles, r.Header.Get("Authorization"))
		out = v.profOut
		v.mu.Unlock()
	default:
		fmt.Fprint(tc, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	fmt.Fprintf(tc, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"+
		"request-id: req_fixture\r\nConnection: close\r\n\r\n%s", len(out), out)
}

// env is what to append to snug's environment to route its HTTPS through the
// vendor. NO_PROXY is emptied so nothing inherited bypasses it.
func (v *hostVendor) env() []string {
	return []string{"HTTPS_PROXY=http://" + v.addr, "https_proxy=http://" + v.addr,
		"NO_PROXY=", "no_proxy=", "SSL_CERT_FILE=" + v.caFile, "SSL_CERT_DIR="}
}

func (v *hostVendor) seen() (connects, tokens, profiles []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string{}, v.connects...), append([]string{}, v.tokens...), append([]string{}, v.profiles...)
}

// waitToken blocks until a token request reached the vendor.
func (v *hostVendor) waitToken(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-v.arrived:
	case <-time.After(d):
		t.Fatalf("the token endpoint was never asked within %s, so nothing below was measured mid-exchange", d)
	}
}

// hostLoginAccount is hostLoginHome for the account acct: ~/.claude.json
// pins acc-<acct>/org-<acct> and the credential file holds FIXTURE-AT-<acct>
// and FIXTURE-RT-<acct>, so two homes never share a value.
func hostLoginAccount(t *testing.T, acct string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		".claude.json": fmt.Sprintf(`{"oauthAccount":{"accountUuid":"acc-%[1]s","organizationUuid":"org-%[1]s",`+
			`"emailAddress":"fixture-%[1]s@example.com"}}`, acct),
		".claude/.credentials.json": fmt.Sprintf(`{"claudeAiOauth":{"accessToken":"FIXTURE-AT-%[1]s",`+
			`"refreshToken":"FIXTURE-RT-%[1]s","expiresAt":4102444800000,"scopes":["user:inference"],`+
			`"subscriptionType":"max","rateLimitTier":"t"}}`, acct),
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// hostRun is one host-mode snug run held at a pending login: the opener ran,
// the host listener is up, and the probe waits in the sandbox.
type hostRun struct {
	s     *bgSandbox
	f     *loginFixture
	home  string
	rt    string
	port  int
	state string
}

var hostStateRe = regexp.MustCompile(`[&?]state=([A-Za-z0-9_-]+)`)

// startHostRun starts a host-mode run for home against the vendor and waits
// until the browser has been "opened" (the fake opener recorded the URL) and
// the host listener accepts. The probe stays in the sandbox until the test
// writes the file named release.
//
// prelude is bash run before the probe in the same sandbox; a test that
// wants a view from inside backgrounds a loop in it.
func startHostRun(t *testing.T, f *loginFixture, rt, home string, v *hostVendor, prelude string, probeArgs ...string) *hostRun {
	t.Helper()
	f.addProfile(t, "login-host", "[profile.login-host]\ndescription = \"host mode\"\nlogin.claude = \"host\"\n")
	env := append(append(append([]string{}, f.env...), fixtureHome(home)...), v.env()...)
	args := []string{"-p", "@claude", "-p", "@net", "-p", "login-host", f.proj, "--", "/bin/bash", "-c",
		"printf '%s\\n' " + payloadMarker + "\n" + prelude + "\n./loginprobe " + strings.Join(append(probeArgs, "release=release"), " ")}
	cmd := exec.Command(snugFor(env), args...)
	cmd.Env = env
	log, err := os.CreateTemp(t.TempDir(), "snug-host-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log
	s := &bgSandbox{proc: startBgProc(t, cmd), logPath: log.Name(), proj: f.proj}
	out := waitForLogLine(t, s, "SHIM-RC", 30*time.Second)
	if !loginWaitOpenerRan(t, f.rec, 10*time.Second) {
		t.Fatalf("precondition: the fake opener never ran:\n%s", out)
	}
	argv, _ := loginRec(t, f.rec, "argv")
	m := hostStateRe.FindStringSubmatch(argv)
	if m == nil {
		t.Fatalf("precondition: the opener's argv carries no state:\n%s", argv)
	}
	port := loginPort(t, out)
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: the host listener is not up on %d:\n%s", port, s.log())
	}
	return &hostRun{s: s, f: f, home: home, rt: rt, port: port, state: m[1]}
}

// callback plays the human's browser: one callback with a fake code and the
// state of the URL the opener was given. The answer arrives on the channel,
// "" if the connection ended without one.
func (r *hostRun) callback(t *testing.T) <-chan string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		out, _ := loginHostRequest(t, r.port, "/callback?code=FAKE-CODE-1&state="+r.state)
		ch <- out
	}()
	return ch
}

func (r *hostRun) runDir() string   { return r.s.runDir(r.rt) }
func (r *hostRun) hostCred() string { return filepath.Join(r.home, ".claude", ".credentials.json") }
