package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/kubebroker"
	"github.com/gomoni/snug/internal/kubeproxy"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

// hostAddressesForResolve feeds identity.kubectl's host-owned-server refusal. It
// is a usability check, not the seal, so an interface enumeration that fails
// leaves it empty rather than refusing the run; the stage enumerates again and
// does refuse.
func hostAddressesForResolve() []string {
	a, err := sandbox.HostAddresses()
	if err != nil {
		return nil
	}
	return a
}

// kubeMintTimeout bounds one run of the exec plugin. A plugin that hangs — a
// network that blackholes, a login that never answers — must not hold the run.
const kubeMintTimeout = 30 * time.Second

// checkHostBinaryIsELF refuses a host program identity.kubectl runs that is not
// an ELF executable: a distrobox-export wrapper, a host-spawn shim, an asdf
// shim, aws CLI v1 (a Python script). snug runs it with a cluster credential,
// so it must be a program snug can reason about, not a script that runs
// something else. what names it in messages, name is the program.
func checkHostBinaryIsELF(what, name, path string) error {
	// HOSTREAD-EXEMPT: four bytes of a file that is tens of megabytes, which
	// hostread's whole-file read cannot express. O_NONBLOCK keeps a FIFO
	// planted at the path from blocking the open, and the Stat below refuses
	// anything but a regular file before a byte is read.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("%s %s: %w", what, policy.VisibleText(path), err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s %s is not a regular file; snug runs it on the host with your "+
			"cluster credential, so it must be the %s binary itself", what, policy.VisibleText(path), name)
	}
	// A second hard link is a second name the grant checks never judged — one
	// inside a target an earlier run could write lets that run replace the
	// bytes in place (red team, measured).
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return fmt.Errorf("%s %s has %d hard links; a second name for the binary is a second "+
			"place it can be rewritten from, and snug runs it with your cluster credential — install "+
			"%s as a file of its own", what, policy.VisibleText(path), st.Nlink, name)
	}
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	if n == 4 && string(head) == "\x7fELF" {
		return nil
	}
	kind := ""
	if n >= 2 && string(head[:2]) == "#!" {
		kind = ": it is a script"
	}
	return fmt.Errorf("%s %s is not an executable snug can reason about%s. snug runs it on the "+
		"host with your cluster credential, so it must be the %s binary itself — install the official "+
		"release binary (for aws, CLI v2) where snug looks for it", what, policy.VisibleText(path), kind, name)
}

// lookPluginPATH finds a bare plugin command on policy.KubePluginPATH only;
// an absolute one is returned as written, for ResolveKubeHostBinary.
func lookPluginPATH(env policy.Environ, cmd string) (string, error) {
	if filepath.IsAbs(cmd) {
		return cmd, nil
	}
	// Stat, not ResolveExistingHostPath: that resolves the longest existing
	// prefix and succeeds for a file that is not there, which returned the
	// first PATH entry for every name (red team, measured).
	for _, dir := range strings.Split(policy.KubePluginPATH, ":") {
		c := dir + "/" + cmd
		if fi, err := env.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c, nil
		}
	}
	return "", fmt.Errorf("%s not found on %s; snug looks up a bare exec-plugin command there only, never on "+
		"your PATH — install it there, or name it by absolute path in the kubeconfig",
		policy.VisibleText(cmd), policy.KubePluginPATH)
}

// judgeKubePlugin finds and judges the host context's exec plugin and the
// helpers it runs, recording the verdict on pol for the --dry-run row. A
// helper is judged for writability only: az is a script on every install.
func judgeKubePlugin(pol *policy.Policy, env policy.Environ) (string, error) {
	pl := pol.Kube.Plugin
	what := "kube exec plugin"
	found, err := lookPluginPATH(env, pl.Command)
	if err == nil {
		if found, err = pol.ResolveKubeHostBinary(env, what, found); err == nil {
			err = checkHostBinaryIsELF(what, pl.Row, found)
		}
	}
	for _, h := range pl.Helpers {
		if err != nil {
			break
		}
		if hp, lerr := lookPluginPATH(env, h); lerr == nil {
			_, err = pol.ResolveKubeHostBinary(env, "kube exec plugin helper", hp)
		}
	}
	if err != nil {
		pol.KubePluginProblem = err.Error()
		return "", err
	}
	pol.KubePluginBinary = found
	return found, nil
}

// kubeMintCmd builds the one host command a plugin run is. Its own user and pid
// namespace is what reaps grandchildren: the plugin is pid 1 there, Pdeathsig
// kills it when the thread that started it dies, and the kernel kills every
// other process in a pid namespace when its pid 1 exits — a plain process
// group does not survive SIGKILL of snug that way. Measured with unshare: a
// setsid grandchild under --pid --kill-child was gone after SIGKILL of the
// parent; the same grandchild without the pid namespace survived.
func kubeMintCmd(ctx context.Context, argv, env []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = "/"
	uid, gid := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
		Setpgid:                    true,
	}
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 2 * time.Second
	return cmd
}

// cappedBuffer keeps the first max bytes written and drops the rest.
type cappedBuffer struct {
	b   bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.b.Len(); room > 0 {
		c.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// runKubeExec runs a plugin to completion and parses its ExecCredential. Only the token and its expiry are kept: a certificate in
// the answer refuses, because snug's proxy holds no client certificate, and
// every other field and the plugin's stderr stay on the host.
func runKubeExec(cmd *exec.Cmd, apiVersion string) (kubebroker.Token, string, error) {
	out, stderr, err := runKubeCmd(cmd)
	if err != nil {
		return kubebroker.Token{}, stderr, err
	}
	var ec struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token                 string `json:"token"`
			ExpirationTimestamp   string `json:"expirationTimestamp"`
			ClientCertificateData string `json:"clientCertificateData"`
			ClientKeyData         string `json:"clientKeyData"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &ec); err != nil {
		return kubebroker.Token{}, stderr, fmt.Errorf("its output is not an ExecCredential: %w", err)
	}
	if ec.Kind != "ExecCredential" || ec.APIVersion != apiVersion {
		return kubebroker.Token{}, stderr, fmt.Errorf("its output is %s %s, want ExecCredential %s",
			policy.VisibleText(ec.Kind), policy.VisibleText(ec.APIVersion), apiVersion)
	}
	if ec.Status.ClientCertificateData != "" || ec.Status.ClientKeyData != "" {
		return kubebroker.Token{}, stderr, errors.New("it answered with a client certificate; snug presents " +
			"an exec plugin's token only")
	}
	t, err := tokenOf(ec.Status.Token, ec.Status.ExpirationTimestamp)
	return t, stderr, err
}

func tokenOf(tok, expiry string) (kubebroker.Token, error) {
	if !policy.KubeTokenOK(tok) {
		return kubebroker.Token{}, errors.New("its token is empty, oversized or not a bearer token")
	}
	exp, err := time.Parse(time.RFC3339, expiry)
	if err != nil || !exp.After(time.Now()) {
		return kubebroker.Token{}, errors.New("its expirationTimestamp is missing or in the past; a token " +
			"of unknown life is not cached")
	}
	return kubebroker.Token{Value: policy.Secret(tok), Expiry: exp}, nil
}

// runKubeCmd runs cmd to completion on a locked OS thread — Pdeathsig fires
// when the THREAD that forked the child exits, and the Go scheduler may retire
// an unlocked one while the child still runs. It returns stdout (capped at 1
// MiB) and stderr (capped at 16 KiB).
//
// The thread is UNLOCKED again once the child has been waited for, and that is
// not tidiness. A goroutine that exits while locked takes its OS thread with
// it, and the thread it locked may be one an EARLIER fork ran on — the stage's.
// The stage carries Pdeathsig too, so retiring that thread SIGKILLs it: measured
// as `the stage closed the control channel without reporting the payload's
// exit` partway through TestKubeBrokerBudgetRefuses, 64 mints in one run.
func runKubeCmd(cmd *exec.Cmd) ([]byte, string, error) {
	var out, errb cappedBuffer
	out.max, errb.max = 1<<20, 16<<10
	cmd.Stdout, cmd.Stderr = &out, &errb
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		done <- cmd.Run()
	}()
	if err := <-done; err != nil {
		return nil, errb.b.String(), err
	}
	return out.b.Bytes(), errb.b.String(), nil
}

// kubeRun is identity.kubectl's run-time half: the credential the proxy
// presents — a client certificate, a static token, or the exec plugin's token
// source — and, once the stage has handed over the relay socket, the proxy
// listening on it inside the sandbox's network namespace.
type kubeRun struct {
	pol    *policy.Policy
	src    *kubebroker.Source // exec only
	token  *policy.Secret     // static token only; a pointer, so fmt never prints it
	cert   *tls.Certificate   // client certificate only
	audit  func(string)
	mu     sync.Mutex
	proxy  *kubeproxy.Proxy
	closed bool
}

// startKubeIdentity is everything identity.kubectl needs before the sandbox
// starts: the credential loaded into snug's memory and, for an exec plugin,
// the plugin judged and run once. A dry run judges and names, and starts
// nothing. The proxy itself starts in apply's relay callback, because its
// socket does not exist until the stage makes it. Nothing here writes a file.
func startKubeIdentity(pol *policy.Policy, env policy.Environ, verbose, dryRun bool) (*kubeRun, error) {
	k := pol.Kube
	if k == nil {
		return nil, nil
	}
	var plugin string
	var perr error
	if k.Plugin != nil {
		plugin, perr = judgeKubePlugin(pol, env)
	}
	if dryRun {
		return nil, nil
	}
	if perr != nil {
		return nil, perr
	}
	audit := func(string) {}
	if verbose {
		audit = func(msg string) { fmt.Fprintln(os.Stderr, "snug: kubectl: "+policy.VisibleText(msg)) }
	}
	r := &kubeRun{pol: pol, audit: audit}
	server := policy.VisibleText(k.Server)
	switch k.Credential {
	case policy.KubeCredentialClientCert:
		// The clock is read here, not in Resolve: a certificate past its
		// notAfter would answer every request with a handshake failure.
		if time.Now().After(k.CertNotAfter) {
			return nil, fmt.Errorf("identity.kubectl: the client certificate of context %s (%s) expired on %s; "+
				"refresh it with your cloud's get-credentials command", policy.VisibleText(k.Context),
				k.CertSubject, k.CertNotAfter.UTC().Format(time.DateOnly))
		}
		c, err := tls.X509KeyPair(k.HostUser.ClientCertData, k.HostUser.ClientKeyData)
		if err != nil {
			return nil, fmt.Errorf("identity.kubectl: the client certificate of context %s: %w",
				policy.VisibleText(k.Context), err)
		}
		r.cert = &c
		audit(fmt.Sprintf("presenting client certificate %s (expires %s) to %s as context %s", k.CertSubject,
			k.CertNotAfter.UTC().Format(time.DateOnly), server, policy.VisibleText(k.Context)))
	case policy.KubeCredentialToken:
		tok := k.HostUser.Token
		r.token = &tok
		audit(fmt.Sprintf("presenting static token (%d chars) to %s as context %s", k.TokenLen, server,
			policy.VisibleText(k.Context)))
	case policy.KubeCredentialExec:
		// The plugin runs as the host user it is: HOME is the host home, where
		// its own ~/.azure or ~/.aws lives (judged unwritable by Resolve).
		pl := k.Plugin
		argv := pl.KubeExecArgv(plugin)
		describe := policy.VisibleText(strings.Join(argv, " "))
		mint := func(ctx context.Context) (kubebroker.Token, error) {
			ctx, cancel := context.WithTimeout(ctx, kubeMintTimeout)
			defer cancel()
			t, stderr, err := runKubeExec(kubeMintCmd(ctx, argv, pl.KubePluginEnv(pol.Home)), pl.APIVersion)
			if err != nil {
				return kubebroker.Token{}, fmt.Errorf("kube exec plugin failed: %s (env %s, cwd /) exited %v: %s",
					describe, strings.Join(pl.EnvNames(), " "), err, policy.VisibleText(strings.TrimSpace(stderr)))
			}
			return t, nil
		}
		first, err := mint(context.Background())
		if err != nil {
			return nil, fmt.Errorf("%w. kubectl inside would have no cluster to reach; not starting", err)
		}
		audit(fmt.Sprintf("presenting the %s plugin's token (valid until %s) to %s as context %s", pl.Row,
			first.Expiry.UTC().Format(time.RFC3339), server, policy.VisibleText(k.Context)))
		src, err := kubebroker.New(kubebroker.Config{Mint: mint, MintTimeout: kubeMintTimeout, Audit: audit}, first)
		if err != nil {
			return nil, err
		}
		r.src = src
	default:
		return nil, fmt.Errorf("identity.kubectl: no credential resolved for context %s", policy.VisibleText(k.Context))
	}
	return r, nil
}

// apply asks the stage for the proxy's one relay socket. A nil run — no kube
// identity, or a dry run — asks for none.
func (r *kubeRun) apply(o *sandbox.Options) {
	if r == nil {
		return
	}
	addRelaySockets(o, 1, r.listen)
}

// listen binds the relay socket to policy.KubeProxyGuest inside the sandbox's
// network namespace and starts the proxy on it. It runs before bwrap is
// forked, so nothing inside can hold the port first; and the socket is bound
// without SO_REUSEADDR or SO_REUSEPORT, so nothing inside can bind it beside
// the proxy afterwards either (measured: a payload bind on 127.0.0.1:6443 and
// on 0.0.0.0:6443 gets EADDRINUSE).
func (r *kubeRun) listen(fs []*os.File) error {
	f := fs[0]
	defer f.Close()
	fd := int(f.Fd())
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: policy.KubeProxyGuestPort, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return fmt.Errorf("identity.kubectl: binding the proxy to 127.0.0.1:%d inside the sandbox: %w",
			policy.KubeProxyGuestPort, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return fmt.Errorf("identity.kubectl: listening on 127.0.0.1:%d inside the sandbox: %w",
			policy.KubeProxyGuestPort, err)
	}
	ln, err := net.FileListener(f)
	if err != nil {
		return fmt.Errorf("identity.kubectl: the proxy's listener: %w", err)
	}
	k := r.pol.Kube
	server, err := url.Parse(k.Server)
	if err != nil {
		ln.Close()
		return fmt.Errorf("identity.kubectl: server %s: %w", policy.VisibleText(k.Server), err)
	}
	var pool *x509.CertPool
	if len(k.CAData) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(k.CAData) {
			ln.Close()
			return errors.New("identity.kubectl: the cluster's certificate-authority-data holds no certificate")
		}
	}
	var hosts []netip.Addr
	for _, h := range hostAddressesForResolve() {
		if a, err := netip.ParseAddr(h); err == nil {
			hosts = append(hosts, a)
		}
	}
	cfg := kubeproxy.Config{
		Listener: ln, Server: server, CAs: pool, TLSName: k.TLSServerName,
		ClientCert: r.cert, HostAddrs: hosts, Audit: r.audit,
	}
	switch {
	case r.src != nil:
		cfg.Token = r.src.Token
	case r.token != nil:
		tok := *r.token
		cfg.Token = func(context.Context) (policy.Secret, error) { return tok, nil }
	}
	p, err := kubeproxy.New(cfg)
	if err != nil {
		ln.Close()
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		ln.Close()
		return errors.New("identity.kubectl: the run ended before the proxy started")
	}
	r.proxy = p
	go p.Serve()
	return nil
}

// close stops the proxy — every connection on both sides — and cancels a
// plugin run in flight. Safe on a nil run.
func (r *kubeRun) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	p := r.proxy
	r.mu.Unlock()
	if p != nil {
		p.Close()
	}
	if r.src != nil {
		r.src.Close()
	}
}
