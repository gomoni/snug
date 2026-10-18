package cli

import (
	"bytes"
	"context"
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
	"regexp"
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

// hostAddressesForResolve feeds identity.kube's host-owned-server refusal. It
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

// kubeMintTimeout bounds one host-side mint. A kubectl that hangs — a network
// that blackholes, a cluster that never answers — must not hold the run.
const kubeMintTimeout = 30 * time.Second

// checkKubectlIsABinary refuses a host kubectl that is not an ELF executable:
// a distrobox-export wrapper, a host-spawn shim, an asdf shim. snug runs it
// with a cluster credential, so it must be a program snug can reason about,
// not a script that runs something else.
func checkKubectlIsABinary(path string) error {
	// HOSTREAD-EXEMPT: four bytes of a file that is tens of megabytes, which
	// hostread's whole-file read cannot express. O_NONBLOCK keeps a FIFO
	// planted at the path from blocking the open, and the Stat below refuses
	// anything but a regular file before a byte is read.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("host kubectl %s: %w", policy.VisibleText(path), err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("host kubectl %s is not a regular file; snug runs it on the host with your "+
			"cluster credential, so it must be the kubectl binary itself", policy.VisibleText(path))
	}
	// A second hard link is a second name the grant checks never judged — one
	// inside a target an earlier run could write lets that run replace the
	// bytes in place (red team, measured).
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return fmt.Errorf("host kubectl %s has %d hard links; a second name for the binary is a second "+
			"place it can be rewritten from, and snug runs it with your cluster credential — install "+
			"kubectl as a file of its own", policy.VisibleText(path), st.Nlink)
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
	return fmt.Errorf("host kubectl %s is not an executable snug can reason about%s. snug runs it on the "+
		"host with your cluster credential, so it must be the kubectl binary itself — put the official "+
		"static release (it is one file) on PATH ahead of it", policy.VisibleText(path), kind)
}

// judgeKubeMintBinary finds and judges the host kubectl, recording the verdict
// on pol for the --dry-run row.
func judgeKubeMintBinary(pol *policy.Policy, env policy.Environ) (string, error) {
	found, err := env.LookPath("kubectl")
	if err != nil {
		err = fmt.Errorf("kubectl not found on PATH; identity.kube mints its token with the host's kubectl")
	} else if found, err = pol.ResolveKubeMintBinary(env, found); err == nil {
		err = checkKubectlIsABinary(found)
	}
	if err != nil {
		pol.KubeMintProblem = err.Error()
		return "", err
	}
	pol.KubeMintBinary = found
	return found, nil
}

// kubeMintCmd builds the one host command a mint runs. Its own user and pid
// namespace is what reaps grandchildren: kubectl is pid 1 there, Pdeathsig
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

var kubeTokenShape = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// runKubeMint runs cmd to completion on a locked OS thread — Pdeathsig fires
// when the THREAD that forked the child exits, and the Go scheduler may retire
// an unlocked one while the child still runs — and parses the TokenRequest.
//
// The thread is UNLOCKED again once the child has been waited for, and that is
// not tidiness. A goroutine that exits while locked takes its OS thread with
// it, and the thread it locked may be one an EARLIER fork ran on — the stage's.
// The stage carries Pdeathsig too, so retiring that thread SIGKILLs it: measured
// as `the stage closed the control channel without reporting the payload's
// exit` partway through TestKubeBrokerBudgetRefuses, 64 mints in one run.
func runKubeMint(cmd *exec.Cmd) (kubebroker.Token, string, error) {
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
		return kubebroker.Token{}, errb.b.String(), err
	}
	var tr struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out.b.Bytes(), &tr); err != nil {
		return kubebroker.Token{}, errb.b.String(), fmt.Errorf("its output is not a TokenRequest: %w", err)
	}
	if len(tr.Status.Token) > 16<<10 || !kubeTokenShape.MatchString(tr.Status.Token) {
		return kubebroker.Token{}, errb.b.String(), errors.New("its token is empty, oversized or not a bearer token")
	}
	exp, err := time.Parse(time.RFC3339, tr.Status.ExpirationTimestamp)
	if err != nil || !exp.After(time.Now()) {
		return kubebroker.Token{}, errb.b.String(), errors.New("its expirationTimestamp is missing or in the past")
	}
	return kubebroker.Token{Value: policy.Secret(tr.Status.Token), Expiry: exp}, "", nil
}

// kubeRun is identity.kube's run-time half: the token source and, once the
// stage has handed over the relay socket, the proxy listening on it inside
// the sandbox's network namespace.
type kubeRun struct {
	pol    *policy.Policy
	src    *kubebroker.Source
	audit  func(string)
	mu     sync.Mutex
	proxy  *kubeproxy.Proxy
	closed bool
}

// startKubeIdentity is everything identity.kube needs before the sandbox
// starts: the host kubectl judged, the preflight mint, and the token source.
// A dry run judges and names, and starts nothing. The proxy itself starts in
// apply's relay callback, because its socket does not exist until the stage
// makes it.
func startKubeIdentity(pol *policy.Policy, env policy.Environ, verbose, dryRun bool) (*kubeRun, error) {
	k := pol.Kube
	if k == nil {
		return nil, nil
	}
	kubectl, kerr := judgeKubeMintBinary(pol, env)
	if dryRun {
		return nil, nil
	}
	if kerr != nil {
		return nil, kerr
	}
	rt, err := openRuntimeDir()
	if err != nil {
		return nil, err
	}
	home, err := rt.Mkdir("kube-home")
	if err != nil {
		return nil, err
	}
	cache, err := rt.Mkdir("kube-cache")
	if err != nil {
		return nil, err
	}
	const mintName = "kube-mint.json"
	mintFile := filepath.Join(rt.Path(), mintName)
	argv := k.MintArgv(kubectl, mintFile, cache)
	describe := policy.VisibleText(strings.Join(argv, " "))

	// The host credential is on disk only while a mint is in flight. A SIGKILL
	// mid-mint leaves it in this run's directory, under XDG_RUNTIME_DIR (a
	// tmpfs), until the next run's stale-directory sweep removes it.
	mint := func(ctx context.Context) (kubebroker.Token, error) {
		if _, err := rt.CreateFile(mintName, k.MintKubeconfig(), 0o600); err != nil {
			return kubebroker.Token{}, err
		}
		defer rt.RemoveFile(mintName)
		ctx, cancel := context.WithTimeout(ctx, kubeMintTimeout)
		defer cancel()
		t, stderr, err := runKubeMint(kubeMintCmd(ctx, argv, policy.KubeMintEnv(home)))
		if err != nil {
			return kubebroker.Token{}, fmt.Errorf("kube token mint failed: %s (env %s, cwd /) exited %v: %s",
				describe, strings.Join(policy.KubeMintEnvNames(), " "), err,
				policy.VisibleText(strings.TrimSpace(stderr)))
		}
		return t, nil
	}

	first, err := mint(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%w. kubectl inside would have no cluster to reach; not starting", err)
	}
	// The cluster decides the lifetime. The token never enters the sandbox,
	// so a long one is no longer a long life for a stolen copy — but it is
	// how long the cluster would honour this one if it leaked from the host.
	if first.Expiry.After(time.Now().Add(time.Hour + 10*time.Minute)) {
		fmt.Fprintf(os.Stderr, "snug: the cluster issued a token valid until %s (requested 1h).\n",
			first.Expiry.UTC().Format(time.RFC3339))
	}
	audit := func(string) {}
	if verbose {
		audit = func(msg string) { fmt.Fprintln(os.Stderr, "snug: kube: "+policy.VisibleText(msg)) }
	}
	audit(fmt.Sprintf("kube token minted at start, valid until %s", first.Expiry.UTC().Format(time.RFC3339)))
	src, err := kubebroker.New(kubebroker.Config{Mint: mint, MintTimeout: kubeMintTimeout, Audit: audit}, first)
	if err != nil {
		return nil, err
	}
	return &kubeRun{pol: pol, src: src, audit: audit}, nil
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
		return fmt.Errorf("identity.kube: binding the proxy to 127.0.0.1:%d inside the sandbox: %w",
			policy.KubeProxyGuestPort, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return fmt.Errorf("identity.kube: listening on 127.0.0.1:%d inside the sandbox: %w",
			policy.KubeProxyGuestPort, err)
	}
	ln, err := net.FileListener(f)
	if err != nil {
		return fmt.Errorf("identity.kube: the proxy's listener: %w", err)
	}
	k := r.pol.Kube
	server, err := url.Parse(k.Server)
	if err != nil {
		ln.Close()
		return fmt.Errorf("identity.kube: server %s: %w", policy.VisibleText(k.Server), err)
	}
	var pool *x509.CertPool
	if len(k.CAData) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(k.CAData) {
			ln.Close()
			return errors.New("identity.kube: the cluster's certificate-authority-data holds no certificate")
		}
	}
	var hosts []netip.Addr
	for _, h := range hostAddressesForResolve() {
		if a, err := netip.ParseAddr(h); err == nil {
			hosts = append(hosts, a)
		}
	}
	p, err := kubeproxy.New(kubeproxy.Config{
		Listener: ln, Server: server, CAs: pool, TLSName: k.TLSServerName,
		Token: r.src.Token, HostAddrs: hosts, Audit: r.audit,
	})
	if err != nil {
		ln.Close()
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		ln.Close()
		return errors.New("identity.kube: the run ended before the proxy started")
	}
	r.proxy = p
	go p.Serve()
	return nil
}

// close stops the proxy — every connection on both sides — and cancels a mint
// in flight. Safe on a nil run.
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
	r.src.Close()
}
