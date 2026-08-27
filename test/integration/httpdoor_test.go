//go:build integration

package integration

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── @http-proxy: the descriptor handover ───────────────────────────────────
//
// The design's own §9 admitted this was unmeasured through snug: a red-team
// round proved a descriptor crosses bwrap by mirroring snug's flags in a bare
// bwrap invocation, which is evidence about bwrap and not about snug. This test
// is the end-to-end version, and it asserts the three things the feature stands
// on:
//
//	the descriptor ARRIVES, at the number LISTEN_FDS names, still listening
//	LISTEN_PID equals the payload's OWN pid, so a conforming client uses it
//	the socket carries TRAFFIC — the host connects and the payload answers
//
// The third is what stops the first two passing on a socket that exists and goes
// nowhere. LISTEN_PID is the one a naive implementation gets wrong: snug cannot
// predict a pid inside a fresh pid namespace, so a staged script sets it with
// `exec`, and a wrong value makes every conforming library SILENTLY ignore the
// descriptor — a door that reaches a sandbox where nothing ever accepts.

func buildDoorProbe(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "doorprobe")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/doorprobe")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/doorprobe: %v: %s", err, out.String())
	}
	return bin
}

func TestTheHTTPDoorDescriptorReachesThePayload(t *testing.T) {
	// BEFORE budget(t): buildDoorProbe runs `go build`, and a cold one takes
	// longer than the 10s budget the watchdog allows for sandbox work. Measured
	// — this test passed when a sibling had already warmed the build cache and
	// blew the budget when run alone, which is a test that fails for a reason
	// that has nothing to do with what it asserts.
	probe := buildDoorProbe(t)
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	env := envProfileLayer(t, "door.toml", fmt.Sprintf(`[profile.doortest]
description = "one http door, and the probe that answers on it"
ro = ["%s:/doorprobe"]
listen_names = ["web"]
`, probe), os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, snugBin, "-p", "doortest", proj, "--", "/doorprobe")
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting snug: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	found := awaitDoorProbe(t, proj)

	if got := found["LISTEN-FDS"]; got != "1" {
		t.Errorf("LISTEN_FDS = %q inside, want \"1\" — one door was declared", got)
	}
	if got := found["LISTEN-FDNAMES"]; got != "web" {
		t.Errorf("LISTEN_FDNAMES = %q inside, want \"web\"", got)
	}
	// THE assertion. Equal, not merely present: a plausible-looking wrong pid is
	// exactly the failure mode, because conforming clients ignore the descriptor
	// silently rather than complaining.
	pid, mine := found["LISTEN-PID"], found["MY-PID"]
	if pid == "" || mine == "" {
		// Without this the comparison below passes when BOTH are empty, which is
		// exactly what a run that never set the variables looks like — the
		// vacuous pass this file's own subject matter is about.
		t.Fatalf("LISTEN_PID = %q and the payload's pid = %q: one of them is missing, so the "+
			"equality check below would pass on a run that set neither", pid, mine)
	}
	if pid != mine {
		t.Errorf("LISTEN_PID = %q but the payload's own pid is %q. A conforming client ignores "+
			"the descriptor on mismatch, silently, so the door would reach a sandbox where "+
			"nothing ever accepts. The staged `exec` handover is what makes these equal",
			pid, mine)
	}

	sock := found["SOCKET"]
	if sock == "" {
		t.Fatal("the payload never reported the socket path getsockname gave it, so there is " +
			"nothing to connect to and the traffic half of this test cannot run")
	}
	// The path is visible from inside — a leak the design states rather than
	// fixes, because `snug proxy` connects to this socket BY PATH and unlinking
	// it would break the feature.
	if !strings.HasSuffix(sock, "door-web.sock") {
		t.Errorf("socket path %q does not end in the door's own name; the name is what "+
			"LISTEN_FDNAMES promises and what --dry-run prints", sock)
	}

	// Now the traffic. This is the host side of the door: exactly what
	// `snug proxy` does, minus the HTTP checks.
	c, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		t.Fatalf("the host cannot connect to the socket the payload is accepting on (%s): %v",
			sock, err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: doortest\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("writing to the door socket: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading the payload's answer: %v", err)
	}
	if !strings.Contains(string(body), "served-by-the-payload") {
		t.Errorf("the payload answered, but not with its own body — the socket exists and "+
			"carries something else:\n%s", body)
	}

	// And the socket must be gone with the run. A door still listening on the
	// host after teardown is a leaked inbound hole, which rates with a policy
	// leak rather than with litter.
	_ = cmd.Wait()
	if _, err := os.Stat(sock); err == nil {
		t.Errorf("%s still exists after the run exited — the run directory is removed on the "+
			"way out, so a surviving socket means something else is holding it", sock)
	}
}

// The negative arm. Without a door, nothing in the sandbox names one — no
// LISTEN_FDS, no handover script on the command, no socket. Without this, every
// assertion above could pass on a build that set the variables unconditionally.
func TestWithoutAnHTTPDoorNothingNamesOne(t *testing.T) {
	budget(t)
	requireSandbox(t)

	proj, _ := target(t)
	out, code := cli(t, baseEnv(), proj, "--", "/bin/sh", "-c",
		`echo "FDS=[${LISTEN_FDS-unset}] NAMES=[${LISTEN_FDNAMES-unset}] PID=[${LISTEN_PID-unset}]"; ls /snug/bin 2>&1 || true`)
	if code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "FDS=[unset]") ||
		!strings.Contains(out, "NAMES=[unset]") ||
		!strings.Contains(out, "PID=[unset]") {
		t.Errorf("a sandbox with no http door still carries the socket-activation variables, "+
			"so a payload would look for a descriptor nothing handed it:\n%s", out)
	}
	if strings.Contains(out, "http-door-handover") {
		t.Errorf("the handover script is staged for a run that declared no door:\n%s", out)
	}
}

// TestSnugProxyServesTheDoorToTheHost is the whole feature end to end: a run
// declares a door, a HUMAN runs `snug proxy`, and a request from the host
// reaches the payload and comes back.
//
// It also pins the four refusals that are the door's entire bound, because the
// package's own unit tests drive them through httptest while this drives them
// through a real listener on a real per-run address:
//
//	a cross-site initiator, a foreign Origin, a wrong token, a rebound Host
//
// And it asserts what the door STRIPS: a hostile backend sending
// Access-Control-Allow-Origin must not have it forwarded, or a page on any
// origin could read the sandbox's answers.
func TestSnugProxyServesTheDoorToTheHost(t *testing.T) {
	probe := buildDoorProbe(t) // before budget(t); see the sibling test
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	env := envProfileLayer(t, "door.toml", fmt.Sprintf(`[profile.doortest]
description = "one http door, and a probe that answers on it"
ro = ["%s:/doorprobe"]
listen_names = ["web"]
`, probe), os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	run := exec.CommandContext(ctx, snugBin, "-p", "doortest", proj, "--", "/doorprobe")
	run.Env = env
	run.WaitDelay = waitDelay
	var runOut strings.Builder
	run.Stdout, run.Stderr = &runOut, &runOut
	if err := run.Start(); err != nil {
		t.Fatalf("starting the sandbox: %v", err)
	}
	defer func() {
		// Kill rather than Wait: the payload serves ONE request and this test
		// makes several, so the run may still be sitting in accept(). A test
		// that leaves a sandbox behind is a finding in its own right.
		_ = run.Process.Kill()
		_ = run.Wait()
	}()

	awaitDoorProbe(t, proj)

	// The human's command. Its stderr carries the URL and the escape sentence,
	// which is the channel the payload cannot rewrite — unlike the generated
	// CLAUDE.md preamble, which lives in the writable project tree.
	proxy := exec.CommandContext(ctx, snugBin, "proxy", proj)
	proxy.Env = env
	proxy.WaitDelay = waitDelay
	proxyErr, err := proxy.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.Start(); err != nil {
		t.Fatalf("starting snug proxy: %v", err)
	}
	defer func() {
		_ = proxy.Process.Signal(os.Interrupt)
		_ = proxy.Wait()
	}()

	var url, announced string
	psc := bufio.NewScanner(proxyErr)
	for psc.Scan() {
		line := psc.Text()
		announced += line + "\n"
		// "Open:" appears only from the door's Ready callback, i.e. after the
		// listener is bound — so finding it here is also the test's proof that
		// the URL is never printed before it works.
		if i := strings.Index(line, "http://"); i >= 0 {
			url = strings.TrimSpace(line[i:])
			break
		}
	}
	if url == "" {
		t.Fatalf("`snug proxy` never printed a URL:\n%s", announced)
	}
	// Drain the rest, or the proxy blocks writing its refusal log lines into a
	// pipe nobody reads — the same shape as the payload-stdout hang that made
	// awaitDoorProbe poll a file instead.
	go func() { _, _ = io.Copy(io.Discard, proxyErr) }()
	if !strings.Contains(announced, "SANDBOX ESCAPE") {
		t.Errorf("`snug proxy` opened a door without telling the human on their own terminal "+
			"that it is an escape. That sentence must not live only in the generated "+
			"preamble, which the payload can rewrite:\n%s", announced)
	}

	// A cookie jar, because the URL a human opens is a BOOTSTRAP: it plants a
	// cookie and redirects to the app's own root. Without the jar every request
	// after the first is refused, which is also the proof that the token is not
	// a path prefix the app has to live under.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 20 * time.Second, Jar: jar}
	// Jar-LESS: what a page the human never opened actually has. The bootstrap
	// cookie lives in `client` above and must not leak into these rows, or
	// "wrong token" would be admitted by the cookie and prove nothing.
	plain := &http.Client{Timeout: 20 * time.Second}

	get := func(t *testing.T, c *http.Client, u string, hdr map[string]string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range hdr {
			if k == "Host" {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	resp, body := get(t, client, url, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("the human's own request got %d, want 200:\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "served-by-the-payload") {
		t.Errorf("the door answered 200 but not with the payload's body — something other "+
			"than the sandbox is serving this address:\n%s", body)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("the door forwarded a response without its own frame-ancestors policy")
	}

	// The four refusals. Each is the whole bound for one attack, so each gets an
	// assertion rather than a comment.
	for _, tc := range []struct {
		name string
		url  string
		hdr  map[string]string
	}{
		{"a cross-site initiator", url, map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"a foreign Origin", url, map[string]string{"Origin": "https://evil.example"}},
		{"a wrong token", strings.TrimSuffix(url, "/")[:strings.LastIndex(strings.TrimSuffix(url, "/"), "/")] + "/deadbeefdeadbeef/", nil},
		{"a rebound Host", url, map[string]string{"Host": "evil.test:8099"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := get(t, plain, tc.url, tc.hdr)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s got %d, want 403 — this is the door's entire defence against "+
					"a page the human never opened:\n%s", tc.name, resp.StatusCode, body)
			}
		})
	}
}

// awaitDoorProbe waits for the probe's report FILE to say READY and returns what
// it found, keyed by the part before the "=".
//
// Polling a file rather than reading the payload's stdout through an os/exec
// pipe: the pipe version hung intermittently before the first line arrived,
// while the identical run by hand always worked. The cause was never pinned
// down, and a test whose failure mode is "sometimes never starts" cannot grade
// anything — so the pipe is gone rather than worked around.
func awaitDoorProbe(t *testing.T, proj string) map[string]string {
	t.Helper()
	path := filepath.Join(proj, "doorprobe-report.txt")
	deadline := time.Now().Add(8 * time.Second)
	for {
		body, err := os.ReadFile(path)
		if err == nil {
			found := map[string]string{}
			for _, line := range strings.Split(string(body), "\n") {
				if k, v, ok := strings.Cut(line, "="); ok {
					found[k] = v
				}
				if strings.HasPrefix(line, "FAIL=") {
					t.Fatalf("the payload could not use the descriptor snug handed it: %s\n"+
						"whole report:\n%s", line, body)
				}
			}
			if _, ok := found["READY"]; ok {
				return found
			}
			if _, ok := found["SOCKET"]; ok {
				return found
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the payload never reported READY in %s. Its report file (%s) is:\n%s",
				8*time.Second, path, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
