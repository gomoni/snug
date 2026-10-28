//go:build integration

package integration

// identity.glab, end to end through a real sandbox. glab is not installed on
// CI, so both tests use token_source = "netrc" with a scratch account home: the
// host side reads a fake ~/.netrc this test wrote, never the developer's.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	glabFakeUser  = "snug-fake-user"
	glabFakeToken = "glpat-FAKE0123456789"
	glabOtherHost = "other-gitlab.example.invalid"
	glabOtherTok  = "glpat-OTHERHOSTSECRET"
)

// glabFixture is a scratch account home whose ~/.netrc holds the pinned host's
// credential AND a second host's, and a ~/.config/glab-cli holding a decoy
// token, so a test can tell "staged the pinned entry" from "mounted the host's
// files".
func glabFixture(t *testing.T) (env []string, home string) {
	t.Helper()
	home = t.TempDir()
	netrc := "machine 127.0.0.1 login " + glabFakeUser + " password " + glabFakeToken + "\n" +
		"machine " + glabOtherHost + " login someone-else password " + glabOtherTok + "\n"
	if err := os.WriteFile(filepath.Join(home, ".netrc"), []byte(netrc), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".config", "glab-cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := "hosts:\n  " + glabOtherHost + ":\n    token: " + glabOtherTok + "\n"
	for _, f := range []string{"config.yml", "host-only-sibling.yml"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(decoy), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prof := "[profile.glabpin]\n" +
		"description = \"a GitLab account staged from netrc\"\n" +
		"[profile.glabpin.identity.glab]\n" +
		"host = \"127.0.0.1\"\n" +
		"user = \"" + glabFakeUser + "\"\n" +
		"token_source = \"netrc\"\n"
	return writeProfile(t, prof, fixtureHome(home)...), home
}

// TestGlabIdentityHttpsGitUsesStagedNetrc fails if the generated ~/.netrc stops
// reaching git over https (the spec's "no credential helper" route), or if it
// carries any other bytes than Basic base64(user:token) for the pinned host.
//
// The 401-answering server runs INSIDE the sandbox, on the sandbox's own
// loopback: the host's 127.0.0.1 is deliberately unreachable from in there, so
// a host-side server could not be the test's far end. Positive controls: the
// server logged an unauthenticated request first (git was challenged, so the
// header that follows answers a real 401), and git's own ls-remote output is
// not asserted on at all, only what the server received. It does not cover the
// glab binary reading config.yml; glab is not installed here.
func TestGlabIdentityHttpsGitUsesStagedNetrc(t *testing.T) {
	requireSandbox(t)
	requirePython(t)
	budget(t)
	env, _ := glabFixture(t)
	proj, _ := target(t)

	script := `
cat > srv.py <<'PY'
import http.server, sys
log = open("auth.log", "w")
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        log.write("AUTH=%s\n" % self.headers.get("Authorization")); log.flush()
        if self.headers.get("Authorization") is None:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open("port", "w").write(str(s.server_port))
s.serve_forever()
PY
python3 srv.py &
for i in $(seq 1 50); do [ -s port ] && break; sleep 0.1; done
echo "PORT=$(cat port)"
git ls-remote "http://127.0.0.1:$(cat port)/x/y.git" >/dev/null 2>&1
echo "GIT-EXIT=$?"
cat auth.log
kill %1
`
	r := runEnv(t, env, []string{"-p", "glabpin"}, proj, script).mustRun(t)
	if !strings.Contains(r.out, "PORT=") || strings.Contains(r.out, "PORT=\n") {
		t.Fatalf("the in-sandbox server never announced a port; nothing below measured anything:\n%s", r.out)
	}
	if !strings.Contains(r.out, "AUTH=None") {
		t.Fatalf("the server never saw the unauthenticated first request, so git was not "+
			"challenged and the credential line below proves nothing:\n%s", r.out)
	}
	want := "AUTH=Basic " + base64.StdEncoding.EncodeToString([]byte(glabFakeUser+":"+glabFakeToken))
	if !strings.Contains(r.out, want) {
		t.Errorf("git over http did not send the staged netrc credential (want %q):\n%s", want, r.out)
	}
	if strings.Contains(r.out, glabOtherTok) {
		t.Errorf("the other host's token appeared in the payload's output:\n%s", r.out)
	}
}

// TestGlabIdentityHostNetrcAndConfigNotVisible fails if the sandbox sees the
// host's ~/.netrc or glab config directory instead of snug's generated copies:
// the second machine entry, the decoy token, or any file in the config dir
// besides config.yml. Controls: the generated files exist (so "absent" is not
// a sandbox that never staged them) and carry the pinned token.
func TestGlabIdentityHostNetrcAndConfigNotVisible(t *testing.T) {
	requireSandbox(t)
	budget(t)
	env, _ := glabFixture(t)
	proj, _ := target(t)

	script := `
echo "NETRC-LINES=$(wc -l < ~/.netrc)"
echo "NETRC-BEGIN"; cat ~/.netrc; echo "NETRC-END"
echo "CFGDIR=$(ls -A ~/.config/glab-cli | tr '\n' ' ')"
echo "CFG-BEGIN"; cat ~/.config/glab-cli/config.yml; echo "CFG-END"
echo "GLAB_CONFIG_DIR=$GLAB_CONFIG_DIR"
`
	r := runEnv(t, env, []string{"-p", "glabpin"}, proj, script).mustRun(t)
	netrcWant := "machine 127.0.0.1 login " + glabFakeUser + " password " + glabFakeToken
	if !strings.Contains(r.out, "NETRC-BEGIN\n"+netrcWant+"\nNETRC-END") {
		t.Fatalf("~/.netrc is not exactly the one generated machine line (control failed):\n%s", r.out)
	}
	if !strings.Contains(r.out, "NETRC-LINES=1") {
		t.Errorf("~/.netrc has more than one line:\n%s", r.out)
	}
	if !strings.Contains(r.out, "CFGDIR=config.yml \n") {
		t.Errorf("~/.config/glab-cli holds more than config.yml:\n%s", r.out)
	}
	if !strings.Contains(r.out, "token: "+glabFakeToken) {
		t.Errorf("config.yml does not carry the pinned token (control failed):\n%s", r.out)
	}
	for _, leak := range []string{glabOtherHost, glabOtherTok, "someone-else", "host-only-sibling"} {
		if strings.Contains(r.out, leak) {
			t.Errorf("the host's %q is visible inside the sandbox:\n%s", leak, r.out)
		}
	}
}
