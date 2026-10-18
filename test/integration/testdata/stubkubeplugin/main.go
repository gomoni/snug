// Command stubkubeplugin stands in for a host exec-credential plugin
// (kubelogin) in the identity.kube host-exec integration tests. It is built
// under the name kubelogin, so snug matches its row. Like stubkubectl it reads
// its behaviour from "mode" beside its executable — ok, cert or grandchild —
// and appends its argv and its environment to "calls" beside it.
//
// In ok mode its answer carries, beside the token and expiry, an extra field
// and a refresh-token-shaped value, and it writes to stderr: none of that may
// reach the sandbox.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	self, err := os.Executable()
	if err != nil {
		os.Exit(9)
	}
	dir := filepath.Dir(self)
	env := os.Environ()
	sort.Strings(env)
	f, _ := os.OpenFile(filepath.Join(dir, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintf(f, "ARGV %s\nENV %s\n", strings.Join(os.Args[1:], " "), strings.Join(env, " "))
	f.Close()
	mode, _ := os.ReadFile(filepath.Join(dir, "mode"))
	status := map[string]string{
		"token":               "stub-plugin-token-4567",
		"expirationTimestamp": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"refreshToken":        "STUBREFRESHTOKEN",
	}
	switch strings.TrimSpace(string(mode)) {
	case "cert":
		status["clientCertificateData"] = "STUBCERT"
		status["clientKeyData"] = "STUBKEY"
	case "grandchild":
		c := exec.Command("sleep", "302")
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		_ = c.Start()
		os.WriteFile(filepath.Join(dir, "grandchild"), []byte("started"), 0o600)
		time.Sleep(10 * time.Minute)
	}
	fmt.Fprintln(os.Stderr, "stub plugin diagnostics STUBSTDERR")
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1beta1", "kind": "ExecCredential", "status": status})
}
