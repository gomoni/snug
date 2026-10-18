// Command stubkubectl stands in for the host kubectl in the identity.kube
// integration tests. snug runs the mint with a built environment, so the stub
// reads its behaviour from a file beside its own executable rather than from
// the environment: "mode" holds ok, short, hang or grandchild. Every call
// appends its argv to "calls" beside it, so a test can count mints.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	f, _ := os.OpenFile(filepath.Join(dir, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintln(f, strings.Join(os.Args[1:], " "))
	f.Close()
	mode, _ := os.ReadFile(filepath.Join(dir, "mode"))
	life := time.Hour
	switch strings.TrimSpace(string(mode)) {
	case "hang":
		time.Sleep(10 * time.Minute)
	case "grandchild":
		c := exec.Command("sleep", "301")
		c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		_ = c.Start()
		os.WriteFile(filepath.Join(dir, "grandchild"), []byte("started"), 0o600)
		time.Sleep(10 * time.Minute)
	case "short":
		life = 2 * time.Second
	}
	out := map[string]any{"kind": "TokenRequest", "status": map[string]string{
		"token": "stub-token-0123", "expirationTimestamp": time.Now().Add(life).UTC().Format(time.RFC3339)}}
	json.NewEncoder(os.Stdout).Encode(out)
}
