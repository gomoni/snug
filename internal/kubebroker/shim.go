package kubebroker

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// shimDial is how the shim reaches the broker; a test seam.
var shimDial = func() (net.Conn, error) { return net.Dial("unix", policy.KubeTokenSocketGuest) }

// ShimMain is the in-sandbox exec-credential plugin, run when snug's binary is
// invoked as snug-kube-token. It takes no flags and reads no environment —
// KUBERNETES_EXEC_INFO included — because the broker would ignore anything it
// sent: it connects, prints the credential the broker answers with, and exits.
func ShimMain() int {
	c, err := shimDial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug-kube-token: cannot reach snug's token broker: %v\n", err)
		return 1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(35 * time.Second))
	b, err := io.ReadAll(io.LimitReader(c, 64<<10))
	if err != nil || len(b) == 0 {
		fmt.Fprintf(os.Stderr, "snug-kube-token: no answer from snug's token broker (%v)\n", err)
		return 1
	}
	if b[0] != statusOK {
		fmt.Fprintf(os.Stderr, "snug-kube-token: %s\n", b[1:])
		return 1
	}
	os.Stdout.Write(b[1:])
	return 0
}
