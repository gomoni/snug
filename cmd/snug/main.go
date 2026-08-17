// Command snug runs a command inside an unprivileged bubblewrap sandbox that
// starts out sharing nothing.
//
// Everything the binary does lives in internal/cli, so it can be imported and
// tested from outside package main — this file's only job is to be the thing
// `go build ./cmd/snug` produces.
package main

import "github.com/gomoni/snug/internal/cli"

func main() {
	cli.Main()
}
