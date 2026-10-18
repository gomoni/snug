package cli

import (
	"os"

	"github.com/gomoni/snug/internal/sandbox"
)

// addRelaySockets asks the stage for n more relay sockets on o and hands
// exactly those n to fn, after every consumer registered before it has had
// its own. The stage makes one batch per run; this is what lets the login
// bridge and identity.kubectl's proxy share it without either knowing the other.
// When an earlier consumer refuses, the sockets meant for later ones are
// closed and its error is the run's.
func addRelaySockets(o *sandbox.Options, n int, fn func([]*os.File) error) {
	prevN, prev := o.RelaySockets, o.OnRelaySockets
	o.RelaySockets = prevN + n
	o.OnRelaySockets = func(fs []*os.File) error {
		if prev != nil {
			if err := prev(fs[:prevN]); err != nil {
				for _, f := range fs[prevN:] {
					f.Close()
				}
				return err
			}
		}
		return fn(fs[prevN:])
	}
}
