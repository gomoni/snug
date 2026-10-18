package cli

import (
	"errors"
	"os"
	"testing"

	"github.com/gomoni/snug/internal/sandbox"
)

// The login bridge and identity.kube share one batch of relay sockets; each
// gets exactly its own slice, in registration order, and a consumer that
// refuses stops the run with the later consumers' sockets closed.
func TestRelaySocketConsumersGetTheirOwnSlice(t *testing.T) {
	files := make([]*os.File, 4)
	for i := range files {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		files[i] = r
	}
	var o sandbox.Options
	var first, second []*os.File
	addRelaySockets(&o, 3, func(fs []*os.File) error { first = fs; return nil })
	addRelaySockets(&o, 1, func(fs []*os.File) error { second = fs; return nil })
	if o.RelaySockets != 4 {
		t.Fatalf("RelaySockets = %d, want 4", o.RelaySockets)
	}
	if err := o.OnRelaySockets(files); err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || first[0] != files[0] || len(second) != 1 || second[0] != files[3] {
		t.Errorf("first %v second %v from %v", first, second, files)
	}

	var o2 sandbox.Options
	refused := errors.New("refused")
	called := false
	addRelaySockets(&o2, 3, func([]*os.File) error { return refused })
	addRelaySockets(&o2, 1, func([]*os.File) error { called = true; return nil })
	if err := o2.OnRelaySockets(files); !errors.Is(err, refused) {
		t.Errorf("err = %v, want the first consumer's refusal", err)
	}
	if called {
		t.Error("the second consumer ran after the first refused")
	}
	if _, err := files[3].Stat(); err == nil {
		t.Error("the second consumer's socket was left open")
	}
}
