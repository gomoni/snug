package gbnf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/intent"
)

// TestGBNFMentionsEveryOp: an op added to schema.json without regenerating
// schema.gbnf would be accepted by the Go gate and the server backend and
// impossible for the in-process one to emit. Each op, and each enum value of
// $defs, must appear as a quoted literal in the grammar.
func TestGBNFMentionsEveryOp(t *testing.T) {
	var s struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
		Props struct {
			Actions struct {
				Items struct {
					OneOf []struct {
						Properties struct {
							Op struct {
								Const string `json:"const"`
							} `json:"op"`
						} `json:"properties"`
					} `json:"oneOf"`
				} `json:"items"`
			} `json:"actions"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(intent.Schema, &s); err != nil {
		t.Fatal(err)
	}
	ops := s.Props.Actions.Items.OneOf
	if len(ops) < 10 {
		t.Fatalf("read only %d ops from schema.json; the test is reading the wrong shape", len(ops))
	}
	for _, o := range ops {
		if lit := `"\"` + o.Properties.Op.Const + `\""`; o.Properties.Op.Const == "" || !strings.Contains(Schema, lit) {
			t.Errorf("op %q is not in schema.gbnf as %s: regenerate it with scripts/0041", o.Properties.Op.Const, lit)
		}
	}
	for name, d := range s.Defs {
		for _, v := range d.Enum {
			if !strings.Contains(Schema, `\"`+v+`\"`) {
				t.Errorf("$defs.%s value %q is not in schema.gbnf: regenerate it with scripts/0041", name, v)
			}
		}
	}
}
