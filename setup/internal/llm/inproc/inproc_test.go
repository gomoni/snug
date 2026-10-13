//go:build !snug_setup_noinproc

package inproc

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/gbnf"
	"github.com/gomoni/snug/setup/internal/intent"
)

func opts() Options { return Options{Schema: intent.Schema, Grammar: gbnf.Schema} }

func TestCheckBuild(t *testing.T) {
	for _, v := range []string{"v2", "v3", "v4"} {
		if err := checkBuild("amd64", map[string]string{"GOAMD64": v}); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, s := range []map[string]string{{"GOAMD64": "v1"}, {}} {
		err := checkBuild("amd64", s)
		if err == nil || !strings.Contains(err.Error(), "GOAMD64=v3") || !strings.Contains(err.Error(), "--llm-url") {
			t.Errorf("%v accepted or unhelpful: %v", s, err)
		}
	}
	if err := checkBuild("arm64", nil); err != nil {
		t.Errorf("arm64 has no GOAMD64: %v", err)
	}
}

// gguf builds the start of a GGUF file: magic, version 3, then counts.
func gguf(tensors, kvs uint64) []byte {
	b := []byte("GGUF")
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = binary.LittleEndian.AppendUint64(b, tensors)
	return binary.LittleEndian.AppendUint64(b, kvs)
}

// TestOpenRefusesBadModelFiles: the model file is untrusted input to a C++
// parser. Every shape below must come back as a Go error that says what to do,
// not take snug-setup down.
func TestOpenRefusesBadModelFiles(t *testing.T) {
	if err := checkBuild("amd64", buildSettings()); err != nil {
		t.Skip("test binary is not built with GOAMD64>=v2: " + err.Error())
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"empty":        write("empty.gguf", nil),
		"text":         write("text.gguf", []byte("this is not a model\n")),
		"magic only":   write("magic.gguf", []byte("GGUF")),
		"header only":  write("header.gguf", gguf(0, 0)),
		"huge counts":  write("huge.gguf", gguf(1<<62, 1<<62)),
		"truncated kv": write("trunc.gguf", append(gguf(1, 1000), make([]byte, 64)...)),
	}
	if m := os.Getenv("SNUG_SETUP_TEST_MODEL"); m != "" {
		if b, err := os.ReadFile(m); err == nil {
			cases["real model cut at 1 MiB"] = write("cut.gguf", b[:1<<20])
		}
	}
	for name, p := range cases {
		e, err := Open(p, opts())
		if err == nil {
			e.Close()
			t.Errorf("%s: opened", name)
			continue
		}
		if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "--llm-url") {
			t.Errorf("%s: error does not name the file and the alternative: %v", name, err)
		}
	}
	if _, err := Open(filepath.Join(dir, "missing.gguf"), opts()); err == nil || !strings.Contains(err.Error(), "missing.gguf") {
		t.Errorf("missing file: %v", err)
	}
}

func TestOpenNeedsSchemaAndGrammar(t *testing.T) {
	if _, err := Open("x", Options{}); err == nil {
		t.Error("opened without a schema")
	}
}
