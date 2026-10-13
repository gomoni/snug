//go:build snug_setup_noinproc

package main

import (
	"errors"

	"github.com/gomoni/snug/setup/internal/llm"
)

func openInproc(string, int) (llm.Backend, error) {
	return nil, errors.New("this snug-setup was built with -tags snug_setup_noinproc and has no in-process engine; use --llama-server-model FILE.gguf or --llm-url URL")
}
