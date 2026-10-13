//go:build !snug_setup_noinproc

package main

import (
	"github.com/gomoni/snug/setup/internal/gbnf"
	"github.com/gomoni/snug/setup/internal/intent"
	"github.com/gomoni/snug/setup/internal/llm"
	"github.com/gomoni/snug/setup/internal/llm/inproc"
)

func openInproc(model string, threads int) (llm.Backend, error) {
	return inproc.Open(model, inproc.Options{Schema: intent.Schema, Grammar: gbnf.Schema, Threads: threads})
}
