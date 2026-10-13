// Package gbnf holds the GBNF grammar form of the intent schema, for engines
// that take a grammar rather than a JSON schema.
package gbnf

import _ "embed"

// Schema is schema.gbnf: the grammar llama.cpp's json-schema-to-grammar
// derives from internal/intent/schema.json, byte for byte. The converter lives
// in llama.cpp's C++ common library and is not ported; scripts/0041 diffs this
// file against llama-server's own conversion, and TestGBNFMentionsEveryOp
// fails the gate when an op of the schema is missing from it. Decoding under
// it is an optimisation of the contract, never the contract: intent.Parse
// still validates every reply.
//
//go:embed schema.gbnf
var Schema string
