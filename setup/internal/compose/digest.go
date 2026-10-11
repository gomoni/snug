// Package compose reads the files the model may ask about and reduces them to
// the digest the prompt carries. A compose file becomes one line per service
// with environment variable NAMES only; every other file is its first bytes.
package compose

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// VerbatimLimit is how many bytes of a non-compose file reach the prompt.
const VerbatimLimit = 1200

// IsComposeName reports whether name is spelled like a compose file.
func IsComposeName(name string) bool {
	l := strings.ToLower(name)
	for _, pat := range []string{"docker-compose*.y*ml", "compose*.y*ml"} {
		if ok, _ := path.Match(pat, l); ok {
			return true
		}
	}
	return false
}

// Digest returns the prompt body for the file name with content body. A
// compose file that parses becomes `service NAME: build= image= ports=
// volumes= env=` lines (fields omitted when empty, environment NAMES only,
// never values); anything else, including a compose file that does not parse,
// is its first VerbatimLimit bytes cut on a character boundary.
func Digest(name string, body []byte) string {
	if IsComposeName(name) {
		if s, err := digestCompose(body); err == nil {
			return s
		}
	}
	return Verbatim(body)
}

// Verbatim returns the first VerbatimLimit bytes of body, without a trailing
// partial UTF-8 sequence.
func Verbatim(body []byte) string {
	if len(body) > VerbatimLimit {
		body = body[:VerbatimLimit]
		for len(body) > 0 && !utf8.Valid(body) {
			body = body[:len(body)-1]
		}
	}
	return string(body)
}

func digestCompose(body []byte) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return "", fmt.Errorf("not a mapping")
	}
	services := mapGet(doc.Content[0], "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return "", fmt.Errorf("no services")
	}
	var lines []string
	for i := 0; i+1 < len(services.Content); i += 2 {
		name, svc := services.Content[i].Value, services.Content[i+1]
		var parts []string
		add := func(k, v string) {
			if v != "" {
				parts = append(parts, k+"="+v)
			}
		}
		if svc.Kind == yaml.MappingNode {
			add("build", buildOf(mapGet(svc, "build")))
			add("image", scalar(mapGet(svc, "image")))
			add("ports", strings.Join(portsOf(mapGet(svc, "ports")), ","))
			add("volumes", strings.Join(volumesOf(mapGet(svc, "volumes")), ","))
			add("env", strings.Join(envNames(mapGet(svc, "environment")), ","))
		}
		line := "service " + clean(name) + ":"
		if len(parts) > 0 {
			line += " " + strings.Join(parts, " ")
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no services")
	}
	return strings.Join(lines, "\n"), nil
}

// clean keeps a value on one line of the prompt.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return deref(m.Content[i+1])
		}
	}
	return nil
}

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		return n.Alias
	}
	return n
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return clean(n.Value)
}

func buildOf(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.MappingNode {
		return scalar(mapGet(n, "context"))
	}
	return scalar(n)
}

func portsOf(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, it := range n.Content {
		it = deref(it)
		if it.Kind == yaml.MappingNode {
			pub, tgt := scalar(mapGet(it, "published")), scalar(mapGet(it, "target"))
			switch {
			case pub != "" && tgt != "":
				out = append(out, pub+":"+tgt)
			case tgt != "":
				out = append(out, tgt)
			}
			continue
		}
		if s := scalar(it); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func volumesOf(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, it := range n.Content {
		it = deref(it)
		if it.Kind == yaml.MappingNode {
			src, dst := scalar(mapGet(it, "source")), scalar(mapGet(it, "target"))
			if dst == "" {
				continue
			}
			s := dst
			if src != "" {
				s = src + ":" + dst
			}
			if ro, _ := strconv.ParseBool(scalar(mapGet(it, "read_only"))); ro {
				s += ":ro"
			}
			out = append(out, s)
			continue
		}
		if s := scalar(it); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func envNames(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	var out []string
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			out = append(out, clean(n.Content[i].Value))
		}
	case yaml.SequenceNode:
		for _, it := range n.Content {
			name, _, _ := strings.Cut(scalar(deref(it)), "=")
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}
