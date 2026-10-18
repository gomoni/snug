// Package kubecfg decodes a host kubeconfig into the few facts snug needs from
// it: the contexts, the clusters and the users, each by name. It does no
// policy; internal/policy decides what any of it means.
//
// It is a strict decoder for the subset of YAML that kubectl and az write —
// block mappings, block sequences, one-line scalars — and for JSON, which is
// what a kubeconfig becomes after `kubectl config view -o json`. Everything
// outside that subset is REFUSED with the line it is on rather than guessed at:
// anchors, aliases, tags, block scalars, flow collections other than the empty
// `{}` and `[]`, multi-line plain scalars, complex keys, merge keys, a second
// document, and a key written twice. go.mod carries no YAML library, and this
// file is not trying to be one.
//
// A parser differential with client-go cannot widen anything snug hands over,
// because kubectl never reads the host file through snug: snug re-encodes the
// allowlisted values it extracted here into a file it writes itself. The cost
// of a differential is a refusal of a file kubectl would have accepted, and the
// refusal names the construct.
package kubecfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is what a Value holds.
type Kind int

const (
	Scalar Kind = iota
	Map
	Seq
)

func (k Kind) String() string {
	switch k {
	case Map:
		return "mapping"
	case Seq:
		return "sequence"
	}
	return "scalar"
}

// Value is one field of a cluster or user entry. For a Scalar, Text is its
// content and Quoted says whether it was written quoted — `insecure-skip-tls-verify:
// "false"` is a string to kubectl, not a boolean, and policy must not read the
// two the same. For a Map or Seq, Len is the number of entries; their content is
// not kept, because nothing snug accepts is nested beyond what User.Exec carries.
type Value struct {
	Kind   Kind
	Text   string
	Quoted bool
	Len    int
	Line   int
}

// Context is one entry of `contexts:`. Other names every key of the context
// mapping beyond cluster, user and namespace, in file order.
type Context struct {
	Name, Cluster, User, Namespace string
	Other                          []string
	Line                           int
}

// Cluster is one entry of `clusters:`, its `cluster:` mapping kept as Fields.
type Cluster struct {
	Name   string
	Fields map[string]Value
	Line   int
}

// Exec is the part of a user's `exec:` mapping snug reports in a refusal.
type Exec struct {
	Command string
}

// User is one entry of `users:`, its `user:` mapping kept as Fields. Exec is
// non-nil when the mapping has an `exec:` mapping.
type User struct {
	Name   string
	Fields map[string]Value
	Exec   *Exec
	Line   int
}

// File is a decoded kubeconfig, entries in file order. Duplicate names are
// kept, not merged: deciding that two entries with one name is an error is the
// caller's, and it can only do that if it sees both.
type File struct {
	Contexts []Context
	Clusters []Cluster
	Users    []User
}

// Parse decodes data as a kubeconfig. JSON is recognised by its first
// non-blank byte being `{`; anything else is parsed as the YAML subset the
// package doc names. The error for a construct outside the subset begins with
// "line N:", 1-based. A document that parses but is not a kubeconfig — its top
// level is not a mapping, or `clusters:` is not a list of mappings with a name
// — is an error naming the field.
func Parse(data []byte) (File, error) {
	if !utf8.Valid(data) {
		return File{}, errors.New("is not UTF-8")
	}
	var root *node
	var err error
	if t := bytes.TrimLeft(data, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		root, err = parseJSON(data)
	} else {
		root, err = parseYAML(data)
	}
	if err != nil {
		return File{}, err
	}
	return extract(root)
}

// node is the generic tree both front ends build. keys keeps a mapping's order.
type node struct {
	kind   Kind
	text   string
	quoted bool
	line   int
	keys   []string
	m      map[string]*node
	seq    []*node
}

func newMap(line int) *node { return &node{kind: Map, line: line, m: map[string]*node{}} }

func (n *node) set(k string, v *node, line int) error {
	if _, dup := n.m[k]; dup {
		return fmt.Errorf("line %d: key %q appears twice in one mapping", line, k)
	}
	n.keys = append(n.keys, k)
	n.m[k] = v
	return nil
}

func (n *node) value() Value {
	v := Value{Kind: n.kind, Text: n.text, Quoted: n.quoted, Line: n.line}
	switch n.kind {
	case Map:
		v.Len = len(n.keys)
	case Seq:
		v.Len = len(n.seq)
	}
	return v
}

// ---- YAML subset ----

type yline struct {
	n      int // 1-based line number
	indent int
	text   string // comment and trailing blanks removed; never empty
}

func parseYAML(data []byte) (*node, error) {
	lines, err := yamlLines(data)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("is empty")
	}
	p := &yparser{lines: lines}
	root, err := p.block(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		l := p.lines[p.i]
		return nil, fmt.Errorf("line %d: indentation does not match any open block", l.n)
	}
	return root, nil
}

// yamlLines splits data into significant lines: blank and comment-only lines
// dropped, one leading `---` accepted, every other document marker and
// directive refused.
func yamlLines(data []byte) ([]yline, error) {
	var out []yline
	raw := strings.Split(string(data), "\n")
	sawContent := false
	for i, s := range raw {
		n := i + 1
		s = strings.TrimSuffix(s, "\r")
		indent := 0
		for indent < len(s) && s[indent] == ' ' {
			indent++
		}
		if indent < len(s) && s[indent] == '\t' {
			return nil, fmt.Errorf("line %d: a tab in indentation; YAML indents with spaces", n)
		}
		body, err := stripComment(s[indent:], n)
		if err != nil {
			return nil, err
		}
		body = strings.TrimRight(body, " \t")
		if body == "" {
			continue
		}
		if indent == 0 {
			switch {
			case body == "---" || strings.HasPrefix(body, "--- "):
				if sawContent || body != "---" {
					return nil, fmt.Errorf("line %d: a second YAML document (or content after ---); a kubeconfig is one document", n)
				}
				continue
			case body == "...":
				return nil, fmt.Errorf("line %d: the YAML document end marker ... is not supported", n)
			case body[0] == '%':
				return nil, fmt.Errorf("line %d: YAML directives are not supported", n)
			}
		}
		sawContent = true
		out = append(out, yline{n: n, indent: indent, text: body})
	}
	return out, nil
}

// stripComment removes a `#` comment: one at the start of the content, or one
// preceded by a space, outside quotes. A quote left open at the end of the line
// is a multi-line quoted scalar, which the subset refuses.
func stripComment(s string, n int) (string, error) {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
		case quote == '"':
			if c == '\\' {
				i++
				continue
			}
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			// A quote opens a quoted scalar only where a scalar starts:
			// at the start of the content, after "- ", or after ": ".
			if i == 0 || strings.HasSuffix(s[:i], ": ") || strings.HasSuffix(s[:i], "- ") {
				quote = c
			}
		case c == '#' && (i == 0 || s[i-1] == ' '):
			return s[:i], nil
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("line %d: a quoted scalar that continues past the end of the line; multi-line scalars are not supported", n)
	}
	return s, nil
}

type yparser struct {
	lines []yline
	i     int
}

// block parses the mapping or sequence whose lines start at exactly indent.
func (p *yparser) block(indent int) (*node, error) {
	l := p.lines[p.i]
	if isSeqItem(l.text) {
		return p.seq(indent)
	}
	return p.mapping(indent)
}

func isSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *yparser) seq(indent int) (*node, error) {
	out := &node{kind: Seq, line: p.lines[p.i].n}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent || !isSeqItem(l.text) {
			if l.indent > indent {
				return nil, fmt.Errorf("line %d: indentation does not match any open block", l.n)
			}
			break
		}
		if l.text == "-" {
			p.i++
			if p.i >= len(p.lines) || p.lines[p.i].indent <= indent {
				out.seq = append(out.seq, &node{kind: Scalar, line: l.n})
				continue
			}
			item, err := p.block(p.lines[p.i].indent)
			if err != nil {
				return nil, err
			}
			out.seq = append(out.seq, item)
			continue
		}
		rest := l.text[2:]
		pad := 2
		for strings.HasPrefix(rest, " ") {
			rest = rest[1:]
			pad++
		}
		if _, _, ok, err := splitKey(rest, l.n); err != nil {
			return nil, err
		} else if ok || isSeqItem(rest) {
			// A compact item: "- key: v" opens a mapping (or "- - x" a
			// sequence) whose first line is the rest of this one, at the
			// column the rest starts in. Rewriting the line in place lets
			// the ordinary block parser take it from there.
			p.lines[p.i] = yline{n: l.n, indent: indent + pad, text: rest}
			item, err := p.block(indent + pad)
			if err != nil {
				return nil, err
			}
			out.seq = append(out.seq, item)
			continue
		}
		v, err := scalar(rest, l.n)
		if err != nil {
			return nil, err
		}
		p.i++
		if err := p.noContinuation(indent, l.n); err != nil {
			return nil, err
		}
		out.seq = append(out.seq, v)
	}
	return out, nil
}

func (p *yparser) mapping(indent int) (*node, error) {
	out := newMap(p.lines[p.i].n)
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: indentation does not match any open block", l.n)
		}
		if isSeqItem(l.text) {
			// A sequence at a mapping's own indentation belongs to the
			// key above it, which mapping() has already consumed; meeting
			// one here means it follows a key that had a value.
			return nil, fmt.Errorf("line %d: a sequence item where a mapping key was expected", l.n)
		}
		k, rest, ok, err := splitKey(l.text, l.n)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("line %d: expected `key: value`", l.n)
		}
		p.i++
		var v *node
		if rest == "" {
			switch {
			case p.i < len(p.lines) && p.lines[p.i].indent > indent:
				v, err = p.block(p.lines[p.i].indent)
			case p.i < len(p.lines) && p.lines[p.i].indent == indent && isSeqItem(p.lines[p.i].text):
				// kubectl writes `clusters:` with its items at the key's
				// own column.
				v, err = p.seq(indent)
			default:
				v = &node{kind: Scalar, line: l.n}
			}
			if err != nil {
				return nil, err
			}
		} else {
			if v, err = scalar(rest, l.n); err != nil {
				return nil, err
			}
			if err := p.noContinuation(indent, l.n); err != nil {
				return nil, err
			}
		}
		if err := out.set(k, v, l.n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// noContinuation refuses a line indented deeper than the entry just read: that
// is a multi-line plain scalar, the one way to continue a value the subset does
// not support.
func (p *yparser) noContinuation(indent, n int) error {
	if p.i < len(p.lines) && p.lines[p.i].indent > indent {
		return fmt.Errorf("line %d: a value continued on the next line; multi-line scalars are not supported", p.lines[p.i].n)
	}
	_ = n
	return nil
}

// splitKey splits "key: rest" or "key:". ok is false when the line is not a
// mapping entry at all. The key must be plain: a quoted, anchored, tagged,
// complex or merge key is refused, because none of them is something kubectl
// or az writes and each has a meaning this decoder does not implement.
func splitKey(t string, n int) (key, rest string, ok bool, err error) {
	if t == "" {
		return "", "", false, nil
	}
	switch t[0] {
	case '?':
		if t == "?" || strings.HasPrefix(t, "? ") {
			return "", "", false, fmt.Errorf("line %d: complex mapping keys (?) are not supported", n)
		}
	case '\'', '"':
		if i := strings.Index(t, ":"); i > 0 {
			return "", "", false, fmt.Errorf("line %d: quoted mapping keys are not supported", n)
		}
		return "", "", false, nil
	case '&', '*', '!':
		if i := strings.Index(t, ": "); i > 0 || strings.HasSuffix(t, ":") {
			return "", "", false, fmt.Errorf("line %d: %s on a mapping key is not supported", n, describeIndicator(t[0]))
		}
	case '{', '[':
		return "", "", false, nil
	}
	i := strings.Index(t, ": ")
	if i < 0 {
		if !strings.HasSuffix(t, ":") {
			return "", "", false, nil
		}
		i = len(t) - 1
	}
	key = t[:i]
	if key == "<<" {
		return "", "", false, fmt.Errorf("line %d: the YAML merge key << is not supported", n)
	}
	if strings.ContainsAny(key, "#") || strings.HasSuffix(key, " ") {
		return "", "", false, fmt.Errorf("line %d: malformed mapping key %q", n, key)
	}
	rest = strings.TrimLeft(t[i+1:], " ")
	return key, rest, true, nil
}

func describeIndicator(c byte) string {
	switch c {
	case '&':
		return "a YAML anchor (&)"
	case '*':
		return "a YAML alias (*)"
	case '!':
		return "a YAML tag (!)"
	}
	return string(c)
}

// scalar decodes a one-line value.
func scalar(s string, n int) (*node, error) {
	switch s[0] {
	case '&', '*', '!':
		return nil, fmt.Errorf("line %d: %s is not supported", n, describeIndicator(s[0]))
	case '|', '>':
		return nil, fmt.Errorf("line %d: block scalars (| and >) are not supported", n)
	case '{':
		if s == "{}" {
			return newMap(n), nil
		}
		return nil, fmt.Errorf("line %d: flow mappings are not supported (only the empty {})", n)
	case '[':
		if s == "[]" {
			return &node{kind: Seq, line: n}, nil
		}
		return nil, fmt.Errorf("line %d: flow sequences are not supported (only the empty [])", n)
	case '@', '`':
		return nil, fmt.Errorf("line %d: a plain scalar may not start with %q", n, s[0])
	case '\'':
		return singleQuoted(s, n)
	case '"':
		return doubleQuoted(s, n)
	}
	if strings.Contains(s, ": ") {
		return nil, fmt.Errorf("line %d: a plain value containing \": \"; quote it", n)
	}
	return &node{kind: Scalar, text: s, line: n}, nil
}

func singleQuoted(s string, n int) (*node, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] != '\'' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == '\'' {
			b.WriteByte('\'')
			i++
			continue
		}
		if i != len(s)-1 {
			return nil, fmt.Errorf("line %d: text after a closing quote", n)
		}
		return &node{kind: Scalar, text: b.String(), quoted: true, line: n}, nil
	}
	return nil, fmt.Errorf("line %d: unterminated single-quoted scalar", n)
}

func doubleQuoted(s string, n int) (*node, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			if i != len(s)-1 {
				return nil, fmt.Errorf("line %d: text after a closing quote", n)
			}
			return &node{kind: Scalar, text: b.String(), quoted: true, line: n}, nil
		case '\\':
			if i+1 >= len(s) {
				return nil, fmt.Errorf("line %d: unterminated escape", n)
			}
			i++
			switch e := s[i]; e {
			case '\\', '"', '/':
				b.WriteByte(e)
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'u':
				if i+4 >= len(s) {
					return nil, fmt.Errorf("line %d: short \\u escape", n)
				}
				r, err := strconv.ParseUint(s[i+1:i+5], 16, 32)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad \\u escape", n)
				}
				b.WriteRune(rune(r))
				i += 4
			default:
				return nil, fmt.Errorf("line %d: the escape \\%c is not supported", n, e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return nil, fmt.Errorf("line %d: unterminated double-quoted scalar", n)
}

// ---- JSON ----

// parseJSON walks tokens rather than decoding into map[string]any, because
// encoding/json keeps the LAST of two equal keys without a word, and a
// kubeconfig whose `server` is written twice must refuse in JSON as it does in
// YAML. JSON carries no line numbers here; errors say "line 0" only through
// the extract step, which reports field names.
func parseJSON(data []byte) (*node, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	n, err := jsonValue(d)
	if err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("JSON: content after the top-level value")
	}
	return n, nil
}

func jsonValue(d *json.Decoder) (*node, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := newMap(0)
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				val, err := jsonValue(d)
				if err != nil {
					return nil, err
				}
				if _, dup := m.m[k]; dup {
					return nil, fmt.Errorf("key %q appears twice in one object", k)
				}
				m.keys = append(m.keys, k)
				m.m[k] = val
			}
			_, err := d.Token()
			return m, err
		case '[':
			s := &node{kind: Seq}
			for d.More() {
				val, err := jsonValue(d)
				if err != nil {
					return nil, err
				}
				s.seq = append(s.seq, val)
			}
			_, err := d.Token()
			return s, err
		}
	case string:
		return &node{kind: Scalar, text: v, quoted: true}, nil
	case json.Number:
		return &node{kind: Scalar, text: v.String()}, nil
	case bool:
		return &node{kind: Scalar, text: strconv.FormatBool(v)}, nil
	case nil:
		return &node{kind: Scalar}, nil
	}
	return nil, fmt.Errorf("unexpected token %v", t)
}

// ---- extraction ----

func extract(root *node) (File, error) {
	if root.kind != Map {
		return File{}, errors.New("top level is not a mapping")
	}
	var f File
	items := func(field string) ([]*node, error) {
		v, ok := root.m[field]
		if !ok || (v.kind == Scalar && v.text == "" && !v.quoted) {
			return nil, nil
		}
		if v.kind != Seq {
			return nil, fmt.Errorf("line %d: %s is a %s, not a list", v.line, field, v.kind)
		}
		return v.seq, nil
	}
	named := func(field, inner string, it *node) (string, *node, error) {
		if it.kind != Map {
			return "", nil, fmt.Errorf("line %d: an entry of %s is a %s, not a mapping", it.line, field, it.kind)
		}
		nm, ok := it.m["name"]
		if !ok || nm.kind != Scalar || nm.text == "" {
			return "", nil, fmt.Errorf("line %d: an entry of %s has no name", it.line, field)
		}
		for _, k := range it.keys {
			if k != "name" && k != inner {
				return "", nil, fmt.Errorf("line %d: %s entry %q has an unknown key %q", it.line, field, nm.text, k)
			}
		}
		body, ok := it.m[inner]
		if !ok {
			return nm.text, newMap(it.line), nil
		}
		if body.kind != Map {
			return "", nil, fmt.Errorf("line %d: %s entry %q: %s is a %s, not a mapping", body.line, field, nm.text, inner, body.kind)
		}
		return nm.text, body, nil
	}

	cs, err := items("clusters")
	if err != nil {
		return File{}, err
	}
	for _, it := range cs {
		name, body, err := named("clusters", "cluster", it)
		if err != nil {
			return File{}, err
		}
		f.Clusters = append(f.Clusters, Cluster{Name: name, Fields: fields(body), Line: it.line})
	}

	us, err := items("users")
	if err != nil {
		return File{}, err
	}
	for _, it := range us {
		name, body, err := named("users", "user", it)
		if err != nil {
			return File{}, err
		}
		u := User{Name: name, Fields: fields(body), Line: it.line}
		if ex, ok := body.m["exec"]; ok && ex.kind == Map {
			u.Exec = &Exec{}
			if c, ok := ex.m["command"]; ok && c.kind == Scalar {
				u.Exec.Command = c.text
			}
		}
		f.Users = append(f.Users, u)
	}

	xs, err := items("contexts")
	if err != nil {
		return File{}, err
	}
	for _, it := range xs {
		name, body, err := named("contexts", "context", it)
		if err != nil {
			return File{}, err
		}
		c := Context{Name: name, Line: it.line}
		for _, k := range body.keys {
			v := body.m[k]
			dst := map[string]*string{"cluster": &c.Cluster, "user": &c.User, "namespace": &c.Namespace}[k]
			if dst == nil {
				c.Other = append(c.Other, k)
				continue
			}
			if v.kind != Scalar {
				return File{}, fmt.Errorf("line %d: context %q: %s is a %s, not a name", v.line, name, k, v.kind)
			}
			*dst = v.text
		}
		f.Contexts = append(f.Contexts, c)
	}
	return f, nil
}

func fields(m *node) map[string]Value {
	out := make(map[string]Value, len(m.keys))
	for _, k := range m.keys {
		out[k] = m.m[k].value()
	}
	return out
}
