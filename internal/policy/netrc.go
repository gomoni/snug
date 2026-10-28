package policy

import (
	"errors"
	"fmt"
	"strings"
)

// ParseNetrcEntry returns the login and password the netrc file data holds for
// exactly the machine host, and refuses everything it cannot read the way curl
// does without guessing.
//
// It is a parser for ONE thing: pulling one credential out of a file a human
// maintains, so that a second reader (curl, git, the file's other consumers)
// and this one cannot disagree about which entry a token belongs to. Where the
// grammar is ambiguous the whole file is refused, never the nearest reading:
//
//   - `macdef` is refused anywhere. A macro body runs to the next blank line and
//     may contain a forged `machine HOST login x password y`; whether a reader
//     skips the body is exactly what readers disagree about.
//
//   - A token starting with `"` is refused. Some netrc readers honour quoting
//     and some do not, so a password written with a space inside it is a
//     different credential depending on who reads the file.
//
//   - An unknown keyword, a keyword with no value, a login or password keyword
//     before any machine, and a repeated login or password inside the entry
//     are refused.
//
//   - Two `machine host` entries are refused: which one wins is a property of
//     the reader.
//
//   - `default` ends the parse. If host was not found before it, the error
//     says so; snug never stages a default credential, because it was never
//     the pinned host's.
//
//   - Any control byte other than tab, CR and LF is refused anywhere in the
//     file. curl splits tokens on space, tab, CR and LF only, so a vertical tab
//     or form feed is part of a token there; a reader that split on it would
//     move a password from one machine entry to the next (redteam on #709).
//     NUL is refused for the same reason: C readers stop at it.
//
// The comparison on host is ASCII case-insensitive, as curl's is, so
// `machine GITLAB.example.com` is the same entry as `machine gitlab.example.com`
// and two of them are the duplicate refused above. A line whose first non-blank
// character is `#` is a comment; `account` takes a value and discards it.
//
// Errors name line numbers and keywords, never a token's text: an unknown
// "keyword" is as likely to be the tail of a password containing a space as
// anything else.
func ParseNetrcEntry(data []byte, host string) (login string, pw Secret, err error) {
	type entry struct {
		seen                  bool
		login, password       string
		hasLogin, hasPassword bool
	}
	var want entry
	inWant := false
	inAny := false
	sawDefault := false

	const (
		kwNone = iota
		kwMachine
		kwLogin
		kwPassword
		kwAccount
	)
	pending := kwNone

	for i, b := range data {
		if (b < 0x20 && b != '\t' && b != '\r' && b != '\n') || b == 0x7f {
			return "", nil, fmt.Errorf("the netrc file holds control byte 0x%02x at offset %d. Readers split "+
				"tokens on different control bytes, so snug refuses the file", b, i)
		}
	}

lines:
	for n, line := range strings.Split(string(data), "\n") {
		lineNo := n + 1
		toks := netrcFields(line)
		if len(toks) == 0 {
			continue
		}
		if strings.HasPrefix(toks[0], "#") {
			if pending != kwNone {
				return "", nil, fmt.Errorf("line %d of the netrc file is a comment where a keyword's value "+
					"was expected; snug will not guess", lineNo)
			}
			continue
		}
		for _, t := range toks {
			if strings.HasPrefix(t, `"`) {
				return "", nil, fmt.Errorf("line %d of the netrc file starts a token with a double quote; "+
					"readers disagree on whether that quotes, so snug refuses the file. "+
					"Write the credential without quotes", lineNo)
			}
			if pending != kwNone {
				switch pending {
				case kwMachine:
					inAny = true
					inWant = strings.EqualFold(t, host)
					if inWant {
						if want.seen {
							return "", nil, fmt.Errorf("the netrc file has two `machine %s` entries (the second on line %d); "+
								"which one a reader uses differs between readers, so snug refuses the file. "+
								"Keep one", host, lineNo)
						}
						want.seen = true
					}
				case kwLogin:
					if inWant {
						if want.hasLogin {
							return "", nil, fmt.Errorf("line %d of the netrc file repeats `login` inside the entry for %s", lineNo, host)
						}
						want.login, want.hasLogin = t, true
					}
				case kwPassword:
					if inWant {
						if want.hasPassword {
							return "", nil, fmt.Errorf("line %d of the netrc file repeats `password` inside the entry for %s", lineNo, host)
						}
						want.password, want.hasPassword = t, true
					}
				}
				pending = kwNone
				continue
			}
			switch t {
			case "machine":
				pending = kwMachine
			case "login", "password":
				if !inAny {
					return "", nil, fmt.Errorf("line %d of the netrc file has `%s` before any `machine`; "+
						"snug will not guess which host it belongs to", lineNo, t)
				}
				if t == "login" {
					pending = kwLogin
				} else {
					pending = kwPassword
				}
			case "account":
				if !inAny {
					return "", nil, fmt.Errorf("line %d of the netrc file has `account` before any `machine`", lineNo)
				}
				pending = kwAccount
			case "macdef":
				return "", nil, fmt.Errorf("line %d of the netrc file holds a `macdef`. A macro body can contain a forged "+
					"`machine` line, and readers disagree on whether they skip it, so snug refuses the file. "+
					"Remove the macro from ~/.netrc", lineNo)
			case "default":
				sawDefault = true
				break lines
			default:
				return "", nil, fmt.Errorf("line %d of the netrc file has a token that is not a netrc keyword "+
					"(machine, login, password, account, default). snug refuses a file it cannot read the "+
					"way curl does; a password containing a space is the usual cause", lineNo)
			}
		}
	}
	if pending != kwNone {
		return "", nil, errors.New("the netrc file ends after a keyword that needs a value")
	}
	switch {
	case !want.seen && sawDefault:
		return "", nil, fmt.Errorf("the netrc file has no `machine %s` entry; only a `default` entry would match, "+
			"and snug never stages a default credential", host)
	case !want.seen:
		return "", nil, fmt.Errorf("the netrc file has no `machine %s` entry", host)
	case !want.hasLogin:
		return "", nil, fmt.Errorf("the netrc entry for %s has no `login`", host)
	case !want.hasPassword:
		return "", nil, fmt.Errorf("the netrc entry for %s has no `password`", host)
	}
	return want.login, Secret(want.password), nil
}

// netrcFields splits on space, tab and CR, the separators curl uses on a line.
// strings.Fields would also split on \v, \f, U+0085 and U+00A0, which curl does
// not; the control bytes never get here, ParseNetrcEntry refuses them first.
func netrcFields(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r':
			return true
		}
		return false
	})
}

// CheckForgeToken refuses a forge token outside the alphabet real tokens use:
// letters, digits and . _ ~ + / = -.
//
// The token is interpolated UNQUOTED into a YAML scalar and into a netrc line,
// where a space, newline, quote, `#` or `:` is syntax: it would author a second
// credential or a second YAML key. The refusal never prints the value.
func CheckForgeToken(tok Secret) error {
	if len(tok) == 0 {
		return errors.New("the token is empty")
	}
	for _, b := range tok {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9',
			b == '.', b == '_', b == '~', b == '+', b == '/', b == '=', b == '-':
		default:
			return errors.New("the token holds a character outside letters, digits and . _ ~ + / = - " +
				"(its text is not shown). snug writes it unquoted into a YAML file and a netrc line, " +
				"where any other character is syntax")
		}
	}
	return nil
}
