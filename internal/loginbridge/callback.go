package loginbridge

import (
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// callbackKeysPendingMeasurement0e is the callback's accepted query key set.
// The measurement this predicate needs — capturing the request a real
// login's browser redirect actually sends to a loopback listener — has not
// been taken (issue #455). {code, state} is what the authorize request
// authorize.go builds asks the browser to send back, not yet a measured fact
// about what it also sends alongside them. Change this variable, and nothing
// else, once that measurement is taken; every other check in ParseCallback
// names "code" and "state" directly.
var callbackKeysPendingMeasurement0e = map[string]bool{
	"code": true, "state": true,
}

// Callback is a GET /callback request ParseCallback has checked against the
// pinned key set and a flow's own state.
type Callback struct {
	// Code is the raw, still query-encoded value exactly as the browser sent
	// it. The relay forwards it unchanged: decoding and re-encoding it would
	// be a second parser with its own chance to disagree with the one
	// Claude Code's token endpoint uses.
	Code string
}

// ParseCallback checks an already-parsed HTTP request line's method and
// request-target against the one callback shape snug relays, and its state
// parameter against expectedState.
//
// It does no I/O and holds no state across calls. The listener that owns a
// live flow enforces the request-head size cap and the read deadline, tracks
// whether the flow has been confirmed, and is what calls ParseCallback once
// per accepted connection with the state it is holding for that flow — none
// of that belongs in a pure predicate, so ParseCallback checks the request
// on its own terms and lets the caller decide whether a flow was open to
// check it against at all.
func ParseCallback(method, target, expectedState string) (Callback, error) {
	if method != "GET" {
		return Callback{}, fmt.Errorf("method %s, want GET", policy.VisibleText(method))
	}
	if !strings.HasPrefix(target, "/") {
		return Callback{}, fmt.Errorf("request target %s is not origin-form (does not start with \"/\")",
			policy.VisibleText(target))
	}
	path, query, _ := strings.Cut(target, "?")
	if path != "/callback" {
		return Callback{}, fmt.Errorf("path %s is not \"/callback\"", policy.VisibleText(path))
	}

	order, values, err := parseQueryPairs(query)
	if err != nil {
		return Callback{}, err
	}
	// Every unknown key is named, together with the whole key set, not just
	// the first: the refusal is the record of what a real browser sent, and a
	// login whose callback was refused cannot be retried to learn the rest.
	// Names only — a value here may be the authorization code.
	var unknown []string
	for _, k := range order {
		if !callbackKeysPendingMeasurement0e[k] {
			unknown = append(unknown, fmt.Sprintf("%q", k))
		}
	}
	if len(unknown) > 0 {
		all := make([]string, len(order))
		for i, k := range order {
			all[i] = fmt.Sprintf("%q", k)
		}
		return Callback{}, fmt.Errorf("parameter %s is not one snug relays (the callback's keys: %s)",
			strings.Join(unknown, ", "), strings.Join(all, ", "))
	}
	for k := range callbackKeysPendingMeasurement0e {
		if _, ok := values[k]; !ok {
			return Callback{}, fmt.Errorf("parameter %q is missing", k)
		}
	}

	// Both operands come from the network (the browser's request and the
	// state stapled to this flow when it was confirmed), so a length- or
	// early-exit-driven compare would let a network observer measure timing
	// against a value that is otherwise never revealed to them.
	if subtle.ConstantTimeCompare([]byte(values["state"]), []byte(expectedState)) != 1 {
		return Callback{}, fmt.Errorf("state does not match this flow's")
	}

	code := values["code"]
	if !isRawCode(code) {
		return Callback{}, fmt.Errorf("parameter \"code\" (%s) is not 1-1024 bytes of an RFC 3986 "+
			"unreserved character or a %%XX escape", policy.VisibleText(code))
	}

	return Callback{Code: code}, nil
}

// isRawCode matches the authorization code's shape in the form the query
// string carries it — before any percent-decoding, since ParseCallback's
// caller relays these bytes unchanged rather than decoding and
// re-encoding them.
func isRawCode(s string) bool {
	if len(s) < 1 || len(s) > 1024 {
		return false
	}
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			i++
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 3
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
