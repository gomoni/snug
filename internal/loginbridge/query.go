// Package loginbridge is the pure half of the Claude login browser bridge
// (issue #455): given a line the sandbox handed snug, decide whether it is
// the one Claude Code login URL snug knows how to open, and rebuild the URL
// snug actually opens from its own constants plus the values that line
// supplied. It also checks the browser's callback request the same way. The
// sandbox's own bytes never reach the browser or the sandbox's own answer —
// only the checked, rebuilt values do; that rebuild is the whole point of
// parsing rather than forwarding.
//
// No I/O, no globals, no exec: every function here is (input, injected
// value) -> (result, error), so the security-critical checks run as plain
// unit tests with no root and no namespaces.
package loginbridge

import (
	"fmt"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// parseQueryPairs splits a query string on '&' only — never net/url's
// ParseQuery, which also treats ';' as a separator and silently drops a
// segment with no "=" instead of refusing it — and returns every key exactly
// once, in the order it appeared, or refuses.
//
// It enforces only the query's own grammar: no empty segment ("&&", a
// leading or trailing "&"), exactly one "=" per segment, no empty key, no key
// twice. Which keys are acceptable, and what their values must look like, is
// the caller's rule.
func parseQueryPairs(query string) (order []string, values map[string]string, err error) {
	values = map[string]string{}
	if query == "" {
		return nil, values, nil
	}
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			return nil, nil, fmt.Errorf("query has an empty parameter (\"&&\", or a leading or trailing \"&\")")
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, nil, fmt.Errorf("parameter %s has no \"=\"", policy.VisibleText(part))
		}
		if strings.Contains(v, "=") {
			return nil, nil, fmt.Errorf("parameter %s has more than one \"=\"", policy.VisibleText(part))
		}
		if k == "" {
			return nil, nil, fmt.Errorf("parameter %s has an empty name", policy.VisibleText(part))
		}
		if _, dup := values[k]; dup {
			return nil, nil, fmt.Errorf("parameter %q appears twice", k)
		}
		values[k] = v
		order = append(order, k)
	}
	return order, values, nil
}
