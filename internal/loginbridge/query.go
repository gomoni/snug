// Package loginbridge is the host half of the Claude login browser bridge
// (issue #455) and of its host mode, login.claude = "host" (issue #662).
//
// Its predicates decide, given a line the sandbox handed snug, whether it is
// the one Claude Code login URL snug knows how to open, and rebuild the URL
// snug actually opens from its own constants plus the values that line
// supplied; they check the browser's callback request the same way. The
// sandbox's own bytes never reach the browser or the sandbox's own answer —
// only the checked, rebuilt values do; that rebuild is the whole point of
// parsing rather than forwarding. ParseAuthorize, ParseCallback, ParseDenial
// and the query grammar under them do no I/O and hold no state, so the
// security-critical checks run as plain unit tests with no root and no
// namespaces.
//
// The Bridge around them listens on host loopback, relays into the sandbox,
// runs the opener and, in host mode, calls Claude's token and profile
// endpoints. Everything it does to the outside world is injected (Deps,
// HostLogin, HostFiles, Doer), so it is tested the same way. HostLogin's doc
// comment carries host mode's abuse sentence.
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
