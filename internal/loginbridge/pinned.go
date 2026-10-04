package loginbridge

import "net/url"

// PinnedClientID is the OAuth client id the bridge admits, for the screens
// that report what snug will open. It is clientID, not a copy of it.
func PinnedClientID() string { return clientID }

// PinnedAuthorizeBase is the scheme, host and path of the one URL shape the
// bridge opens, without the query. It is authorizePrefix less its `?`.
func PinnedAuthorizeBase() string {
	return authorizePrefix[:len(authorizePrefix)-1]
}

// PinnedScopes returns the seven scopes the bridge admits, unescaped, in the
// order scopeTokens holds them. The slice is a fresh copy.
func PinnedScopes() []string {
	out := make([]string, len(scopeTokens))
	for i, tok := range scopeTokens {
		s, err := url.QueryUnescape(tok)
		if err != nil {
			// scopeTokens is a constant table; a malformed escape in it is a
			// source error, and showing the raw token keeps the screen
			// truthful about what the predicate compares against.
			s = tok
		}
		out[i] = s
	}
	return out
}
