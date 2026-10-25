package hostfacts

import (
	"context"
	"strings"
)

// GitAuthor is the global git identity.
type GitAuthor struct {
	Name, Email string
}

// String renders "Name <email>", the spelling used in the model's context.
func (a GitAuthor) String() string { return a.Name + " <" + a.Email + ">" }

// GitAuthors returns the global author from `git config --global`. It is a
// list because per-directory identities (includeIf) could add more; today it
// holds zero or one entry. A missing name or email yields no entry, because
// identity.git needs both.
func GitAuthors(ctx context.Context, run Runner) []GitAuthor {
	get := func(key string) string {
		res, err := run(ctx, nil, "git", "config", "--global", key)
		if err != nil {
			return ""
		}
		return cleanText(strings.TrimSpace(string(res.Stdout)))
	}
	name, email := get("user.name"), get("user.email")
	if name == "" || email == "" {
		return nil
	}
	return []GitAuthor{{Name: name, Email: email}}
}

// GitSigning returns the global git config's user.signingkey and
// gpg.ssh.allowedSignersFile, "" for each that is not set. Only --global is
// asked: the repository's own config is the target's, and is never consulted.
func GitSigning(ctx context.Context, run Runner) (signingKey, allowedSigners string) {
	get := func(key string) string {
		res, err := run(ctx, nil, "git", "config", "--global", "--get", key)
		if err != nil {
			return ""
		}
		return cleanText(strings.TrimSpace(string(res.Stdout)))
	}
	return get("user.signingkey"), get("gpg.ssh.allowedSignersFile")
}
