package hostfacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// GHAccount is one login known to gh.
type GHAccount struct {
	Host   string
	User   string
	Active bool
}

var (
	ghLoggedIn = regexp.MustCompile(`Logged in to (\S+) account (\S+)`)
	ghLegacy   = regexp.MustCompile(`Logged in to (\S+) as (\S+)`)
	ghActive   = regexp.MustCompile(`Active account:\s*(true|false)`)
)

// ParseGHStatus extracts the logged-in accounts from `gh auth status` output
// (stdout and stderr together: older gh versions print to stderr). Accounts
// whose token gh reports as failing are not listed. The older single-account
// format ("Logged in to H as U") is read as active.
func ParseGHStatus(out string) []GHAccount {
	var accts []GHAccount
	for _, line := range strings.Split(out, "\n") {
		if m := ghLoggedIn.FindStringSubmatch(line); m != nil {
			accts = append(accts, GHAccount{Host: m[1], User: m[2]})
			continue
		}
		if m := ghLegacy.FindStringSubmatch(line); m != nil {
			accts = append(accts, GHAccount{Host: m[1], User: m[2], Active: true})
			continue
		}
		if m := ghActive.FindStringSubmatch(line); m != nil && len(accts) > 0 {
			accts[len(accts)-1].Active = m[1] == "true"
		}
	}
	return accts
}

// GitHubAccounts runs `gh auth status`. A missing gh is not an error: it
// returns no accounts and installed=false. A gh that is installed but exits
// non-zero still has its output parsed, because gh exits non-zero when any
// login is broken while still listing the good ones.
func GitHubAccounts(ctx context.Context, run Runner) (accts []GHAccount, installed bool) {
	res, err := run(ctx, nil, "gh", "auth", "status")
	if errors.Is(err, exec.ErrNotFound) {
		return nil, false
	}
	return ParseGHStatus(string(res.Stdout) + "\n" + string(res.Stderr)), true
}

// KeyCheck is the outcome of comparing a local public key with an account.
type KeyCheck struct {
	// Match is true when the account's keys on GitHub include the local key.
	Match bool
	// Detail names the fingerprints compared, for display.
	Detail string
}

// CheckKeyOwnership asks GitHub, as host's account user, whether it lists key.
// This is the one network call snug-setup makes: `gh auth token --hostname H
// --user U` mints the token, which is handed to `gh api` through the child's
// environment only (GH_TOKEN, or GH_ENTERPRISE_TOKEN for a host other than
// github.com) and never printed or stored. The login the token belongs to must
// equal user, or the result is an error rather than a verdict about the wrong
// account. Any failure to reach gh or GitHub is returned as an error.
func CheckKeyOwnership(ctx context.Context, run Runner, host, user string, key SSHKey) (KeyCheck, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tok, err := run(ctx, nil, "gh", "auth", "token", "--hostname", host, "--user", user)
	if err != nil {
		return KeyCheck{}, fmt.Errorf("gh auth token --hostname %s --user %s: %w", host, user, err)
	}
	token := strings.TrimSpace(string(tok.Stdout))
	if token == "" {
		return KeyCheck{}, fmt.Errorf("gh has no token for %s on %s (try `gh auth login --hostname %s`)", user, host, host)
	}
	envName := "GH_TOKEN"
	if host != "github.com" {
		envName = "GH_ENTERPRISE_TOKEN"
	}
	env := []string{envName + "=" + token}

	me, err := run(ctx, env, "gh", "api", "--hostname", host, "user")
	if err != nil {
		return KeyCheck{}, fmt.Errorf("gh api user on %s: %w", host, err)
	}
	var who struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(me.Stdout, &who); err != nil || who.Login == "" {
		return KeyCheck{}, fmt.Errorf("gh api user on %s: unreadable reply", host)
	}
	if !strings.EqualFold(who.Login, user) {
		return KeyCheck{}, fmt.Errorf("the token gh minted for %s on %s belongs to %s", user, host, who.Login)
	}

	ks, err := run(ctx, env, "gh", "api", "--hostname", host, "user/keys")
	if err != nil {
		return KeyCheck{}, fmt.Errorf("gh api user/keys on %s: %w", host, err)
	}
	var list []struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(ks.Stdout, &list); err != nil {
		return KeyCheck{}, fmt.Errorf("gh api user/keys on %s: unreadable reply", host)
	}
	var theirs []string
	for _, k := range list {
		f := strings.Fields(k.Key)
		if len(f) < 2 {
			continue
		}
		fp, err := FingerprintOf(f[1])
		if err != nil {
			continue
		}
		if fp == key.Fingerprint {
			return KeyCheck{Match: true, Detail: key.Fingerprint}, nil
		}
		theirs = append(theirs, fp)
	}
	return KeyCheck{Detail: fmt.Sprintf("local %s; %s lists %s", key.Fingerprint, user, listOrNone(theirs))}, nil
}

func listOrNone(xs []string) string {
	if len(xs) == 0 {
		return "no keys"
	}
	return strings.Join(xs, ", ")
}
