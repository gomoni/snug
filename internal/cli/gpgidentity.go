package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/gpgproxy"
	"github.com/gomoni/snug/internal/policy"
)

// gpgGrips is one pinned key as the host agent knows it: the primary keygrip
// and the encryption subkey's keygrip, both 40 hex characters.
//
// BOTH are needed because signing and decryption use DIFFERENT keygrips through
// the agent: SIGKEY/PKSIGN take the primary key's grip, SETKEY/PKDECRYPT take
// the encryption subkey's. The fingerprint names the key; the grips are what
// the proxy compares against, and they are resolved HERE, on the host, before
// the proxy exists — internal/gpgproxy never learns a fingerprint.
type gpgGrips struct {
	primary   string // the primary key's keygrip: signs
	encryptor string // the encryption subkey's keygrip: decrypts ("" if none)
}

// gpgKeyInfo asks the host gpg for the keygrips behind a fingerprint.
//
// `gpg --with-colons --with-keygrip --list-secret-keys <fingerprint>` is the
// one host touch of the gpg half, and it is deliberately a READ: snug never
// copies key material. The `grp:` lines carry the keygrips the AGENT uses, and
// the `fpr:` lines that follow a `sec:`/`ssb:` record say which key each grip
// belongs to.
//
// A fingerprint with no SECRET key is refused rather than staged: the sandbox
// could still encrypt to the public half, but it could not sign or decrypt, and
// a gpg block that grants neither is a pin that does not exist. The refusal
// names the fingerprint and says what to do.
func gpgKeyInfo(fingerprint string) (gpgGrips, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return gpgGrips{}, fmt.Errorf("identity.gpg needs gpg on the host to resolve the key's " +
			"keygrips, and no gpg is on PATH")
	}
	cmd := exec.Command(gpg, "--batch", "--with-colons", "--with-keygrip",
		"--list-secret-keys", fingerprint)
	// The HOST's own GNUPGHOME, if the caller has one set. Not staging the
	// sandbox's: this runs before the sandbox exists.
	cmd.Env = os.Environ()
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs
	if err := cmd.Run(); err != nil {
		return gpgGrips{}, fmt.Errorf("identity.gpg.fingerprint %q: `gpg --list-secret-keys` "+
			"failed: %v: %s", fingerprint, err, strings.TrimSpace(errs.String()))
	}
	grips, ok := parseKeygrips(out.String(), fingerprint)
	if !ok {
		return gpgGrips{}, fmt.Errorf("identity.gpg.fingerprint %q: the host gpg has no SECRET "+
			"key with that fingerprint.\n\n"+
			"      The sandbox signs and decrypts THROUGH the host agent, so the private\n"+
			"      half must be on this host and available to gpg. Check `gpg --list-secret-keys`\n"+
			"      on the host, or correct the fingerprint (40 hex characters, the string\n"+
			"      `gpg --fingerprint` prints).", fingerprint)
	}
	return grips, nil
}

// parseKeygrips reads the colon-delimited listing and returns the primary
// keygrip and, if the key has an encryption subkey, that subkey's keygrip.
//
// It is a small parser ON PURPOSE: it consumes only `sec:`, `ssb:`, `fpr:` and
// `grp:`, and it keys the primary/subkey choice off the capability field of
// `ssb:` (the `e` in the 12th field). A key whose subkey is sign-only, or that
// has no subkey at all, yields an empty encryptor — decryption is then refused
// by the proxy for want of a grip, which is the correct narrow answer.
func parseKeygrips(listing, fingerprint string) (gpgGrips, bool) {
	var g gpgGrips
	// The order of records is: a `sec:` line, then its `fpr:` and `grp:`, then
	// each subkey's `ssb:` followed by its own `fpr:` and `grp:`. So the first
	// `grp:` after the matching `sec:`/`fpr:` is the primary key's, and a
	// later one is a subkey's.
	var (
		havePrimary   bool
		pendingSubkey bool
		subkeyDecrypt bool
		lastFpr       string
	)
	for line := range strings.SplitSeq(listing, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "sec":
			pendingSubkey = false
		case "ssb":
			pendingSubkey = true
			// The 12th field is the capability string; `e` means encrypt.
			subkeyDecrypt = len(fields) > 11 && strings.Contains(fields[11], "e")
		case "fpr":
			if len(fields) > 9 {
				lastFpr = strings.ToUpper(fields[9])
			}
		case "grp":
			if len(fields) <= 9 || fields[9] == "" {
				continue
			}
			grip := strings.ToUpper(fields[9])
			if !pendingSubkey {
				// The primary key's grip. Guard against a subkey record that
				// arrived before its `sec:` by only taking it if it belongs to
				// the fingerprint we asked for.
				if lastFpr == "" || lastFpr == strings.ToUpper(fingerprint) || !havePrimary {
					g.primary = grip
					havePrimary = true
				}
			} else if subkeyDecrypt && g.encryptor == "" {
				g.encryptor = grip
			}
		}
	}
	return g, havePrimary
}

// startGPGIdentity is everything identity.gpg needs: the Assuan proxy to the
// host gpg-agent, the pinned key's PUBLIC keyring, and GNUPGHOME.
//
// It is gated by its caller on the presence of the block (id.GPG is not the
// zero value) rather than on a mode, because the block IS the proxy.
func startGPGIdentity(pol *policy.Policy, id *policy.Identity, verbose, dryRun bool) (cleanup func(), err error) {
	cleanup = func() {}

	var sock string
	if dryRun {
		sock, err = plannedSocket("gpg-agent.sock")
		if err != nil {
			return nil, err
		}
	} else {
		rt, rerr := openRuntimeDir()
		if rerr != nil {
			return nil, rerr
		}
		sock, err = rt.Socket("gpg-agent.sock")
		if err != nil {
			return nil, err
		}
	}

	if dryRun {
		pol.BindSocket(sock, pol.Home+"/"+policy.GPGAgentSocketGuest,
			identityProvenance(pol, "gpg"))
		pol.AuthorEnv("GNUPGHOME", pol.Home+"/"+policy.GPGHomeGuest)
		return cleanup, nil
	}

	grips, err := gpgKeyInfo(id.GPG.Fingerprint)
	if err != nil {
		cleanup()
		return nil, err
	}

	// The pinned set: the primary grip for signing and decrypting, plus the
	// encryption subkey grip when the profile asked for decryption. A primary
	// key IS a decryption key, so it decrypts with its own grip; the subkey is
	// added so that a message addressed to the subkey — which is every message
	// gpg produces for this key by default — grounds out on a pinned grip.
	scope, serr := gpgScopeFor(id.GPG.Scope)
	if serr != nil {
		cleanup()
		return nil, serr
	}
	pinned := []gpgproxy.PinnedGrip{{
		Field: "identity.gpg.fingerprint",
		Grip:  grips.primary,
		Scope: scope,
	}}
	if policy.GPGScopeHas(id.GPG.Scope, policy.GPGScopeDecrypt) && grips.encryptor != "" {
		pinned = append(pinned, gpgproxy.PinnedGrip{
			Field: "identity.gpg.fingerprint",
			Grip:  grips.encryptor,
			Scope: gpgproxy.ScopeDecrypt,
		})
	}

	upstream := gpgAgentSocket()
	if upstream == "" {
		cleanup()
		return nil, fmt.Errorf("identity.gpg needs a running host gpg-agent: " +
			"no socket at `gpgconf --list-dirs agent-socket`.\n\n" +
			"      Start one with `gpg-connect-agent /bye` or let gpg start it, then retry.")
	}

	audit := func(string) {}
	if verbose {
		audit = func(msg string) { fmt.Fprintln(os.Stderr, "snug: gpg-agent: "+msg) }
	}
	slow := time.AfterFunc(2*time.Second, func() {
		fmt.Fprintln(os.Stderr, "snug: waiting for the host gpg-agent to answer a startup probe.\n"+
			"      If a pinned key needs a passphrase or confirmation, your agent is asking for it.")
	})
	p, perr := gpgproxy.New(pinned, upstream, sock, audit)
	slow.Stop()
	if perr != nil {
		cleanup()
		return nil, perr
	}
	go p.Serve()
	inner := cleanup
	cleanup = func() { p.Close(); inner() }

	// The pinned PUBLIC keyring, so gpg inside knows the key it may act on.
	// Only public material; the private half stays in the host agent.
	keyring, kerr := gpgExportPublicKey(id.GPG.Fingerprint)
	if kerr != nil {
		cleanup()
		return nil, kerr
	}
	pol.Replace(policy.Mount{
		Guest: pol.Home + "/" + policy.GPGKeyringGuest, Kind: policy.KindData,
		Access: policy.AccessRO, Content: keyring,
		From: []string{identityProvenance(pol, "gpg")},
	})

	pol.BindSocket(sock, pol.Home+"/"+policy.GPGAgentSocketGuest,
		identityProvenance(pol, "gpg"))
	pol.AuthorEnv("GNUPGHOME", pol.Home+"/"+policy.GPGHomeGuest)
	return cleanup, nil
}

// gpgScopeFor maps the profile's canonical scope spelling to the proxy's bit
// set. It is the ONE place the two vocabularies meet: internal/policy carries a
// comparable string leaf, internal/gpgproxy a bitmask, and neither imports the
// other.
//
// A spelling that maps to no bit is refused rather than passed on: gpgproxy.New
// already refuses a zero scope, but this refusal names the PROFILE field rather
// than the proxy's constructor.
func gpgScopeFor(scope string) (gpgproxy.Scope, error) {
	var out gpgproxy.Scope
	for _, part := range strings.Split(scope, ",") {
		switch part {
		case "":
			continue
		case policy.GPGScopeSign:
			out |= gpgproxy.ScopeSign
		case policy.GPGScopeDecrypt:
			out |= gpgproxy.ScopeDecrypt
		default:
			// An unknown part is refused HERE as well as in
			// ParseGPGRuntimeScope: this function maps the two vocabularies, and
			// a mapping that silently dropped a word it did not know would turn a
			// scope snug cannot enforce into one it can. Two doors, one answer.
			return 0, fmt.Errorf("unknown identity.gpg.scope %q (want %s or %s)",
				part, policy.GPGScopeSign, policy.GPGScopeDecrypt)
		}
	}
	if out == 0 {
		return 0, fmt.Errorf("identity.gpg.scope %q grants nothing; "+
			"want %s or %s, or both", scope, policy.GPGScopeSign, policy.GPGScopeDecrypt)
	}
	return out, nil
}

// gpgAgentSocket is the host's gpg-agent socket, from gpgconf, which is the
// only authority on where it lives (it depends on GNUPGHOME, which the caller
// may or may not have set).
func gpgAgentSocket() string {
	gpgconf, err := exec.LookPath("gpgconf")
	if err != nil {
		return ""
	}
	cmd := exec.Command(gpgconf, "--list-dirs", "agent-socket")
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(out))
	if _, statErr := os.Stat(path); statErr != nil {
		return ""
	}
	return path
}

// gpgExportPublicKey is `gpg --export <fingerprint>`: the PUBLIC half only, the
// bytes the sandbox's keyring holds. It never asks for a secret key.
func gpgExportPublicKey(fingerprint string) ([]byte, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return nil, fmt.Errorf("identity.gpg needs gpg on the host, and none is on PATH")
	}
	cmd := exec.Command(gpg, "--batch", "--export", fingerprint)
	cmd.Env = os.Environ()
	var out, errs bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errs
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("identity.gpg.fingerprint %q: `gpg --export` failed: %v: %s",
			fingerprint, err, strings.TrimSpace(errs.String()))
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("identity.gpg.fingerprint %q: `gpg --export` produced no public "+
			"key; the host gpg does not know it", fingerprint)
	}
	return out.Bytes(), nil
}
