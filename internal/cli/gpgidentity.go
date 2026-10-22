package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/gpgproxy"
	"github.com/gomoni/snug/internal/policy"
)

// gpgGrips is one pinned key as the host agent knows it: the keygrips of the
// subkeys that sign and of those that decrypt, each 40 hex characters.
//
// The PRIMARY key's grip is deliberately not among them. The primary carries
// Certify, and the agent signs a hash without knowing what it is for, so a
// pinned primary is a certification oracle: measured through this proxy,
// `gpg --quick-add-uid <fp> 'Evil <evil@attacker.example>'` inside the sandbox
// added a user ID certified by the host's primary key — a change to the key
// itself that outlives the run. The same PKSIGN can bind a subkey the attacker
// holds or make a revocation. Subkeys cannot certify.
//
// Both lists can hold several grips, for two measured reasons. A key can carry
// more than one subkey of a kind, and gpg uses the newest, so pinning only the
// first would leave the one actually used unpinned. And a gpg 2.5
// post-quantum subkey (ky768_bp256) is composite: its `grp:` line carries TWO
// grips, comma-separated, and decryption names both (`SETKEY <first>` then
// `SETKEY --another <second>`).
type gpgGrips struct {
	signers    []string // signing-capable, unrevoked, unexpired subkeys' grips
	encryptors []string // encryption subkeys' grips, expired ones included
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
	ctx, cancel := context.WithTimeout(context.Background(), gpgHostTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpg, "--batch", "--with-colons", "--with-keygrip",
		"--list-secret-keys", "--", fingerprint)
	// The HOST's own GNUPGHOME, if the caller has one set (inherited): this
	// runs before the sandbox exists.
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

// parseKeygrips reads the colon-delimited listing of ONE key and returns its
// subkeys' grips, and whether the listing held the asked-for key at all.
//
// It is a small parser ON PURPOSE: it consumes only `sec:`, `ssb:`, `fpr:` and
// `grp:`, keys signing and encryption off the capability field of `ssb:` (the
// 12th: `s`, `e`), and reads only the block whose primary `fpr:` is the one
// asked for, so a listing holding a second key adds nothing. Validity (the 2nd
// field) keeps a revoked or expired subkey from SIGNING; it still decrypts,
// because mail already addressed to it is the reason to keep it.
func parseKeygrips(listing, fingerprint string) (gpgGrips, bool) {
	var g gpgGrips
	var (
		inKey    bool // inside the asked-for key's block
		atSec    bool // the next fpr: is the primary's
		found    bool
		validity string
		caps     string
	)
	want := strings.ToUpper(fingerprint)
	for line := range strings.SplitSeq(listing, "\n") {
		fields := strings.Split(line, ":")
		field := func(n int) string {
			if len(fields) > n {
				return fields[n]
			}
			return ""
		}
		switch fields[0] {
		case "sec":
			inKey, atSec, caps = false, true, ""
		case "ssb":
			atSec = false
			validity, caps = field(1), field(11)
		case "fpr":
			if atSec {
				inKey = strings.ToUpper(field(9)) == want
				found = found || inKey
				atSec = false
			}
		case "grp":
			if !inKey || caps == "" || field(9) == "" {
				continue
			}
			grips := strings.Split(strings.ToUpper(field(9)), ",")
			if strings.Contains(caps, "s") && validity != "r" && validity != "e" {
				g.signers = append(g.signers, grips...)
			}
			if strings.Contains(caps, "e") {
				g.encryptors = append(g.encryptors, grips...)
			}
		}
	}
	return g, found
}

// gpgPins is the pin set for one key and scope. A scope the key has no subkey
// for is refused rather than pinned to nothing: a profile that grants signing
// on a key that cannot sign through snug would run, and every `git commit`
// inside would fail with no cause on screen.
func gpgPins(fingerprint, scope string, g gpgGrips) ([]gpgproxy.PinnedGrip, error) {
	var pins []gpgproxy.PinnedGrip
	if policy.GPGScopeHas(scope, policy.GPGScopeSign) {
		if len(g.signers) == 0 {
			return nil, fmt.Errorf("identity.gpg.fingerprint %q has no signing subkey, and "+
				"snug signs only with a subkey.\n\n"+
				"      The primary key also CERTIFIES: through it the sandbox could add a user\n"+
				"      ID, bind a subkey or revoke the key, and those outlive the run. Add a\n"+
				"      signing subkey on the host:  gpg --quick-add-key %s ed25519 sign",
				fingerprint, fingerprint)
		}
		for _, grip := range g.signers {
			pins = append(pins, gpgproxy.PinnedGrip{
				Field: "identity.gpg.fingerprint", Grip: grip, Scope: gpgproxy.ScopeSign})
		}
	}
	if policy.GPGScopeHas(scope, policy.GPGScopeDecrypt) {
		if len(g.encryptors) == 0 {
			return nil, fmt.Errorf("identity.gpg.fingerprint %q has no encryption subkey, so "+
				"scope \"decrypt\" has nothing to decrypt with.\n"+
				"      Drop \"decrypt\" from identity.gpg.scope, or add one on the host:\n"+
				"      gpg --quick-add-key %s cv25519 encr", fingerprint, fingerprint)
		}
		for _, grip := range g.encryptors {
			pins = append(pins, gpgproxy.PinnedGrip{
				Field: "identity.gpg.fingerprint", Grip: grip, Scope: gpgproxy.ScopeDecrypt})
		}
	}
	return pins, nil
}

// startGPGIdentity is what identity.gpg needs from the host: the Assuan proxy
// to the host gpg-agent and the pinned key's PUBLIC keyring.
//
// ~/.gnupg itself (a 0700 tmpfs) and GNUPGHOME are Resolve's; this stages what
// needs host state inside it.
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
		// The public keyring is staged here too, so --dry-run shows the row a
		// real run mounts. It is public material read from the host gpg; a host
		// that does not know the key is a warning on a dry run, as a missing gh
		// token is, because a dry run inspects a policy on hosts where the real
		// run may never happen.
		if keyring, kerr := gpgExportPublicKey(id.GPG.Fingerprint); kerr != nil {
			fmt.Fprintln(os.Stderr, "snug: "+kerr.Error())
			fmt.Fprintln(os.Stderr, "      (dry run: continuing, and the FILESYSTEM block below "+
				"therefore has no pubring.kbx row)")
		} else {
			stageGPGKeyring(pol, keyring)
		}
		pol.BindSocket(sock, pol.Home+"/"+policy.GPGAgentSocketGuest,
			identityProvenance(pol, "gpg"))
		return cleanup, nil
	}

	grips, err := gpgKeyInfo(id.GPG.Fingerprint)
	if err != nil {
		cleanup()
		return nil, err
	}

	if _, err := gpgScopeFor(id.GPG.Scope); err != nil {
		cleanup()
		return nil, err
	}
	pinned, err := gpgPins(id.GPG.Fingerprint, id.GPG.Scope, grips)
	if err != nil {
		cleanup()
		return nil, err
	}

	upstream, err := gpgAgentSocket()
	if err != nil {
		cleanup()
		return nil, err
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
	stageGPGKeyring(pol, keyring)

	pol.BindSocket(sock, pol.Home+"/"+policy.GPGAgentSocketGuest,
		identityProvenance(pol, "gpg"))
	return cleanup, nil
}

// stageGPGKeyring mounts the pinned key's public keyring read-only.
func stageGPGKeyring(pol *policy.Policy, keyring []byte) {
	pol.Replace(policy.Mount{
		Guest: pol.Home + "/" + policy.GPGKeyringGuest, Kind: policy.KindData,
		Access: policy.AccessRO, Content: keyring,
		From: []string{identityProvenance(pol, "gpg")},
	})
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
// may or may not have set). Each failure names its own cause: "start an agent"
// is the wrong advice when gpgconf itself is missing.
func gpgAgentSocket() (string, error) {
	gpgconf, err := exec.LookPath("gpgconf")
	if err != nil {
		return "", errors.New("identity.gpg needs gpgconf on the host to find the gpg-agent " +
			"socket, and no gpgconf is on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gpgHostTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, gpgconf, "--list-dirs", "agent-socket").Output()
	if err != nil {
		return "", fmt.Errorf("identity.gpg: `gpgconf --list-dirs agent-socket` failed: %v", err)
	}
	path := strings.TrimSpace(string(out))
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("identity.gpg needs a running host gpg-agent, and there is no "+
			"socket at %s.\n\n"+
			"      Start one with `gpg-connect-agent /bye` or let gpg start it, then retry.", path)
	}
	return path, nil
}

// gpgHostTimeout bounds each host gpg/gpgconf call. They read a keyring and
// print; none of them prompts.
const gpgHostTimeout = 30 * time.Second

// gpgExportPublicKey is `gpg --export <fingerprint>`: the PUBLIC half only, the
// bytes the sandbox's keyring holds. It never asks for a secret key.
func gpgExportPublicKey(fingerprint string) ([]byte, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return nil, fmt.Errorf("identity.gpg needs gpg on the host, and none is on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), gpgHostTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gpg, "--batch", "--export", "--", fingerprint)
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
