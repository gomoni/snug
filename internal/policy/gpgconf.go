package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// GPGConfGuest is the generated per-user gpg.conf inside the sandbox's
// GNUPGHOME, and GPGSystemConfName the file name gpg reads in its sysconfdir
// (`gpgconf --list-dirs sysconfdir`). gpg reads the system file BEFORE the
// user's and lets the user's override it, except for options the system file
// marks `[force]` — measured on gpg 2.5.24 with `digest-algo` and a signature's
// `digest algo` packet field. snug generates both files rather than merging
// them into one so that gpg inside applies that precedence itself.
const (
	GPGConfGuest      = GPGHomeGuest + "/gpg.conf"
	GPGSystemConfName = "gpg.conf"
)

// GPGConfOptions is every gpg.conf option snug carries from the host into the
// files it generates, mapped to whether the option takes an argument. Each
// names a cryptographic or trust CHOICE the gpg client makes: which digest
// signs, which cipher encrypts, which digests a signature may not use, which
// trust model and compliance mode decide validity.
//
// It also carries the choices that decide what an encrypted message LEAKS:
// `throw-keyids` (measured: the host wrote keyid 0000000000000000, the
// sandbox the real key ID until it was carried), `disable-signer-uid`, and
// compression, which hosts turn off against compression-before-encryption
// side channels (`compress-algo none` measured: no compressed packet on the
// host, `compressed packet: algo=2` in the sandbox until carried).
//
// It is an ALLOWLIST because gpg.conf is partly a command table: `exec-path`,
// `photo-viewer` and `verify-options show-photos` name programs to run, and
// `keyserver`, `keyserver-options`, `auto-key-retrieve` and `auto-key-locate`
// send the sandbox to the network on gpg's initiative. None of those is on
// this list, and nothing naming a file or socket: `assert-signer` and
// `trusted-key` also accept a FILE name (measured: `assert-signer signers.txt`
// read ./signers.txt), so they carry hex key IDs only (gpgConfHexOptions).
// Leaving the network ones behind is not enough on its own — gpg's DEFAULT
// does a WKD lookup through a dirmngr it starts itself — so the user file
// always ends in `disable-dirmngr` (renderGPGConf).
//
// The `allow-*` relaxations and their kin (`allow-weak-digest-algos`,
// `allow-weak-key-signatures`, `allow-old-cipher-algos`, `ignore-mdc-error`,
// `no-require-cross-certification`, `override-compliance-check`,
// `always-trust`) are absent ON PURPOSE: each only switches a check off, so
// dropping one leaves the sandbox's gpg stricter than the host's, never looser.
// A host that needs one to verify an old signature does that on the host. The
// VALUE of a carried choice is the host's whatever it is: `trust-model always`
// and `compliance pgp6` are carried as written, because the sandbox then
// matches the host, and the rule above is about dropping a line, not about
// second-guessing one.
//
// Dropping a line is safe only if no carried line depends on it, and two kinds
// of gpg option do: an ALIAS of a carried option (`personal-cipher-prefs`) and
// a SHORTCUT that sets a carried option's value (`gnupg`, `openpgp`, `no-pgp6`
// … set `compliance`). Both are carried AS WRITTEN, never rewritten to the
// canonical spelling: gpg records `[force]` per option-table entry, and an
// alias or a shortcut is a different entry from the option it sets. Measured
// by the red team on gpg 2.5.24: system `[force] openpgp` with user
// `compliance gnupg` gave AES256/SHA-256 on the host and, once both were
// rewritten to `compliance`, 3DES/SHA-1 in the sandbox; a dropped
// `personal-cipher-prefs AES128` or `gnupg` gave the same class of downgrade.
//
// A hostile process inside is not bound by any of this — it can point gpg at a
// GNUPGHOME of its own. The files exist so that git and every other HONEST
// client inside signs and verifies the way the host's gpg would.
var GPGConfOptions = map[string]bool{
	"personal-cipher-preferences": true,
	"personal-digest-preferences": true,
	"personal-aead-preferences":   true,
	"cipher-algo":                 true,
	"digest-algo":                 true,
	"cert-digest-algo":            true,
	"aead-algo":                   true,
	"s2k-mode":                    true,
	"s2k-digest-algo":             true,
	"s2k-cipher-algo":             true,
	"s2k-count":                   true,
	"weak-digest":                 true,
	"disable-cipher-algo":         true,
	"disable-pubkey-algo":         true,
	"assert-pubkey-algo":          true,
	"compliance":                  true,
	"trust-model":                 true,
	"completes-needed":            true,
	"marginals-needed":            true,
	"max-cert-depth":              true,
	"min-cert-level":              true,
	"trusted-key":                 true,
	"tofu-default-policy":         true,
	"assert-signer":               true,

	"personal-compress-preferences": true,
	"compress-algo":                 true,
	"compress-level":                true,
	"bzip2-compress-level":          true,

	"require-compliance":          false,
	"require-cross-certification": false,
	"require-backsigs":            false,
	"require-secmem":              false,
	"require-pqc-encryption":      false,
	"force-aead":                  false,
	"no-symkey-cache":             false,
	"throw-keyids":                false,
	"no-throw-keyids":             false,
	"disable-signer-uid":          false,
	"no-compress":                 false,

	// Aliases, as `gpg --dump-options` lists them.
	"personal-cipher-prefs":   true,
	"personal-compress-prefs": true,
	"compression-algo":        true,
	"force-ocb":               false,
	"use-ocb-sym":             false,

	// Compliance shortcuts: each sets `compliance` (no-pgpN back to gnupg).
	"gnupg":      false,
	"openpgp":    false,
	"rfc2440":    false,
	"rfc4880":    false,
	"rfc4880bis": false,
	"pgp6":       false,
	"pgp7":       false,
	"pgp8":       false,
	"no-pgp2":    false,
	"no-pgp6":    false,
	"no-pgp7":    false,
	"no-pgp8":    false,
}

// gpgConfHexOptions take a key ID or fingerprint — and, to gpg, alternatively
// a file name. snug carries the key-ID form only.
var gpgConfHexOptions = map[string]bool{"trusted-key": true, "assert-signer": true}

// gpgConfHexOK is one or more key IDs or fingerprints (8 to 64 hex digits,
// optional 0x), separated by blanks or commas.
func gpgConfHexOK(v string) bool {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' })
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		f = strings.TrimPrefix(strings.TrimPrefix(f, "0x"), "0X")
		if len(f) < 8 || len(f) > 64 {
			return false
		}
		for _, r := range f {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return false
			}
		}
	}
	return true
}

// gpgConfBlanks is what gpg takes as the gap between an option and its
// argument: measured, `digest-algo` followed by VT, FF or CR and then a bogus
// name each failed with "selected digest algorithm is invalid", so all three
// separate as space and tab do.
const gpgConfBlanks = " \t\v\f\r"

// gpgConfMeta is every meta command snug carries verbatim from the SYSTEM file.
// gpg accepts meta commands only there (in a user file it fails with
// "unexpected meta command") and fails on one it does not know ("unknown meta
// command"); both measured on gpg 2.5.24. They are carried rather than
// interpreted so that gpg inside applies them to the carried lines exactly as
// the host's does: `[force]` lets a system option win over the user file and
// the command line, `[ignore]` drops the system options after it, and
// `[ignore-all]` makes gpg skip the user file. `[user NAME]` is carried with
// its argument checked by gpgConfValueOK.
var gpgConfMeta = []string{
	"force", "+force", "-force",
	"ignore", "+ignore", "-ignore", "ignore-all",
	"verbose", "+verbose", "-verbose",
}

// SortedGPGConfOptions is GPGConfOptions' keys in a stable order.
func SortedGPGConfOptions() []string {
	out := make([]string, 0, len(GPGConfOptions))
	for k := range GPGConfOptions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GPGConfFrom reads one host gpg.conf as DATA and returns the file snug
// generates in its place: the allowlisted option lines and, for the system
// file, the meta commands, in the host's order, each rendered by snug.
// `host` names the file in errors and in the header.
//
// The grammar is the part of gpg's that the host's own gpg accepts, measured
// on gpg 2.5.24: one option per line; leading and trailing blanks ignored; `#`
// starts a comment only at the start of a line (`digest-algo SHA256 # c` is
// the argument "SHA256 # c", and gpg rejects it); option names are exact and
// lowercase (`digest-al`, `DIGEST-ALGO`, `--digest-algo` and
// `digest-algo=SHA256` are each "invalid option"); one `"…"` pair around an
// argument is stripped; the last of a repeated scalar option wins.
//
// It returns an error, never a quieter file, for an allowlisted option it
// cannot carry faithfully: an argument missing, present on a flag, or shaped
// like nothing a crypto or trust option takes. Dropping that line would give
// the sandbox gpg's compiled-in default for the option — the silent downgrade
// this file exists to prevent. Lines naming any other option are left behind;
// GPGConfSummary names them (never their values) for the -v log, because
// every drop is named (.claude/design/GENERATED-CONFIG.md §6a).
func GPGConfFrom(src []byte, host string, system bool) ([]byte, error) {
	carried, _, err := gpgConfRead(src, host, system)
	if err != nil {
		return nil, err
	}
	return renderGPGConf(host, system, carried), nil
}

// GPGConfSummary is the option NAMES one host file contributes (carried) and
// those it leaves behind (dropped), each once, in file order — for the -v log
// and for deciding whether the user file carries anything at all. Values are
// never returned: a keyserver URL or a path is the host user's, not a
// screen's. A file GPGConfFrom refuses summarises as nothing; the refusal is
// what the human sees.
func GPGConfSummary(src []byte, system bool) (carried, dropped []string) {
	lines, dropped, err := gpgConfRead(src, "", system)
	if err != nil {
		return nil, nil
	}
	for _, l := range lines {
		if l[0] == '[' {
			continue
		}
		name, _, _ := strings.Cut(l, " ")
		if !slices.Contains(carried, name) {
			carried = append(carried, name)
		}
	}
	return carried, dropped
}

// gpgConfRead is GPGConfFrom's parse: the carried lines as snug renders them,
// and the names of the options left behind.
func gpgConfRead(src []byte, host string, system bool) (carried, dropped []string, err error) {
	for i, raw := range strings.Split(string(src), "\n") {
		line := strings.Trim(raw, gpgConfBlanks)
		if line == "" || line[0] == '#' {
			continue
		}
		where := fmt.Sprintf("%s:%d", host, i+1)
		if line[0] == '[' {
			if !system {
				return nil, nil, fmt.Errorf("%s: %q is a meta command, which gpg accepts only in "+
					"the system-wide gpg.conf. The host's gpg refuses this file too; remove the line",
					where, VisibleText(line))
			}
			m, err := gpgConfMetaLine(line)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %v", where, err)
			}
			carried = append(carried, m)
			continue
		}
		name, arg := line, ""
		if i := strings.IndexAny(line, gpgConfBlanks); i >= 0 {
			name, arg = line[:i], strings.Trim(line[i:], gpgConfBlanks)
		}
		if !gpgConfNameOK(name) {
			return nil, nil, fmt.Errorf("%s: %q is not spelled like a gpg option (lowercase letters, "+
				"digits and dashes), so snug cannot tell which option the host's gpg reads it as; "+
				"fix or remove the line", where, VisibleText(name))
		}
		takesArg, ok := GPGConfOptions[name]
		if !ok {
			if !slices.Contains(dropped, name) {
				dropped = append(dropped, name)
			}
			continue
		}
		if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
			arg = arg[1 : len(arg)-1]
		}
		switch {
		case !takesArg && arg != "":
			return nil, nil, fmt.Errorf("%s: %s takes no argument, and this line gives it %q. "+
				"snug cannot tell what the host's gpg makes of it; write the option alone",
				where, name, VisibleText(arg))
		case takesArg && arg == "":
			return nil, nil, fmt.Errorf("%s: %s needs an argument. The host's gpg refuses this "+
				"line too (\"missing argument\"); give it one or remove it", where, name)
		case takesArg && gpgConfHexOptions[name] && !gpgConfHexOK(arg):
			return nil, nil, fmt.Errorf("%s: %s %q is not a key ID or fingerprint. gpg also reads "+
				"a FILE name here, and a file in the sandbox is not the host's file, so snug "+
				"carries key IDs only; leaving the line out would drop the host's check. "+
				"Write the fingerprints in gpg.conf", where, name, VisibleText(arg))
		case takesArg && !gpgConfValueOK(arg):
			return nil, nil, fmt.Errorf("%s: %s %q is not shaped like an algorithm list, a "+
				"number or a key ID, so snug will not write it into the sandbox's gpg.conf, "+
				"and leaving it out would hand the sandbox gpg's compiled-in default instead. "+
				"Spell it as gpg(1) does, e.g. `personal-digest-preferences SHA512 SHA384`",
				where, name, VisibleText(arg))
		}
		if takesArg {
			carried = append(carried, name+" "+arg)
		} else {
			carried = append(carried, name)
		}
	}
	return carried, dropped, nil
}

func gpgConfNameOK(name string) bool {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return name != ""
}

func gpgConfMetaLine(line string) (string, error) {
	if !strings.HasSuffix(line, "]") {
		return "", fmt.Errorf("%q opens a meta command and does not close it", VisibleText(line))
	}
	inner := strings.Trim(line[1:len(line)-1], " \t")
	if user, ok := strings.CutPrefix(inner, "user"); ok && (user == "" || user[0] == ' ' || user[0] == '\t') {
		user = strings.Trim(user, " \t")
		if user == "" || !gpgConfValueOK(user) || strings.Contains(user, " ") {
			return "", fmt.Errorf("[user %s] names a user snug cannot carry; "+
				"want one login name or *", VisibleText(user))
		}
		return "[user " + user + "]", nil
	}
	for _, m := range gpgConfMeta {
		if inner == m {
			return "[" + m + "]", nil
		}
	}
	return "", fmt.Errorf("[%s] is a meta command snug does not know (it carries %s and [user NAME]); "+
		"without it snug cannot say what the system options around it mean",
		VisibleText(inner), "["+strings.Join(gpgConfMeta, "] [")+"]")
}

// gpgConfValueOK admits exactly what the allowlisted options take — algorithm
// names (`SHA512`, `AES256`, `cv25519`), lists of them separated by blanks or
// commas, numbers, key IDs (`0xD4381E1CE2880244`), the compliance and trust
// words (`de-vs`, `pgp`), `assert-pubkey-algo`'s comparisons (`>=rsa3072`), and
// the `*` of `[user *]` — as an allowed set rather than a list of dangerous
// characters. It refuses `"` and `#`, the two characters gpg.conf's grammar
// gives meaning inside a line, and every control character, so a carried value
// cannot become a second line or a comment.
func gpgConfValueOK(v string) bool {
	if v == "" || len(v) > 1024 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(" ,.-_+<>=*", r):
		default:
			return false
		}
	}
	return true
}

func renderGPGConf(host string, system bool, carried []string) []byte {
	var b strings.Builder
	if system {
		b.WriteString("# Generated by snug from this host's system-wide gpg.conf,\n")
	} else {
		b.WriteString("# Generated by snug from this host's gpg.conf,\n")
	}
	fmt.Fprintf(&b, "# %s.\n", VisibleText(host))
	b.WriteString("#\n")
	b.WriteString("# Only cryptographic, trust and leak choices are carried (digest,\n")
	b.WriteString("# cipher, weak-digest, compliance, trust model, key-ID hiding,\n")
	b.WriteString("# compression), each line written by snug.\n")
	b.WriteString("# Options that run a program or reach the network (exec-path,\n")
	b.WriteString("# photo-viewer, keyserver, auto-key-retrieve, auto-key-locate) and\n")
	b.WriteString("# the allow-* relaxations are left behind.\n")
	if len(carried) == 0 {
		b.WriteString("#\n# The host's file sets none of the carried options.\n")
	} else {
		b.WriteString("\n")
		for _, l := range carried {
			b.WriteString(l)
			b.WriteString("\n")
		}
	}
	if !system {
		// snug's own line, not the host's. gpg's DEFAULT auto-key-locate does a
		// WKD lookup through a dirmngr it starts itself (measured inside: with
		// the host's no-auto-key-locate left behind, encrypting to
		// wk@gnupg.org fetched over WKD and failed only at "no writable
		// keyring found"). The staged keyring is read-only, so no lookup can
		// import anything: what one does is tell the network which address
		// the sandbox asked about. Nothing that works inside is lost.
		b.WriteString("\n# snug: no dirmngr — the sandbox's keyring is read-only.\ndisable-dirmngr\n")
	}
	return []byte(b.String())
}
