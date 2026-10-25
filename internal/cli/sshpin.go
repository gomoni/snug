package cli

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/hostread"
	"github.com/gomoni/snug/internal/policy"
)

// maxKnownHostsBytes bounds the read of each known_hosts file and of the
// RevokedHostKeys file. A busy user can accumulate thousands of hosts, each
// roughly a few hundred bytes (hostname patterns, key type, base64 key blob,
// optional comment); 8 MiB covers tens of thousands of such entries with room
// to spare while still bounding the host-side allocation a planted symlink or
// oversized file would otherwise demand (issue #337).
const maxKnownHostsBytes = 8 << 20

// sshPin is what the host's ssh resolves for the pinned identity.ssh.host,
// read once before Resolve.
type sshPin struct {
	values     policy.SSHValues
	knownHosts []byte
	revoked    []byte // nil when the host's ssh names no RevokedHostKeys
}

// probeSSHPin asks the host's ssh what it would do connecting to host as git,
// the user the generated ~/.ssh/config names, and turns the answer into the
// three things the sandbox's ssh checks the pinned host against (#688): the
// whitelisted algorithm values of whatever `Host`/`Match` block matches it
// (F4), its known_hosts entries from every file ssh would read (F1, F5), and its
// RevokedHostKeys file (F5).
//
// Every failure refuses. The sandbox's ssh verifies the one host it holds a
// credential for, and a probe that could not be asked, or a file that could not
// be read, would leave it verifying that host less strictly than the host does.
//
// The generated Host block names host and nothing else, so the sandbox's ssh
// connects to host on port 22 and looks its key up under host. A host config
// that makes the host's ssh do anything else for it — HostName, Port,
// HostKeyAlias, a KnownHostsCommand — refuses (#688 redteam F2, F3): the
// known_hosts lines and revocations snug carried would be the ones for the
// wrong name, and the host's ssh would be checking keys the sandbox's never
// sees.
//
// A host with no ssh is asked nothing, and its known_hosts are read from
// OpenSSH's default locations: the sandbox may still carry an ssh of its own.
func probeSSHPin(home, host string) (sshPin, error) {
	// Resolve refuses the same spelling later; this is the copy that runs
	// before host reaches an argv, where a leading '-' is an ssh option.
	if host == "" || !policy.IsHostName(host) {
		return sshPin{}, fmt.Errorf("identity.ssh.host = %s is not a host name. Use the bare host, "+
			"letters, digits, '.' and '-' only (for example ghe.corp)", policy.VisibleText(host))
	}
	files := []string{
		filepath.Join(home, ".ssh", "known_hosts"), filepath.Join(home, ".ssh", "known_hosts2"),
		"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2",
	}
	var pin sshPin
	revokedFile := ""
	if ssh, err := exec.LookPath("ssh"); err == nil {
		stdout, stderr, err := runSSHProbe(ssh, "-G", "-o", "BatchMode=yes", "-l", "git", "--", host)
		if err != nil {
			return sshPin{}, sshProbeError(host, err, stderr)
		}
		if pin.values, err = parseSSHValues(stdout); err != nil {
			return sshPin{}, err
		}
		files = nil
		for line := range strings.SplitSeq(stdout, "\n") {
			key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch key {
			case "userknownhostsfile", "globalknownhostsfile":
				// `ssh -G` prints the list space-separated and unquoted, so
				// a path with a space in it comes back as fragments, and a
				// fragment after the space is RELATIVE — opened against the
				// project directory, which is the sandboxed material choosing
				// which key is trusted (#688 redteam F1). Every path ssh
				// prints here is absolute (it expands ~ and %-tokens first),
				// so a relative one can only be such a fragment.
				for f := range strings.FieldsSeq(value) {
					if f == "none" {
						continue
					}
					if !filepath.IsAbs(f) {
						return sshPin{}, fmt.Errorf("identity.ssh: this host's ssh reads known_hosts "+
							"for %s from %s, which snug cannot split into paths: a path with a space "+
							"in it is printed unquoted. Move that known_hosts file to a path without "+
							"spaces", host, policy.VisibleText(value))
					}
					files = append(files, f)
				}
			case "revokedhostkeys":
				if value != "none" {
					revokedFile = value
				}
			case "knownhostscommand":
				if value != "none" {
					return sshPin{}, pinDivergesError(host, "KnownHostsCommand", value,
						"the keys it prints never reach the sandbox, and an @revoked line among them "+
							"would be lost")
				}
			case "hostkeyalias":
				return sshPin{}, pinDivergesError(host, "HostKeyAlias", value,
					"the host's ssh looks the key up under that name, the sandbox's under "+host)
			case "hostname":
				if !strings.EqualFold(value, host) {
					return sshPin{}, pinDivergesError(host, "HostName", value,
						"the sandbox's ssh would connect to "+host+" itself, and check a different "+
							"server's key than the host's ssh does")
				}
			case "port":
				if value != "22" {
					return sshPin{}, pinDivergesError(host, "Port", value,
						"the sandbox's ssh connects on port 22, where a [host]:port known_hosts "+
							"line does not apply")
				}
			}
		}
	}
	kh, n, err := knownHostsFor(host, files)
	if err != nil {
		return sshPin{}, err
	}
	if n == 0 {
		return sshPin{}, fmt.Errorf("identity.ssh: this host has no known_hosts entry for %s (read %s). "+
			"The sandbox's ssh refuses a host key it cannot check rather than trusting the first one "+
			"it is shown. Connect once from the host (`ssh -T git@%s`), check the fingerprint "+
			"against the one %s publishes, and run snug again",
			host, strings.Join(files, " "), host, host)
	}
	pin.knownHosts = kh
	if revokedFile != "" {
		data, err := hostread.Required(revokedFile, maxKnownHostsBytes)
		if err != nil {
			return sshPin{}, fmt.Errorf("identity.ssh: this host's ssh names %s as RevokedHostKeys for %s, "+
				"and snug cannot carry it into the sandbox: %v. Fix the file, or the RevokedHostKeys line",
				revokedFile, host, err)
		}
		if data == nil {
			data = []byte{}
		}
		pin.revoked = data
	}
	return pin, nil
}

// knownHostsFor extracts the entries for one host from the host's known_hosts
// files, and counts the ones that let the sandbox's ssh accept a key on port
// 22, which is where it connects: every match except an @revoked line or a
// `[host]:port` one, which ssh consults only for that port.
//
// Binding the whole file would tell the sandbox every machine you have ever
// connected to — an inventory of your infrastructure, for no benefit. So each
// line is matched the way ssh matches it (knownHostsLineMatches), and kept
// verbatim, marker and all: an @revoked line is what makes the sandbox's ssh
// refuse a key the host's refuses, and an @cert-authority line is what lets it
// accept a certificate the host's accepts.
//
// An absent file is no entries, as it is to ssh, and so is one this uid may not
// open: ssh skips it the same way (measured: a mode-000 known_hosts holding
// an @revoked line, and the host's ssh connected). What hostread refuses — a
// FIFO, an oversized file — refuses the run: it may be the one holding the
// @revoked line.
func knownHostsFor(host string, files []string) (out []byte, usable int, err error) {
	var b strings.Builder
	b.WriteString("# Generated by snug: only entries for " + host + ".\n")
	for _, f := range files {
		// hostread, not os.ReadFile: a FIFO at a known_hosts path would hang
		// every run before the sandbox exists (issue #337).
		data, note := hostread.Optional(f, maxKnownHostsBytes)
		if note != "" {
			return nil, 0, fmt.Errorf("identity.ssh: cannot read %s, a known_hosts file this host's "+
				"ssh reads for %s: %s", f, host, note)
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			m := knownHostsLineMatches(line, host)
			if !m.ok {
				continue
			}
			b.WriteString(strings.TrimRight(line, "\r") + "\n")
			if !m.revoked && m.port22 {
				usable++
			}
		}
	}
	return []byte(b.String()), usable, nil
}

// knownHostsLineMatches reports whether one known_hosts line applies to host,
// whether it is an @revoked line, and whether a pattern other than a
// `[host]:port` one matched, following sshd(8) "SSH_KNOWN_HOSTS FILE
// FORMAT": an optional marker, then a comma-separated pattern list, then the
// key. A pattern is a plain name, `[name]:port`, a `*`/`?` wildcard, a hashed
// `|1|salt|hash` entry, or any of those negated with `!`, which vetoes the line.
func knownHostsLineMatches(line, host string) (m knownHostsMatch) {
	fields := strings.Fields(line)
	if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
		return knownHostsMatch{}
	}
	if strings.HasPrefix(fields[0], "@") {
		switch fields[0] {
		case "@revoked":
			m.revoked = true
		case "@cert-authority":
		default:
			return knownHostsMatch{}
		}
		fields = fields[1:]
	}
	if len(fields) < 3 {
		return knownHostsMatch{}
	}
	host = strings.ToLower(host)
	for pattern := range strings.SplitSeq(fields[0], ",") {
		negated := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(pattern, "!")
		if !knownHostsPatternMatches(pattern, host) {
			continue
		}
		if negated {
			return knownHostsMatch{}
		}
		m.ok = true
		m.port22 = m.port22 || !strings.HasPrefix(pattern, "[")
	}
	return m
}

type knownHostsMatch struct{ ok, revoked, port22 bool }

func knownHostsPatternMatches(pattern, host string) bool {
	if rest, ok := strings.CutPrefix(pattern, "|1|"); ok {
		salt64, hash64, ok := strings.Cut(rest, "|")
		if !ok {
			return false
		}
		salt, err1 := base64.StdEncoding.DecodeString(salt64)
		want, err2 := base64.StdEncoding.DecodeString(hash64)
		if err1 != nil || err2 != nil {
			return false
		}
		m := hmac.New(sha1.New, salt)
		m.Write([]byte(host))
		return hmac.Equal(m.Sum(nil), want)
	}
	// Names compare case-insensitively, as ssh's match_hostname does; a hashed
	// pattern is base64 and is not folded.
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "[") {
		name, _, ok := strings.Cut(pattern[1:], "]:")
		if !ok {
			return false
		}
		pattern = name
	}
	return sshWildcardMatch(pattern, host)
}

// sshWildcardMatch is OpenSSH's match_pattern: `*` is any run, `?` any one
// character, everything else literal.
func sshWildcardMatch(pattern, s string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for i := len(s); i >= 0; i-- {
				if sshWildcardMatch(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || s[0] != pattern[0] {
				return false
			}
		}
		pattern, s = pattern[1:], s[1:]
	}
	return s == ""
}

// pinDivergesError refuses a pinned host whose host ssh config resolves key to
// something the generated Host block does not reproduce.
func pinDivergesError(host, key, value, why string) error {
	return fmt.Errorf("identity.ssh: this host's ssh config sets %s %s for %s, and the ssh config "+
		"snug generates for the sandbox does not carry it: %s. Set identity.ssh.host to the name "+
		"ssh really connects to, or remove %s from the block that matches %s",
		key, policy.VisibleText(value), host, why, key, host)
}
