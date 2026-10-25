package ingest

import (
	"bufio"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/safe"
)

// SSHHost is one `Host` block of an ssh_config: the patterns it applies to and
// the three keywords snug-setup reads from it. Everything else in the file is
// ignored, and a `Match` block is skipped whole.
type SSHHost struct {
	Patterns      []string
	HostName      string
	User          string
	IdentityFiles []string
}

// SSHFacts is what the public side of ~/.ssh says about which key goes where.
type SSHFacts struct {
	Hosts []SSHHost
	// Known are the host names in known_hosts; hashed entries have none.
	Known map[string]bool
	// Signers maps a principal (an email, usually) from allowed_signers to the
	// key fingerprints it lists.
	Signers  map[string][]string
	Warnings []string
}

const (
	maxSSHFile  = 256 << 10
	maxIncludes = 8
	maxHosts    = 256
)

// ParseSSHConfig reads Host, HostName, User and IdentityFile from an
// ssh_config. Keywords are case-insensitive, values may be quoted or follow
// `=`; Include is the loader's business and Match blocks are skipped.
func ParseSSHConfig(r io.Reader) []SSHHost {
	var out []SSHHost
	var cur *SSHHost
	skip := false
	sc := bufio.NewScanner(io.LimitReader(r, maxSSHFile))
	for sc.Scan() {
		kw, val := splitKeyword(sc.Text())
		switch strings.ToLower(kw) {
		case "host":
			skip = false
			if len(out) >= maxHosts {
				return out
			}
			out = append(out, SSHHost{Patterns: fields(val)})
			cur = &out[len(out)-1]
		case "match":
			skip, cur = true, nil
		case "hostname":
			if cur != nil && !skip {
				cur.HostName = clean(first(val))
			}
		case "user":
			if cur != nil && !skip {
				cur.User = clean(first(val))
			}
		case "identityfile":
			if cur != nil && !skip {
				cur.IdentityFiles = append(cur.IdentityFiles, clean(first(val)))
			}
		}
	}
	return out
}

func clean(s string) string { return cut(s) }

func splitKeyword(l string) (kw, val string) {
	l = strings.TrimSpace(l)
	if l == "" || l[0] == '#' {
		return "", ""
	}
	i := strings.IndexAny(l, " \t=")
	if i < 0 {
		return l, ""
	}
	return l[:i], strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(l[i:]), "="))
}

func fields(v string) []string {
	var out []string
	for _, f := range strings.Fields(v) {
		out = append(out, strings.Trim(f, `"`))
	}
	return out
}

func first(v string) string {
	f := fields(v)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// StemsFor returns the key stems (file name without .pub) that the blocks give
// host, most specific first: a block whose pattern equals host, then one whose
// HostName equals it, then a wildcard that matches it. An IdentityFile is
// reduced to its base name; its contents are never opened, because the .pub
// beside it is what snug-setup lists.
func StemsFor(hosts []SSHHost, host string) []string {
	host = strings.ToLower(host)
	var exact, byName, wild []string
	for _, h := range hosts {
		stems := make([]string, 0, len(h.IdentityFiles))
		for _, f := range h.IdentityFiles {
			stems = append(stems, strings.TrimSuffix(path.Base(f), ".pub"))
		}
		switch {
		case slices.ContainsFunc(h.Patterns, func(p string) bool { return strings.ToLower(p) == host }):
			exact = append(exact, stems...)
		case strings.ToLower(h.HostName) == host:
			byName = append(byName, stems...)
		case matchesPatterns(h.Patterns, host):
			wild = append(wild, stems...)
		}
	}
	var out []string
	for _, s := range slices.Concat(exact, byName, wild) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// stemFor is the first of StemsFor's stems and the patterns of the Host line
// it came from, as the config spells them ("*" for `Host *`): what a reason
// shows, rather than the remote's host, which the project chose.
func stemFor(hosts []SSHHost, host string) (stem, patterns string) {
	stems := StemsFor(hosts, host)
	if len(stems) == 0 {
		return "", ""
	}
	low := strings.ToLower(host)
	for _, pass := range []func(SSHHost) bool{
		func(h SSHHost) bool {
			return slices.ContainsFunc(h.Patterns, func(p string) bool { return strings.ToLower(p) == low })
		},
		func(h SSHHost) bool { return strings.ToLower(h.HostName) == low },
		func(h SSHHost) bool { return matchesPatterns(h.Patterns, low) },
	} {
		for _, h := range hosts {
			if !pass(h) {
				continue
			}
			for _, f := range h.IdentityFiles {
				if strings.TrimSuffix(path.Base(f), ".pub") == stems[0] {
					return stems[0], strings.Join(h.Patterns, " ")
				}
			}
		}
	}
	return stems[0], ""
}

// MatchHost returns the key stem the ssh config gives host and the patterns of
// the Host line it came from, as the config spells them. Both are empty when
// no block gives host a key; patterns alone is empty when the Host line
// cannot be found again.
func MatchHost(hosts []SSHHost, host string) (stem, patterns string) { return stemFor(hosts, host) }

// matchesPatterns applies ssh's Host rule: a name matches when some positive
// pattern matches and no `!` pattern does.
func matchesPatterns(pats []string, host string) bool {
	ok := false
	for _, p := range pats {
		neg := strings.HasPrefix(p, "!")
		m, _ := path.Match(strings.ToLower(strings.TrimPrefix(p, "!")), host)
		if m && neg {
			return false
		}
		ok = ok || (m && !neg)
	}
	return ok
}

// ParseKnownHosts returns the host names in a known_hosts file: the first
// field, comma separated, with [host]:port reduced to host. Hashed entries
// (|1|...) and marker lines' markers are skipped.
func ParseKnownHosts(r io.Reader) map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(io.LimitReader(r, 4<<20))
	for sc.Scan() && len(out) < 4096 {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && strings.HasPrefix(f[0], "@") {
			f = f[1:]
		}
		if len(f) < 3 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], "|") {
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			h = strings.TrimPrefix(h, "!")
			if strings.HasPrefix(h, "[") {
				if e := strings.Index(h, "]"); e > 0 {
					h = h[1:e]
				}
			}
			if h != "" && !strings.ContainsAny(h, "*?") {
				out[strings.ToLower(clean(h))] = true
			}
		}
	}
	return out
}

// ParseAllowedSigners maps each principal of an allowed_signers file to the
// SHA256 fingerprints of the keys listed for it. A line is
// `principals [options] key-type base64 [comment]`; options are skipped.
func ParseAllowedSigners(r io.Reader) map[string][]string {
	out := map[string][]string{}
	sc := bufio.NewScanner(io.LimitReader(r, maxSSHFile))
	for sc.Scan() && len(out) < 1024 {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.Fields(l)
		k := slices.IndexFunc(f, func(s string) bool {
			return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-") || strings.HasPrefix(s, "sk-")
		})
		if k < 1 || k+1 >= len(f) {
			continue
		}
		fp, err := hostfacts.FingerprintOf(f[k+1])
		if err != nil {
			continue
		}
		for _, p := range strings.Split(f[0], ",") {
			p = clean(strings.Trim(p, `"`))
			if p != "" && !slices.Contains(out[p], fp) {
				out[p] = append(out[p], fp)
			}
		}
	}
	return out
}

// LoadSSH reads ~/.ssh/config (and the files it Includes from inside ~/.ssh),
// ~/.ssh/known_hosts and the allowed_signers file at signersPath when it is
// not "". Nothing else under ~/.ssh is opened: not a private key, not
// authorized_keys, not an IdentityFile.
//
// Abuse: ~/.ssh is the human's, but the files in it can be symlinks, FIFOs or
// huge, and an Include is a path chosen by whoever wrote the config. Every
// open goes through an os.Root on ~/.ssh (so an Include cannot read outside it,
// not even through a link), regular files only, non-blocking, size-capped, at
// most maxIncludes files. A missing file is not an error.
func LoadSSH(home, signersPath string) SSHFacts {
	f := SSHFacts{Known: map[string]bool{}, Signers: map[string][]string{}}
	dir := filepath.Join(home, ".ssh")
	if root, err := os.OpenRoot(dir); err == nil {
		defer root.Close()
		loaded := 0
		var load func(name string, depth int)
		load = func(name string, depth int) {
			if loaded >= maxIncludes || depth > 3 {
				return
			}
			loaded++
			b, err := readSmallIn(root, name, maxSSHFile)
			if err != nil {
				return
			}
			f.Hosts = append(f.Hosts, ParseSSHConfig(strings.NewReader(string(b)))...)
			for _, l := range strings.Split(string(b), "\n") {
				if kw, val := splitKeyword(l); strings.EqualFold(kw, "include") {
					for _, pat := range fields(val) {
						pat = strings.TrimPrefix(strings.TrimPrefix(pat, "~/.ssh/"), dir+"/")
						if filepath.IsAbs(pat) || strings.HasPrefix(pat, "~") || strings.Contains(pat, "..") {
							continue
						}
						ms, _ := filepath.Glob(filepath.Join(dir, pat))
						slices.Sort(ms)
						for _, m := range ms {
							if rel, err := filepath.Rel(dir, m); err == nil {
								load(rel, depth+1)
							}
						}
					}
				}
			}
		}
		load("config", 0)
		if b, err := readSmallIn(root, "known_hosts", 4<<20); err == nil {
			f.Known = ParseKnownHosts(strings.NewReader(string(b)))
		}
	}
	if signersPath != "" {
		signersPath = expandHome(signersPath, home)
		if b, err := readSmall(signersPath); err == nil && int64(len(b)) <= maxSSHFile {
			f.Signers = ParseAllowedSigners(strings.NewReader(string(b)))
		} else if err != nil && !os.IsNotExist(err) {
			f.Warnings = append(f.Warnings, "not read: "+safe.Inline(signersPath))
		}
	}
	return f
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}
