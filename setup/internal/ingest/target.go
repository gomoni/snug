// Package ingest reads what the host and the target directory already say
// about the sandbox the human wants, and turns it into a proposal. It decides
// nothing: its output is a list of actions the human is asked to accept, and
// the draft's own rules apply to each of them as they would to a request.
//
// Everything here is deterministic and reads names, not prose. The target is
// the least trusted input snug-setup has: whatever is in it, a hostile
// project controls, so nothing read from it is ever run, followed or shown
// without safe.Inline, and nothing it contains is allowed to become a grant by
// being read.
package ingest

import (
	"bufio"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"

	"github.com/gomoni/snug/setup/internal/safe"
)

// Bounds on what AnalyzeTarget touches, whatever the target holds.
const (
	maxEntries = 512      // names looked at in the target's top level
	maxSubdirs = 16       // subdirectories looked into for monorepo markers
	maxSubDirN = 256      // names looked at in each of those
	maxMarker  = 64 << 10 // bytes read from a marker file for its name
	maxName    = 80       // runes of a project name kept
)

// Lang is one language the target's marker files show.
type Lang struct {
	Name    string // go, node, python, rust
	Marker  string // the file that showed it, relative to the target
	Project string // the name the marker file declares, "" when not read
}

// TargetFacts is what the names in the target directory say.
type TargetFacts struct {
	Languages []Lang
	// Containers are the container build files found: Dockerfile*,
	// Containerfile*, compose and docker-compose files.
	Containers []string
	// Git is true when .git exists in the target, as a directory or as the
	// file a worktree or submodule has. Nothing inside it is read here.
	Git bool
	// RepoProfile is true when the target ships .snug or snug.toml. It is
	// reported and never read: profiles come from the human's own config.
	RepoProfile bool
	// Secrets are the names of files that look like credentials, names only.
	Secrets []string
	// Warnings are things the scan could not do or chose not to.
	Warnings []string
}

// EnvHint is a variable the analysis proposes to set, with the file that
// suggested it.
type EnvHint struct {
	Name, Value, Why string
}

// Pick is a built-in profile the analysis proposes to include.
type Pick struct {
	Name, Why string
	// Sure is true for what the target's own contents make plain; false for
	// what only the human can know (does the sandbox need the internet).
	Sure bool
}

// Proposal is what the facts add up to. Pure: Propose computes it from the
// facts alone.
type Proposal struct {
	Include []Pick
	Env     []EnvHint
}

// AnalyzeTarget looks at the top level of target, and one level into a few
// subdirectories for monorepo markers. It lists names through an os.Root on
// the target and Lstats each one, never follows a symlink, and reads at most
// maxMarker bytes from a go.mod, package.json, pyproject.toml or Cargo.toml
// that is a regular file, for the project name only.
//
// Abuse: a hostile target can plant a go.mod that is a symlink to a private
// key (so the name read would be key bytes), a FIFO (so a read would block), a
// directory of a million entries, or a module line carrying a terminal escape.
// Lstat at the name refuses the symlink, O_NONBLOCK plus the regular-file check
// refuses the FIFO, the entry counts bound the directory, and the name leaves
// here through safe.Inline and a length cap.
func AnalyzeTarget(target string) TargetFacts {
	var f TargetFacts
	root, err := os.OpenRoot(target)
	if err != nil {
		f.Warnings = append(f.Warnings, "cannot open the target directory: "+safe.Inline(err.Error()))
		return f
	}
	defer root.Close()

	names, trunc := listDir(root, ".", maxEntries)
	if trunc {
		f.Warnings = append(f.Warnings, "the target has more than 512 entries; only the first were looked at.")
	}
	scan(root, "", names, &f)

	subs := 0
	for _, n := range names {
		if subs >= maxSubdirs {
			break
		}
		if strings.HasPrefix(n, ".") || skipDir[n] {
			continue
		}
		fi, err := root.Lstat(n)
		if err != nil || !fi.IsDir() {
			continue
		}
		subs++
		sub, _ := listDir(root, n, maxSubDirN)
		scan(root, n+"/", sub, &f)
	}
	return f
}

var skipDir = map[string]bool{"node_modules": true, "vendor": true, "target": true, "dist": true, "build": true, "__pycache__": true}

func listDir(root *os.Root, dir string, limit int) ([]string, bool) {
	d, err := root.Open(dir)
	if err != nil {
		return nil, false
	}
	defer d.Close()
	ents, err := d.ReadDir(limit + 1)
	if err != nil && err != io.EOF && len(ents) == 0 {
		return nil, false
	}
	trunc := len(ents) > limit
	if trunc {
		ents = ents[:limit]
	}
	out := make([]string, len(ents))
	for i, e := range ents {
		out[i] = e.Name()
	}
	slices.Sort(out)
	return out, trunc
}

// scan reads the markers among names, which are in prefix ("" for the target
// itself, "dir/" for a subdirectory). Git, repo-profile and secret names count
// only at the top level.
func scan(root *os.Root, prefix string, names []string, f *TargetFacts) {
	top := prefix == ""
	has := func(n string) bool { return slices.Contains(names, n) }
	add := func(l Lang) {
		if !slices.ContainsFunc(f.Languages, func(x Lang) bool { return x.Name == l.Name && x.Marker == l.Marker }) {
			f.Languages = append(f.Languages, l)
		}
	}
	for _, n := range names {
		low := strings.ToLower(n)
		switch {
		case low == "dockerfile" || strings.HasPrefix(low, "dockerfile.") || strings.HasSuffix(low, ".dockerfile") ||
			low == "containerfile" || strings.HasPrefix(low, "containerfile.") || strings.HasSuffix(low, ".containerfile"),
			isComposeName(low):
			f.Containers = append(f.Containers, prefix+n)
		}
		if !top {
			continue
		}
		switch {
		case n == ".git":
			f.Git = true
		case n == ".snug" || n == "snug.toml":
			f.RepoProfile = true
		case low == ".env" || strings.HasPrefix(low, ".env.") && low != ".env.example" && low != ".env.sample" && low != ".env.template",
			strings.HasSuffix(low, ".pem"), strings.HasSuffix(low, ".p12"), strings.HasSuffix(low, ".pfx"),
			strings.HasPrefix(n, "id_") && !strings.HasSuffix(n, ".pub"):
			f.Secrets = append(f.Secrets, n)
		}
	}
	if has("go.mod") {
		add(Lang{"go", prefix + "go.mod", readName(root, prefix+"go.mod", goModule)})
	}
	if has("package.json") {
		add(Lang{"node", prefix + "package.json", readName(root, prefix+"package.json", jsonName)})
	}
	switch {
	case has("pyproject.toml"):
		add(Lang{"python", prefix + "pyproject.toml", readName(root, prefix+"pyproject.toml", tomlName("project"))})
	case has("uv.lock"):
		add(Lang{"python", prefix + "uv.lock", ""})
	case has("Pipfile"):
		add(Lang{"python", prefix + "Pipfile", ""})
	case has("setup.py"):
		add(Lang{"python", prefix + "setup.py", ""})
	default:
		for _, n := range names {
			if strings.HasPrefix(n, "requirements") && strings.HasSuffix(n, ".txt") {
				add(Lang{"python", prefix + n, ""})
				break
			}
		}
	}
	if has("Cargo.toml") {
		add(Lang{"rust", prefix + "Cargo.toml", readName(root, prefix+"Cargo.toml", tomlName("package"))})
	}
}

func isComposeName(low string) bool {
	for _, p := range []string{"docker-compose", "compose"} {
		if strings.HasPrefix(low, p) && (strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml")) {
			rest := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(low, p), ".yaml"), ".yml")
			if rest == "" || rest[0] == '.' || rest[0] == '-' {
				return true
			}
		}
	}
	return false
}

// readName reads the regular file name in root, at most maxMarker bytes, and
// returns what parse finds in it, cleaned and shortened. A symlink at the name,
// anything that is not a regular file and any error give "".
func readName(root *os.Root, name string, parse func(io.Reader) string) string {
	li, err := root.Lstat(name)
	if err != nil || li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() {
		return ""
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	n := parse(io.LimitReader(f, maxMarker))
	n = safe.Inline(n)
	if r := []rune(n); len(r) > maxName {
		n = string(r[:maxName-3]) + "..."
	}
	return strings.TrimSpace(n)
}

func goModule(r io.Reader) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(l, "module"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			return strings.Trim(strings.TrimSpace(rest), "\"`")
		}
	}
	return ""
}

func jsonName(r io.Reader) string {
	var v struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r).Decode(&v) != nil {
		return ""
	}
	return v.Name
}

// tomlName finds `name = "..."` inside the [table] section, line by line. It
// is not a TOML parser and does not need to be: a file it misreads yields an
// empty or wrong project name on the screen, never a grant.
func tomlName(table string) func(io.Reader) string {
	return func(r io.Reader) string {
		sc := bufio.NewScanner(r)
		in := false
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(l, "[") {
				in = l == "["+table+"]"
				continue
			}
			if !in {
				continue
			}
			if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == "name" {
				v = strings.TrimSpace(v)
				if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
					if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
						return v[1 : 1+end]
					}
				}
				return ""
			}
		}
		return ""
	}
}

// Propose computes the proposal for t. Sure picks and env hints are what the
// target's own files make plain; the unsure picks are listed so the human can
// ask for them, and never go on a card.
func Propose(t TargetFacts) Proposal {
	var p Proposal
	if t.Git {
		p.Include = append(p.Include, Pick{"@git", ".git", true})
	}
	seen := map[string]bool{}
	hint := func(name, value, why string) {
		if !seen[name] {
			seen[name] = true
			p.Env = append(p.Env, EnvHint{name, value, why})
		}
	}
	for _, l := range t.Languages {
		m := path.Base(l.Marker)
		switch l.Name {
		case "go":
			hint("GOMODCACHE", "{target}/.cache/go-mod", m)
			hint("GOCACHE", "{target}/.cache/go-build", m)
			p.Include = append(p.Include, Pick{"@net", "go mod download", false})
		case "node":
			hint("NPM_CONFIG_CACHE", "{target}/.cache/npm", m)
			p.Include = append(p.Include, Pick{"@net", "npm install", false})
		case "python":
			hint("PIP_CACHE_DIR", "{target}/.cache/pip", m)
			if m == "uv.lock" {
				hint("UV_CACHE_DIR", "{target}/.cache/uv", m)
			}
			p.Include = append(p.Include, Pick{"@net", "pip install", false})
		case "rust":
			hint("CARGO_HOME", "{target}/.cache/cargo", m)
			p.Include = append(p.Include, Pick{"@net", "cargo fetch", false})
		}
	}
	if len(t.Containers) > 0 {
		build := slices.ContainsFunc(t.Containers, func(n string) bool { return !isComposeName(strings.ToLower(path.Base(n))) })
		if build {
			p.Include = append(p.Include, Pick{"@podman-build", path.Base(t.Containers[0]), false})
		} else {
			p.Include = append(p.Include, Pick{"@podman-socket", path.Base(t.Containers[0]), false})
		}
		p.Include = append(p.Include, Pick{"@net", "container images", false})
	}
	p.Include = mergePicks(p.Include)
	return p
}

// mergePicks joins picks of one name into the first, reasons joined; a pick is
// sure only if every one of them was.
func mergePicks(in []Pick) []Pick {
	var out []Pick
	for _, p := range in {
		i := slices.IndexFunc(out, func(q Pick) bool { return q.Name == p.Name })
		if i < 0 {
			out = append(out, p)
			continue
		}
		if !strings.Contains(out[i].Why, p.Why) {
			out[i].Why += ", " + p.Why
		}
		out[i].Sure = out[i].Sure && p.Sure
	}
	return out
}

// Facts is everything ingest found.
type Facts struct {
	Target TargetFacts
}

// Gather runs every analysis.
func Gather(target string) Facts { return Facts{Target: AnalyzeTarget(target)} }
