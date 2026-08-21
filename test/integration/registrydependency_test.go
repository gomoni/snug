//go:build integration

package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The suite's dependency on a public registry must be ONE dependency, written
// in ONE place, and this test is what keeps it that way.
//
// It exists because of how issue #235 actually went wrong. The dependency was
// a fully qualified image reference inside a python heredoc inside a helper
// function, and nothing on screen ever named it — so when Docker Hub started
// refusing anonymous pulls, the failure was a thirty-second budget expiring
// next to an unrelated cgroup warning. It was diagnosed as cgroup delegation,
// then as the container proxy, then as container preflight P5, then filed with
// a causal claim ("every container test needs the pull") that was itself
// wrong: two tests needed it, twenty did not, and the difference was invisible
// without grepping for the base image.
//
// A reviewer cannot see a new registry reference appear in a heredoc. This
// can.
//
// Deliberately NOT a `grep`. Two reasons, both measured elsewhere in this
// repository: a comment is not a dependency (this file is full of prose naming
// docker.io, and every such mention would be a false positive), and a grep
// pattern that matches nothing looks exactly like proof of absence — CLAUDE.md
// records a claim in this very repo that was "verified" by a `grep -rn 'a|b'`
// with no -E, which matched a literal pipe. Parsing the Go source and walking
// only string literals gets the first for free, and the positive control below
// gets the second.

// registryHosts are the registry hostnames a test could reach for. A short
// list of real registries rather than a pattern: the point is to catch a new
// dependency being ADDED, which happens by someone pasting a reference to a
// registry that exists.
var registryHosts = []string{
	"docker.io",
	"index.docker.io",
	"registry-1.docker.io",
	"quay.io",
	"ghcr.io",
	"gcr.io",
	"mirror.gcr.io",
	"public.ecr.aws",
	"registry.access.redhat.com",
	"registry.fedoraproject.org",
}

// registryLiteralsIn reports every string literal in src that names a registry
// host, as "line: literal", excluding the literals of the declarations named
// in allowedConsts (the one place the dependency is allowed to be written).
//
// src is parsed rather than scanned so that comments — which this suite writes
// a great many of, about registries — cannot register as dependencies.
func registryLiteralsIn(t *testing.T, name, src string, allowedConsts ...string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}

	// The positions of the values of the allowed declaration, so the one
	// legitimate reference is recognised by WHERE it is written and not by
	// what it says — a second copy of the same string elsewhere is still a
	// finding.
	allowedName := map[string]bool{}
	for _, n := range allowedConsts {
		allowedName[n] = true
	}
	allowed := map[token.Pos]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, id := range spec.Names {
			if !allowedName[id.Name] {
				continue
			}
			for _, v := range spec.Values {
				allowed[v.Pos()] = true
			}
		}
		return true
	})

	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || allowed[lit.Pos()] {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		// Line by line, and comment lines skipped. Most of the big literals
		// in this suite are python payloads, and those payloads carry their
		// own commentary about registries — runContainerAndCollectFn explains
		// why a locally built image has to be addressed as "localhost/<tag>"
		// and NOT as the docker.io name podman would otherwise expand it to.
		// Prose about a registry is not a dependency on one, in a Go comment
		// or in a python one; a line of code is.
		start := fset.Position(lit.Pos()).Line
		for i, line := range strings.Split(val, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			low := strings.ToLower(trimmed)
			for _, h := range registryHosts {
				if strings.Contains(low, h) {
					found = append(found, strconv.Itoa(start+i)+": "+trimmed)
					break
				}
			}
		}
		return true
	})
	return found
}

// hubHost and otherHost are the two hostnames the positive control plants.
// Taken from registryHosts by index rather than spelled again, so a control
// that plants something the detector was never taught to find is impossible.
var (
	hubHost   = registryHosts[0]
	otherHost = registryHosts[3]
)

func TestTheSuiteHasExactlyOneRegistryDependency(t *testing.T) {
	// POSITIVE CONTROL FIRST. Without it this test passes on a detector that
	// finds nothing at all — which is the shape of every vacuous check
	// CLAUDE.md's "a test that cannot fail is worse than no test" is about,
	// and the shape three of issue #235's own measurements turned out to have.
	planted := "package p\n" +
		"\n" +
		"// " + hubHost + " in a Go comment is not a dependency.\n" +
		"const ok = \"" + hubHost + "/library/alpine\"\n" +
		"\n" +
		"const payload = `\n" +
		"# " + otherHost + " in a payload comment is not a dependency either.\n" +
		"print(\"hello\")\n" +
		"`\n" +
		"\n" +
		"func f() string { return \"" + otherHost + "/sneaky/image:1\" }\n"

	control := registryLiteralsIn(t, "planted.go", planted, "ok")
	if len(control) != 1 || !strings.Contains(control[0], otherHost+"/sneaky") {
		t.Fatalf("the detector does not work, so a green result below would mean nothing. It "+
			"must report exactly ONE thing — the reference on a line of code outside the "+
			"allowed declaration — and neither of the two comments nor the allowed constant; "+
			"got %v", control)
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		// This file itself is a CATALOGUE of registry hostnames — the list
		// above, the planted control below, and the failure text that has to
		// quote one to be legible. Excluded by name rather than by some
		// cleverer rule, and the trade is stated: a dependency hidden in the
		// detector's own source would not be caught. That is acceptable here
		// and nowhere else, because this file starts no sandbox and runs no
		// payload — there is nothing in it that COULD contact a registry.
		if e.Name() == "registrydependency_test.go" {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		// dockerHubImage is the one declaration allowed to name a registry.
		// It lives in containerengine_test.go beside the single test that
		// contacts one; every other file gets no allowance at all.
		found := registryLiteralsIn(t, e.Name(), string(src), "dockerHubRegistry", "dockerHubImage", "dockerHubTag")
		for _, hit := range found {
			t.Errorf("%s:%s names a registry outside the dockerHub* constants. The suite is meant to have "+
				"exactly ONE registry dependency, reached through dockerHubRegistry/"+
				"dockerHubImage/dockerHubTag and exercised by one test that may skip when the "+
				"registry refuses (issue #235). If this reference is deliberate, it needs its "+
				"own gate that names the registry when it is unreachable — a pull with no such "+
				"gate is a thirty-second silence, and that silence has been misdiagnosed four "+
				"times", e.Name(), hit)
		}
	}
}

// testdata is deliberately out of scope above: those directories are separate
// main packages built for the host architecture, they contain no registry
// reference by construction (every one of them exists BECAUSE a `FROM scratch`
// image needs no base layer), and filepath.Walk-ing into them would trade a
// clear rule for a recursive one. If a probe ever does need a registry, it
// needs a design conversation, not a pattern match.
