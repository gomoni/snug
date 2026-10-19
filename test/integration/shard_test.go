//go:build integration

package integration

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// $SNUG_TEST_SHARD splits this package into two disjoint halves (issue #675):
//
//	engine   the tests that reach a container engine, and nothing else
//	sandbox  every other test
//
// Unset, the whole package runs, which is what `make integration` and a human
// want. CI sets it so the engine job runs only the tests a Tumbleweed container
// is there for; before, it ran the whole sandbox suite a second time.
//
// MEMBERSHIP IS READ FROM THE SOURCE, never from a list. A test is in the engine
// shard when its body — closures and subtests included — names one of
// engineGates, or a helper that does, transitively. A list of names is the
// catalogue that drifts; this is answered by the same file the test lives in,
// so a new engine test joins the shard by calling the gate it already has to
// call.
//
// The two directions are held differently, and both are held:
//
//   - A test the classifier misses would run in the sandbox shard and reach an
//     engine gate there. The gates call refuseOutsideEngineShard, so that is a
//     FAILURE naming the classifier, not a skip.
//   - A test the classifier over-includes runs in the engine shard only. It
//     still runs once; nothing is lost but a little engine-job time.
//
// So a test is in exactly one shard, and the only wrong answer that could go
// unnoticed is the harmless one.
const shardEnv = "SNUG_TEST_SHARD"

// engineGates are the helpers every engine test reaches before it touches an
// engine: hostEngine resolves the binary, requireEngine and requireRealEngine
// gate on it. Each one calls refuseOutsideEngineShard.
var engineGates = []string{"hostEngine", "requireEngine", "requireRealEngine"}

// refuseOutsideEngineShard is the half of the partition the classifier cannot
// hold by itself: a test that reached an engine gate while the run selected the
// sandbox shard was misclassified, and a skip would hide it from both jobs.
func refuseOutsideEngineShard(t *testing.T) {
	t.Helper()
	if os.Getenv(shardEnv) == "sandbox" {
		t.Fatalf("%s=sandbox, and this test reached an engine gate. engineTests "+
			"(shard_test.go) classified it as not touching an engine, so it runs in "+
			"neither job's engine tier. Make the call to %s visible in the test's "+
			"own source, or fix the classifier.", shardEnv, strings.Join(engineGates, "/"))
	}
}

// engineTests parses every _test.go file in dir and returns the names of the
// top-level Test functions whose bodies reach an engine gate.
//
// "Reach" is a fixed point over every function declared in the package: a
// function is an engine helper when its body names a gate or another engine
// helper. Names are matched as identifiers anywhere in the body, including a
// method selector and a function passed as a value, which over-includes on a
// name collision and never under-includes.
func engineTests(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	bodies := map[string][]*ast.BlockStmt{}
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				bodies[fd.Name.Name] = append(bodies[fd.Name.Name], fd.Body)
			}
		}
	}
	for _, g := range engineGates {
		if _, ok := bodies[g]; !ok {
			return nil, fmt.Errorf("engine gate %s is not declared in %s; engineGates "+
				"names a helper that no longer exists, so the engine shard would be empty", g, dir)
		}
	}

	engine := map[string]bool{}
	for _, g := range engineGates {
		engine[g] = true
	}
	names := func(body *ast.BlockStmt) (hit bool) {
		ast.Inspect(body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && engine[id.Name] {
				hit = true
			}
			return !hit
		})
		return hit
	}
	for changed := true; changed; {
		changed = false
		for name, bs := range bodies {
			if engine[name] {
				continue
			}
			for _, b := range bs {
				if names(b) {
					engine[name] = true
					changed = true
					break
				}
			}
		}
	}

	var tests []string
	for name := range engine {
		if strings.HasPrefix(name, "Test") && name != "TestMain" {
			tests = append(tests, name)
		}
	}
	slices.Sort(tests)
	return tests, nil
}

// selectShard turns $SNUG_TEST_SHARD into -test.run or -test.skip. It must run
// after flag.Parse and before m.Run.
//
// The sandbox shard ADDS to an existing -skip, because the Makefile already
// skips the signal tests there. The engine shard refuses an existing -run: two
// selections ANDed together is a third shard nobody named.
func selectShard() error {
	shard := os.Getenv(shardEnv)
	if shard == "" {
		return nil
	}
	tests, err := engineTests(".")
	if err != nil {
		return fmt.Errorf("%s=%s: classifying the engine tests: %w", shardEnv, shard, err)
	}
	if len(tests) == 0 {
		return fmt.Errorf("%s=%s: no test reaches an engine gate (%s), so the engine shard "+
			"is empty and the sandbox shard is everything; refusing a partition that "+
			"partitions nothing", shardEnv, shard, strings.Join(engineGates, ", "))
	}
	quoted := make([]string, len(tests))
	for i, n := range tests {
		quoted[i] = regexp.QuoteMeta(n)
	}
	re := "^(" + strings.Join(quoted, "|") + ")$"

	switch shard {
	case "engine":
		if prev := flag.Lookup("test.run").Value.String(); prev != "" {
			return fmt.Errorf("%s=engine selects with -run, and -run %q is already set", shardEnv, prev)
		}
		fmt.Printf("%s=engine: %d test(s) reach an engine gate\n", shardEnv, len(tests))
		return flag.Set("test.run", re)
	case "sandbox":
		skip := re
		if prev := flag.Lookup("test.skip").Value.String(); prev != "" {
			skip = prev + "|" + re
		}
		fmt.Printf("%s=sandbox: skipping %d engine test(s), which the engine job runs\n", shardEnv, len(tests))
		return flag.Set("test.skip", skip)
	default:
		return fmt.Errorf("%s=%q: the shards are \"engine\" and \"sandbox\"; unset it to run both", shardEnv, shard)
	}
}

// TestEngineShardClassifiesKnownEngineTests holds the classifier against tests
// whose engine dependence is reached only indirectly — through a helper, or from
// a closure inside a table — which is where a body scan for a gate's name would
// first go wrong.
func TestEngineShardClassifiesKnownEngineTests(t *testing.T) {
	budget(t)
	tests, err := engineTests(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d engine test(s): %s", len(tests), strings.Join(tests, " "))
	for _, want := range []string{
		// requireRealEngine called directly.
		"TestPodmanBuildIsFilteredEndToEnd",
		// the gate is inside a closure in a table, not in the test body.
		"TestASignalWhileThePayloadIsParkedNeverReleasesIt",
		// reaches hostEngine only through containerEngineEnv and startEngineRun.
		"TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns",
	} {
		if !slices.Contains(tests, want) {
			t.Errorf("%s is not classified as an engine test", want)
		}
	}
	for _, not := range []string{"TestMain", "TestEngineShardClassifiesKnownEngineTests"} {
		if slices.Contains(tests, not) {
			t.Errorf("%s is classified as an engine test and touches no engine", not)
		}
	}
}
