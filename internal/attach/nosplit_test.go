package attach

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// childPathPragmas are the three compiler directives every function on B's
// path must carry, and each is load-bearing for a different instrumentation:
// nosplit removes the stack-growth prologue (issue #221 itself), norace the
// calls a -race build injects, nocheckptr the ones -d=checkptr injects. Any
// of the three reaches the Go runtime from a process that cannot run it.
var childPathPragmas = []string{"//go:nosplit", "//go:norace", "//go:nocheckptr"}

// rawSyscallEntryPoints are the only calls outside this package a function on
// B's path may make: golang.org/x/sys/unix's RawSyscall and RawSyscall6 are
// NOSPLIT assembly that jumps straight to syscall's own NOSPLIT assembly, so
// they issue the trap without a prologue and without entersyscall.
var rawSyscallEntryPoints = map[string]bool{
	"unix.RawSyscall":  true,
	"unix.RawSyscall6": true,
}

// notCalls are the conversions and builtins that share call syntax with a
// function call and are not one: no code is entered, so none of them can put
// the fork child in the runtime. unsafe.Pointer in particular appears all
// over this path.
var notCalls = map[string]bool{
	"unsafe.Pointer": true,
	"len":            true, "cap": true, "uintptr": true, "int": true,
	"uint32": true, "uint16": true, "byte": true, "string": true,
}

// TestEveryFunctionOnTheChildPathIsNosplit is the half the toolchain does not
// check. The LINKER enforces that a //go:nosplit chain fits the stack budget,
// so a frame that grows too large is a build failure — but nothing at all
// catches the edit that adds a call to a function which simply is not marked,
// and that edit reintroduces issue #221 exactly: rare, load-dependent, and
// invisible until a fork child wedges on a loaded machine.
//
// So this walks the real call graph from child() over the package's own
// source and asserts the property on the SET rather than at a site.
func TestEveryFunctionOnTheChildPathIsNosplit(t *testing.T) {
	fset := token.NewFileSet()
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test source files in this package — the walk below would be empty")
	}

	decls := map[string]*ast.FuncDecl{}
	for _, f := range files {
		{
			for _, d := range f.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
					decls[fn.Name.Name] = fn
				}
			}
		}
	}
	if decls["child"] == nil {
		t.Fatal("no child() in package attach — this walker would report an empty path " +
			"and pass vacuously")
	}

	seen := map[string]bool{}
	var external []string
	var walk func(name string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		fn := decls[name]
		if fn == nil {
			return
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if decls[f.Name] != nil {
					walk(f.Name)
				} else if !notCalls[f.Name] {
					external = append(external, name+" -> "+f.Name)
				}
			case *ast.SelectorExpr:
				if pkgIdent, ok := f.X.(*ast.Ident); ok {
					qualified := pkgIdent.Name + "." + f.Sel.Name
					if !rawSyscallEntryPoints[qualified] && !notCalls[qualified] {
						external = append(external, name+" -> "+qualified)
					}
				}
			}
			return true
		})
	}
	walk("child")

	// Positive control on the WALKER: a walk that found only child() itself
	// would report no violations and pass, so name what it must have found.
	for _, must := range []string{"child", "exitGroupRaw", "writeRaw", "readRaw", "prctlRaw",
		"rtSigprocmaskRaw", "dup3Raw", "setsidRaw", "ioctlSetCttyRaw", "waitStatusToExitCode"} {
		if !seen[must] {
			t.Errorf("the call-graph walk never reached %s(), which child() demonstrably "+
				"calls — the walker is broken and every assertion below is vacuous", must)
		}
	}

	for name := range seen {
		fn := decls[name]
		if fn == nil {
			continue
		}
		var doc string
		if fn.Doc != nil {
			doc = fn.Doc.Text()
			for _, c := range fn.Doc.List {
				doc += c.Text + "\n"
			}
		}
		for _, pragma := range childPathPragmas {
			if !strings.Contains(doc, pragma) {
				t.Errorf("%s() is reachable from child() but does not carry %s — a fork "+
					"child that calls it can enter the Go runtime and stop there forever "+
					"(issue #221)", name, pragma)
			}
		}
	}

	if len(external) > 0 {
		t.Errorf("functions reachable from child() call outside this package: %v. Only %v "+
			"may be called: everything else is an ordinary Go function whose prologue, "+
			"instrumentation or locks the fork child cannot survive",
			external, rawSyscallEntryPoints)
	}
}
