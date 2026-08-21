package transport_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbidden are import paths that must not escape their one package. The list is
// the enforcement mechanism for NFR19: the transport is behind an interface so
// that adopting WebTransport later deletes code instead of adding a second
// protocol. A convention nobody checks is not an abstraction.
var forbidden = map[string]string{
	"github.com/coder/websocket": "pkg/transport/websocket",
}

func TestNoTransportImplementationLeaks(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var violations []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "_bmad", "_bmad-output", "node_modules", "web", "vendor":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		dir := filepath.ToSlash(filepath.Dir(rel))
		for _, imp := range file.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			for bad, allowed := range forbidden {
				if p != bad && !strings.HasPrefix(p, bad+"/") {
					continue
				}
				if dir == allowed || strings.HasPrefix(dir, allowed+"/") {
					continue
				}
				violations = append(violations,
					rel+" imports "+p+" (only "+allowed+" may)")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	for _, v := range violations {
		t.Error(v)
	}
	if len(violations) > 0 {
		t.Log("Everything above pkg/transport speaks transport.Conn. If a new " +
			"transport is needed, add a package beside websocket and extend " +
			"`forbidden` — do not widen the exemption.")
	}
}

// TestForbiddenListIsLive guards against the check quietly passing because the
// dependency was renamed or dropped: if nothing imports the path at all, the
// entry is stale and the test is measuring nothing.
func TestForbiddenListIsLive(t *testing.T) {
	root := moduleRoot(t)
	for bad, allowed := range forbidden {
		found := false
		err := filepath.WalkDir(filepath.Join(root, allowed), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr == nil && strings.Contains(string(b), bad) {
				found = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", allowed, err)
		}
		if !found {
			t.Errorf("%q is on the forbidden list but %s does not import it — "+
				"the entry is stale and this check is asserting nothing", bad, allowed)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test directory")
		}
		dir = parent
	}
}
