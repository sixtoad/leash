package enforcement

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fail-closed is the only posture. No production source may produce the
// "proxy-only" enforcement level or carry the proxy-only opt-out (flag, env
// var or capability): a grep over every non-test Go file of the module.
func TestNoProductionCodeProducesProxyOnly(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found from %s: %v", root, err)
	}
	forbidden := []string{`"proxy-only"`, "=proxy-only", "allow-proxy-only", "LEASH_ALLOW_PROXY_ONLY", "AllowProxyOnly", "LevelProxyOnly"}
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for _, f := range forbidden {
			if strings.Contains(string(data), f) {
				t.Errorf("%s contains %q", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("scanned only %d Go files; the walk did not cover the module", scanned)
	}
}
