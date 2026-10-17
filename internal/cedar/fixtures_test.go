package cedar

import (
	"path/filepath"
	"testing"
)

// The e2e policy fixtures (one is the exact policy Walk generates) must keep
// loading: in particular none carries a constraint #164 rejects.
func TestE2EPolicyFixturesCompile(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "e2e", "testdata", "*.cedar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no e2e policy fixtures found")
	}
	for _, f := range files {
		if _, err := CompileFile(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
