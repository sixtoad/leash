package policycli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const legacy = `forbid (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/"] };
permit (principal, action == Action::"FileOpen", resource) when { resource in [Dir::"/a/b/"] };
`

func TestMigrateStdoutAndWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leash.cedar")
	if err := os.WriteFile(path, []byte(legacy), 0o640); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := Main([]string{"migrate", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `unless { resource in Dir::"/a/b/" }`) || !strings.Contains(errOut.String(), "exception:") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", out.String(), errOut.String())
	}
	if data, _ := os.ReadFile(path); string(data) != legacy {
		t.Fatal("without --write the file must not change")
	}

	out.Reset()
	errOut.Reset()
	if code := Main([]string{"migrate", "--write", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `@leash_semantics("cedar")`) || out.Len() != 0 {
		t.Fatalf("--write: file:\n%s\nstdout: %q", data, out.String())
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}

	errOut.Reset()
	if code := Main([]string{"migrate", "--write", path}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "already uses strict") {
		t.Fatalf("second migrate: %d %s", code, errOut.String())
	}
}

func TestMigrateErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Main(nil, &out, &errOut); code != 2 {
		t.Fatalf("no args: %d", code)
	}
	if code := Main([]string{"migrate"}, &out, &errOut); code != 1 {
		t.Fatalf("no file: %d", code)
	}
	path := filepath.Join(t.TempDir(), "bad.cedar")
	_ = os.WriteFile(path, []byte(`permit (principal, action in [Action::"FileOpen", Secret::Action::"Read"], resource);`), 0o600)
	if code := Main([]string{"migrate", path}, &out, &errOut); code != 1 {
		t.Fatalf("mixed namespaces must fail: %d", code)
	}
}
