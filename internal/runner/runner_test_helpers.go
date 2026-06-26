package runner

import (
	"context"
	"io"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	origExecWithInput := execWithInput
	execWithInput = func(context.Context, string, string, string, io.Reader) error {
		return nil
	}
	code := m.Run()
	execWithInput = origExecWithInput
	os.Exit(code)
}
