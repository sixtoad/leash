package runner

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/managercontract"
)

type managerMetadataRuntime struct {
	labels string
	runs   [][]string
}

func (m *managerMetadataRuntime) Run(_ context.Context, args ...string) error {
	m.runs = append(m.runs, append([]string(nil), args...))
	return nil
}

func (m *managerMetadataRuntime) Output(_ context.Context, args ...string) (string, error) {
	m.runs = append(m.runs, append([]string(nil), args...))
	if len(args) >= 5 && args[0] == "image" && args[1] == "inspect" && args[2] == "--format" {
		return m.labels, nil
	}
	return "local-image", nil
}

func (m *managerMetadataRuntime) ExecWithInput(context.Context, string, string, io.Reader) error {
	return nil
}

func (m *managerMetadataRuntime) Cmd(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "true")
}

func (m *managerMetadataRuntime) Name() string { return "fake" }

func managerLabels(revision string, minimum, maximum int) string {
	return fmt.Sprintf(
		`{"%s":"%d","%s":"%d","%s":"%s"}`,
		managercontract.LabelContractVersion, maximum,
		managercontract.LabelMinCompatibleContract, minimum,
		managercontract.LabelRevision, revision,
	)
}

func TestValidateManagerImageRequiresDefaultRevision(t *testing.T) {
	rt := &managerMetadataRuntime{labels: managerLabels("old", 1, 1)}
	r := &runner{
		runtime: rt,
		cfg: config{
			leashImage:       "manager@sha256:expected",
			leashImageSource: imageSourceDefault,
		},
	}

	oldRevision := expectedManagerRevision
	expectedManagerRevision = "new"
	t.Cleanup(func() { expectedManagerRevision = oldRevision })

	err := r.validateManagerImage(context.Background())
	if err == nil || !strings.Contains(err.Error(), "revision mismatch") {
		t.Fatalf("validateManagerImage error = %v", err)
	}
	for _, args := range rt.runs {
		if len(args) > 0 && args[0] == "run" {
			t.Fatalf("validation started a container: %v", args)
		}
	}
}

func TestValidateManagerImageAllowsCompatibleExplicitOverride(t *testing.T) {
	rt := &managerMetadataRuntime{labels: managerLabels("custom", 1, 2)}
	r := &runner{
		runtime: rt,
		cfg: config{
			leashImage:       "example.test/custom:one",
			leashImageSource: imageSourceFlag,
		},
	}

	oldRevision := expectedManagerRevision
	expectedManagerRevision = "release-revision"
	t.Cleanup(func() { expectedManagerRevision = oldRevision })

	if err := r.validateManagerImage(context.Background()); err != nil {
		t.Fatalf("validateManagerImage: %v", err)
	}
}

func TestValidateManagerImageRejectsUnlabeledOverride(t *testing.T) {
	r := &runner{
		runtime: &managerMetadataRuntime{labels: "null"},
		cfg: config{
			leashImage:       "example.test/unlabeled:one",
			leashImageSource: imageSourceEnv,
		},
	}
	err := r.validateManagerImage(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unverifiable") {
		t.Fatalf("validateManagerImage error = %v", err)
	}
}
