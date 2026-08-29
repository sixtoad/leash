package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/strongdm/leash/internal/managercontract"
)

var (
	defaultLeashImage       = "ghcr.io/sixtoad/leash-manager:dev"
	expectedManagerRevision string
	requiredManagerContract = managercontract.Current
)

// SetManagerRelease applies values stamped into a released CLI. The image is a
// content-addressed ref in release builds; development builds retain :dev.
func SetManagerRelease(image, revision, contract string) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return fmt.Errorf("embedded manager image is empty")
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(contract))
	if err != nil || parsed <= 0 {
		return fmt.Errorf("embedded manager contract must be a positive integer, got %q", contract)
	}
	defaultLeashImage = image
	expectedManagerRevision = strings.TrimSpace(revision)
	requiredManagerContract = parsed
	return nil
}

func (r *runner) validateManagerImage(ctx context.Context) error {
	out, err := r.rt().Output(ctx, "image", "inspect", "--format", "{{json .Config.Labels}}", r.cfg.leashImage)
	if err != nil {
		return fmt.Errorf("inspect selected manager image %q: %w", r.cfg.leashImage, err)
	}
	var labels map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &labels); err != nil {
		return fmt.Errorf("inspect selected manager image %q: invalid OCI labels: %w", r.cfg.leashImage, err)
	}
	metadata, err := managercontract.Parse(labels)
	if err != nil {
		return fmt.Errorf("selected manager image %q is unverifiable: %w", r.cfg.leashImage, err)
	}
	expectedRevision := ""
	if r.cfg.leashImageSource == imageSourceDefault {
		expectedRevision = expectedManagerRevision
	}
	if err := managercontract.Validate(metadata, requiredManagerContract, expectedRevision); err != nil {
		return fmt.Errorf("selected manager image %q is incompatible: %w", r.cfg.leashImage, err)
	}
	return nil
}
