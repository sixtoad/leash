// Package managercontract defines the compatibility metadata shared by the
// released leash CLI and its privileged manager image.
package managercontract

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	Current = 1

	LabelContractVersion       = "io.leash.manager.contract.version"
	LabelMinCompatibleContract = "io.leash.manager.contract.min-compatible"
	LabelRevision              = "org.opencontainers.image.revision"
)

// Metadata is the compatibility and provenance advertised by a manager image.
type Metadata struct {
	ContractVersion       int
	MinCompatibleContract int
	Revision              string
}

// Parse rejects unlabeled and malformed images. A privileged manager with
// unverifiable provenance must never be started by a released CLI.
func Parse(labels map[string]string) (Metadata, error) {
	if len(labels) == 0 {
		return Metadata{}, fmt.Errorf("manager image has no OCI compatibility labels")
	}
	version, err := positiveIntLabel(labels, LabelContractVersion)
	if err != nil {
		return Metadata{}, err
	}
	minimum, err := positiveIntLabel(labels, LabelMinCompatibleContract)
	if err != nil {
		return Metadata{}, err
	}
	if minimum > version {
		return Metadata{}, fmt.Errorf("manager image contract range is invalid: minimum %d exceeds version %d", minimum, version)
	}
	revision := strings.TrimSpace(labels[LabelRevision])
	if revision == "" {
		return Metadata{}, fmt.Errorf("manager image is missing OCI label %q", LabelRevision)
	}
	return Metadata{ContractVersion: version, MinCompatibleContract: minimum, Revision: revision}, nil
}

// Validate requires the CLI's manager contract to fall inside the image's
// advertised range. expectedRevision is non-empty only for the generated
// release default; compatible explicit overrides intentionally need not share
// the CLI source revision.
func Validate(metadata Metadata, requiredContract int, expectedRevision string) error {
	if requiredContract < metadata.MinCompatibleContract || requiredContract > metadata.ContractVersion {
		return fmt.Errorf(
			"manager contract mismatch: CLI requires %d, image supports %d..%d",
			requiredContract, metadata.MinCompatibleContract, metadata.ContractVersion,
		)
	}
	expectedRevision = strings.TrimSpace(expectedRevision)
	if expectedRevision != "" && metadata.Revision != expectedRevision {
		return fmt.Errorf("manager revision mismatch: CLI expects %s, image reports %s", expectedRevision, metadata.Revision)
	}
	return nil
}

func positiveIntLabel(labels map[string]string, name string) (int, error) {
	raw := strings.TrimSpace(labels[name])
	if raw == "" {
		return 0, fmt.Errorf("manager image is missing OCI label %q", name)
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("manager image OCI label %q must be a positive integer, got %q", name, raw)
	}
	return value, nil
}
