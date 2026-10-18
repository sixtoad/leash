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
	LabelVersion               = "org.opencontainers.image.version"

	// The leash binary inside the manager image describes its own CLI build
	// contract with the same vocabulary as `leash version --json`
	// (contractVersion, minCompatibleContract, capabilities), so a provisioner
	// can check the image without starting it. Capabilities are a
	// comma-separated list in the order `leash version --json` emits them.
	LabelCLIContractVersion       = "io.leash.manager.cli.contract.version"
	LabelCLIMinCompatibleContract = "io.leash.manager.cli.contract.min-compatible"
	LabelCapabilities             = "io.leash.manager.capabilities"
)

// CLIMetadata is what the image advertises about the leash binary it carries.
// Each field is nil (or Capabilities empty with CapabilitiesPresent false)
// when the image predates the label, so absence never reads as a real value.
type CLIMetadata struct {
	Version               string
	ContractVersion       *int
	MinCompatibleContract *int
	Capabilities          []string
	CapabilitiesPresent   bool
}

// ParseCLI reads the optional CLI-description labels. A label that is present
// but malformed is an error: an image that claims a surface it cannot spell
// must not be read as advertising nothing.
func ParseCLI(labels map[string]string) (CLIMetadata, error) {
	out := CLIMetadata{Version: strings.TrimSpace(labels[LabelVersion]), Capabilities: []string{}}
	for _, field := range []struct {
		name string
		dst  **int
	}{
		{LabelCLIContractVersion, &out.ContractVersion},
		{LabelCLIMinCompatibleContract, &out.MinCompatibleContract},
	} {
		raw, ok := labels[field.name]
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || value < 0 {
			return CLIMetadata{}, fmt.Errorf("manager image OCI label %q must be a non-negative integer, got %q", field.name, raw)
		}
		v := value
		*field.dst = &v
	}
	if out.ContractVersion != nil && out.MinCompatibleContract != nil && *out.MinCompatibleContract > *out.ContractVersion {
		return CLIMetadata{}, fmt.Errorf("manager image CLI contract range is invalid: minimum %d exceeds version %d", *out.MinCompatibleContract, *out.ContractVersion)
	}
	if raw, ok := labels[LabelCapabilities]; ok && strings.TrimSpace(raw) != "" {
		out.CapabilitiesPresent = true
		seen := map[string]bool{}
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				return CLIMetadata{}, fmt.Errorf("manager image OCI label %q has an empty capability name", LabelCapabilities)
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			out.Capabilities = append(out.Capabilities, name)
		}
	}
	return out, nil
}

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
